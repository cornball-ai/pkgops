## The preview core: build a receipt-free request, spawn the unprivileged
## runix-apt-preview planner, strictly validate its one JSON line, and turn it
## into either an advisory `pkgops_preview` (ok / no_op) or a typed condition.
## A preview opens no intent, takes no lock, and mints nothing: it is advisory.
## The authoritative resolution happens later, under the dpkg lock, at commit
## time (a separate slice); a preview that drifts from that re-resolution is a
## safe availability refusal there, never a wrong mutation.

## The planner's fixed install path (pkgexec ships it here, on PATH). Unlike the
## root commit entrypoints, this is an unprivileged read-only binary, so there is
## no privilege boundary to protect with a hard-coded-only path; tests still
## avoid it entirely by injecting a fake runner.
.PREVIEW_BIN <- "/usr/bin/runix-apt-preview"

## The planner's nine closed statuses, and the four that carry a plan digest
## (pkgexec tools/preview.cc): ok and the three policy refusals resolve a plan
## and hash it; every other status has no digest.
.PREVIEW_STATUSES <- c("ok", "no_op", "schema_invalid", "resolve_failed",
                       "package_not_owned", "held", "protected_package",
                       "dpkg_broken", "internal")
.PREVIEW_HASH_STATUSES <- c("ok", "package_not_owned", "held",
                            "protected_package")

## The exact top-level key set the planner always emits (unavailable fields are
## JSON null, but the key is still present) -- checked so a reply with a missing
## or extra field is refused, never partially trusted.
.PREVIEW_KEYS <- c("schema_version", "status", "verb", "packages",
                   "plan_schema", "resource", "plan_hash", "records",
                   "detail")

## The statuses whose reply reflects a parsed-and-resolved request: they echo the
## verb, echo the requested packages, and carry a (possibly empty) resource
## string (pkgexec tools/preview.cc emit sites). schema_invalid is the sole
## pre-parse status -- its verb and resource are null and are not echoed.
.PREVIEW_RESOLVED <- c("ok", "no_op", "package_not_owned", "held",
                       "protected_package")

.or_na_chr <- function(x) {
    if (is.null(x)) {
        NA_character_
    } else {
        as.character(x)
    }
}

## Strict scalar predicates for validating the reply. A JSON number that is not
## integer-VALUED must never be truncated into the schema: `.exact_int(1.5, 1L)`
## is FALSE, so a `plan_schema` of 1.5 is refused rather than silently read as 1.
.exact_int <- function(x, val) {
    is.numeric(x) && length(x) == 1L && is.finite(x) && x == floor(x) &&
    x == val
}
.is_scalar_str <- function(x) {
    is.character(x) && length(x) == 1L && !is.na(x)
}
.is_str_or_null <- function(x) {
    is.null(x) || .is_scalar_str(x)
}
## janssonr decodes a JSON array to an unnamed list (any length, including 0 and
## 1) and a JSON scalar to an atomic vector, so `is.list` with no names is an
## exact "this is a JSON array" test -- a scalar `"nginx"` where an array is
## required fails it.
.is_json_array <- function(x) {
    is.list(x) && (length(x) == 0L || is.null(names(x)))
}
.is_json_object <- function(x) {
    is.list(x) && !is.null(names(x)) && all(nzchar(names(x)))
}

## A planner reply the issuer cannot trust (unparseable, wrong shape, exit code
## inconsistent with the status, a digest where there should be none or vice
## versa, an echo that does not match the request) is fail-closed as
## runix_preview_failed -- never salvaged into a usable plan.
.preview_bad <- function(..., data = list()) {
    reason <- paste0(...)
    stop_pkgops("preview helper returned an untrustworthy result: ", reason,
                class = "runix_preview_failed",
                data = c(list(reason = reason), data))
}

## Strict validation of the planner's single stdout line against the request
## that produced it. Returns the parsed object (with a checked `status`) or
## fails closed. Every check here is an integrity gate: the issuer trusts the
## preview's {verb, resource, plan_hash} only if the reply is exactly the shape
## the planner contract promises for that status.
.parse_preview_response <- function(res, verb_spec, req_packages) {
    out <- res$output[nzchar(res$output)]
    if (length(out) != 1L) {
        .preview_bad("expected one JSON line on stdout, got ", length(out))
    }
    parsed <- tryCatch(janssonr::from_json(out), error = function(e) e)
    if (inherits(parsed, "condition")) {
        .preview_bad("unparseable JSON (", conditionMessage(parsed), ")")
    }
    if (!is.list(parsed) || is.null(names(parsed))) {
        .preview_bad("response is not a JSON object")
    }
    ## exact top-level key set: neither a missing nor an extra field is tolerated
    if (length(parsed) != length(.PREVIEW_KEYS) ||
        !setequal(names(parsed), .PREVIEW_KEYS)) {
        .preview_bad("response keys are not exactly the nine planner fields")
    }
    ## schema_version is the integer-valued 1 (1.5 must NOT truncate to 1)
    if (!.exact_int(parsed$schema_version, 1L)) {
        .preview_bad("schema_version is not integer 1")
    }
    ## status is a scalar string from the closed nine
    status <- parsed$status
    if (!.is_scalar_str(status) || !status %in% .PREVIEW_STATUSES) {
        .preview_bad("status is not one of the nine planner statuses")
    }
    ## field types: strings where the planner emits strings, null tolerated only
    ## where it emits null (verb/resource are null for schema_invalid)
    if (!.is_str_or_null(parsed$verb)) {
        .preview_bad("verb is not a string or null")
    }
    if (!.is_str_or_null(parsed$resource)) {
        .preview_bad("resource is not a string or null")
    }
    if (!.is_str_or_null(parsed$plan_hash)) {
        .preview_bad("plan_hash is not a string or null")
    }
    if (!.is_str_or_null(parsed$detail)) {
        .preview_bad("detail is not a string or null")
    }
    ## plan_schema is either null or the integer-valued 1 (never truncated)
    if (!(is.null(parsed$plan_schema) || .exact_int(parsed$plan_schema, 1L))) {
        .preview_bad("plan_schema is neither null nor integer 1")
    }
    ## packages must be an actual JSON array of scalar strings, not a scalar
    if (!.is_json_array(parsed$packages) ||
        !all(vapply(parsed$packages, .is_scalar_str, logical(1)))) {
        .preview_bad("packages is not a JSON array of strings")
    }
    ## records must be an actual JSON array of JSON objects. The verb-specific
    ## field grammar within each record (transaction / hold / configure / update)
    ## is NOT validated here: in this preview slice the schema-1 plan_hash is the
    ## integrity authority and the records are advisory, carried verbatim. The
    ## per-field record grammar is deferred to the commit slice, where records
    ## feed pkgstate verification and the exact shape becomes load-bearing; it
    ## will be pinned there against real (VM-exercised) planner output.
    if (!.is_json_array(parsed$records) ||
        !all(vapply(parsed$records, .is_json_object, logical(1)))) {
        .preview_bad("records is not a JSON array of objects")
    }
    ## the planner exits 0 exactly for ok / no_op
    ok_exit <- status %in% c("ok", "no_op")
    if ((res$status == 0L) != ok_exit) {
        .preview_bad("exit status ", res$status, " inconsistent with '",
                     status, "'")
    }
    ## a digest is present exactly for the four hash-bearing statuses
    has_hash <- status %in% .PREVIEW_HASH_STATUSES
    if (has_hash) {
        if (is.null(parsed$plan_hash) ||
            !grepl("^[0-9a-f]{64}$", parsed$plan_hash)) {
            .preview_bad("plan_hash missing or not 64 lowercase hex for '",
                         status, "'")
        }
        if (!.exact_int(parsed$plan_schema, 1L)) {
            .preview_bad("plan_schema is not 1 for '", status, "'")
        }
    } else {
        if (!is.null(parsed$plan_hash)) {
            .preview_bad("plan_hash present for the non-digest status '",
                         status, "'")
        }
        if (!is.null(parsed$plan_schema)) {
            .preview_bad("plan_schema present for the non-digest status '",
                         status, "'")
        }
    }
    ## a resolved status echoes the verb and the requested packages IN ORDER, and
    ## carries a resource; schema_invalid is pre-parse (verb null, packages [],
    ## resource null) and is not echoed -- it fails closed below via its status.
    if (status != "schema_invalid") {
        if (!identical(parsed$verb, verb_spec$request_verb)) {
            .preview_bad("verb echo does not match the request")
        }
        got <- as.character(unlist(parsed$packages, use.names = FALSE))
        if (!identical(got, req_packages)) {
            .preview_bad("packages echo does not match the request ",
                         "(order-sensitive)")
        }
    }
    if (status %in% .PREVIEW_RESOLVED && is.null(parsed$resource)) {
        .preview_bad("resource is null for the resolved status '", status, "'")
    }
    parsed$status <- status
    parsed
}

## Build the advisory object for the two success statuses. Carries exactly what
## the hash bound: the verb, the canonical resource, the digest, the verb-
## specific records verbatim, and the original validated targets (never
## reconstructed from `resource`). `no_op` carries no digest (nothing to apply).
.new_preview <- function(verb_spec, packages, parsed) {
    schema <- if (is.null(parsed$plan_schema)) {
        NA_integer_
    } else {
        as.integer(parsed$plan_schema)
    }
    structure(list(
                   schema_version = 1L,
                   verb = verb_spec$request_verb,
                   resource = .or_na_chr(parsed$resource),
                   plan_schema = schema,
                   plan_hash = .or_na_chr(parsed$plan_hash),
                   autonomous = verb_spec$autonomous,
                   packages = packages,
                   records = if (is.null(parsed$records)) list() else parsed$records,
                   advisory_verdict = parsed$status,
                   advisory_detail = .or_na_chr(parsed$detail)),
              class = "pkgops_preview")
}

## Map a non-success planner status to its typed, fail-closed condition. The
## three policy refusals resolved a plan, so they carry its records + digest +
## offending package (in `detail`); the rest carry status/verb/resource/detail.
## Class names mirror the commit channel (pkgops-plan.md 6.4) so preview and
## commit never diverge on what "held" or "not owned" is called.
.raise_preview_status <- function(status, verb_spec, parsed) {
    cls <- switch(status, schema_invalid = "runix_preview_failed",
                  resolve_failed = "runix_resolve_failed",
                  package_not_owned = "runix_not_owned", held = "runix_held",
                  protected_package = "runix_protected",
                  dpkg_broken = "runix_dpkg_broken",
                  internal = "runix_helper_internal")
    detail <- .or_na_chr(parsed$detail)
    data <- list(status = status, verb = verb_spec$request_verb,
                 resource = .or_na_chr(parsed$resource), detail = detail)
    if (status %in% c("package_not_owned", "held", "protected_package")) {
        data$plan_hash <- parsed$plan_hash
        data$records <- parsed$records
    }
    if (!is.na(detail) && nzchar(detail)) {
        suffix <- paste0(" (", detail, ")")
    } else {
        suffix <- ""
    }

    msg <- switch(status,
                  schema_invalid = "the planner rejected the request as malformed",
                  resolve_failed = paste0("apt could not resolve the request", suffix),
                  package_not_owned = paste0("refused: a target is not rapt-owned", suffix),
                  held = paste0("refused: a target is held", suffix),
                  protected_package = paste0("refused: a protected package is affected", suffix),
                  dpkg_broken = paste0("dpkg is in a broken state", suffix),
                  internal = paste0("the planner reported an internal error", suffix))
    stop_pkgops(msg, class = cls, data = data)
}

## The shared entry every apt_<verb>_preview() delegates to: validate targets
## against the verb's arity, spawn the planner with a receipt-free JSON request,
## strictly validate the reply, and return an advisory object or raise.
.preview <- function(verb, packages = character(0)) {
    verb_spec <- .PKGOPS_VERBS[[verb]]
    if (is.null(verb_spec)) {
        ## an internal guard: the exported wrappers only ever pass the nine keys
        stop_pkgops("unknown verb: ", verb, class = "pkgops_bad_request")
    }
    packages <- .check_targets(verb_spec, packages)
    ## as.list() forces a JSON array even for a single target; encode_json_line
    ## would otherwise collapse a length-1 vector to a scalar the planner rejects
    req <- runix::encode_json_line(list(schema_version = 1L,
                                        verb = verb_spec$request_verb,
                                        packages = as.list(packages)))
    res <- runner()(.PREVIEW_BIN, character(0), req)
    parsed <- .parse_preview_response(res, verb_spec, packages)
    if (parsed$status %in% c("ok", "no_op")) {
        return(.new_preview(verb_spec, packages, parsed))
    }
    .raise_preview_status(parsed$status, verb_spec, parsed)
}

#' @export
print.pkgops_preview <- function(x, ...) {
    hash <- if (is.na(x$plan_hash)) {
        "<none>"
    } else {
        paste0(substr(x$plan_hash, 1L, 12L), "...")
    }
    tgt <- if (length(x$packages)) {
        paste(x$packages, collapse = ", ")
    } else {
        "(whole system)"
    }
    if (is.na(x$resource) || !nzchar(x$resource)) {
        resource <- "(none)"
    } else {
        resource <- x$resource
    }

    cat(sprintf("<pkgops preview: %s [%s]>\n", x$verb, x$advisory_verdict))
    cat(sprintf("  targets   : %s\n", tgt))
    cat(sprintf("  resource  : %s\n", resource))
    cat(sprintf("  records   : %d\n", length(x$records)))
    cat(sprintf("  digest    : %s (schema %s)\n", hash,
            if (is.na(x$plan_schema)) "-" else x$plan_schema))
    cat(sprintf("  autonomous: %s\n",
            if (x$autonomous) "yes (update/hold group)" else "no (auth_admin)"))
    cat("  advisory only: opens no intent, mints nothing\n")
    invisible(x)
}
