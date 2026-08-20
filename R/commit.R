## The commit-session orchestrator: the branched commit lifecycle of the contract
## (pkgops-plan.md 4), wiring runix's exported effect-session API to the pure
## classifier (R/classify.R), the polkit decision (R/polkit.R), and pkgstate
## verification (R/verify.R). Steps wired: 1 capability, 2 authorization (the
## polkit branch + the plain-intent terminal refusal), 3-5 open/commit/classify,
## 6 verification (capture the verdict on the outcome, never raise), 7
## write_outcome, 8 return/signal, with the outcome-closed-before-signal
## discipline (4.8). The mutation-capable path stays internal (.commit_session)
## and hermetic (fake session-ops + fake pkcheck + fake pkgstate reader) until the
## exported per-verb apt_<verb>() commit entrypoint (its own later increment,
## which adds the preview {verb,resource,plan_hash} match check).

## The broker's well-known AF_UNIX socket (matches runix's effect_capability
## default). A caller may override for a test/staging broker.
.PKGOPS_BROKER_SOCKET <- "/run/runix-audit.sock"

## The durable audit record pkgops hands to write_outcome. runix's C wraps it as
## {type:"write_outcome", binding, record} and the broker appends `record` to the
## audit line, stamping correlation_id (from the binding), phase, host, pid, actor,
## time and schema_version itself (durable-audit-contract.md 112).
##
## The record's field grammar is pinned to the broker's RECORD_SCHEMA
## (runix-audit-broker/src/json.c): a CLOSED allow-list of 16 domain fields, each
## with a fixed type, and the broker HARD-REJECTS (schema_invalid) any field not on
## the list or any broker-reserved key a client sends. The R adapter only rejects
## the reserved keys locally, so `.validate_record()` below is pkgops's own guard
## that the record it builds conforms -- the real allow-list + type enforcement is
## broker-side and proven in the VM-gated increment.
.PKGOPS_RECORD_FIELDS <- c(operation = "string", outcome = "string",
                           resource = "string", scope = "string",
                           audit_scope = "string", authorized_via = "string",
                           completion_method = "string",
                           job_result = "string", observed_reason = "string",
                           preview = "bool", effect_issued = "bool",
                           changed = "bool", state_changed = "bool",
                           observed_failed = "bool", elapsed = "number",
                           observed = "object")

## The broker-stamped keys a client must NEVER send (audit_broker_sink.R:200-202);
## including one is a runix_broker_reserved_field error at the broker.
.PKGOPS_RECORD_RESERVED <- c("schema_version", "record_type",
                             "correlation_id", "phase", "host", "pid",
                             "actor", "time", "binding", "broker")

## Whether a value matches its allow-list type: a scalar non-NA string/bool/number
## (number >= 0), or a named-list object.
.record_type_ok <- function(value, type) {
    switch(type, string = is.character(value) && length(value) == 1L &&
           !is.na(value), bool = is.logical(value) && length(value) == 1L &&
           !is.na(value), number = is.numeric(value) && length(value) == 1L &&
           !is.na(value) && value >= 0, object = is.list(value) &&
           (length(value) == 0L || !is.null(names(value))), FALSE)
}

## Assert a built record conforms BEFORE it is sent: fully named, no reserved key,
## every field on the allow-list, every value the right type. A non-conforming
## record is a pkgops bug -> fail closed, never sent (the real broker would reject
## it as schema_invalid; this catches it hermetically).
.validate_record <- function(rec) {
    nm <- names(rec)
    if (length(rec) > 0L && (is.null(nm) || any(!nzchar(nm)))) {
        stop_pkgops("internal: outcome record must be a fully-named list",
                    class = "pkgops_bad_request")
    }
    bad <- intersect(nm, .PKGOPS_RECORD_RESERVED)
    if (length(bad) > 0L) {
        stop_pkgops("internal: outcome record carries a broker-reserved field: ",
                    bad[1L], class = "pkgops_bad_request")
    }
    unknown <- setdiff(nm, names(.PKGOPS_RECORD_FIELDS))
    if (length(unknown) > 0L) {
        stop_pkgops("internal: outcome record carries a non-allow-list field: ",
                    unknown[1L], class = "pkgops_bad_request")
    }
    for (f in nm) {
        if (!.record_type_ok(rec[[f]], unname(.PKGOPS_RECORD_FIELDS[f]))) {
            stop_pkgops("internal: outcome record field `", f,
                        "` has the wrong type", class = "pkgops_bad_request")
        }
    }
    rec
}

## Build the durable record from a closed effect-intent outcome (VM-gate plan 2.2).
## Maps pkgops's outcome fields onto the allow-list: `verified` -> `changed` (but
## unknown, hence omitted, when the post-read failed -- pkgops cannot then claim the
## state did not change), `verify_detail` -> `observed_reason`, the captured
## post-state -> `observed`, plus `authorized_via` / `scope` / `preview` /
## `observed_failed` / `state_changed`. An optional field is OMITTED (never an
## explicit key) when NA/NULL: the broker treats an absent optional field as null,
## and this keeps the record deterministic. `effect_issued` is always a known
## boolean here (the effect-unknown path never reaches write_outcome).
## NB exact `[[` access throughout: `$` partial-matches, and `observed` is a strict
## prefix of `observed_failed`/`observed_reason`, so `outcome$observed` would
## resolve to the wrong field when the `observed` element is absent.
.outcome_record <- function(outcome) {
    ei <- outcome[["effect_issued"]]
    if (!(length(ei) == 1L && is.logical(ei) && !is.na(ei))) {
        ## defensive: write_outcome is only reached on a KNOWN-effect close
        stop_pkgops("internal: outcome record needs a known effect_issued",
                    class = "pkgops_bad_request")
    }
    ## a read failure leaves the functional verdict unknown -> omit `changed`,
    ## never write a false "did not change".
    changed <- if (isTRUE(outcome[["observed_failed"]])) {
        NA
    } else {
        outcome[["verified"]]
    }
    add <- function(rec, key, value) {
        if (is.null(value) || (is.atomic(value) && length(value) == 1L &&
                is.na(value))) {
            rec
        } else {
            rec[[key]] <- value
            rec
        }
    }
    rec <- list(operation = outcome[["verb"]], resource = outcome[["resource"]],
                effect_issued = ei, scope = "system", preview = FALSE)
    rec <- add(rec, "authorized_via", outcome[["authorized_via"]])
    rec <- add(rec, "observed", outcome[["observed"]])
    rec <- add(rec, "changed", changed)
    rec <- add(rec, "state_changed", outcome[["state_changed"]])
    rec <- add(rec, "observed_reason", outcome[["verify_detail"]])
    rec <- add(rec, "observed_failed", outcome[["observed_failed"]])
    .validate_record(rec)
}

## Map a persist failure (write_outcome status other than "ok") to a fail-closed
## condition. The effect may well have happened, but the durable record could not
## be written, so the intent is LEFT OPEN for reconciliation (4.8) and the caller
## is told the persist failed. A finer transport-tag -> condition mapping (as
## effect_session_open does) could be added later; the status/detail are carried
## in `data` regardless.
.raise_persist_failed <- function(outcome, wr) {
    if (is.null(wr$detail) || is.na(wr$detail)) {
        detail <- NA_character_
    } else {
        detail <- wr$detail
    }

    stop_pkgops("apt ", outcome$verb,
                ": the effect outcome could not be persisted (", wr$status, ")",
                class = "runix_broker_error",
                data = list(verb = outcome$verb, resource = outcome$resource,
                            plan_hash = outcome$plan_hash,
                            correlation_id = outcome$correlation_id,
                            effect_issued = outcome$effect_issued,
                            persist_status = wr$status, detail = detail))
}

## step 6 (contract 4.7 / VM-gate plan 2.2-2.4): cross-check the committed preview's
## resolved records against native ground truth and CAPTURE onto the outcome the
## verdict (verified/verify_detail), the observed POST-state, the post-read-failure
## flag, and the pre/post diff (state_changed, from the pre-commit `before`
## snapshot). OBSERVATIONAL -- it never changes the close/open decision and never
## raises: a disagreeing post-state is verified = FALSE + a detail, not a signal, so
## the outcome is still written (step 7) and outcome-before-signal holds. .verify()
## reads only the plan and the ground truth, never the helper's self-report (4.7);
## by the time this runs the commit has applied, so the reader sees the POST-state.
##
## Both .verify() and .observe() already normalize malformed reader/record data
## without raising; the extra tryCatch is belt-and-suspenders so a residual error
## can never abort before write_outcome.
.capture_post <- function(outcome, preview, before) {
    ## the verdict and the observed post-state derive from ONE cached read, so they
    ## describe the same snapshot (no double dpkg read, no post-lock TOCTOU).
    post_reader <- .freeze_reader(pkgstate_reader())
    v <- tryCatch(.verify(preview, post_reader), error = function(e) {
        list(verified = FALSE,
             detail = paste0("verification error: ", conditionMessage(e)))
    })
    after <- tryCatch(.observe(preview, post_reader),
                      error = function(e) list(state = NULL, read_failed = TRUE))
    outcome$verified <- v$verified
    outcome$verify_detail <- v$detail
    outcome$observed <- after$state
    outcome$observed_failed <- isTRUE(after$read_failed)
    outcome$state_changed <- .state_changed(before, after)
    outcome
}

## Run the commit and classify it into list(outcome, condition, leave_open),
## NEVER letting an exception escape before the caller can attempt the outcome
## close (4.3 step 8). A commit that RAISES is effect-UNKNOWN at the R boundary --
## pkgops cannot tell whether the child spawned and did work -- so the intent is
## left OPEN (fail-closed, never fabricating effect_issued=false) and the original
## runix condition is re-signaled after the (skipped) close.
##
## BOUNDARY [REVIEW]: this treats EVERY raised commit as effect-unknown. The one
## case that is provably no-effect is runix_capability_unavailable raised BEFORE
## any spawn (no child-side fd-close primitive); a future refinement could close
## that FALSE. Leaving it open is safe (reconciliation resolves an unmatched open
## intent as not-applied) and never fabricates a false effect.
.commit_and_classify <- function(ops, session, preview, lock_timeout,
                                 deadline_ms) {
    commit <- tryCatch(
                       ops$commit(session, packages = preview$packages,
                                  lock_timeout = lock_timeout, deadline_ms = deadline_ms),
                       error = function(e) e)
    if (inherits(commit, "condition")) {
        oc <- new_pkgops_outcome(correlation_id = session$correlation_id,
                                 verb = preview$verb, resource = preview$resource,
                                 plan_hash = preview$plan_hash,
                                 status = "effect_unknown", effect_issued = NA,
                                 condition = commit)
        return(list(outcome = oc, condition = commit, leave_open = TRUE))
    }
    .classify_commit(commit, preview)
}

## Handle a machine-mode polkit refusal (contract 4.4). No effect intent is ever
## opened: for a terminal refusal (unauthorized / approval_required) the attempt
## is recorded as a PLAIN intent + terminal outcome (effect_issued = FALSE) under
## one broker cid, then the mapped condition is signaled -- the record is the
## "close" that precedes the signal. A check that could not be run at all
## (check_failed) is fail-closed WITHOUT recording anything: there is no
## authoritative decision to persist, so pkgops raises and opens nothing.
##
## BOUNDARY [REVIEW]: check_failed -> pkgops_polkit_check_failed (no intent) is a
## pkgops-owned outcome the contract's taxonomy does not name. If the refuse
## RECORD itself fails (broker down / intent not durable), that raised condition
## propagates -- the refusal could not be recorded, which the caller must see;
## either way no effect ran.
.refuse <- function(ops, socket_path, preview, decision) {
    if (identical(decision, "check_failed")) {
        stop_pkgops("apt ", preview$verb,
                    ": the polkit authorization check could not be run",
                    class = "pkgops_polkit_check_failed",
                    data = list(verb = preview$verb, resource = preview$resource))
    }
    ## record the plain intent + terminal outcome; a raised record error means the
    ## refusal could not be persisted and propagates (nothing ran regardless).
    res <- ops$refuse(socket_path, operation = preview$verb,
                      resource = preview$resource, status = decision)
    ## The refusal is reported as a CLOSED terminal outcome only when it DURABLY
    ## persisted (both intent and outcome, audit_persisted == TRUE) under a real
    ## broker cid. A non-persisted or malformed result must NOT be signaled as a
    ## closed refusal -- that would claim an audit that never landed. Fail closed
    ## as a persistence error instead (like the effect path's persist failure).
    if (is.list(res)) {
        cid <- res$correlation_id
    } else {
        cid <- NULL
    }
    if (!isTRUE(res$audit_persisted) || !.valid_broker_cid(cid)) {
        stop_pkgops("apt ", preview$verb, ": the ", decision,
                    " outcome could not be durably recorded",
                    class = "runix_broker_error",
                    data = list(verb = preview$verb, resource = preview$resource,
                                decision = decision,
                                correlation_id = if (.valid_broker_cid(cid)) {
                    cid
                } else {
                    NA_character_
                },
                                audit_persisted = isTRUE(res$audit_persisted)))
    }
    cls <- .status_condition(decision) # unauthorized -> runix_unauthorized, etc.
    msg <- switch(decision,
                  unauthorized = sprintf("apt %s: authorization denied", preview$verb),
                  approval_required = sprintf(
            "apt %s: authorization requires an approval that was not granted",
            preview$verb),
                  sprintf("apt %s: refused (%s)", preview$verb, decision))
    cond <- .build_commit_condition(cls, msg, preview, cid, decision,
                                    effect_issued = FALSE)
    stop(cond)
}

## Drive the branched commit lifecycle for one committable preview and return the
## pkgops_outcome (success) or SIGNAL the mapped condition (failure), with the
## outcome ALWAYS written before the signal (4.8). Internal for now -- the public
## per-verb API that wraps this (with the preview {verb,resource,plan_hash} match
## check) lands once pkgstate verification completes the lifecycle.
.commit_session <- function(preview, socket_path = .PKGOPS_BROKER_SOCKET,
                            interactive = FALSE, lock_timeout = 0L,
                            deadline_ms = 120000L) {
    if (!inherits(preview, "pkgops_preview")) {
        stop_pkgops("commit requires a pkgops_preview (from apt_<verb>_preview())",
                    class = "pkgops_bad_request")
    }
    ## Only an `ok` preview is committable. This gate is the AUTHORITATIVE
    ## committability check, and a plan-hash-presence check is NOT a substitute:
    ## the three policy-refusal statuses (package_not_owned / held /
    ## protected_package) resolve a plan and carry a valid plan_hash BY DESIGN
    ## (pkgexec tools/preview.cc), so a refusal with a real digest would sail past
    ## a hash check. In the normal flow .preview() raises for any non-ok status,
    ## so a refusal never becomes a pkgops_preview -- but a hand-built or mutated
    ## object must still be refused here, before any capability call or intent.
    if (!identical(preview$advisory_verdict, "ok")) {
        vd <- if (.is_scalar_str(preview$advisory_verdict)) {
            preview$advisory_verdict
        } else {
            "<malformed>"
        }
        stop_pkgops("only an 'ok' preview is committable; this one is '", vd,
                    "' (a no_op or a policy refusal is never committable)",
                    class = "pkgops_bad_request",
                    data = list(verb = preview$verb,
                                advisory_verdict = preview$advisory_verdict))
    }
    ## defensive: an `ok` preview always carries its bound digest (the planner
    ## reply validator guarantees it); refuse a malformed one rather than open an
    ## intent with no plan to bind.
    if (is.na(preview$plan_hash) || is.na(preview$plan_schema)) {
        stop_pkgops("this 'ok' preview carries no plan digest to commit",
                    class = "pkgops_bad_request", data = list(verb = preview$verb))
    }
    ## recover the verb spec from the preview's request verb (for the polkit
    ## action); a hand-built preview with an unknown verb is refused here.
    verb_spec <- .verb_spec_for(preview$verb)
    if (is.null(verb_spec)) {
        stop_pkgops("unrecognised verb in preview: ",
            if (.is_scalar_str(preview$verb)) {
                shQuote(preview$verb)
            } else {
                "<malformed>"
            },
                    class = "pkgops_bad_request")
    }
    ops <- session_ops()

    ## step 1 -- effect-receipt capability negotiation (the real extension +
    ## plan-schema gate, not just peer auth). Raises runix_capability_unavailable
    ## on failure; nothing is opened or minted.
    ops$capability(socket_path, plan_schema = preview$plan_schema)

    ## step 2 -- POLKIT authorization (contract 4.4). Interactive mode defers to
    ## the pkexec prompt at the entrypoint spawn (authorize -> proceed); machine
    ## mode runs a non-interactive pkcheck. A machine-mode refusal never opens an
    ## effect intent: it records a PLAIN intent + terminal outcome and stops, so no
    ## unused effect receipt is minted. A failed check fails closed with nothing
    ## opened.
    dec <- .authorize(verb_spec, interactive)
    if (!identical(dec$decision, "authorized")) {
        return(.refuse(ops, socket_path, preview, dec$decision))
    }

    ## step 3 -- open the effect-required intent. The receipt + outcome binding
    ## are minted into wipeable C heap; R gets only an opaque PID-bound handle and
    ## the non-secret correlation id. Raises runix_broker_* on failure -> nothing
    ## committed, nothing to close.
    session <- ops$open(socket_path, operation = preview$verb,
                        resource = preview$resource,
                        plan_schema = preview$plan_schema,
                        plan_hash = preview$plan_hash)

    ## step 3.5 -- PRE-COMMIT snapshot (D7 = S-B): read the resolved records' state
    ## BEFORE the commit applies, so state_changed can be a real observed diff and
    ## is never inferred from effect_issued. On the same reader seam as verification
    ## (hermetic); never raises (a pre-read failure -> state_changed NA later).
    before <- .observe(preview)

    ## From here the intent is OPEN and every path must attempt to close it before
    ## returning or signaling. steps 4-5 (commit + classify) yield an
    ## (outcome, condition, leave_open) even if the commit itself raised.
    decided <- .commit_and_classify(ops, session, preview, lock_timeout,
                                    deadline_ms)

    ## authorization provenance is known independent of success/failure (the intent
    ## was authorized before it opened), so it is recorded on any classified outcome.
    ## effect-unknown (leave_open, no outcome to close) needs no record.
    if (!is.null(decided$outcome)) {
        decided$outcome$authorized_via <- dec$via
    }

    ## step 6 -- pkgstate VERIFICATION + post-state capture (contract 4.7 / VM-gate
    ## plan 2.2-2.4). Only on the success path (is.null(condition): an ok/no_op that
    ## will be RETURNED, not signaled): cross-check the committed preview against
    ## native ground truth and capture the verdict + the observed post-state + the
    ## pre/post diff onto the outcome. A known failure carries its own condition and
    ## a left-open effect is unknown, so neither has a trustworthy post-state. This
    ## is observational -- never raises, never changes close/open -- so the outcome
    ## is still written below and the outcome-before-signal order holds.
    if (is.null(decided$condition)) {
        decided$outcome <- .capture_post(decided$outcome, preview, before)
    }

    ## step 7 -- close the durable intent, UNLESS the effect is genuinely unknown
    ## (then the intent is left open for reconciliation, 4.8).
    if (!decided$leave_open) {
        wr <- ops$write_outcome(session, .outcome_record(decided$outcome))
        if (!identical(wr$status, "ok")) {
            ## persist failed -> the intent stays open; this supersedes any
            ## underlying failure condition, because the record is now the problem
            .raise_persist_failed(decided$outcome, wr)
        }
    }

    ## step 8 -- only now return (success) or signal (a closed known failure, or a
    ## left-open effect-unknown). The outcome, if any, was written above first.
    if (is.null(decided$condition)) {
        return(decided$outcome)
    }
    stop(decided$condition)
}
