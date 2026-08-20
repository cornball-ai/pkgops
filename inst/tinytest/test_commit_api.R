# The exported per-verb commit API (R/commit_api.R): thin wrappers over
# .commit_session that add the verb/preview match check and pass the commit
# parameters through. Hermetic: the session ops, pkcheck, and (unused here, since
# the previews carry no records) the pkgstate reader are all behind seams.

H <- strrep("b", 64L)
CID <- "20250101000000000000-0123456789abcdef"
set_ops <- pkgops:::set_session_ops
set_pkcheck <- pkgops:::set_pkcheck

## A committable `ok` preview for a given verb. records = list() so step-6
## verification short-circuits (verified NA) and never touches the reader.
mkprev <- function(verb, resource = "nginx", packages = "nginx",
                   records = list(), advisory_verdict = "ok") {
    structure(list(schema_version = 1L, verb = verb, resource = resource,
                   plan_schema = 1L, plan_hash = H, autonomous = FALSE,
                   packages = packages, records = records,
                   advisory_verdict = advisory_verdict,
                   advisory_detail = NA_character_), class = "pkgops_preview")
}

newlog <- function() {
    e <- new.env(parent = emptyenv())
    e$seq <- character(0)
    e
}

## A recording fake ops set that commits cleanly (ok, effect TRUE).
ok_ops <- function(log) {
    list(capability = function(socket_path, plan_schema, ...) {
        log$seq <- c(log$seq, "capability")
        invisible(TRUE)
    }, refuse = function(socket_path, operation, resource, status, ...) {
        log$seq <- c(log$seq, "refuse")
        log$refuse <- list(operation = operation, status = status)
        list(correlation_id = CID, audit_persisted = TRUE)
    }, open = function(socket_path, operation, resource, plan_schema, plan_hash,
                       ...) {
        log$seq <- c(log$seq, "open")
        log$open <- list(operation = operation, resource = resource)
        structure(list(handle = "fake", correlation_id = CID),
                  class = "runix_effect_session")
    }, commit = function(session, packages, lock_timeout, deadline_ms, ...) {
        log$seq <- c(log$seq, "commit")
        log$commit <- list(packages = packages, lock_timeout = lock_timeout,
                           deadline_ms = deadline_ms)
        structure(list(session_status = "ok", status = "ok",
                       effect_issued = TRUE, correlation_id = CID,
                       detail = NULL), class = "runix_commit_result")
    }, write_outcome = function(session, record, ...) {
        log$seq <- c(log$seq, "write_outcome")
        list(status = "ok", detail = NULL)
    })
}

## Run an exported commit fn under the fakes; return list(res, log). res is the
## outcome (success) or the raised condition. interactive is forced (default
## FALSE) so the run is deterministic regardless of the test session's mode.
run_api <- function(fn, preview, interactive = FALSE, pkcheck = function(a) 0L,
                    log = newlog(), ...) {
    old_ops <- set_ops(ok_ops(log))
    old_pk <- set_pkcheck(pkcheck)
    on.exit({
        set_ops(old_ops)
        set_pkcheck(old_pk)
    })
    res <- tryCatch(fn(preview, socket_path = "/fake.sock",
                       interactive = interactive, ...),
                    condition = function(c) c)
    list(res = res, log = log)
}

## The nine exported verbs and the request verb each commits.
verbs <- list(list(fn = pkgops::apt_install, verb = "apt.install"),
              list(fn = pkgops::apt_remove, verb = "apt.remove"),
              list(fn = pkgops::apt_purge, verb = "apt.purge"),
              list(fn = pkgops::apt_hold, verb = "apt.hold"),
              list(fn = pkgops::apt_unhold, verb = "apt.unhold"),
              list(fn = pkgops::apt_update, verb = "apt.update"),
              list(fn = pkgops::apt_upgrade, verb = "apt.upgrade"),
              list(fn = pkgops::apt_dist_upgrade, verb = "apt.dist_upgrade"),
              list(fn = pkgops::apt_configure, verb = "apt.configure"))

## ---- each fn commits its OWN verb's preview, verb (not a path) reaches open ---
for (v in verbs) {
    out <- run_api(v$fn, mkprev(v$verb))
    expect_inherits(out$res, "pkgops_outcome")
    expect_equal(out$res$verb, v$verb)
    expect_equal(out$log$open$operation, v$verb)       # verb, never a path
    expect_equal(out$log$seq,
                 c("capability", "open", "commit", "write_outcome"))
}

## ---- each fn REFUSES a preview for a different verb, before anything opens ----
for (i in seq_along(verbs)) {
    v <- verbs[[i]]
    other <- verbs[[if (i == 1L) 2L else 1L]]$verb     # some other verb
    out <- run_api(v$fn, mkprev(other))
    expect_inherits(out$res, "pkgops_bad_request")
    expect_true(grepl("mismatch", conditionMessage(out$res)))
    expect_equal(length(out$log$seq), 0L)              # nothing opened or minted
}

## ---- a non-preview argument is refused, nothing opened -----------------------
out <- run_api(pkgops::apt_install, 42)
expect_inherits(out$res, "pkgops_bad_request")
expect_equal(length(out$log$seq), 0L)
out <- run_api(pkgops::apt_purge, list(verb = "apt.purge"))   # bare list
expect_inherits(out$res, "pkgops_bad_request")
expect_equal(length(out$log$seq), 0L)

## the not-a-preview message names the matching preview constructor (incl. the
## underscore verb, so the apt.<x> -> apt_<x> derivation is right)
out <- run_api(pkgops::apt_dist_upgrade, 42)
expect_true(grepl("apt_dist_upgrade_preview", conditionMessage(out$res)))

## ---- a non-ok preview is still refused through the wrapper -------------------
out <- run_api(pkgops::apt_install, mkprev("apt.install", advisory_verdict = "no_op"))
expect_inherits(out$res, "pkgops_bad_request")
expect_equal(length(out$log$seq), 0L)
for (verdict in c("held", "protected_package", "package_not_owned")) {
    out <- run_api(pkgops::apt_install,
                   mkprev("apt.install", advisory_verdict = verdict))
    expect_inherits(out$res, "pkgops_bad_request")
    expect_equal(length(out$log$seq), 0L)
}

## ---- commit parameters pass through to the session commit -------------------
out <- run_api(pkgops::apt_install, mkprev("apt.install"),
               lock_timeout = 300L, deadline_ms = 45000L)
expect_equal(out$log$commit$lock_timeout, 300L)
expect_equal(out$log$commit$deadline_ms, 45000L)
out <- run_api(pkgops::apt_update, mkprev("apt.update", resource = "@indexes",
                                          packages = character(0)))
expect_inherits(out$res, "pkgops_outcome")
expect_equal(out$log$commit$packages, character(0))    # whole-system: no targets

## ---- interactive = TRUE defers to the pkexec prompt: pkcheck is NOT run ------
never_pk <- function(a) stop("pkcheck must not run when interactive")
out <- run_api(pkgops::apt_install, mkprev("apt.install"), interactive = TRUE,
               pkcheck = never_pk)
expect_inherits(out$res, "pkgops_outcome")
expect_false("refuse" %in% out$log$seq)
expect_equal(out$log$seq, c("capability", "open", "commit", "write_outcome"))

## ---- interactive = FALSE runs pkcheck: a denial is a durably-audited refusal --
out <- run_api(pkgops::apt_install, mkprev("apt.install"), interactive = FALSE,
               pkcheck = function(a) 1L)
expect_inherits(out$res, "runix_unauthorized")
expect_equal(out$log$seq, c("capability", "refuse"))   # never opened the effect

## ---- an autonomous verb (apt.update) commits for a member (rc 0) ------------
out <- run_api(pkgops::apt_update, mkprev("apt.update", resource = "@indexes",
                                          packages = character(0)),
               pkcheck = function(a) if (grepl("update$", a)) 0L else 1L)
expect_inherits(out$res, "pkgops_outcome")
expect_equal(out$log$seq, c("capability", "open", "commit", "write_outcome"))

## ---- the exported surface is exactly the nine commit verbs ------------------
exp_commit <- c("apt_install", "apt_remove", "apt_purge", "apt_hold",
                "apt_unhold", "apt_update", "apt_upgrade", "apt_dist_upgrade",
                "apt_configure")
ns <- getNamespaceExports("pkgops")
expect_true(all(exp_commit %in% ns))                   # all nine exported
expect_true(all(paste0(exp_commit, "_preview") %in% ns))  # and their preview twins
