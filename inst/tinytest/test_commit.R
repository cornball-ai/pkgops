# The commit-session orchestrator (R/commit.R): capability -> open -> commit ->
# classify -> [verify deferred] -> write_outcome -> signal, with the outcome
# ALWAYS written before the condition is signaled (contract 4.8). Hermetic: the
# four runix effect-session calls are replaced through the session-ops seam
# (R/session_ops.R), so nothing reaches a broker, a pkexec entrypoint, or dpkg.

H <- strrep("a", 64L)
CID <- "20250101000000000000-0123456789abcdef"
commit_session <- pkgops:::.commit_session
set_ops <- pkgops:::set_session_ops

## A committable preview: an `ok` plan carrying a bound digest.
mkprev <- function(verb = "apt.install", resource = "nginx", packages = "nginx",
                   plan_hash = H, plan_schema = 1L, advisory_verdict = "ok") {
    structure(list(schema_version = 1L, verb = verb, resource = resource,
                   plan_schema = plan_schema, plan_hash = plan_hash,
                   autonomous = FALSE, packages = packages, records = list(),
                   advisory_verdict = advisory_verdict,
                   advisory_detail = NA_character_), class = "pkgops_preview")
}
prev <- mkprev()

## A raw runix_commit_result (what runix's C hands back; the frame parse, cid
## check and delivery gate already happened there).
cr <- function(session_status, status = NULL, effect_issued = NA, detail = NULL) {
    list(session_status = session_status, status = status,
         effect_issued = effect_issued, correlation_id = CID, detail = detail)
}

## A recording fake ops set. `commit` is either a runix_commit_result list (the
## commit returns it) or, when raise=TRUE, a condition the commit throws. `cap`,
## `open` are conditions to throw at those steps (NULL = succeed). `wo` is the
## write_outcome reply.
newlog <- function() {
    e <- new.env(parent = emptyenv())
    e$seq <- character(0)
    e
}
ops_for <- function(log, commit, raise = FALSE,
                    wo = list(status = "ok", detail = NULL),
                    cap = NULL, open = NULL) {
    list(
        capability = function(socket_path, plan_schema, ...) {
            log$seq <- c(log$seq, "capability")
            log$cap <- list(socket_path = socket_path, plan_schema = plan_schema)
            if (!is.null(cap)) stop(cap)
            invisible(TRUE)
        },
        open = function(socket_path, operation, resource, plan_schema,
                        plan_hash, ...) {
            log$seq <- c(log$seq, "open")
            log$open <- list(socket_path = socket_path, operation = operation,
                             resource = resource, plan_schema = plan_schema,
                             plan_hash = plan_hash)
            if (!is.null(open)) stop(open)
            structure(list(handle = "fake", correlation_id = CID),
                      class = "runix_effect_session")
        },
        commit = function(session, packages, lock_timeout, deadline_ms, ...) {
            log$seq <- c(log$seq, "commit")
            log$commit <- list(packages = packages, lock_timeout = lock_timeout,
                               deadline_ms = deadline_ms)
            if (raise) stop(commit)
            structure(commit, class = "runix_commit_result")
        },
        write_outcome = function(session, record, ...) {
            log$seq <- c(log$seq, "write_outcome")
            log$record <- record
            wo
        })
}

## Run .commit_session under a fake ops set; return the outcome (success) or the
## raised condition (failure). Always restores the seam.
run_commit <- function(ops, preview = prev, ...) {
    old <- set_ops(ops)
    on.exit(set_ops(old))
    tryCatch(commit_session(preview, socket_path = "/fake.sock", ...),
             condition = function(c) c)
}

## ---- success: ok -> outcome returned, written, in the right order -----------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)))
expect_inherits(r, "pkgops_outcome")
expect_equal(r$status, "ok")
expect_identical(r$effect_issued, TRUE)
expect_equal(lg$seq, c("capability", "open", "commit", "write_outcome"))
expect_identical(lg$record$effect_issued, TRUE)          # the broker's gate
expect_equal(lg$record$operation, "apt.install")
expect_equal(lg$record$resource, "nginx")

## capability + open received the preview's schema/verb/resource/hash ----------
expect_equal(lg$cap$plan_schema, 1L)
expect_equal(lg$open$operation, "apt.install")           # verb, never a path
expect_equal(lg$open$resource, "nginx")
expect_equal(lg$open$plan_hash, H)
expect_equal(lg$open$plan_schema, 1L)
expect_equal(lg$commit$packages, "nginx")                # request targets

## ---- no_op result closes with effect FALSE ---------------------------------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "no_op", FALSE)))
expect_inherits(r, "pkgops_outcome")
expect_equal(r$status, "no_op")
expect_identical(lg$record$effect_issued, FALSE)
expect_true("write_outcome" %in% lg$seq)

## ---- known failure: outcome WRITTEN, then the mapped condition signaled -----
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "operation_failed", TRUE, detail = "dpkg exited 100")))
expect_inherits(r, "runix_operation_failed")
expect_inherits(r, "pkgops_error")
# outcome-closed-before-signal: write_outcome ran before we got the condition
expect_equal(lg$seq, c("capability", "open", "commit", "write_outcome"))
expect_identical(lg$record$effect_issued, TRUE)          # the effect happened
expect_equal(r$verb, "apt.install")
expect_equal(r$detail, "dpkg exited 100")

## ---- dpkg_broken: both effect_issued values close and signal ----------------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "dpkg_broken", TRUE)))
expect_inherits(r, "runix_dpkg_broken")
expect_identical(lg$record$effect_issued, TRUE)
expect_true("write_outcome" %in% lg$seq)
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "dpkg_broken", FALSE)))
expect_inherits(r, "runix_dpkg_broken")
expect_identical(lg$record$effect_issued, FALSE)         # pre-existing broken

## ---- apt_locked: closed, signaled, and retryable ---------------------------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "apt_locked", FALSE)))
expect_inherits(r, "runix_apt_locked")
expect_true(runix::is_retryable(r))                      # .onLoad registered it
expect_true("write_outcome" %in% lg$seq)                 # refused pre-commit, closed

## ---- unauthorized session: closed FALSE, runix_unauthorized ----------------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("unauthorized", effect_issued = FALSE)))
expect_inherits(r, "runix_unauthorized")
expect_identical(lg$record$effect_issued, FALSE)
expect_true("write_outcome" %in% lg$seq)

## ---- spawn_failed session: closed FALSE, pkgops_spawn_failed ----------------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("spawn_failed", effect_issued = FALSE)))
expect_inherits(r, "pkgops_spawn_failed")
expect_identical(lg$record$effect_issued, FALSE)
expect_true("write_outcome" %in% lg$seq)

## ---- effect_unknown session: intent LEFT OPEN, no write_outcome -------------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("effect_unknown", effect_issued = NA)))
expect_inherits(r, "runix_helper_bad_result")
expect_false("write_outcome" %in% lg$seq)                # intent left open
expect_equal(lg$seq, c("capability", "open", "commit"))

## ---- a RAISED commit is effect-unknown: left open, original re-signaled -----
lg <- newlog()
boom <- structure(class = c("runix_capability_unavailable", "runix_error",
                            "error", "condition"),
                  list(message = "no closefrom primitive", call = NULL))
r <- run_commit(ops_for(lg, boom, raise = TRUE))
expect_inherits(r, "runix_capability_unavailable")       # the original, re-signaled
expect_false("write_outcome" %in% lg$seq)                # left open
expect_equal(lg$seq, c("capability", "open", "commit"))

## ---- persist failure: write_outcome ran, effect open, broker_error ---------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE),
                        wo = list(status = "broker_error", detail = "disk full")))
expect_inherits(r, "runix_broker_error")
expect_true("write_outcome" %in% lg$seq)                 # attempted, then failed
expect_equal(r$persist_status, "broker_error")
expect_identical(r$effect_issued, TRUE)                  # effect may have happened

## ---- capability fails: nothing opened, nothing minted ----------------------
lg <- newlog()
capfail <- structure(class = c("runix_capability_unavailable", "runix_error",
                               "error", "condition"),
                     list(message = "no extension", call = NULL))
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE), cap = capfail))
expect_inherits(r, "runix_capability_unavailable")
expect_equal(lg$seq, "capability")                       # never reached open

## ---- open fails: never reached commit --------------------------------------
lg <- newlog()
openfail <- structure(class = c("runix_broker_unavailable", "runix_error",
                                "error", "condition"),
                      list(message = "no broker", call = NULL))
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE), open = openfail))
expect_inherits(r, "runix_broker_unavailable")
expect_equal(lg$seq, c("capability", "open"))            # commit never called

## ---- a no_op / hashless preview is refused before anything opens ------------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)),
                preview = mkprev(plan_hash = NA_character_, plan_schema = NA_integer_,
                                 advisory_verdict = "no_op"))
expect_inherits(r, "pkgops_bad_request")
expect_equal(length(lg$seq), 0L)                         # nothing minted

## ---- a non-preview argument is refused -------------------------------------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), preview = list(verb = "apt.install"))
expect_inherits(r, "pkgops_bad_request")
expect_equal(length(lg$seq), 0L)

## ---- a whole-system verb commits with no packages --------------------------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)),
                preview = mkprev(verb = "apt.update", resource = "@indexes",
                                 packages = character(0)))
expect_inherits(r, "pkgops_outcome")
expect_equal(lg$open$operation, "apt.update")
expect_equal(lg$commit$packages, character(0))
