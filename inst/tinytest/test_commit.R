# The commit-session orchestrator (R/commit.R): capability -> open -> commit ->
# classify -> [verify deferred] -> write_outcome -> signal, with the outcome
# ALWAYS written before the condition is signaled (contract 4.8). Hermetic: the
# four runix effect-session calls are replaced through the session-ops seam
# (R/session_ops.R), so nothing reaches a broker, a pkexec entrypoint, or dpkg.

H <- strrep("a", 64L)
CID <- "20250101000000000000-0123456789abcdef"
commit_session <- pkgops:::.commit_session
set_ops <- pkgops:::set_session_ops
set_pkcheck <- pkgops:::set_pkcheck

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
                    cap = NULL, open = NULL,
                    refuse = list(correlation_id = CID, audit_persisted = TRUE),
                    refuse_err = NULL) {
    list(
        capability = function(socket_path, plan_schema, ...) {
            log$seq <- c(log$seq, "capability")
            log$cap <- list(socket_path = socket_path, plan_schema = plan_schema)
            if (!is.null(cap)) stop(cap)
            invisible(TRUE)
        },
        refuse = function(socket_path, operation, resource, status, ...) {
            log$seq <- c(log$seq, "refuse")
            log$refuse <- list(operation = operation, resource = resource,
                               status = status)
            if (!is.null(refuse_err)) stop(refuse_err)
            refuse
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
## raised condition (failure). Also installs a fake pkcheck (default: rc 0 ->
## authorized, so the effect-path tests reach step 3 hermetically); restores both.
run_commit <- function(ops, preview = prev, interactive = FALSE,
                       pkcheck = function(action) 0L, ...) {
    old_ops <- set_ops(ops)
    old_pk <- set_pkcheck(pkcheck)
    on.exit({
        set_ops(old_ops)
        set_pkcheck(old_pk)
    })
    tryCatch(commit_session(preview, socket_path = "/fake.sock",
                            interactive = interactive, ...),
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

## ---- a HASH-BEARING policy refusal is NOT committable -----------------------
## held / protected_package / package_not_owned resolve a plan and carry a valid
## plan_hash by design, so the digest-presence check is not enough: the
## advisory_verdict=="ok" gate must refuse a hand-built/mutated refusal preview
## BEFORE any capability call opens an effect-required intent.
for (verdict in c("held", "protected_package", "package_not_owned")) {
    lg <- newlog()
    r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)),
                    preview = mkprev(advisory_verdict = verdict))  # valid hash H
    expect_inherits(r, "pkgops_bad_request")
    expect_equal(length(lg$seq), 0L)                     # no capability, nothing opened
}

## a preview with a malformed (non-string) verdict is refused too
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)),
                preview = mkprev(advisory_verdict = NA_character_))
expect_inherits(r, "pkgops_bad_request")
expect_equal(length(lg$seq), 0L)

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

## ============================================================================
## step 2 -- the polkit authorization branch (contract 4.4)
## ============================================================================

## ---- machine-mode UNAUTHORIZED: plain intent recorded, NO effect intent -----
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), pkcheck = function(a) 1L)
expect_inherits(r, "runix_unauthorized")
expect_inherits(r, "pkgops_error")
expect_identical(r$effect_issued, FALSE)                 # no effect ran
expect_equal(lg$seq, c("capability", "refuse"))          # never opened the effect intent
expect_equal(lg$seq[1], "capability")                    # capability precedes the decision
expect_equal(lg$refuse$status, "unauthorized")           # the terminal outcome recorded
expect_equal(lg$refuse$operation, "apt.install")
expect_equal(lg$refuse$resource, "nginx")
expect_equal(r$correlation_id, CID)                      # cid from the plain intent

## ---- machine-mode APPROVAL_REQUIRED: plain intent + runix_approval_required -
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), pkcheck = function(a) 2L)
expect_inherits(r, "runix_approval_required")
expect_identical(r$effect_issued, FALSE)
expect_equal(lg$seq, c("capability", "refuse"))
expect_equal(lg$refuse$status, "approval_required")

## ---- CHECK_FAILED: fail closed, NOTHING recorded (no authoritative decision) -
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), pkcheck = function(a) 127L)
expect_inherits(r, "pkgops_polkit_check_failed")
expect_equal(lg$seq, "capability")                       # no refuse, no open
expect_false("refuse" %in% lg$seq)

## ---- INTERACTIVE mode: pkcheck is NOT run, proceed to the effect intent ------
lg <- newlog()
never_pk <- function(a) stop("pkcheck must not run in interactive mode")
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), interactive = TRUE,
                pkcheck = never_pk)
expect_inherits(r, "pkgops_outcome")                     # the pkexec prompt authorizes later
expect_equal(lg$seq, c("capability", "open", "commit", "write_outcome"))

## ---- the plain-intent RECORD itself fails: propagate, no effect intent ------
lg <- newlog()
audit_err <- structure(class = c("runix_audit_error", "runix_error", "error",
                                 "condition"),
                       list(message = "intent not durable", call = NULL))
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE), refuse_err = audit_err),
                pkcheck = function(a) 1L)
expect_inherits(r, "runix_audit_error")                  # record failure surfaces
expect_equal(lg$seq, c("capability", "refuse"))          # never opened the effect intent

## ---- autonomous verb, machine mode, a member (rc 0) proceeds ----------------
lg <- newlog()
autofn <- function(action) {
    if (grepl("\\.(update|hold)$", action)) 0L else 1L
}
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)),
                preview = mkprev(verb = "apt.update", resource = "@indexes",
                                 packages = character(0)),
                pkcheck = autofn)
expect_inherits(r, "pkgops_outcome")                     # update authorized for a member
expect_equal(lg$seq, c("capability", "open", "commit", "write_outcome"))

## a non-member hitting a non-autonomous verb is refused (same check) ----------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), pkcheck = autofn)  # apt.install -> rc 1
expect_inherits(r, "runix_unauthorized")
expect_equal(lg$seq, c("capability", "refuse"))
