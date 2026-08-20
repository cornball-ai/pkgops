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
set_reader <- pkgops:::set_pkgstate_reader

## A committable preview: an `ok` plan carrying a bound digest. `records` are the
## resolved records step 6 verifies; the default is empty (nothing to verify ->
## verified NA, and the pkgstate reader is never touched, so the effect-path tests
## stay hermetic without injecting one).
mkprev <- function(verb = "apt.install", resource = "nginx", packages = "nginx",
                   plan_hash = H, plan_schema = 1L, advisory_verdict = "ok",
                   records = list()) {
    structure(list(schema_version = 1L, verb = verb, resource = resource,
                   plan_schema = plan_schema, plan_hash = plan_hash,
                   autonomous = FALSE, packages = packages, records = records,
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
                       pkcheck = function(action) 0L, reader = NULL, ...) {
    old_ops <- set_ops(ops)
    old_pk <- set_pkcheck(pkcheck)
    if (!is.null(reader)) {
        old_rd <- set_reader(reader)
    }
    on.exit({
        set_ops(old_ops)
        set_pkcheck(old_pk)
        if (!is.null(reader)) {
            set_reader(old_rd)
        }
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
expect_equal(lg$record$outcome, "ok")                    # broker-required, success -> ok

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
expect_equal(lg$record$outcome, "ok")                    # no_op is a success -> ok
expect_true("write_outcome" %in% lg$seq)

## ---- known failure: outcome WRITTEN, then the mapped condition signaled -----
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "operation_failed", TRUE, detail = "dpkg exited 100")))
expect_inherits(r, "runix_operation_failed")
expect_inherits(r, "pkgops_error")
# outcome-closed-before-signal: write_outcome ran before we got the condition
expect_equal(lg$seq, c("capability", "open", "commit", "write_outcome"))
expect_identical(lg$record$effect_issued, TRUE)          # the effect happened
expect_equal(lg$record$outcome, "error")                 # a closed failure -> error
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
expect_equal(r$correlation_id, CID)                      # left-open intent stays reconcilable

## ---- a RAISED commit is effect-unknown: left open, original re-signaled -----
lg <- newlog()
boom <- structure(class = c("runix_capability_unavailable", "runix_error",
                            "error", "condition"),
                  list(message = "no closefrom primitive", call = NULL))
r <- run_commit(ops_for(lg, boom, raise = TRUE))
expect_inherits(r, "runix_capability_unavailable")       # the original, re-signaled
expect_false("write_outcome" %in% lg$seq)                # left open
expect_equal(lg$seq, c("capability", "open", "commit"))
## the raw runix condition carried no cid; .ensure_cid attaches the SESSION cid so
## the killed/lost intent is reconcilable (G-INT), without replacing its class/fields
expect_equal(r$correlation_id, CID)
expect_inherits(r, "runix_capability_unavailable")       # class preserved
expect_equal(conditionMessage(r), "no closefrom primitive")   # message preserved

## ---- a left-open result whose delivered frame LOST its cid falls back to the
## session cid (never leaving an unreconcilable open intent) -------------------
lg <- newlog()
lost <- list(session_status = "effect_unknown", status = NULL,
             effect_issued = NA, correlation_id = NULL, detail = NULL)
r <- run_commit(ops_for(lg, lost))
expect_inherits(r, "runix_helper_bad_result")
expect_false("write_outcome" %in% lg$seq)
expect_equal(r$correlation_id, CID)                      # fell back to the session cid

## ---- .ensure_cid: an EMPTY or MALFORMED existing cid is REPLACED (not only a
## missing/NA one), while a VALID broker cid is kept. This is the G-INT invariant:
## an open intent must never be left with an unreconcilable cid ------------------
ec <- pkgops:::.ensure_cid
mkcond <- function(cid) structure(list(message = "m", call = NULL,
                                       correlation_id = cid),
                                  class = c("runix_error", "error", "condition"))
OTHER <- "20250202000000000000-fedcba9876543210"       # a DIFFERENT valid broker cid
expect_equal(ec(mkcond(NULL), CID)$correlation_id, CID)            # missing -> stamped
expect_equal(ec(mkcond(NA_character_), CID)$correlation_id, CID)   # NA -> stamped
expect_equal(ec(mkcond(""), CID)$correlation_id, CID)             # empty -> REPLACED
expect_equal(ec(mkcond("not-a-broker-cid"), CID)$correlation_id, CID)  # malformed -> REPLACED
expect_equal(ec(mkcond(c(CID, CID)), CID)$correlation_id, CID)    # non-scalar -> REPLACED
expect_equal(ec(mkcond(OTHER), CID)$correlation_id, OTHER)        # valid cid KEPT
## a non-well-formed session cid is never stamped (no replacing bad with bad)
expect_equal(ec(mkcond(""), "bad")$correlation_id, "")
expect_null(ec(mkcond(NULL), "bad")$correlation_id)
## class + message preserved through the replacement
badc <- ec(mkcond(""), CID)
expect_inherits(badc, "runix_error")
expect_equal(conditionMessage(badc), "m")

## ---- G-INT end to end: a raised commit whose condition carries an EMPTY or
## MALFORMED cid still leaves a reconcilable open intent (the bad cid is replaced
## with the session cid), class + message intact --------------------------------
for (badcid in list("", "not-a-broker-cid", NA_character_)) {
    lg <- newlog()
    boom2 <- structure(list(message = "killed mid-commit", call = NULL,
                            correlation_id = badcid),
                       class = c("runix_capability_unavailable", "runix_error",
                                 "error", "condition"))
    r <- run_commit(ops_for(lg, boom2, raise = TRUE))
    expect_inherits(r, "runix_capability_unavailable")
    expect_false("write_outcome" %in% lg$seq)            # left open
    expect_equal(r$correlation_id, CID)                  # bad cid replaced by session cid
    expect_equal(conditionMessage(r), "killed mid-commit")
}

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

## ---- a NON-PERSISTED refusal result is NOT reported as a closed refusal ------
## audit_two_phase can return audit_persisted=FALSE (e.g. the terminal outcome did
## not land) WITHOUT raising; that must fail closed as a persistence error, never
## be signaled as a clean runix_unauthorized.
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE),
                        refuse = list(correlation_id = CID, audit_persisted = FALSE)),
                pkcheck = function(a) 1L)
expect_inherits(r, "runix_broker_error")
expect_false(inherits(r, "runix_unauthorized"))          # not a closed refusal
expect_false(isTRUE(r$audit_persisted))
expect_equal(lg$seq, c("capability", "refuse"))

## ---- a refusal result with a MALFORMED cid also fails closed ----------------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE),
                        refuse = list(correlation_id = "not-a-broker-cid",
                                      audit_persisted = TRUE)),
                pkcheck = function(a) 2L)
expect_inherits(r, "runix_broker_error")
expect_false(inherits(r, "runix_approval_required"))
expect_true(is.na(r$correlation_id))                     # the bad cid is not carried through

## ---- a missing audit_persisted field is treated as not persisted ------------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE),
                        refuse = list(correlation_id = CID)),  # no audit_persisted
                pkcheck = function(a) 1L)
expect_inherits(r, "runix_broker_error")

## ---- the broker cid grammar (pinned to runix .BROKER_CID_RE) -----------------
vcid <- pkgops:::.valid_broker_cid
expect_true(vcid("20250101000000000000-0123456789abcdef"))
expect_true(vcid("00001786382512165708-a061ec02cffe1b2b"))            # 20 digit + 16 hex
expect_false(vcid("2025-abc"))
expect_false(vcid("20250101000000000000-0123456789ABCDEF"))           # uppercase hex rejected
expect_false(vcid(NA_character_))
expect_false(vcid(NULL))
expect_false(vcid(""))

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

## ============================================================================
## step 6 -- pkgstate verification (contract 4.7). The verdict is CAPTURED onto
## the outcome, NEVER raised; the outcome is still written, in order; and
## verification runs ONLY on the success path (an ok/no_op that is returned).
## ============================================================================

## A committable install preview carrying one resolved txn record, and a fake
## reader whose installed() reports a canned post-state (and counts its calls, so
## a test can prove verification did or did not run). selections() is unused by
## the txn family but must be a valid frame.
irec <- list(package = "nginx", architecture = "amd64", action = "install",
             from_version = "", to_version = "1.2", flags = list())
prev1 <- mkprev(records = list(irec))
empty_sel <- function(packages = NULL) {
    data.frame(package = character(), architecture = character(),
               selection = character(), stringsAsFactors = FALSE)
}
counting_reader <- function(status = "installed", version = "1.2") {
    e <- new.env(parent = emptyenv())
    e$n <- 0L
    e$reader <- list(installed = function() {
        e$n <- e$n + 1L
        data.frame(package = "nginx", version = version, architecture = "amd64",
                   status = status, stringsAsFactors = FALSE)
    }, selections = empty_sel)
    e
}

## success + a MATCHING post-state -> verified TRUE, outcome returned + written,
## and verification ran exactly once (it read the post-state).
cr_ok <- counting_reader(status = "installed", version = "1.2")
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), preview = prev1,
                reader = cr_ok$reader)
expect_inherits(r, "pkgops_outcome")
expect_identical(r$verified, TRUE)
expect_true(is.na(r$verify_detail))
expect_equal(lg$seq, c("capability", "open", "commit", "write_outcome"))
## the reader is read twice on a success txn: the pre-commit snapshot
## (state_changed), and ONE cached post-read shared by the verdict + observation
expect_equal(cr_ok$n, 2L)

## success + a DISAGREEING post-state -> verified FALSE + a detail, but the
## outcome is STILL returned (not a raised condition) and STILL written: a failed
## verification never raises and never changes the close.
cr_bad <- counting_reader(status = "installed", version = "1.1")
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), preview = prev1,
                reader = cr_bad$reader)
expect_inherits(r, "pkgops_outcome")
expect_false(inherits(r, "condition"))
expect_identical(r$verified, FALSE)
expect_true(grepl("version 1.1", r$verify_detail))
expect_equal(lg$seq, c("capability", "open", "commit", "write_outcome"))

## a reader that EXPLODES is captured, never propagated -> verified FALSE, the
## outcome is still returned and written (the belt over .verify()).
boom_reader <- list(installed = function() stop("dpkg exploded"),
                    selections = empty_sel)
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), preview = prev1,
                reader = boom_reader)
expect_inherits(r, "pkgops_outcome")
expect_identical(r$verified, FALSE)
expect_true(grepl("verification error|absent|malformed", r$verify_detail))
expect_true("write_outcome" %in% lg$seq)

## no resolved records -> nothing to verify -> verified NA on a success (and the
## reader is never touched, so the default hermetic tests stay clean).
cr_untouched <- counting_reader()
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), preview = prev,
                reader = cr_untouched$reader)
expect_inherits(r, "pkgops_outcome")
expect_true(is.na(r$verified))
expect_equal(cr_untouched$n, 0L)                         # short-circuits, no read

## a KNOWN FAILURE is not verified: verification does not run (a failure path has
## no trustworthy post-state), and the mapped condition is still signaled after
## the outcome was written.
cr_fail <- counting_reader(status = "installed", version = "1.2")  # would verify TRUE
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "operation_failed", TRUE)), preview = prev1,
                reader = cr_fail$reader)
expect_inherits(r, "runix_operation_failed")
## only the pre-commit snapshot reads on a failure path; the verdict + post-state
## observation are success-path only, so no post-commit read happens
expect_equal(cr_fail$n, 1L)
expect_true("write_outcome" %in% lg$seq)                 # known close still written

## a LEFT-OPEN effect_unknown is not verified either (the effect is unknown) and
## the intent stays open (no write_outcome).
cr_open <- counting_reader(status = "installed", version = "1.2")
lg <- newlog()
r <- run_commit(ops_for(lg, cr("effect_unknown", effect_issued = NA)),
                preview = prev1, reader = cr_open$reader)
expect_inherits(r, "runix_helper_bad_result")
expect_equal(cr_open$n, 1L)                              # only the pre-commit snapshot
expect_false("write_outcome" %in% lg$seq)

## verification is INDEPENDENT of the helper status (4.7): a clean `ok` whose
## post-state disagrees is a verification FAILURE, not a pass.
cr_lie <- counting_reader(status = "half-configured", version = "1.2")
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), preview = prev1,
                reader = cr_lie$reader)
expect_identical(r$verified, FALSE)                      # helper said ok; the host disagrees
expect_true(grepl("half-configured", r$verify_detail))

## ============================================================================
## Part A -- the durable record the commit writes (observed/changed/state_changed/
## authorized_via), and state_changed from a real pre/post diff.
## ============================================================================

## a matching success commit: the record carries the full grammar --------------
cr_match <- counting_reader(status = "installed", version = "1.2")
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), preview = prev1,
                reader = cr_match$reader)
expect_inherits(r, "pkgops_outcome")
rec <- lg$record
expect_equal(rec$operation, "apt.install")
expect_equal(rec$scope, "system")
expect_identical(rec$preview, FALSE)
expect_equal(rec$authorized_via, "pkcheck")              # machine, non-autonomous
expect_identical(rec$changed, TRUE)                      # verified matched
expect_identical(rec$observed_failed, FALSE)
expect_equal(rec$observed, list("nginx:amd64" = list(status = "installed",
                                                     version = "1.2")))
expect_false(any(names(rec) %in% pkgops:::.PKGOPS_RECORD_RESERVED))
expect_true(all(names(rec) %in% names(pkgops:::.PKGOPS_RECORD_FIELDS)))

## a DISAGREEING post-state: changed=FALSE + observed_reason, still written ------
cr_dis <- counting_reader(status = "installed", version = "1.1")
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), preview = prev1,
                reader = cr_dis$reader)
expect_identical(lg$record$changed, FALSE)
expect_true(grepl("version 1.1", lg$record$observed_reason))

## state_changed from a REAL pre/post diff: a stateful reader returns the
## pre-state on the first read and the post-state after, so the pre-commit
## snapshot differs from the post-state -> state_changed TRUE.
stateful_reader <- function(pre, post) {
    e <- new.env(parent = emptyenv())
    e$n <- 0L
    list(installed = function() {
        e$n <- e$n + 1L
        if (e$n == 1L) pre else post
    }, selections = empty_sel)
}
absent <- data.frame(package = character(), version = character(),
                     architecture = character(), status = character(),
                     stringsAsFactors = FALSE)
installed <- data.frame(package = "nginx", version = "1.2",
                        architecture = "amd64", status = "installed",
                        stringsAsFactors = FALSE)
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), preview = prev1,
                reader = stateful_reader(absent, installed))
expect_identical(lg$record$state_changed, TRUE)          # absent -> installed
expect_identical(lg$record$changed, TRUE)                # verified against post

## no on-disk change (pre == post) -> state_changed FALSE -----------------------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), preview = prev1,
                reader = stateful_reader(installed, installed))
expect_identical(lg$record$state_changed, FALSE)

## a read failure -> observed_failed TRUE, changed + observed OMITTED -----------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), preview = prev1,
                reader = boom_reader)
expect_identical(lg$record$observed_failed, TRUE)
expect_false("changed" %in% names(lg$record))
expect_false("observed" %in% names(lg$record))

## authorized_via reflects the mode: interactive -> pkexec ----------------------
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)), preview = prev1,
                reader = counting_reader()$reader, interactive = TRUE)
expect_equal(lg$record$authorized_via, "pkexec")

## an autonomous verb authorized in machine mode -> authorized_via = autonomous --
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "ok", TRUE)),
                preview = mkprev(verb = "apt.update", resource = "@indexes",
                                 packages = character(0)),
                reader = counting_reader()$reader,
                pkcheck = function(a) if (grepl("update$", a)) 0L else 1L)
expect_equal(lg$record$authorized_via, "autonomous")

## a known FAILURE record still carries authorized_via (the intent was authorized)
lg <- newlog()
r <- run_commit(ops_for(lg, cr("ok", "operation_failed", TRUE)), preview = prev1,
                reader = counting_reader()$reader)
expect_inherits(r, "runix_operation_failed")
expect_equal(lg$record$authorized_via, "pkcheck")        # authorized before it failed
expect_false("changed" %in% names(lg$record))            # not verified on a failure
