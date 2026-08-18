## The commit-result contract: pkgops's model of the privileged helper's result
## channel, and the typed outcome an issuer records. This is the pure foundation
## of the commit lifecycle (a later increment wires the effect-session, polkit,
## and pkgstate verification on top of it): the closed status vocabulary, the
## status -> condition mapping, the tri-state effect_issued, cid-equality, and
## the pkgops_outcome object. No effect, no spawn, no broker -- pure and
## hermetically testable.

## The privileged helper's closed commit-status vocabulary and each status's
## stable runix condition class (pkgops-plan.md 4.4). ok/no_op are success (no
## error condition, so they map to themselves); every other status maps to a
## runix_* class. The overlapping names (not_owned/held/protected/resolve_failed/
## dpkg_broken/helper_internal) are IDENTICAL to the preview channel's, so the two
## never diverge on what a refusal is called. Pinned bytewise to shipped pkgexec
## v0.0.3 (src/result.c pkgx_status_name; tests/test_result.c) -- a rename there
## must break the drift test in test_outcome.R.
.PKGOPS_STATUS_CONDITION <- c(ok = "ok", no_op = "no_op",
                              apt_locked = "runix_apt_locked",
                              package_not_owned = "runix_not_owned",
                              held = "runix_held",
                              protected_package = "runix_protected",
                              no_intent = "runix_no_intent",
                              resolve_failed = "runix_resolve_failed",
                              not_applied = "runix_not_applied",
                              operation_failed = "runix_operation_failed",
                              dpkg_broken = "runix_dpkg_broken",
                              internal = "runix_helper_internal")

## The commit channel's twelve statuses, in enum order (three more than the
## preview channel's nine: apt_locked, no_intent, not_applied, operation_failed).
.PKGOPS_COMMIT_STATUSES <- names(.PKGOPS_STATUS_CONDITION)

## The two success statuses: nothing is raised, the outcome stands on its own.
.PKGOPS_SUCCESS_STATUSES <- c("ok", "no_op")

## The ONLY definitely-no-effect retryable status: apt_locked is lock contention
## refused BEFORE the commit runs, so the host was provably not touched (plan R3).
## Its runix_apt_locked class is registered retryable in .onLoad. A generic
## transport/timeout is NOT here: an outcome-phase timeout after the receipt was
## delivered leaves the effect unknown, never safe to auto-retry.
.PKGOPS_RETRYABLE_STATUSES <- "apt_locked"

## The SESSION-level statuses runix's effect_session_commit reports when the
## helper did not produce a trustworthy result of its own (src/effect_session.c),
## and their conditions. These are distinct from the twelve HELPER statuses above
## (which come from a helper that spoke): they describe how the session itself
## ended when no helper status exists.
##   spawn_failed    posix_spawn produced no child -> the effect definitely did
##                   not run. The contract's condition taxonomy does not name
##                   this case; pkgops owns pkgops_spawn_failed for it. [REVIEW]
##   unauthorized    pkexec denied/not-found -> a known pre-exec refusal
##                   (runix_unauthorized), close false.
##   effect_unknown  the child ran but gave nothing trustworthy -> the effect is
##                   UNKNOWN (runix_helper_bad_result), the intent is left open.
.PKGOPS_SESSION_CONDITION <- c(spawn_failed = "pkgops_spawn_failed",
                               unauthorized = "runix_unauthorized",
                               effect_unknown = "runix_helper_bad_result")

## The POLKIT-terminal statuses, produced by the machine-mode authorization branch
## BEFORE any effect intent is opened (contract 4.4). Both close a plain intent
## with effect_issued = FALSE (no effect ran) and never leave anything open.
##   unauthorized       a flat polkit denial (shares runix_unauthorized with the
##                      pkexec session-level denial above -- same status, same
##                      condition, so the two channels never diverge).
##   approval_required  a challenge that cannot be obtained non-interactively; a
##                      human admin could authorize a re-run (runix_approval_required).
.PKGOPS_POLKIT_CONDITION <- c(approval_required = "runix_approval_required")

## The full status vocabulary an outcome may carry: a helper status (mapped to its
## runix condition), a session-level status, or a polkit-terminal status. All are
## canonical inputs to new_pkgops_outcome(); the drift test pins only the twelve
## HELPER statuses. (unauthorized appears once, shared by the session and polkit
## channels.)
.PKGOPS_ALL_STATUS_CONDITION <- c(.PKGOPS_STATUS_CONDITION,
                                  .PKGOPS_SESSION_CONDITION,
                                  .PKGOPS_POLKIT_CONDITION)

## The runix condition class for a status -- a helper status ("held" ->
## "runix_held", "ok"/"no_op" -> themselves) or a session-level status
## ("unauthorized" -> "runix_unauthorized"). An unrecognised status is a result
## pkgops cannot trust -- fail closed as runix_helper_bad_result, never guessed.
.status_condition <- function(status) {
    if (!.is_scalar_str(status) ||
        !status %in% names(.PKGOPS_ALL_STATUS_CONDITION)) {
        stop_pkgops("unknown commit status: ",
            if (.is_scalar_str(status)) shQuote(status) else "<malformed>",
                    class = "runix_helper_bad_result",
                    data = list(status = status))
    }
    unname(.PKGOPS_ALL_STATUS_CONDITION[status])
}

.status_is_success <- function(status) {
    .is_scalar_str(status) && status %in% .PKGOPS_SUCCESS_STATUSES
}

## The helper's first-class effect_issued, normalized to a strict tri-state. TRUE
## and FALSE are the helper's honest answer to "was the host possibly mutated?"
## and are NEVER inferred from the status: dpkg_broken carries TRUE when a commit
## broke dpkg and FALSE when a pre-existing broken state was found before anything
## ran (pkgexec tests/test_result.c). NA is reserved for a result pkgops cannot
## trust (malformed / lost / undelivered), and only NA leaves the intent open.
.norm_effect_issued <- function(x) {
    if (length(x) == 1L && is.logical(x) && !is.na(x)) {
        x
    } else {
        NA
    }
}

## A commit result is bound to its intent only when its correlation_id equals the
## one the intent was opened under, and both are the real, non-empty cid string.
## A mismatch means the result may belong to a different operation -- fail closed.
.cid_equal <- function(result_cid, intent_cid) {
    .is_scalar_str(result_cid) && .is_scalar_str(intent_cid) &&
    nzchar(result_cid) && identical(result_cid, intent_cid)
}

## Enforce a tri-state field (TRUE / FALSE / NA). Unlike effect_issued -- which
## carries UNTRUSTED helper input and normalizes a bad value to the NA "unknown"
## -- `verified` is pkgops's OWN verification verdict, so a value outside the
## tri-state is a programming error and fails closed rather than degrading.
.check_tristate <- function(x, what) {
    if (!(length(x) == 1L && is.logical(x))) {
        stop_pkgops("`", what, "` must be TRUE, FALSE, or NA",
                    class = "pkgops_bad_request")
    }
    x
}

## The typed, versioned outcome an issuer records for a commit (pkgops-plan.md
## 6.2). CANONICAL REPRESENTATION: `status` is stored as the MAPPED runix
## condition name (or "ok"/"no_op" for success) -- the constructor takes the RAW
## helper status, maps it through .status_condition(), and rejects any status
## outside the closed vocabulary (fail closed as runix_helper_bad_result), so the
## object never carries an unmapped or unknown status. `effect_issued` is the
## helper's tri-state (untrusted -> normalized); `verified` is pkgops's own
## tri-state verdict (enforced, not normalized); `condition` is the runix
## condition object for a non-success outcome, or NULL. `verified`/`verify_detail`
## are NA in this increment -- pkgstate verification lands in a later one.
new_pkgops_outcome <- function(correlation_id, verb, resource, plan_hash,
                               status, effect_issued = NA, verified = NA,
                               verify_detail = NA_character_,
                               condition = NULL) {
    structure(list(schema_version = 1L, correlation_id = correlation_id,
                   verb = verb, resource = resource, plan_hash = plan_hash,
                   status = .status_condition(status),
                   effect_issued = .norm_effect_issued(effect_issued),
                   verified = .check_tristate(verified, "verified"),
                   verify_detail = verify_detail, condition = condition),
              class = "pkgops_outcome")
}

#' @export
print.pkgops_outcome <- function(x, ...) {
    ei <- if (is.na(x$effect_issued)) {
        "unknown"
    } else if (x$effect_issued) {
        "yes"
    } else {
        "no"
    }
    vf <- if (is.na(x$verified)) "n/a" else if (x$verified) "ok" else "FAILED"
    cat(sprintf("<pkgops outcome: %s [%s]>\n", x$verb, x$status))
    cat(sprintf("  resource     : %s\n",
            if (is.null(x$resource) || is.na(x$resource)) {
                "(none)"
            } else {
                x$resource
            }))
    cat(sprintf("  effect issued: %s\n", ei))
    cat(sprintf("  verified     : %s\n", vf))
    cat(sprintf("  correlation  : %s\n",
            if (is.null(x$correlation_id) || is.na(x$correlation_id)) {
                "(none)"
            } else {
                x$correlation_id
            }))
    invisible(x)
}
