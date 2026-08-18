## The commit-result classifier: the pure decision layer of the effect-session
## wiring. Given runix's already-parsed runix_commit_result (its C owns the JSON
## frame parse, the cid check, the exit/status consistency gate, and the delivery
## gate) and the preview that was committed, it produces the pkgops_outcome to
## record, the runix condition to signal, and whether the intent must be left
## open. It NEVER raises and NEVER does IO: the orchestration (a later increment)
## writes the outcome FIRST and only then signals the returned condition
## (outcome-closed-before-signal, pkgops-plan.md 4.8). The actual open/commit/
## write_outcome calls, the polkit branch, and pkgstate verification are separate
## later increments.

## Build a runix condition object WITHOUT raising it. The classifier returns it;
## the orchestration raises it after the outcome is written. It inherits
## pkgops_error and runix_error, and carries the structured fields a caller
## branches on (never parses out of the message).
.build_commit_condition <- function(class, message, preview, correlation_id,
                                    status, effect_issued, detail = NULL) {
    structure(
              c(list(message = message, verb = preview$verb,
                     resource = preview$resource, plan_hash = preview$plan_hash,
                     correlation_id = correlation_id, status = status,
                     effect_issued = effect_issued, detail = detail)),
              class = c(class, "pkgops_error", "runix_error", "error", "condition"))
}

## Classify a runix_commit_result into list(outcome, condition, leave_open).
## `outcome` is always a pkgops_outcome; `condition` is the runix condition for a
## non-success result, or NULL for ok/no_op; `leave_open` is TRUE only when the
## effect state is genuinely unknown (the intent must NOT be closed, plan 4.8).
##
## runix's session_status (src/effect_session.c) drives the four cases:
##   ok             the helper spoke consistently and the receipt was delivered
##                  -> KNOWN TRUTH: its status + effect_issued rule; CLOSE.
##   spawn_failed   posix_spawn produced no child -> effect definitely did not
##                  run (effect_issued FALSE); CLOSE.
##   unauthorized   pkexec denied/not-found -> a known pre-exec refusal
##                  (effect_issued FALSE); CLOSE.
##   effect_unknown the child ran but gave nothing trustworthy -> effect UNKNOWN
##                  (effect_issued NA); LEAVE OPEN.
## effect_issued is read from runix verbatim (normalized), never fabricated:
## runix already reports FALSE for the provably-no-effect cases and NA for the
## unknown one (plan 4.8, "pkgops never fabricates effect_issued:false").
.classify_commit <- function(commit, preview) {
    ss <- commit$session_status
    ei <- .norm_effect_issued(commit$effect_issued)
    cid <- commit$correlation_id
    if (is.null(commit$detail)) {
        detail <- NA_character_
    } else {
        detail <- commit$detail
    }

    outcome <- function(status, condition = NULL) {
        new_pkgops_outcome(correlation_id = cid, verb = preview$verb,
                           resource = preview$resource,
                           plan_hash = preview$plan_hash, status = status,
                           effect_issued = ei, condition = condition)
    }
    failure <- function(status, cls, message, leave_open) {
        cond <- .build_commit_condition(cls, message, preview, cid, status, ei,
                                        detail)
        list(outcome = outcome(status, condition = cond), condition = cond,
             leave_open = leave_open)
    }
    ## a result runix could not trust -> effect UNKNOWN, intent left open (4.6/4.8)
    unknown <- function(why) {
        failure("effect_unknown", "runix_helper_bad_result",
                sprintf("apt %s: %s", preview$verb, why), leave_open = TRUE)
    }

    if (identical(ss, "ok")) {
        st <- commit$status
        ## ss=="ok" guarantees a valid helper status from runix; defend anyway
        if (!.is_scalar_str(st) || !st %in% .PKGOPS_COMMIT_STATUSES) {
            return(unknown("helper reported an unrecognised status"))
        }
        if (.status_is_success(st)) {
            return(list(outcome = outcome(st), condition = NULL,
                        leave_open = FALSE))
        }
        cls <- .status_condition(st)
        msg <- sprintf("apt %s failed: %s%s", preview$verb, st,
            if (!is.na(detail) && nzchar(detail)) {
                paste0(" (", detail, ")")
            } else {
                ""
            })
        ## every parseable helper status is KNOWN TRUTH -> close (even
        ## operation_failed / dpkg_broken / no_intent), with its effect_issued
        return(failure(st, cls, msg, leave_open = FALSE))
    }
    if (identical(ss, "unauthorized")) {
        return(failure("unauthorized", "runix_unauthorized",
                       sprintf("apt %s: authorization denied", preview$verb),
                       leave_open = FALSE))
    }
    if (identical(ss, "spawn_failed")) {
        return(failure("spawn_failed", "pkgops_spawn_failed",
                       sprintf("apt %s: the privileged helper could not be started",
                               preview$verb),
                       leave_open = FALSE))
    }
    if (identical(ss, "effect_unknown")) {
        return(unknown("the helper produced no trustworthy result"))
    }
    ## an unrecognised session_status is itself untrustworthy -> effect unknown
    unknown(sprintf("unrecognised session status %s",
            if (.is_scalar_str(ss)) shQuote(ss) else "<malformed>"))
}
