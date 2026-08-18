## The commit-session orchestrator: the branched commit lifecycle of the contract
## (pkgops-plan.md 4), wiring runix's exported effect-session API to the pure
## classifier (R/classify.R). This increment builds the open/commit/write_outcome
## wiring and the outcome-closed-before-signal discipline (4.8). TWO steps of the
## full lifecycle are DEFERRED to their own later increments and are marked below:
##   - the polkit authorization branch (contract 4.4), and
##   - pkgstate verification (contract 4.7).
## Until those land there is no exported per-verb apt_<verb>() commit entrypoint:
## an issuer cannot authorize or verify truthfully yet, so the mutation-capable
## path stays internal (.commit_session) and hermetic (fake session-ops).

## The broker's well-known AF_UNIX socket (matches runix's effect_capability
## default). A caller may override for a test/staging broker.
.PKGOPS_BROKER_SOCKET <- "/run/runix-audit.sock"

## The durable outcome record pkgops hands to write_outcome. runix's C wraps it as
## {type:"write_outcome", binding, record} and the broker appends `record` to the
## audit line, filling correlation_id (from the binding), phase, host, pid, actor
## and time itself (durable-audit-contract.md 112). `effect_issued` is the
## broker's gate and is ALWAYS a real boolean here: the effect-unknown path leaves
## the intent open and never reaches write_outcome, so this builder rejects an NA.
##
## BOUNDARY [REVIEW]: this record is intentionally MINIMAL and carries only the
## audit-schema fields pkgops authoritatively owns before verification
## (`operation`, `resource`, `effect_issued`). The post-state fields
## (`observed`/`changed`/`state_changed`) are the pkgstate-verification
## increment's OUTPUT and are added there; `authorized_via` is the polkit
## increment's. The exact grammar and its alignment with the broker's
## RECORD_SCHEMA / record_schema_version (which rejects unknown fields) is pinned
## in the VM-gated increment, where write_outcome meets a real broker.
.outcome_record <- function(outcome) {
    ei <- outcome$effect_issued
    if (!(length(ei) == 1L && is.logical(ei) && !is.na(ei))) {
        ## defensive: write_outcome is only reached on a KNOWN-effect close
        stop_pkgops("internal: outcome record needs a known effect_issued",
                    class = "pkgops_bad_request")
    }
    list(operation = outcome$verb, resource = outcome$resource,
         effect_issued = ei)
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

## Drive the branched commit lifecycle for one committable preview and return the
## pkgops_outcome (success) or SIGNAL the mapped condition (failure), with the
## outcome ALWAYS written before the signal (4.8). Internal for now -- the public
## per-verb API that wraps this (with the preview {verb,resource,plan_hash} match
## check) lands once polkit + verification complete the lifecycle.
.commit_session <- function(preview, socket_path = .PKGOPS_BROKER_SOCKET,
                            lock_timeout = 0L, deadline_ms = 120000L) {
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
    ops <- session_ops()

    ## step 1 -- effect-receipt capability negotiation (the real extension +
    ## plan-schema gate, not just peer auth). Raises runix_capability_unavailable
    ## on failure; nothing is opened or minted.
    ops$capability(socket_path, plan_schema = preview$plan_schema)

    ## step 2 -- POLKIT authorization branch: DEFERRED to its own increment.
    ## Machine-mode pkcheck / autonomous-verb handling / the plain-intent
    ## (approval_required|unauthorized) terminal outcome are not wired here yet.
    ## Interactive pkexec still authorizes at the entrypoint spawn inside runix's
    ## C; this orchestrator does no machine-mode pre-check until that increment.

    ## step 3 -- open the effect-required intent. The receipt + outcome binding
    ## are minted into wipeable C heap; R gets only an opaque PID-bound handle and
    ## the non-secret correlation id. Raises runix_broker_* on failure -> nothing
    ## committed, nothing to close.
    session <- ops$open(socket_path, operation = preview$verb,
                        resource = preview$resource,
                        plan_schema = preview$plan_schema,
                        plan_hash = preview$plan_hash)

    ## From here the intent is OPEN and every path must attempt to close it before
    ## returning or signaling. steps 4-5 (commit + classify) yield an
    ## (outcome, condition, leave_open) even if the commit itself raised.
    decided <- .commit_and_classify(ops, session, preview, lock_timeout,
                                    deadline_ms)

    ## step 6 -- pkgstate VERIFICATION: DEFERRED to its own increment. Until then
    ## `verified` stays NA (new_pkgops_outcome's default); a clean helper status
    ## is NOT yet cross-checked against the post-state.

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
