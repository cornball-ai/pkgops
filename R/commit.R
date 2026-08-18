## The commit-session orchestrator: the branched commit lifecycle of the contract
## (pkgops-plan.md 4), wiring runix's exported effect-session API to the pure
## classifier (R/classify.R) and the polkit decision (R/polkit.R). Steps wired:
## 1 capability, 2 authorization (the polkit branch + the plain-intent terminal
## refusal), 3-5 open/commit/classify, 7 write_outcome, 8 return/signal, with the
## outcome-closed-before-signal discipline (4.8). ONE step remains DEFERRED to its
## own later increment and is marked below: pkgstate verification (contract 4.7).
## Until it lands there is no exported per-verb apt_<verb>() commit entrypoint --
## an issuer cannot verify truthfully yet, so the mutation-capable path stays
## internal (.commit_session) and hermetic (fake session-ops + fake pkcheck).

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
    cid <- if (is.list(res) && .is_scalar_str(res$correlation_id)) {
        res$correlation_id
    } else {
        NA_character_
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
    decision <- .authorize(verb_spec, interactive)
    if (!identical(decision, "authorized")) {
        return(.refuse(ops, socket_path, preview, decision))
    }

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
