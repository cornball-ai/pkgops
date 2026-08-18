## Injectable seam over runix's exported effect-session API -- the four calls the
## commit orchestrator (R/commit.R) drives: the capability negotiation, and the
## three-call session (open -> commit -> write_outcome). Same injectable shape as
## the preview runner (R/runner.R): production code calls session_ops()$<fn>(...),
## and a hermetic test swaps in a fake list via set_session_ops(), restoring with
## set_session_ops(NULL).
##
## This seam exists ONLY for hermetic testing (contract 9: no root, no dpkg, no
## broker in the suite). It does NOT weaken the trust boundary: the receipt and
## the outcome binding live in runix's wipeable C heap and never become R
## objects, and the privileged verb -> /usr/libexec/pkgexec/runix-apt-<verb> map
## is a hard C constant inside runix with no runtime seam. A test-substituted
## `commit` replaces only the R-level call; it cannot spawn a real pkexec
## entrypoint, gain privilege, or mutate the host -- worst case it makes pkgops
## believe an in-process commit it never performed, which the fake-broker suite
## exercises deliberately. In production the defaults below are always used.

## The default implementations delegate verbatim to the exported (never `:::`)
## runix effect-session surface. Kept as named functions so a fake can shadow one
## by name and inherit the rest.
cap_default <- function(socket_path, plan_schema, ...) {
    runix::effect_capability(socket_path, plan_schema = plan_schema, ...)
}
open_default <- function(socket_path, operation, resource, plan_schema,
                         plan_hash, ...) {
    runix::effect_session_open(socket_path, operation, resource,
                               plan_schema, plan_hash, ...)
}
commit_default <- function(session, packages, lock_timeout, deadline_ms, ...) {
    runix::effect_session_commit(session, packages = packages,
                                 lock_timeout = lock_timeout,
                                 deadline_ms = deadline_ms, ...)
}
write_outcome_default <- function(session, record, ...) {
    runix::effect_session_write_outcome(session, record, ...)
}

.PKGOPS_SESSION_OPS_DEFAULT <- list(capability = cap_default,
                                    open = open_default,
                                    commit = commit_default,
                                    write_outcome = write_outcome_default)

.pkgops_session_ops <- local({
    state <- new.env(parent = emptyenv())
    ## Merge any injected functions over the defaults, so a test may shadow a
    ## single call while the rest stay real; a hermetic test shadows all four so
    ## nothing reaches the broker.
    session_ops <- function() {
        if (is.null(state$ops)) {
            return(.PKGOPS_SESSION_OPS_DEFAULT)
        }
        ## override the defaults by name (base R; no utils::modifyList) so a
        ## partial injection keeps the rest real
        merged <- .PKGOPS_SESSION_OPS_DEFAULT
        merged[names(state$ops)] <- state$ops
        merged
    }
    set_session_ops <- function(ops = NULL) {
        old <- state$ops
        state$ops <- ops
        invisible(old)
    }
    list(session_ops = session_ops, set_session_ops = set_session_ops)
})

session_ops <- .pkgops_session_ops$session_ops
set_session_ops <- .pkgops_session_ops$set_session_ops
