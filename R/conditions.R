## Typed conditions on the shared runix taxonomy. stop_pkgops() wraps
## runix::runix_abort() so every pkgops condition inherits pkgops_error and
## runix_error: a caller (or rctl, later) can catch the specific semantic class
## (e.g. runix_held), the package class (pkgops_error), or the framework class
## (runix_error). runix has no class registry -- the subclass string IS the
## taxonomy -- so the semantic classes the planner maps to (runix_not_owned,
## runix_held, runix_protected, runix_dpkg_broken, runix_resolve_failed,
## runix_helper_internal, runix_preview_failed, runix_helper_bad_result) are
## raised here as subclass strings, mirroring the commit channel's names so the
## two never diverge.
stop_pkgops <- function(..., class = character(), data = list(),
                        call. = sys.call(-1)) {
    cl <- call. # force the promise in this frame so `call` is the caller's
    runix::runix_abort(paste0(...), subclass = c(class, "pkgops_error"),
                       data = data, call = cl)
}
