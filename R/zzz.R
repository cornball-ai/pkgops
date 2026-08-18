.onLoad <- function(libname, pkgname) {
    ## Register the one definitely-no-effect commit status as retryable in the
    ## shared runix registry, so a consumer (rctl, later) classifies it via
    ## runix::is_retryable() without hardcoding the class. apt_locked is lock
    ## contention refused BEFORE the commit runs -- the host was provably not
    ## touched -- so a retry is safe (plan R3). Generic transport/timeout is NOT
    ## registered: an outcome-phase timeout after the receipt was delivered leaves
    ## the effect unknown. register_retryable() is an idempotent union, so
    ## repeated loads are harmless.
    runix::register_retryable("runix_apt_locked")
    invisible()
}
