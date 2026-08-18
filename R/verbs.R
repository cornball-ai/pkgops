## The closed nine-verb apt vocabulary, shared by every preview entry point.
## Each verb fixes three facts the issuer needs before it spawns the planner:
##   request_verb  the exact "apt.<verb>" token the planner's parser accepts
##                 (note apt.dist_upgrade keeps the underscore; only the pkexec
##                 *binary* name uses a hyphen, and that map lives in C, not here)
##   arity         "targets" (>= 1 package) or "none" (whole-system / index verbs)
##   autonomous    TRUE only for the two verbs polkit may grant non-interactively
##                 to the runix-apt-autonomous group (apt.update, apt.hold); every
##                 other verb defaults to auth_admin. Surfaced on the preview so a
##                 caller sees which grant path a later commit would take.
## Source of truth for arity: pkgexec/src/request.c verb_arity(); for the
## autonomous set: pkgexec/polkit/49-runix-apt-autonomous.rules.
.PKGOPS_VERBS <- list(
                      install = list(request_verb = "apt.install", arity = "targets",
                                     autonomous = FALSE),
                      remove = list(request_verb = "apt.remove", arity = "targets", autonomous = FALSE),
                      purge = list(request_verb = "apt.purge", arity = "targets", autonomous = FALSE),
                      hold = list(request_verb = "apt.hold", arity = "targets", autonomous = TRUE),
                      unhold = list(request_verb = "apt.unhold", arity = "targets", autonomous = FALSE),
                      upgrade = list(request_verb = "apt.upgrade", arity = "none", autonomous = FALSE),
                      dist_upgrade = list(request_verb = "apt.dist_upgrade", arity = "none", autonomous = FALSE),
                      update = list(request_verb = "apt.update", arity = "none", autonomous = TRUE),
                      configure = list(request_verb = "apt.configure", arity = "none", autonomous = FALSE))

## The planner's own limits (pkgexec/src/request.h): a request carries at most
## PKGX_MAX_PACKAGES names, each at most PKGX_MAX_NAME bytes. Enforced here so an
## over-long request is a clean pkgops condition, not a schema_invalid round-trip.
.PKGOPS_MAX_PACKAGES <- 256L
.PKGOPS_MAX_NAME <- 256L

## A strict, optionally arch-qualified Debian package name, mirroring
## pkgexec/src/request.c name_ok(): a name of [a-z0-9] then [a-z0-9+.-] (>= 2
## chars), with an optional ":<arch>" of [a-z0-9] then [a-z0-9-] (no leading '-').
## The planner re-validates; this is the fail-fast copy, pinned to that source.
.valid_package_name <- function(x) {
    !is.na(x) & nchar(x) >= 2L & nchar(x) <= .PKGOPS_MAX_NAME &
    grepl("^[a-z0-9][a-z0-9+.-]+(:[a-z0-9][a-z0-9-]*)?$", x)
}

## Validate a verb's targets against its arity and the name grammar, returning
## the cleaned character vector the request will carry (character(0) for the
## no-target verbs). Fails closed, never coerces:
##  - a "none" verb rejects any target (whole-system verbs are not target-scoped
##    in v1; a target is refused, never silently dropped);
##  - a "targets" verb requires a non-empty character vector of valid, unique
##    names within the count/length caps.
.check_targets <- function(verb_spec, packages) {
    if (verb_spec$arity == "none") {
        if (length(packages) > 0L) {
            stop_pkgops("`", verb_spec$request_verb,
                        "` takes no packages; it is a whole-system operation",
                        class = "pkgops_bad_request")
        }
        return(character(0))
    }
    ## arity == "targets"
    if (!is.character(packages) || length(packages) == 0L) {
        stop_pkgops("`", verb_spec$request_verb,
                    "` requires a non-empty character vector of package names",
                    class = "pkgops_bad_request")
    }
    if (anyNA(packages) || any(!nzchar(packages))) {
        stop_pkgops("package names must be non-empty, non-NA strings",
                    class = "pkgops_bad_request")
    }
    if (length(packages) > .PKGOPS_MAX_PACKAGES) {
        stop_pkgops("too many packages (", length(packages), " > ",
                    .PKGOPS_MAX_PACKAGES, ")", class = "pkgops_bad_request")
    }
    if (anyDuplicated(packages)) {
        dup <- packages[duplicated(packages)][1L]
        stop_pkgops("duplicate package requested: ", shQuote(dup),
                    class = "pkgops_bad_request")
    }
    bad <- which(!.valid_package_name(packages))
    if (length(bad) > 0L) {
        stop_pkgops("invalid package name: ", shQuote(packages[bad[1L]]),
                    class = "pkgops_bad_request")
    }
    ## drop any names so the request encodes as a JSON array (not an object) and
    ## the order-sensitive packages-echo check compares clean character vectors
    unname(packages)
}
