# The nine exported apt_<verb>_preview() wrappers: each dispatches to its exact
# planner verb, target verbs enforce arity before any spawn, and the print
# method shows the advisory summary without inventing a commit.

H <- strrep("b", 64L)
seen <- new.env(parent = emptyenv())
mk <- function(json, exit = 0L) {
    force(json); force(exit)
    function(cmd, args, input) {
        seen$input <- input
        list(status = exit, output = json, stderr = character())
    }
}
resp <- function(status, verb, pkgs, resource, plan_hash) {
    sprintf(paste0('{"schema_version":1,"status":"%s","verb":"%s",',
                   '"packages":%s,"plan_schema":1,"resource":%s,',
                   '"plan_hash":"%s","records":[],"detail":null}'),
            status, verb, pkgs, resource, plan_hash)
}

## ---- each wrapper maps to its exact request verb --------------------------
cases <- list(
    list(fn = apt_install_preview,      verb = "apt.install",      tgt = "nginx"),
    list(fn = apt_remove_preview,       verb = "apt.remove",       tgt = "nginx"),
    list(fn = apt_purge_preview,        verb = "apt.purge",        tgt = "nginx"),
    list(fn = apt_hold_preview,         verb = "apt.hold",         tgt = "nginx"),
    list(fn = apt_unhold_preview,       verb = "apt.unhold",       tgt = "nginx"),
    list(fn = apt_update_preview,       verb = "apt.update",       tgt = NULL),
    list(fn = apt_upgrade_preview,      verb = "apt.upgrade",      tgt = NULL),
    list(fn = apt_dist_upgrade_preview, verb = "apt.dist_upgrade", tgt = NULL),
    list(fn = apt_configure_preview,    verb = "apt.configure",    tgt = NULL))

for (ca in cases) {
    has_tgt <- !is.null(ca$tgt)
    pkgs <- if (has_tgt) '["nginx"]' else "[]"
    res  <- if (has_tgt) '"nginx"' else '""'
    old <- pkgops:::set_runner(mk(resp("ok", ca$verb, pkgs, res, H)))
    p <- if (has_tgt) ca$fn(ca$tgt) else ca$fn()
    pkgops:::set_runner(old)
    expect_inherits(p, "pkgops_preview")
    expect_equal(p$verb, ca$verb)
    expect_true(grepl(paste0('"verb":"', ca$verb, '"'), seen$input, fixed = TRUE))
}

## ---- target verbs validate before spawning (a tripwire runner never fires) -
tripwire <- function(cmd, args, input) stop("planner must not be spawned")
old <- pkgops:::set_runner(tripwire)
expect_error(apt_install_preview(character(0)), "non-empty")
expect_error(apt_install_preview(c("a", "a")), "duplicate")
expect_error(apt_hold_preview("Bad!"), "invalid package name")
expect_error(apt_remove_preview(NA_character_), "non-NA")
pkgops:::set_runner(old)

## ---- the whole-system wrappers take no argument at the R signature level ---
expect_error(apt_update_preview("nginx"))     # unused argument (base R)
expect_error(apt_configure_preview("nginx"))

## ---- print shows an advisory summary, the digest prefix, and no commit ----
old <- pkgops:::set_runner(mk(resp("ok", "apt.install", '["nginx"]', '"nginx"', H)))
p <- apt_install_preview("nginx")
pkgops:::set_runner(old)
out <- capture.output(print(p))
expect_true(any(grepl("pkgops preview", out)))
expect_true(any(grepl("apt.install", out, fixed = TRUE)))
expect_true(any(grepl(substr(H, 1L, 12L), out, fixed = TRUE)))
expect_true(any(grepl("advisory only", out)))
expect_identical(print(p), invisible(p))
