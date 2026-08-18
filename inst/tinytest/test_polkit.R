# The polkit authorization DECISION layer (R/polkit.R): the per-verb action id,
# the pkcheck exit-code -> decision map, and .authorize() (machine mode runs the
# non-interactive check; interactive mode defers to the pkexec prompt). Hermetic:
# pkcheck is replaced through its seam, so no real polkit call happens. The
# plain-intent terminal-outcome wiring and the .commit_session integration are a
# later increment and are NOT exercised here.

verbs <- pkgops:::.PKGOPS_VERBS
action <- pkgops:::.polkit_action
decision <- pkgops:::.pkcheck_decision
authorize <- pkgops:::.authorize
set_pkcheck <- pkgops:::set_pkcheck

## ---- the polkit action id per verb -----------------------------------------
expect_equal(action("apt.install"), "ai.cornball.runix.apt.install")
expect_equal(action("apt.dist_upgrade"), "ai.cornball.runix.apt.dist_upgrade")
expect_equal(action("apt.unhold"), "ai.cornball.runix.apt.unhold")
# every verb maps to a well-formed action in the runix apt namespace
for (v in names(verbs)) {
    a <- action(verbs[[v]]$request_verb)
    expect_true(grepl("^ai\\.cornball\\.runix\\.apt\\.[a-z_]+$", a))
}

## ---- pkcheck exit code -> decision (pinned to the canary matrix) ------------
expect_equal(decision(0), "authorized")
expect_equal(decision(1), "unauthorized")
expect_equal(decision(2), "approval_required")     # challenge, no agent
expect_equal(decision(3), "approval_required")     # challenge required
expect_equal(decision(4), "check_failed")
expect_equal(decision(126), "check_failed")
expect_equal(decision(127), "check_failed")        # no pkcheck / spawn failure
expect_equal(decision(124), "check_failed")        # timeout
# a non-interpretable rc value is check_failed, never silently authorized
expect_equal(decision(NA_integer_), "check_failed")
expect_equal(decision("nope"), "check_failed")
expect_equal(decision(numeric(0)), "check_failed")
# every decision the map can produce is in the closed vocabulary
for (rc in c(-1, 0, 1, 2, 3, 4, 124, 126, 127)) {
    expect_true(decision(rc) %in% pkgops:::.POLKIT_DECISIONS)
}

## ---- .authorize: install a fake pkcheck, run, restore ----------------------
run_authorize <- function(pkfn, verb_spec, interactive) {
    old <- set_pkcheck(pkfn)
    on.exit(set_pkcheck(old))
    authorize(verb_spec, interactive)
}

## interactive mode defers to the pkexec prompt: pkcheck is NOT run ------------
calls <- new.env(parent = emptyenv())
calls$n <- 0L
never <- function(action) {
    calls$n <- calls$n + 1L
    0L
}
expect_equal(run_authorize(never, verbs$install, TRUE), "authorized")
expect_equal(calls$n, 0L)                          # never queried polkit

## machine mode runs pkcheck for the verb's action and maps the result --------
seen <- new.env(parent = emptyenv())
mk <- function(rc) {
    function(action) {
        seen$action <- action
        rc
    }
}
expect_equal(run_authorize(mk(0L), verbs$install, FALSE), "authorized")
expect_equal(seen$action, "ai.cornball.runix.apt.install")   # verb -> action
expect_equal(run_authorize(mk(1L), verbs$remove, FALSE), "unauthorized")
expect_equal(seen$action, "ai.cornball.runix.apt.remove")
expect_equal(run_authorize(mk(2L), verbs$purge, FALSE), "approval_required")
expect_equal(run_authorize(mk(127L), verbs$install, FALSE), "check_failed")

## autonomous needs no special-casing: the SAME check, the rule grants members -
## a fake standing in for "member of runix-apt-autonomous" (update/hold -> rc 0).
autofn <- function(action) {
    if (grepl("\\.(update|hold)$", action)) 0L else 1L
}
expect_equal(run_authorize(autofn, verbs$update, FALSE), "authorized")
expect_equal(run_authorize(autofn, verbs$hold, FALSE), "authorized")
expect_equal(run_authorize(autofn, verbs$unhold, FALSE), "unauthorized")   # not autonomous
expect_equal(run_authorize(autofn, verbs$install, FALSE), "unauthorized")

## ---- the subject builder is pid,start-time,uid (real /proc on Linux) --------
if (file.exists("/proc/self/stat")) {
    subj <- pkgops:::.pkcheck_subject()
    expect_true(grepl("^[0-9]+,[0-9]+,[0-9]+$", subj))
}
