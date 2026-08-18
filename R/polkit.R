## The polkit authorization decision (contract 4.4, lifecycle step 2). This
## increment builds the DECISION layer only: the per-verb polkit action id, a
## native non-interactive `pkcheck` behind an injectable seam, the exit-code ->
## decision map, and .authorize() which runs the check only in machine mode. The
## next increment WIRES this into .commit_session (the authorized path proceeds to
## the effect intent; a machine-mode refusal opens a PLAIN intent + a terminal
## outcome via the generic broker sink and stops) -- none of that is here yet.
##
## Polkit owns authorization; this pre-check only decides, in MACHINE mode,
## whether to proceed to the pkexec boundary or to short-circuit with a terminal
## outcome (so no unused effect receipt is ever minted for a refusal). It is NOT a
## privilege boundary: the real authorization is enforced by polkit at the pkexec
## spawn inside runix's C, so a test-substituted pkcheck (below) cannot grant
## anything -- at worst it makes pkgops proceed to a commit that pkexec then
## denies, or refuse one it would have allowed. Both degrade safely.

## The polkit action-id namespace. Each verb's action is this prefix + the
## request verb, e.g. apt.install -> "ai.cornball.runix.apt.install",
## apt.dist_upgrade -> "ai.cornball.runix.apt.dist_upgrade" (underscore kept).
## Pinned to pkgexec/polkit/ai.cornball.runix.apt.policy.
.POLKIT_ACTION_NS <- "ai.cornball.runix."

## The machine-mode authorization decision vocabulary:
##   authorized         proceed to the effect-required intent (pkexec commit).
##   unauthorized       a flat denial (pkcheck rc 1) -> terminal outcome
##                      `unauthorized`, effect FALSE, stop.
##   approval_required  a challenge is needed but cannot be obtained
##                      non-interactively (pkcheck rc 2/3) -> terminal outcome
##                      `approval_required`, effect FALSE, stop.
##   check_failed       pkcheck could not be run or gave an uninterpretable rc
##                      -> fail closed, open nothing.
.POLKIT_DECISIONS <- c("authorized", "unauthorized", "approval_required",
                       "check_failed")

## The polkit action id for a verb's request token. request_verb is the
## "apt.<verb>" the verb table already validated, so this is a pure string map.
.polkit_action <- function(request_verb) {
    paste0(.POLKIT_ACTION_NS, request_verb)
}

## The race-safe pkcheck subject for THIS process: pid,start-time,uid. start-time
## is field 22 of /proc/self/stat, read PAST the "(comm)" field so a comm
## containing spaces or ')' cannot shift it (mirrors the tested canary harness).
## uid is the process's real uid, read from /proc/self's owner via file.info()
## (base R, no extra dependency).
.pkcheck_subject <- function() {
    stat <- readLines("/proc/self/stat", warn = FALSE)
    rest <- sub(".*\\) ", "", stat)
    start <- strsplit(rest, " ", fixed = TRUE)[[1]][20L]
    uid <- file.info("/proc/self")[["uid"]]
    paste(Sys.getpid(), start, uid, sep = ",")
}

## The default pkcheck executor: a native, NON-interactive polkit check (no
## --allow-user-interaction, so a challenge can never turn into a prompt) of this
## process against `action`. Returns pkcheck's integer exit code. Fails closed on
## a missing binary. Carries no secret (unlike the pkexec commit), so a plain
## system2 spawn without a shell is appropriate; the seam below lets tests replace
## it with a scripted rc.
.pkcheck_default <- function(action) {
    bin <- "/usr/bin/pkcheck"
    if (!nzchar(Sys.which(bin))) {
        stop_pkgops("polkit check tool not found: ", bin,
                    class = "pkgops_missing_tool", data = list(resource = bin))
    }
    args <- c("--action-id", action, "--process", .pkcheck_subject())
    suppressWarnings(st <- system2(bin, args, stdout = FALSE, stderr = FALSE))
    as.integer(st)
}

.pkgops_pkcheck <- local({
    state <- new.env(parent = emptyenv())
    pkcheck_fn <- function() {
        if (is.null(state$fn)) .pkcheck_default else state$fn
    }
    set_pkcheck <- function(fn = NULL) {
        old <- state$fn
        state$fn <- fn
        invisible(old)
    }
    list(pkcheck_fn = pkcheck_fn, set_pkcheck = set_pkcheck)
})
pkcheck_fn <- .pkgops_pkcheck$pkcheck_fn
set_pkcheck <- .pkgops_pkcheck$set_pkcheck

## Map a pkcheck exit code to a decision (pkcheck(1); pinned to the tested canary
## matrix deploy/canary-apt/polkit-matrix.sh:17-18): 0 authorized, 1 not
## authorized, 2 authorization unavailable (a challenge with no agent / no
## interaction), 3 a challenge that required interaction. Machine mode never
## allows interaction, so 2 and 3 are both "a human admin could authorize this" ->
## approval_required; 1 is a flat deny -> unauthorized; anything else (a spawn
## failure, 124/126/127) is uninterpretable -> check_failed, fail closed.
##
## BOUNDARY [REVIEW]: the exact rc 1-vs-2 split between `unauthorized` and
## `approval_required` is pinned here to the canary contract; it is confirmed
## against real polkit behaviour in the VM-gated increment, where the terminal
## outcomes meet a live broker.
.pkcheck_decision <- function(rc) {
    ## require a finite, scalar, INTEGER-VALUED numeric before coercion: a
    ## fractional 1.5 must fail closed as check_failed, never truncate to 1 and be
    ## read as `unauthorized`.
    if (!(length(rc) == 1L && is.numeric(rc) && is.finite(rc) &&
            rc == floor(rc))) {
        return("check_failed")
    }
    switch(as.character(as.integer(rc)), "0" = "authorized",
           "1" = "unauthorized", "2" = "approval_required",
           "3" = "approval_required", "check_failed")
}

## Decide whether a commit may proceed, per contract 4.4. In INTERACTIVE mode the
## check is deferred to the pkexec prompt at the entrypoint spawn, so this returns
## "authorized" WITHOUT running pkcheck (a cancelled prompt becomes a known-false
## unauthorized outcome on the effect intent later). In MACHINE mode it runs the
## non-interactive pkcheck for the verb's action and maps the result. The
## autonomous verbs (apt.update/apt.hold) need no special-casing: the
## runix-apt-autonomous polkit rule grants members rc 0 through the SAME check,
## and a non-member falls through to a refusal like any other verb.
.authorize <- function(verb_spec, interactive) {
    if (isTRUE(interactive)) {
        return("authorized")
    }
    action <- .polkit_action(verb_spec$request_verb)
    rc <- pkcheck_fn()(action)
    .pkcheck_decision(rc)
}
