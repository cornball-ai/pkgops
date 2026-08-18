## Injectable runner for the preview helper. Unlike pkgstate's reads (args ->
## stdout), the planner is spawned with a JSON *request on stdin* and answers
## with one JSON line on stdout, so this runner adds an `input` channel that
## runix::new_runner() does not carry. Same injectable shape otherwise: exported
## code calls runner()(cmd, args, input); tests swap in a fake via set_runner()
## and restore with set_runner(NULL). No effect, no privilege: the planner is
## the unprivileged read-only runix-apt-preview, never a pkexec entrypoint, so a
## test-substituted runner cannot cross a trust boundary (contrast the commit
## path, whose entrypoint map is a hard C constant with no runtime seam).

## The default executor: fail closed on a missing helper, else spawn under a
## fixed C locale, feed `input` to the child's stdin, capture stdout (the one
## JSON line) and stderr (libapt diagnostics) separately so the parser sees
## clean output. Returns list(status, output, stderr) exactly like the pkgstate
## runner, plus honouring the stdin request.
run_preview_default <- function(cmd, args, input) {
    if (Sys.which(cmd) == "") {
        stop_pkgops("preview helper not found on PATH: ", cmd,
                    class = "pkgops_missing_tool", data = list(resource = cmd))
    }
    errfile <- tempfile("pkgops-stderr")
    on.exit(unlink(errfile), add = TRUE)
    out <- suppressWarnings(
                            system2(cmd, args, input = input, stdout = TRUE, stderr = errfile,
                                    env = "LC_ALL=C"))
    status <- attr(out, "status")
    errlines <- if (file.exists(errfile)) {
        readLines(errfile, warn = FALSE)
    } else {
        character()
    }
    list(
         status = if (is.null(status)) 0L else as.integer(status),
         output = as.character(out),
         stderr = errlines)
}

.pkgops_runner <- local({
    state <- new.env(parent = emptyenv())
    runner <- function() {
        if (is.null(state$run)) run_preview_default else state$run
    }
    set_runner <- function(run = NULL) {
        old <- state$run
        state$run <- run
        invisible(old)
    }
    list(runner = runner, set_runner = set_runner)
})

runner <- .pkgops_runner$runner
set_runner <- .pkgops_runner$set_runner
