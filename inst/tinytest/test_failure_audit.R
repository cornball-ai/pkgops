# Known failures must record independently observed state before signaling.
# All external operations are fakes; the public commit API drives the lifecycle.
local({
    set_ops <- pkgops:::set_session_ops
    set_pkcheck <- pkgops:::set_pkcheck
    set_reader <- pkgops:::set_pkgstate_reader
    cid <- "20260919000000000000-0123456789abcdef"
    state <- function(status) {
        data.frame(package = "canary-fixture", architecture = "all",
                   version = "1.0", status = status, stringsAsFactors = FALSE)
    }
    absent <- state("not-installed")[FALSE, ]
    broken <- state("half-configured")

    exercise <- function(verb = "install", effect = TRUE, before = absent,
                         after = broken, read_fail = FALSE, persist_fail = FALSE,
                         unknown = FALSE) {
        events <- character()
        committed <- FALSE
        record <- NULL
        old_ops <- set_ops(list(
            capability = function(...) events <<- c(events, "capability"),
            open = function(...) {
                events <<- c(events, "open")
                list(correlation_id = cid)
            },
            commit = function(...) {
                events <<- c(events, "commit")
                committed <<- TRUE
                list(session_status = if (unknown) "effect_unknown" else "ok",
                     status = "dpkg_broken", effect_issued = if (unknown) NA else effect,
                     correlation_id = cid, detail = "synthetic failure")
            },
            write_outcome = function(session, record, ...) {
                events <<- c(events, "write_outcome")
                assign("record", record, envir = parent.env(environment()))
                list(status = if (persist_fail) "persist_failed" else "ok")
            },
            refuse = function(...) stop("unexpected refusal path")))
        on.exit(set_ops(old_ops), add = TRUE)
        old_pk <- set_pkcheck(function(action) {
            events <<- c(events, "pkcheck")
            0L
        })
        on.exit(set_pkcheck(old_pk), add = TRUE)
        old_reader <- set_reader(list(
            installed = function() {
                events <<- c(events, if (committed) "post-read" else "pre-read")
                if (committed && read_fail) stop("synthetic read failure")
                if (committed) after else before
            },
            selections = function(...) stop("unexpected selection read")))
        on.exit(set_reader(old_reader), add = TRUE)
        preview <- structure(list(verb = paste0("apt.", verb),
            resource = if (verb == "configure") "" else "canary-fixture",
            packages = if (verb == "configure") character() else "canary-fixture",
            plan_schema = 1L, plan_hash = strrep("b", 64L), advisory_verdict = "ok",
            records = list(list(package = "canary-fixture", architecture = "all",
                action = "install", to_version = "1.0", state = "half-configured"))),
            class = "pkgops_preview")
        commit <- if (verb == "configure") pkgops::apt_configure else pkgops::apt_install
        result <- tryCatch(commit(preview, interactive = FALSE), error = function(e) {
            events <<- c(events, "signal")
            e
        })
        list(result = result, record = record, events = events)
    }

    # G6: package installation touched dpkg and left a half-configured package.
    x <- exercise()
    expect_inherits(x$result, "runix_dpkg_broken")
    expect_identical(x$result$effect_issued, TRUE)
    expect_identical(x$result$correlation_id, cid)
    expect_identical(x$events, c("capability", "pkcheck", "open", "pre-read",
                                "commit", "post-read", "write_outcome", "signal"))
    expect_identical(x$record$outcome, "error")
    expect_identical(x$record$effect_issued, TRUE)
    expect_identical(x$record$authorized_via, "pkcheck")
    expect_identical(x$record$observed,
                     list("canary-fixture:all" = list(status = "half-configured", version = "1.0")))
    expect_identical(x$record$changed, FALSE)
    expect_identical(x$record$state_changed, TRUE)
    expect_identical(x$record$observed_failed, FALSE)

    # G7: configure ran but the package is still broken; no observed transition.
    x <- exercise(verb = "configure", before = broken)
    expect_inherits(x$result, "runix_dpkg_broken")
    expect_identical(x$record$operation, "apt.configure")
    expect_identical(x$record$observed[["canary-fixture:all"]]$status, "half-configured")
    expect_identical(x$record$changed, FALSE)
    expect_identical(x$record$state_changed, FALSE)
    expect_identical(x$record$effect_issued, TRUE)
    expect_identical(tail(x$events, 3L), c("post-read", "write_outcome", "signal"))

    # The same status can be a pre-effect refusal; never infer effect from status.
    x <- exercise(effect = FALSE, before = broken)
    expect_inherits(x$result, "runix_dpkg_broken")
    expect_identical(x$result$effect_issued, FALSE)
    expect_identical(x$record$effect_issued, FALSE)
    expect_identical(x$record$state_changed, FALSE)
    expect_identical(x$record$observed[["canary-fixture:all"]]$status, "half-configured")

    # A read failure cannot replace the helper failure or invent observed state.
    x <- exercise(read_fail = TRUE)
    expect_inherits(x$result, "runix_dpkg_broken")
    expect_identical(x$record$outcome, "error")
    expect_identical(x$record$effect_issued, TRUE)
    expect_identical(x$record$observed_failed, TRUE)
    expect_false(any(c("observed", "changed", "state_changed") %in% names(x$record)))
    expect_identical(tail(x$events, 3L), c("post-read", "write_outcome", "signal"))

    # Audit persistence failure still supersedes the known helper failure.
    x <- exercise(persist_fail = TRUE)
    expect_inherits(x$result, "runix_broker_error")
    expect_identical(x$result$persist_status, "persist_failed")
    expect_identical(x$result$effect_issued, TRUE)
    expect_identical(x$record$observed[["canary-fixture:all"]]$status, "half-configured")
    expect_identical(tail(x$events, 3L), c("post-read", "write_outcome", "signal"))

    # Unknown effect: no post-read and no fabricated outcome closes the intent.
    x <- exercise(unknown = TRUE)
    expect_inherits(x$result, "runix_helper_bad_result")
    expect_identical(x$result$effect_issued, NA)
    expect_identical(x$result$correlation_id, cid)
    expect_identical(x$record, NULL)
    expect_identical(x$events, c("capability", "pkcheck", "open", "pre-read", "commit", "signal"))
})
