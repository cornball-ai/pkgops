# The commit-result classifier (R/classify.R): runix_commit_result -> outcome +
# condition + leave_open, applying the contract's close-vs-open rule. Pure: fake
# runix_commit_result inputs, no session call, no IO. The classifier NEVER raises.

H <- strrep("a", 64L)
prev <- list(verb = "apt.install", resource = "nginx", plan_hash = H)
cl <- pkgops:::.classify_commit

cr <- function(session_status, status = NULL, effect_issued = NA,
               correlation_id = "20250101000000000000-0123456789abcdef",
               detail = NULL) {
    list(session_status = session_status, status = status,
         effect_issued = effect_issued, correlation_id = correlation_id,
         detail = detail)
}

## ---- ss=ok, success statuses: no condition, closed --------------------------
r_ok <- cl(cr("ok", "ok", TRUE), prev)
expect_inherits(r_ok$outcome, "pkgops_outcome")
expect_equal(r_ok$outcome$status, "ok")
expect_identical(r_ok$outcome$effect_issued, TRUE)
expect_null(r_ok$condition)
expect_false(r_ok$leave_open)

r_noop <- cl(cr("ok", "no_op", FALSE), prev)
expect_equal(r_noop$outcome$status, "no_op")
expect_null(r_noop$condition)
expect_false(r_noop$leave_open)

## ---- ss=ok, a policy refusal: mapped condition, closed, effect FALSE --------
r_held <- cl(cr("ok", "held", FALSE, detail = "nginx"), prev)
expect_equal(r_held$outcome$status, "runix_held")        # canonical mapped name
expect_inherits(r_held$condition, "runix_held")
expect_inherits(r_held$condition, "pkgops_error")
expect_inherits(r_held$condition, "runix_error")
expect_identical(r_held$outcome$effect_issued, FALSE)
expect_false(r_held$leave_open)                          # known truth -> close
expect_equal(r_held$condition$verb, "apt.install")
expect_equal(r_held$condition$plan_hash, H)
expect_equal(r_held$condition$status, "held")            # raw helper status
expect_equal(r_held$condition$detail, "nginx")
expect_identical(r_held$outcome$condition, r_held$condition)

## ---- dpkg_broken carries the helper's effect_issued either way, both close --
r_broke_t <- cl(cr("ok", "dpkg_broken", TRUE), prev)
expect_inherits(r_broke_t$condition, "runix_dpkg_broken")
expect_identical(r_broke_t$outcome$effect_issued, TRUE)  # a commit broke dpkg
expect_false(r_broke_t$leave_open)
r_broke_f <- cl(cr("ok", "dpkg_broken", FALSE), prev)
expect_identical(r_broke_f$outcome$effect_issued, FALSE) # pre-existing broken
expect_false(r_broke_f$leave_open)

## ---- operation_failed / no_intent are KNOWN -> closed ----------------------
expect_false(cl(cr("ok", "operation_failed", TRUE), prev)$leave_open)
expect_inherits(cl(cr("ok", "operation_failed", TRUE), prev)$condition,
                "runix_operation_failed")
expect_inherits(cl(cr("ok", "no_intent", FALSE), prev)$condition, "runix_no_intent")

## ---- apt_locked maps to the retryable condition ----------------------------
r_lock <- cl(cr("ok", "apt_locked", FALSE), prev)
expect_inherits(r_lock$condition, "runix_apt_locked")
expect_true(runix::is_retryable(r_lock$condition))       # .onLoad registered it
expect_false(runix::is_retryable(r_held$condition))
expect_false(r_lock$leave_open)                          # refused pre-commit, closed

## ---- session-level: unauthorized / spawn_failed close false ----------------
r_unauth <- cl(cr("unauthorized", effect_issued = FALSE), prev)
expect_equal(r_unauth$outcome$status, "runix_unauthorized")
expect_inherits(r_unauth$condition, "runix_unauthorized")
expect_identical(r_unauth$outcome$effect_issued, FALSE)
expect_false(r_unauth$leave_open)

r_spawn <- cl(cr("spawn_failed", effect_issued = FALSE), prev)
expect_equal(r_spawn$outcome$status, "pkgops_spawn_failed")
expect_inherits(r_spawn$condition, "pkgops_spawn_failed")
expect_identical(r_spawn$outcome$effect_issued, FALSE)
expect_false(r_spawn$leave_open)                         # definitely no effect

## ---- effect_unknown and garbage: LEFT OPEN, effect NA ----------------------
r_unk <- cl(cr("effect_unknown", effect_issued = NA), prev)
expect_equal(r_unk$outcome$status, "runix_helper_bad_result")
expect_inherits(r_unk$condition, "runix_helper_bad_result")
expect_true(is.na(r_unk$outcome$effect_issued))
expect_true(r_unk$leave_open)                            # effect genuinely unknown

r_garbage <- cl(cr("nonsense-status", effect_issued = NA), prev)
expect_inherits(r_garbage$condition, "runix_helper_bad_result")
expect_true(r_garbage$leave_open)

# ss=ok but an unrecognised helper status is untrustworthy -> unknown, left open
r_badstatus <- cl(cr("ok", "frobnicated", TRUE), prev)
expect_inherits(r_badstatus$condition, "runix_helper_bad_result")
expect_true(r_badstatus$leave_open)

## ---- effect_issued is normalized (untrusted helper value) ------------------
r_bogus <- cl(cr("ok", "held", "bogus"), prev)
expect_true(is.na(r_bogus$outcome$effect_issued))

## ---- the classifier NEVER raises: every case returns a list ----------------
for (ss in c("ok", "unauthorized", "spawn_failed", "effect_unknown", "weird")) {
    r <- cl(cr(ss, status = "held"), prev)
    expect_true(is.list(r) && all(c("outcome", "condition", "leave_open") %in%
                                  names(r)))
    expect_inherits(r$outcome, "pkgops_outcome")
}
