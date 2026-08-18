# The commit-result contract (R/outcome.R): the closed status vocabulary and its
# runix condition mapping, the tri-state effect_issued, cid-equality, and the
# pkgops_outcome object. Pure -- no effect, no spawn, no broker.

## ---- drift guard: the twelve statuses, pinned to pkgexec v0.0.3 -----------
# Mirrors src/result.c pkgx_status_name / tests/test_result.c, in enum order. A
# rename or reordering in pkgexec must break this test.
expected_statuses <- c("ok", "no_op", "apt_locked", "package_not_owned", "held",
                       "protected_package", "no_intent", "resolve_failed",
                       "not_applied", "operation_failed", "dpkg_broken",
                       "internal")
expect_equal(pkgops:::.PKGOPS_COMMIT_STATUSES, expected_statuses)
expect_equal(length(pkgops:::.PKGOPS_COMMIT_STATUSES), 12L)

## ---- the status -> runix condition mapping (closed, pinned) ----------------
expected_conditions <- c(
    ok = "ok", no_op = "no_op", apt_locked = "runix_apt_locked",
    package_not_owned = "runix_not_owned", held = "runix_held",
    protected_package = "runix_protected", no_intent = "runix_no_intent",
    resolve_failed = "runix_resolve_failed", not_applied = "runix_not_applied",
    operation_failed = "runix_operation_failed", dpkg_broken = "runix_dpkg_broken",
    internal = "runix_helper_internal")
expect_equal(pkgops:::.PKGOPS_STATUS_CONDITION, expected_conditions)

# the overlapping names match the preview channel exactly (no divergence)
for (st in c("package_not_owned", "held", "protected_package", "resolve_failed",
             "dpkg_broken")) {
    expect_true(pkgops:::.status_condition(st) %in%
                c("runix_not_owned", "runix_held", "runix_protected",
                  "runix_resolve_failed", "runix_dpkg_broken"))
}
expect_equal(pkgops:::.status_condition("apt_locked"), "runix_apt_locked")
expect_equal(pkgops:::.status_condition("internal"), "runix_helper_internal")
expect_equal(pkgops:::.status_condition("ok"), "ok")
# session-level and polkit-terminal statuses are canonical inputs too
expect_equal(pkgops:::.status_condition("unauthorized"), "runix_unauthorized")
expect_equal(pkgops:::.status_condition("approval_required"), "runix_approval_required")
expect_equal(pkgops:::.status_condition("effect_unknown"), "runix_helper_bad_result")

# an unknown or malformed status fails closed as runix_helper_bad_result
e <- tryCatch(pkgops:::.status_condition("frobnicated"), error = identity)
expect_inherits(e, "runix_helper_bad_result")
expect_inherits(e, "pkgops_error")
e_empty <- tryCatch(pkgops:::.status_condition(character(0)), error = identity)
expect_inherits(e_empty, "runix_helper_bad_result")
e2 <- tryCatch(pkgops:::.status_condition(c("ok", "held")), error = identity)
expect_inherits(e2, "runix_helper_bad_result")

## ---- success set ----------------------------------------------------------
expect_true(pkgops:::.status_is_success("ok"))
expect_true(pkgops:::.status_is_success("no_op"))
expect_false(pkgops:::.status_is_success("apt_locked"))
expect_false(pkgops:::.status_is_success("internal"))
expect_false(pkgops:::.status_is_success("frobnicated"))

## ---- retryability: only apt_locked, registered in the shared registry -----
expect_equal(pkgops:::.PKGOPS_RETRYABLE_STATUSES, "apt_locked")
apt_locked_cond <- structure(list(message = "locked"),
    class = c("runix_apt_locked", "pkgops_error", "runix_error", "error",
              "condition"))
held_cond <- structure(list(message = "held"),
    class = c("runix_held", "pkgops_error", "runix_error", "error", "condition"))
expect_true(runix::is_retryable(apt_locked_cond))   # .onLoad registered it
expect_false(runix::is_retryable(held_cond))         # every other status: no

## ---- effect_issued tri-state (helper-authoritative, never from status) ----
ne <- pkgops:::.norm_effect_issued
expect_identical(ne(TRUE), TRUE)
expect_identical(ne(FALSE), FALSE)
expect_identical(ne(NA), NA)
expect_identical(ne("true"), NA)          # a string is untrusted -> unknown
expect_identical(ne(1L), NA)               # a number is not the boolean
expect_identical(ne(c(TRUE, FALSE)), NA)   # non-scalar -> unknown
expect_identical(ne(NULL), NA)
expect_identical(ne(logical(0)), NA)

## ---- cid-equality ---------------------------------------------------------
ce <- pkgops:::.cid_equal
cid <- "20250101000000000000-0123456789abcdef"
expect_true(ce(cid, cid))
expect_false(ce(cid, "20250101000000000000-ffffffffffffffff"))  # mismatch
expect_false(ce("", ""))                    # empty is not a real cid
expect_false(ce(cid, NA_character_))
expect_false(ce(c(cid, cid), cid))          # non-scalar

## ---- the pkgops_outcome object + print ------------------------------------
H <- strrep("a", 64L)
ok_out <- pkgops:::new_pkgops_outcome(
    correlation_id = cid, verb = "apt.install", resource = "nginx",
    plan_hash = H, status = "ok", effect_issued = TRUE)
expect_inherits(ok_out, "pkgops_outcome")
expect_equal(ok_out$schema_version, 1L)
expect_equal(ok_out$status, "ok")
expect_identical(ok_out$effect_issued, TRUE)
expect_true(is.na(ok_out$verified))          # verification is a later increment
expect_null(ok_out$condition)

# the constructor takes the RAW helper status and stores its canonical mapped
# form; effect_issued (untrusted) is normalized
held_out <- pkgops:::new_pkgops_outcome(
    correlation_id = cid, verb = "apt.hold", resource = "nginx",
    plan_hash = H, status = "held", effect_issued = "bogus")
expect_equal(held_out$status, "runix_held")    # stored as the mapped condition
expect_identical(held_out$effect_issued, NA)   # bogus -> unknown

# no_op and the commit-only statuses round-trip through the mapping
expect_equal(pkgops:::new_pkgops_outcome(cid, "apt.upgrade", "", H, "no_op")$status,
             "no_op")
expect_equal(pkgops:::new_pkgops_outcome(cid, "apt.install", "nginx", H,
                                         "apt_locked")$status, "runix_apt_locked")

# an unknown status is rejected (fail closed), never stored raw
e_st <- tryCatch(pkgops:::new_pkgops_outcome(cid, "apt.install", "nginx", H,
                                             "frobnicated"), error = identity)
expect_inherits(e_st, "runix_helper_bad_result")
expect_inherits(e_st, "pkgops_error")
# ... and a mapped name fed back in is NOT a valid raw status
e_mapped <- tryCatch(pkgops:::new_pkgops_outcome(cid, "apt.hold", "nginx", H,
                                                 "runix_held"), error = identity)
expect_inherits(e_mapped, "runix_helper_bad_result")

# verified is enforced as a strict tri-state (pkgops's own verdict)
expect_true(is.na(pkgops:::new_pkgops_outcome(cid, "apt.install", "nginx", H,
                                              "ok", verified = NA)$verified))
expect_identical(pkgops:::new_pkgops_outcome(cid, "apt.install", "nginx", H,
                                             "ok", verified = TRUE)$verified, TRUE)
expect_identical(pkgops:::new_pkgops_outcome(cid, "apt.install", "nginx", H,
                                             "ok", verified = FALSE)$verified, FALSE)
for (bad in list("yes", 1L, c(TRUE, FALSE), NULL, NA_character_)) {
    e_v <- tryCatch(pkgops:::new_pkgops_outcome(cid, "apt.install", "nginx", H,
                                                "ok", verified = bad),
                    error = identity)
    expect_inherits(e_v, "pkgops_bad_request")
}

out <- capture.output(print(ok_out))
expect_true(any(grepl("pkgops outcome", out)))
expect_true(any(grepl("apt.install", out, fixed = TRUE)))
expect_true(any(grepl("effect issued: yes", out)))
expect_identical(print(ok_out), invisible(ok_out))
