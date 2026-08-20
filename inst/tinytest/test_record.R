# The durable audit record grammar (R/commit.R): .outcome_record() maps a closed
# effect-intent outcome onto the broker's RECORD_SCHEMA allow-list, and
# .validate_record() guards that the built record conforms (only allow-list fields,
# correct types, no broker-reserved key) before it is ever sent. Hermetic: the real
# allow-list enforcement is broker-side, proven in the VM-gated increment.

rec_of <- pkgops:::.outcome_record
validate <- pkgops:::.validate_record
FIELDS <- pkgops:::.PKGOPS_RECORD_FIELDS
RESERVED <- pkgops:::.PKGOPS_RECORD_RESERVED

## An outcome with the post-state fields set (as .capture_post would).
mkout <- function(verb = "apt.install", resource = "nginx", status = "ok",
                  effect_issued = TRUE, verified = NA, verify_detail = NA_character_,
                  authorized_via = "pkcheck", observed = NULL,
                  observed_failed = NA, state_changed = NA) {
    o <- pkgops:::new_pkgops_outcome(correlation_id = "c", verb = verb,
                                     resource = resource, plan_hash = "h",
                                     status = status, effect_issued = effect_issued,
                                     verified = verified,
                                     verify_detail = verify_detail)
    o$authorized_via <- authorized_via
    o$observed <- observed
    o$observed_failed <- observed_failed
    o$state_changed <- state_changed
    o
}

## ---- every built record conforms to the allow-list ---------------------------
r <- rec_of(mkout())
expect_true(all(names(r) %in% names(FIELDS)))         # only allow-list fields
expect_false(any(names(r) %in% RESERVED))             # never a reserved key
expect_equal(r$operation, "apt.install")
expect_equal(r$resource, "nginx")
expect_identical(r$effect_issued, TRUE)
expect_equal(r$scope, "system")                       # apt is system scope
expect_identical(r$preview, FALSE)                    # a commit, not a preview
expect_equal(r$authorized_via, "pkcheck")

## ---- verified -> changed (only when the post-state was read) ------------------
# a matched verification -> changed TRUE
expect_identical(rec_of(mkout(verified = TRUE, observed_failed = FALSE))$changed,
                 TRUE)
# a mismatch (read OK, disagreed) -> changed FALSE + observed_reason
r <- rec_of(mkout(verified = FALSE, observed_failed = FALSE,
                  verify_detail = "version 1.1, expected 1.2"))
expect_identical(r$changed, FALSE)
expect_equal(r$observed_reason, "version 1.1, expected 1.2")
expect_identical(r$observed_failed, FALSE)
# a READ FAILURE -> changed is OMITTED (unknown, never a false "did not change")
r <- rec_of(mkout(verified = FALSE, observed_failed = TRUE,
                  verify_detail = "verification error: dpkg exploded"))
expect_false("changed" %in% names(r))
expect_identical(r$observed_failed, TRUE)
expect_equal(r$observed_reason, "verification error: dpkg exploded")
# verified NA (no post-state, e.g. update) -> changed omitted
expect_false("changed" %in% names(rec_of(mkout(verified = NA))))

## ---- observed carries the per-package post-state object ----------------------
obs <- list("nginx:amd64" = list(status = "installed", version = "1.2"))
r <- rec_of(mkout(verified = TRUE, observed_failed = FALSE, observed = obs))
expect_equal(r$observed, obs)                         # the object, verbatim
expect_true(is.list(r$observed) && !is.null(names(r$observed)))

## ---- state_changed is a scalar boolean or omitted ----------------------------
expect_identical(rec_of(mkout(state_changed = TRUE))$state_changed, TRUE)
expect_identical(rec_of(mkout(state_changed = FALSE))$state_changed, FALSE)
expect_false("state_changed" %in% names(rec_of(mkout(state_changed = NA))))

## ---- update: no post-state read -> observed/changed/state_changed all OMITTED -
# apt.update reads no package post-state and no pre/post index state, so .observe
# returns NULL (read_failed FALSE) and .state_changed returns NA. The record must
# then carry NONE of the three -- never a fabricated "did change" (blocker 2).
r <- rec_of(mkout(verb = "apt.update", resource = "*", verified = NA,
                  observed = NULL, observed_failed = FALSE, state_changed = NA))
expect_false("observed" %in% names(r))
expect_false("changed" %in% names(r))
expect_false("state_changed" %in% names(r))
expect_identical(r$observed_failed, FALSE)   # a real bool (no read failed); never NA here
expect_equal(r$operation, "apt.update")

## ---- NA/NULL optional fields are OMITTED, not sent as null -------------------
# a bare known-failure-style outcome: no verification captured
r <- rec_of(mkout(verified = NA, authorized_via = "pkexec", observed = NULL,
                  observed_failed = NA, state_changed = NA,
                  verify_detail = NA_character_))
expect_equal(sort(names(r)),
             sort(c("operation", "outcome", "resource", "effect_issued", "scope",
                    "preview", "authorized_via")))
expect_equal(r$outcome, "ok")                 # a success status -> coarse "ok"
expect_equal(r$authorized_via, "pkexec")

## ---- the coarse `outcome`: ok for success, error for every closed failure ------
expect_equal(rec_of(mkout(status = "no_op", effect_issued = FALSE))$outcome, "ok")
expect_equal(rec_of(mkout(status = "operation_failed",
                          effect_issued = TRUE))$outcome, "error")
expect_equal(rec_of(mkout(status = "dpkg_broken", effect_issued = FALSE))$outcome,
             "error")
expect_equal(rec_of(mkout(status = "held", effect_issued = FALSE))$outcome, "error")

## ---- effect_issued must be a known boolean (never NA at write time) ----------
expect_error(rec_of(mkout(effect_issued = NA)), class = "pkgops_bad_request")

## ============================================================================
## .validate_record: the schema guard
## ============================================================================

## a minimal valid record passes (operation + outcome are the broker-required pair)
expect_silent(validate(list(operation = "apt.install", outcome = "ok",
                            resource = "nginx", effect_issued = TRUE,
                            scope = "system", preview = FALSE)))

## the two broker-REQUIRED fields must BOTH be present
expect_error(validate(list(outcome = "ok", resource = "nginx")),
             class = "pkgops_bad_request")               # missing operation
expect_error(validate(list(operation = "apt.install", resource = "nginx")),
             class = "pkgops_bad_request")               # missing outcome

## a broker-RESERVED key is rejected
for (k in RESERVED) {
    bad <- list(operation = "apt.install", outcome = "ok", resource = "nginx",
                effect_issued = TRUE)
    bad[[k]] <- "x"
    expect_error(validate(bad), class = "pkgops_bad_request")
}

## a NON-allow-list field is rejected (the smuggled-field case)
expect_error(validate(list(operation = "apt.install", outcome = "ok",
                           resource = "nginx", effect_issued = TRUE,
                           verified = TRUE)),
             class = "pkgops_bad_request")   # `verified` is NOT a broker field
expect_error(validate(list(operation = "apt.install", outcome = "ok",
                           request_id = "42")),
             class = "pkgops_bad_request")

## wrong TYPES are rejected (the broker validates T_BOOL / T_OBJECT / ...); each
## record carries the required pair so the presence guard does not mask the type
## check.
base_ok <- list(operation = "apt.install", outcome = "ok")
expect_error(validate(c(base_ok, list(changed = "yes"))),
             class = "pkgops_bad_request")                                     # bool
expect_error(validate(c(base_ok, list(observed = "nginx"))),
             class = "pkgops_bad_request")                                     # object
expect_error(validate(c(base_ok, list(state_changed = list(a = 1)))),
             class = "pkgops_bad_request")                                     # bool
expect_error(validate(c(base_ok, list(elapsed = -1))),
             class = "pkgops_bad_request")                                     # >= 0
expect_error(validate(c(base_ok, list(effect_issued = NA))),
             class = "pkgops_bad_request")                                     # non-NA

## a correct object / bool / number pass (with the required pair present)
expect_silent(validate(list(operation = "apt.install", outcome = "ok",
                            observed = list("nginx:amd64" =
                                            list(status = "installed")))))
expect_silent(validate(list(operation = "apt.install", outcome = "error",
                            changed = TRUE, state_changed = FALSE,
                            observed_failed = FALSE, elapsed = 0)))

## ---- the allow-list is exactly the broker's 16 domain fields -----------------
expect_equal(length(FIELDS), 16L)
expect_true(all(c("observed", "changed", "state_changed", "observed_failed",
                  "observed_reason", "authorized_via", "operation", "resource",
                  "effect_issued", "scope", "preview") %in% names(FIELDS)))
