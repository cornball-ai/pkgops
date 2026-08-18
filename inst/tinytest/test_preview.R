# The preview core: the request pkgops builds, the strict validation of the
# planner's reply, and the status -> object / condition mapping. Driven by an
# injected fake runner returning canned JSON, so no planner binary is spawned.

H <- strrep("a", 64L)  # a well-formed 64-hex plan digest

# A fake runner: records the (cmd, input) it saw, returns canned output + exit.
seen <- new.env(parent = emptyenv())
mk <- function(json, exit = 0L) {
    force(json); force(exit)
    function(cmd, args, input) {
        seen$cmd <- cmd
        seen$input <- input
        list(status = exit, output = json, stderr = character())
    }
}

# Build a planner response line with per-field control (defaults form a valid
# install "ok"); pass a field to override or omit.
resp <- function(status, verb = "apt.install", pkgs = '["nginx"]',
                 plan_schema = "null", resource = '"nginx"',
                 plan_hash = "null", records = "[]", detail = "null") {
    sprintf(paste0('{"schema_version":1,"status":"%s","verb":"%s",',
                   '"packages":%s,"plan_schema":%s,"resource":%s,',
                   '"plan_hash":%s,"records":%s,"detail":%s}'),
            status, verb, pkgs, plan_schema, resource, plan_hash, records, detail)
}
quo <- function(s) paste0('"', s, '"')

## ---- ok: an advisory object carrying exactly what the digest bound --------
old <- pkgops:::set_runner(mk(resp("ok", plan_schema = "1",
    plan_hash = quo(H),
    records = '[{"package":"nginx","architecture":"amd64","action":"install"}]')))
p <- pkgops::apt_install_preview("nginx")
pkgops:::set_runner(old)

expect_inherits(p, "pkgops_preview")
expect_equal(p$advisory_verdict, "ok")
expect_equal(p$verb, "apt.install")
expect_equal(p$plan_hash, H)
expect_equal(p$plan_schema, 1L)
expect_equal(p$resource, "nginx")
expect_false(p$autonomous)
expect_equal(p$packages, "nginx")
expect_equal(length(p$records), 1L)
expect_equal(p$records[[1]]$action, "install")
# the request carried a JSON ARRAY for packages (not a scalar) and the exact verb
expect_true(grepl('"packages":["nginx"]', seen$input, fixed = TRUE))
expect_true(grepl('"verb":"apt.install"', seen$input, fixed = TRUE))
expect_equal(seen$cmd, "/usr/bin/runix-apt-preview")

## ---- no_op: a success object with no digest -------------------------------
old <- pkgops:::set_runner(mk(resp("no_op", verb = "apt.upgrade", pkgs = "[]",
    resource = '""')))
n <- pkgops::apt_upgrade_preview()
pkgops:::set_runner(old)
expect_inherits(n, "pkgops_preview")
expect_equal(n$advisory_verdict, "no_op")
expect_true(is.na(n$plan_hash))
expect_true(is.na(n$plan_schema))
expect_equal(length(n$records), 0L)
expect_true(grepl('"packages":[]', seen$input, fixed = TRUE))

## ---- autonomous flag tracks the verb, not the status ----------------------
old <- pkgops:::set_runner(mk(resp("ok", verb = "apt.hold", plan_schema = "1",
    plan_hash = quo(H), records = '[{"package":"nginx","from_state":"install","to_state":"hold"}]')))
ph <- pkgops::apt_hold_preview("nginx")
pkgops:::set_runner(old)
expect_true(ph$autonomous)              # hold is autonomous
expect_equal(ph$records[[1]]$to_state, "hold")

old <- pkgops:::set_runner(mk(resp("ok", verb = "apt.update", pkgs = "[]",
    resource = '""', plan_schema = "1", plan_hash = quo(H))))
pu <- pkgops::apt_update_preview()
pkgops:::set_runner(old)
expect_true(pu$autonomous)              # update is autonomous

## ---- the three policy refusals: typed, carry records + digest -------------
refusals <- list(
    package_not_owned = "runix_not_owned",
    held              = "runix_held",
    protected_package = "runix_protected")
for (st in names(refusals)) {
    old <- pkgops:::set_runner(mk(resp(st, plan_schema = "1", plan_hash = quo(H),
        records = '[{"package":"nginx","action":"install"}]',
        detail = quo("nginx")), exit = 1L))
    e <- tryCatch(pkgops::apt_install_preview("nginx"), error = identity)
    pkgops:::set_runner(old)
    expect_inherits(e, refusals[[st]])
    expect_inherits(e, "pkgops_error")
    expect_inherits(e, "runix_error")
    expect_equal(e$status, st)
    expect_equal(e$plan_hash, H)
    expect_equal(length(e$records), 1L)
    expect_equal(e$detail, "nginx")
}

## ---- the non-digest error statuses that echo the request: typed -----------
## (resolve_failed/dpkg_broken/internal carry the verb, echo the packages, and
## carry a resource; schema_invalid and the pre-parse internal are separate below)
plain <- list(
    resolve_failed = "runix_resolve_failed",
    dpkg_broken    = "runix_dpkg_broken",
    internal       = "runix_helper_internal")
for (st in names(plain)) {
    old <- pkgops:::set_runner(mk(resp(st, detail = quo("boom")), exit = 1L))
    e <- tryCatch(pkgops::apt_install_preview("nginx"), error = identity)
    pkgops:::set_runner(old)
    expect_inherits(e, plain[[st]])
    expect_inherits(e, "pkgops_error")
}

## ---- strict validation: every untrustworthy reply fails closed -----------
bad_cases <- list(
    unparseable      = list(json = "this is not json",      exit = 0L),
    empty_output     = list(json = character(0),            exit = 0L),
    verb_mismatch    = list(json = resp("ok", verb = "apt.remove", plan_schema = "1",
                                        plan_hash = quo(H)), exit = 0L),
    packages_echo    = list(json = resp("ok", pkgs = '["curl"]', plan_schema = "1",
                                        plan_hash = quo(H)), exit = 0L),
    exit_inconsistent= list(json = resp("ok", plan_schema = "1", plan_hash = quo(H)),
                            exit = 1L),                       # ok must exit 0
    err_exit_zero    = list(json = resp("resolve_failed"),  exit = 0L), # error must exit nonzero
    hash_missing_ok  = list(json = resp("ok", plan_schema = "1"), exit = 0L), # ok needs a hash
    hash_on_error    = list(json = resp("resolve_failed", plan_schema = "1",
                                        plan_hash = quo(H)), exit = 1L),
    bad_hash         = list(json = resp("ok", plan_schema = "1",
                                        plan_hash = quo("xyz")), exit = 0L),
    unknown_status   = list(json = resp("frobnicated"),     exit = 1L),
    # a fractional plan_schema must be refused, never truncated to 1
    schema_fractional= list(json = resp("ok", plan_schema = "1.5",
                                        plan_hash = quo(H)), exit = 0L),
    # a digest field on a non-digest status is refused (both hash and schema)
    schema_on_error  = list(json = resp("resolve_failed", plan_schema = "1"),
                            exit = 1L),
    # packages / records must be ACTUAL JSON arrays, not scalars or wrong element types
    scalar_packages  = list(json = resp("ok", pkgs = '"nginx"', plan_schema = "1",
                                        plan_hash = quo(H)), exit = 0L),
    records_not_array= list(json = resp("ok", records = '"x"', plan_schema = "1",
                                        plan_hash = quo(H)), exit = 0L),
    records_nonobject= list(json = resp("ok", records = '["x"]', plan_schema = "1",
                                        plan_hash = quo(H)), exit = 0L))
for (nm in names(bad_cases)) {
    bc <- bad_cases[[nm]]
    old <- pkgops:::set_runner(mk(bc$json, exit = bc$exit))
    e <- tryCatch(pkgops::apt_install_preview("nginx"), error = identity)
    pkgops:::set_runner(old)
    expect_inherits(e, "runix_preview_failed")
    expect_inherits(e, "pkgops_error")
    expect_true(!is.null(e$reason), info = nm)
}

## ---- a schema_version other than 1 is refused -----------------------------
ok_line <- function(sv = "1", extra = "", drop = character()) {
    fields <- c(schema_version = sv, status = '"ok"', verb = '"apt.install"',
                packages = '["nginx"]', plan_schema = "1", resource = '"nginx"',
                plan_hash = quo(H), records = "[]", detail = "null")
    fields <- fields[!(names(fields) %in% drop)]
    body <- paste(sprintf('"%s":%s', names(fields), fields), collapse = ",")
    paste0("{", body, if (nzchar(extra)) paste0(",", extra) else "", "}")
}
refuse <- function(json, exit = 0L) {
    old <- pkgops:::set_runner(mk(json, exit = exit))
    e <- tryCatch(pkgops::apt_install_preview("nginx"), error = identity)
    pkgops:::set_runner(old)
    e
}

# schema_version 2, and the integer-truncation regression: 1.5 must be refused
expect_inherits(refuse(ok_line(sv = "2")), "runix_preview_failed")
expect_inherits(refuse(ok_line(sv = "1.5")), "runix_preview_failed")

## ---- exact top-level key set: a missing or extra field is refused ---------
expect_inherits(refuse(ok_line(drop = "detail")), "runix_preview_failed")
expect_inherits(refuse(ok_line(extra = '"surprise":1')), "runix_preview_failed")

## ---- the packages echo is order-sensitive (identical, not a set) ----------
two <- function(echo_pkgs) {
    resp("ok", pkgs = echo_pkgs, resource = '"curl,nginx"',
         plan_schema = "1", plan_hash = quo(H))
}
# reordered echo -> refused
old <- pkgops:::set_runner(mk(two('["nginx","curl"]')))
e <- tryCatch(pkgops::apt_install_preview(c("curl", "nginx")), error = identity)
pkgops:::set_runner(old)
expect_inherits(e, "runix_preview_failed")

# same order -> accepted, packages carried verbatim in request order
old <- pkgops:::set_runner(mk(two('["curl","nginx"]')))
p2 <- pkgops::apt_install_preview(c("curl", "nginx"))
pkgops:::set_runner(old)
expect_inherits(p2, "pkgops_preview")
expect_equal(p2$packages, c("curl", "nginx"))
expect_true(grepl('"packages":["curl","nginx"]', seen$input, fixed = TRUE))

## ---- exact per-status verb/resource/packages shape -----------------------
# A raw response builder with full control over the pre-parse fields.
raw <- function(status, verb = "null", packages = "[]", resource = "null",
                plan_schema = "null", plan_hash = "null", records = "[]",
                detail = "null") {
    sprintf(paste0('{"schema_version":1,"status":"%s","verb":%s,',
                   '"packages":%s,"plan_schema":%s,"resource":%s,',
                   '"plan_hash":%s,"records":%s,"detail":%s}'),
            status, verb, packages, plan_schema, resource, plan_hash,
            records, detail)
}
call_install <- function(json, exit) {
    old <- pkgops:::set_runner(mk(json, exit = exit))
    e <- tryCatch(pkgops::apt_install_preview("nginx"), error = identity)
    pkgops:::set_runner(old)
    e
}

# schema_invalid: the well-formed pre-parse shape (null verb/resource, no
# packages) is accepted and mapped; any real verb/resource/packages is refused.
expect_inherits(call_install(raw("schema_invalid", detail = quo("bad")), 1L),
                "runix_preview_failed")
expect_inherits(call_install(raw("schema_invalid", verb = '"apt.install"'), 1L),
                "runix_preview_failed")          # a real verb on schema_invalid
expect_inherits(call_install(raw("schema_invalid", resource = '"nginx"'), 1L),
                "runix_preview_failed")          # a real resource on schema_invalid
expect_inherits(call_install(raw("schema_invalid", packages = '["nginx"]'), 1L),
                "runix_preview_failed")          # echoed packages on schema_invalid

# internal: BOTH shapes are valid and map to runix_helper_internal --
#  (a) pre-parse I/O error: null verb/resource, no packages
ei_pre <- call_install(raw("internal", detail = quo("io")), 1L)
expect_inherits(ei_pre, "runix_helper_internal")
#  (b) post-parse: verb + echoed packages, resource may be null
ei_post <- call_install(raw("internal", verb = '"apt.install"',
                            packages = '["nginx"]', resource = "null",
                            detail = quo("apt_init")), 1L)
expect_inherits(ei_post, "runix_helper_internal")
# ... but a half-formed internal (null verb yet echoed packages) is refused
expect_inherits(call_install(raw("internal", packages = '["nginx"]'), 1L),
                "runix_preview_failed")

# resolve_failed / dpkg_broken must carry a non-null resource
expect_inherits(call_install(raw("resolve_failed", verb = '"apt.install"',
                                 packages = '["nginx"]', resource = "null"), 1L),
                "runix_preview_failed")
expect_inherits(call_install(raw("dpkg_broken", verb = '"apt.install"',
                                 packages = '["nginx"]', resource = "null"), 1L),
                "runix_preview_failed")

## ---- a missing planner binary fails closed, typed -------------------------
# (default runner, no injection: /usr/bin/runix-apt-preview is absent here)
if (Sys.which("/usr/bin/runix-apt-preview") == "") {
    e <- tryCatch(pkgops::apt_install_preview("nginx"), error = identity)
    expect_inherits(e, "pkgops_missing_tool")
    expect_inherits(e, "pkgops_error")
}
