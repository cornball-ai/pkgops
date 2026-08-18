# pkgstate verification (R/verify.R): check a committed preview's resolved
# records against native dpkg/apt ground truth, per verb (contract 6.3).
# Hermetic: the pkgstate reads go through a fake reader (canned data frames), so
# dpkg is never queried. Verification is independent of the helper's status --
# .verify() sees only the plan (preview) and the ground truth (reader).

verify <- pkgops:::.verify
fam <- pkgops:::.verify_family
set_reader <- pkgops:::set_pkgstate_reader

## builders -------------------------------------------------------------------
prevv <- function(verb, records) list(verb = verb, records = records)
txn <- function(package, action, to_version = "", architecture = "amd64",
                from_version = "", flags = list()) {
    list(package = package, architecture = architecture, action = action,
         from_version = from_version, to_version = to_version, flags = flags)
}
cfg <- function(package, architecture = "amd64", current_version = "1.0",
                state = "half-configured") {
    list(package = package, architecture = architecture,
         current_version = current_version, state = state)
}
hld <- function(package, from_state, to_state) {
    list(package = package, from_state = from_state, to_state = to_state)
}
inst_df <- function(package = character(), version = character(),
                    architecture = character(), status = character()) {
    data.frame(package = package, version = version,
               architecture = architecture, status = status,
               stringsAsFactors = FALSE)
}
sel_df <- function(package = character(), architecture = character(),
                   selection = character()) {
    data.frame(package = package, architecture = architecture,
               selection = selection, stringsAsFactors = FALSE)
}
reader <- function(installed = inst_df(), selections = sel_df()) {
    list(installed = function() installed,
         selections = function(packages = NULL) {
             if (is.null(packages)) {
                 selections
             } else {
                 selections[selections$package %in% packages, , drop = FALSE]
             }
         })
}

## ---- the verb -> family map -------------------------------------------------
expect_equal(fam("apt.install"), "txn")
expect_equal(fam("apt.remove"), "txn")
expect_equal(fam("apt.purge"), "txn")
expect_equal(fam("apt.upgrade"), "txn")
expect_equal(fam("apt.dist_upgrade"), "txn")
expect_equal(fam("apt.configure"), "configure")
expect_equal(fam("apt.hold"), "hold")
expect_equal(fam("apt.unhold"), "hold")
expect_equal(fam("apt.update"), "update")
expect_null(fam("apt.bogus"))

## ---- transaction: install ---------------------------------------------------
p_inst <- prevv("apt.install", list(txn("nginx", "install", "1.2")))
r <- verify(p_inst, reader(inst_df("nginx", "1.2", "amd64", "installed")))
expect_identical(r$verified, TRUE)
expect_true(is.na(r$detail))

# wrong version installed -> FALSE
r <- verify(p_inst, reader(inst_df("nginx", "1.1", "amd64", "installed")))
expect_identical(r$verified, FALSE)
expect_true(grepl("version 1.1", r$detail))

# absent -> FALSE
r <- verify(p_inst, reader(inst_df()))
expect_identical(r$verified, FALSE)
expect_true(grepl("absent", r$detail))

# installed but only unpacked/half-configured -> FALSE
r <- verify(p_inst, reader(inst_df("nginx", "1.2", "amd64", "half-configured")))
expect_identical(r$verified, FALSE)
expect_true(grepl("half-configured", r$detail))

# wrong architecture -> not the same row -> FALSE (absent for amd64)
r <- verify(p_inst, reader(inst_df("nginx", "1.2", "i386", "installed")))
expect_identical(r$verified, FALSE)

## ---- transaction: architecture is per-record, never a wildcard --------------
# same package on two arches: each record is matched to ITS OWN arch row
two_arch <- reader(inst_df(c("nginx", "nginx"), c("1.2", "1.0"),
                           c("amd64", "i386"), c("installed", "installed")))
p_2a <- prevv("apt.install", list(txn("nginx", "install", "1.2", "amd64"),
                                  txn("nginx", "install", "1.2", "i386")))
r <- verify(p_2a, two_arch)
expect_identical(r$verified, FALSE)                # i386 is at 1.0, not 1.2
expect_true(grepl("version 1.0", r$detail))
# both records match their arch's version -> TRUE
ok_2a <- reader(inst_df(c("nginx", "nginx"), c("1.2", "1.2"),
                        c("amd64", "i386"), c("installed", "installed")))
expect_identical(verify(p_2a, ok_2a)$verified, TRUE)

# a transaction record MISSING architecture is malformed, not a wildcard match
r <- verify(prevv("apt.install",
                  list(list(package = "nginx", action = "install",
                            to_version = "1.2"))),
            reader(inst_df("nginx", "1.2", "amd64", "installed")))
expect_identical(r$verified, FALSE)
expect_true(grepl("malformed", r$detail))
# a configure record MISSING architecture is likewise malformed
r <- verify(prevv("apt.configure", list(list(package = "nginx"))),
            reader(inst_df("nginx", "1.2", "amd64", "installed")))
expect_identical(r$verified, FALSE)
expect_true(grepl("malformed", r$detail))

## ---- transaction: remove ----------------------------------------------------
p_rm <- prevv("apt.remove", list(txn("nginx", "remove")))
expect_identical(verify(p_rm, reader(inst_df("nginx", "1.2", "amd64",
                                             "config-files")))$verified, TRUE)
expect_identical(verify(p_rm, reader(inst_df()))$verified, TRUE)   # dropped row ok
# still installed -> the removal did not take
r <- verify(p_rm, reader(inst_df("nginx", "1.2", "amd64", "installed")))
expect_identical(r$verified, FALSE)

## ---- transaction: purge (config-files is a FAILED purge) --------------------
p_pg <- prevv("apt.purge", list(txn("nginx", "purge")))
expect_identical(verify(p_pg, reader(inst_df()))$verified, TRUE)
expect_identical(verify(p_pg, reader(inst_df("nginx", "", "amd64",
                                             "not-installed")))$verified, TRUE)
r <- verify(p_pg, reader(inst_df("nginx", "1.2", "amd64", "config-files")))
expect_identical(r$verified, FALSE)                # configs remain -> not purged
expect_true(grepl("config-files", r$detail))

## ---- transaction: upgrade / downgrade check to_version ----------------------
p_up <- prevv("apt.upgrade", list(txn("nginx", "upgrade", "2.0",
                                      from_version = "1.2")))
expect_identical(verify(p_up, reader(inst_df("nginx", "2.0", "amd64",
                                             "installed")))$verified, TRUE)
expect_identical(verify(p_up, reader(inst_df("nginx", "1.2", "amd64",
                                             "installed")))$verified, FALSE)
p_dn <- prevv("apt.install", list(txn("nginx", "downgrade", "1.0",
                                      from_version = "1.2")))
expect_identical(verify(p_dn, reader(inst_df("nginx", "1.0", "amd64",
                                             "installed")))$verified, TRUE)

## ---- transaction: mixed records, one failing dependency ---------------------
p_mix <- prevv("apt.install", list(txn("nginx", "install", "1.2"),
                                   txn("libfoo", "install", "3.4"),
                                   txn("oldbar", "remove")))
good <- reader(inst_df(c("nginx", "libfoo", "oldbar"),
                       c("1.2", "3.4", "9"), rep("amd64", 3L),
                       c("installed", "installed", "config-files")))
expect_identical(verify(p_mix, good)$verified, TRUE)
# libfoo failed to install -> FALSE, and the detail names libfoo not nginx
bad <- reader(inst_df(c("nginx", "oldbar"), c("1.2", "9"),
                      c("amd64", "amd64"), c("installed", "config-files")))
r <- verify(p_mix, bad)
expect_identical(r$verified, FALSE)
expect_true(grepl("libfoo", r$detail))
expect_false(grepl("nginx", r$detail))

## ---- configure: package must be fully configured post-commit ----------------
p_cfg <- prevv("apt.configure", list(cfg("nginx", state = "half-configured")))
expect_identical(verify(p_cfg, reader(inst_df("nginx", "1.2", "amd64",
                                              "installed")))$verified, TRUE)
r <- verify(p_cfg, reader(inst_df("nginx", "1.2", "amd64", "half-configured")))
expect_identical(r$verified, FALSE)
expect_identical(verify(p_cfg, reader(inst_df()))$verified, FALSE)   # absent

## ---- hold / unhold: the dpkg selection reads back ---------------------------
p_hold <- prevv("apt.hold", list(hld("nginx", "install", "hold")))
expect_identical(verify(p_hold, reader(selections = sel_df("nginx", "amd64",
                                                           "hold")))$verified, TRUE)
r <- verify(p_hold, reader(selections = sel_df("nginx", "amd64", "install")))
expect_identical(r$verified, FALSE)                # still on install
expect_true(grepl("expected hold", r$detail))
# no selection row at all -> FALSE
expect_identical(verify(p_hold, reader())$verified, FALSE)

p_unhold <- prevv("apt.unhold", list(hld("nginx", "hold", "install")))
expect_identical(verify(p_unhold,
                        reader(selections = sel_df("nginx", "amd64",
                                                   "install")))$verified, TRUE)

# unqualified multi-arch: ALL rows must agree with the intended selection
p_h2 <- prevv("apt.hold", list(hld("nginx", "install", "hold")))
expect_identical(verify(p_h2, reader(selections = sel_df(c("nginx", "nginx"),
                                                         c("amd64", "i386"),
                                                         c("hold", "hold"))))$verified,
                 TRUE)
r <- verify(p_h2, reader(selections = sel_df(c("nginx", "nginx"),
                                             c("amd64", "i386"),
                                             c("hold", "install"))))
expect_identical(r$verified, FALSE)               # one arch not held

## ---- arch-QUALIFIED hold preserves target identity (pkg:arch) ---------------
mixed <- reader(selections = sel_df(c("nginx", "nginx"), c("amd64", "i386"),
                                    c("hold", "install")))
# nginx:amd64 -> hold: matches ONLY the amd64 row (which is hold) -> TRUE
expect_identical(verify(prevv("apt.hold", list(hld("nginx:amd64", "install",
                                                   "hold"))), mixed)$verified, TRUE)
# nginx:i386 -> hold: matches ONLY the i386 row (which is install) -> FALSE
r <- verify(prevv("apt.hold", list(hld("nginx:i386", "install", "hold"))), mixed)
expect_identical(r$verified, FALSE)
expect_true(grepl("nginx:i386", r$detail))        # the qualified identity in the detail
# nginx:amd64 but only an i386 selection row exists -> no match -> FALSE
r <- verify(prevv("apt.hold", list(hld("nginx:amd64", "install", "hold"))),
            reader(selections = sel_df("nginx", "i386", "hold")))
expect_identical(r$verified, FALSE)
expect_true(grepl("no selection", r$detail))
# two qualified targets, each matched to its own arch
p_q2 <- prevv("apt.hold", list(hld("nginx:amd64", "install", "hold"),
                               hld("nginx:i386", "install", "hold")))
expect_identical(verify(p_q2, reader(selections = sel_df(c("nginx", "nginx"),
                                                         c("amd64", "i386"),
                                                         c("hold", "hold"))))$verified,
                 TRUE)
expect_identical(verify(p_q2, mixed)$verified, FALSE)   # i386 is install

## ---- update: no observable post-state -> NA ---------------------------------
r <- verify(prevv("apt.update", list()), reader())
expect_true(is.na(r$verified))
expect_true(grepl("index refresh", r$detail))

## ---- no records / unknown verb -> NA (nothing to verify) --------------------
expect_true(is.na(verify(prevv("apt.install", list()), reader())$verified))
expect_true(is.na(verify(prevv("apt.bogus", list(txn("x", "install"))),
                         reader())$verified))

## ---- a malformed record is a verification FAILURE, not a pass ---------------
r <- verify(prevv("apt.install", list(list(architecture = "amd64"))), reader())
expect_identical(r$verified, FALSE)
expect_true(grepl("malformed", r$detail))

## ---- .verify NEVER raises on malformed reader/record data -------------------
## (contract: a post-state pkgops cannot read is not a pass -- it fails closed.)

# an NA selection is a mismatch, not an if(NA) error
r <- verify(p_hold, reader(selections = sel_df("nginx", "amd64", NA_character_)))
expect_identical(r$verified, FALSE)

# a non-list record (e.g. a stray scalar) -> malformed FAILURE, no error
r <- verify(prevv("apt.install", list("not-a-record")), reader())
expect_identical(r$verified, FALSE)
expect_true(grepl("malformed", r$detail))
r <- verify(prevv("apt.hold", list("not-a-record")), reader())
expect_identical(r$verified, FALSE)

# a reader frame missing an expected column -> normalized to FALSE, not an error
bad_reader <- list(installed = function() data.frame(package = "nginx",
                                                     stringsAsFactors = FALSE),
                   selections = function(packages = NULL) sel_df())
r <- verify(p_inst, bad_reader)
expect_identical(r$verified, FALSE)
expect_true(grepl("verification error", r$detail))

# a reader whose installed() itself throws -> FALSE, not propagated
boom_reader <- list(installed = function() stop("dpkg exploded"),
                    selections = function(packages = NULL) sel_df())
r <- verify(p_inst, boom_reader)
expect_identical(r$verified, FALSE)
expect_true(grepl("verification error", r$detail))

# across a batch of hostile inputs, .verify always returns a well-formed list
hostile <- list(
    verify(prevv("apt.install", list(NA)), reader()),
    verify(prevv("apt.hold", list(list(package = 42L))), reader()),
    verify(prevv("apt.configure", list("x")), reader()),
    verify(p_inst, boom_reader))
for (h in hostile) {
    expect_true(is.list(h) && all(c("verified", "detail") %in% names(h)))
    expect_true(is.logical(h$verified) && length(h$verified) == 1L)
}

## ---- the reader seam: set_pkgstate_reader installs/restores -----------------
old <- set_reader(reader(inst_df("nginx", "1.2", "amd64", "installed")))
expect_identical(verify(p_inst)$verified, TRUE)    # uses the injected reader
set_reader(old)                                    # restore (default pkgstate)
