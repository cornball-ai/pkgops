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

# multi-arch: both rows must agree with the intended selection
p_h2 <- prevv("apt.hold", list(hld("nginx", "install", "hold")))
expect_identical(verify(p_h2, reader(selections = sel_df(c("nginx", "nginx"),
                                                         c("amd64", "i386"),
                                                         c("hold", "hold"))))$verified,
                 TRUE)
r <- verify(p_h2, reader(selections = sel_df(c("nginx", "nginx"),
                                             c("amd64", "i386"),
                                             c("hold", "install"))))
expect_identical(r$verified, FALSE)               # one arch not held

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

## ---- the reader seam: set_pkgstate_reader installs/restores -----------------
old <- set_reader(reader(inst_df("nginx", "1.2", "amd64", "installed")))
expect_identical(verify(p_inst)$verified, TRUE)    # uses the injected reader
set_reader(old)                                    # restore (default pkgstate)
