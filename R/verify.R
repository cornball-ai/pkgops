## pkgstate verification (contract 4.7 / 6.3): read native dpkg/apt ground truth
## and check every RESOLVED RECORD of the committed preview against its planned
## post-state. Verification is INDEPENDENT of the helper's self-report -- a clean
## helper status with a disagreeing post-state is a verification FAILURE, not a
## success (4.7). This layer is pure: the pkgstate reads go through an injectable
## seam (default = pkgstate::dpkg_installed / dpkg_selections), so the suite runs
## against canned data frames and never queries dpkg. The next increment wires
## .verify() into .commit_session step 6, CAPTURING a failure into the outcome
## (never raising -- the outcome must still be written, 4.3 step 6).
##
## Record grammar + post-state semantics are pinned to shipped pkgexec 0.0.3
## (tools/preview.cc, src/apt_common.cc) and pkgstate 0.0.1.9 (dpkg_installed's
## `status` = dpkg's state word verbatim; dpkg_selections' `selection` = the want
## word). The 3a preview slice carried records advisory-only; here they become
## load-bearing.

## The verb -> record family map. Transaction verbs share one record grammar
## (package/architecture/action/from_version/to_version/flags); configure, hold,
## and update each have their own. update has no observable post-state.
.VERIFY_FAMILY <- c(apt.install = "txn", apt.remove = "txn",
                    apt.purge = "txn", apt.upgrade = "txn",
                    apt.dist_upgrade = "txn", apt.configure = "configure",
                    apt.hold = "hold", apt.unhold = "hold",
                    apt.update = "update")

.verify_family <- function(request_verb) {
    if (.is_scalar_str(request_verb) &&
        request_verb %in% names(.VERIFY_FAMILY)) {
        unname(.VERIFY_FAMILY[request_verb])
    } else {
        NULL
    }
}

## The pkgstate reader seam. installed() -> data.frame(package, version,
## architecture, status); selections(packages) -> data.frame(package,
## architecture, selection). Default delegates to pkgstate (the honest Import);
## a hermetic test injects canned frames via set_pkgstate_reader().
installed_default <- function() {
    pkgstate::dpkg_installed()
}
selections_default <- function(packages = NULL) {
    pkgstate::dpkg_selections(packages)
}
.PKGOPS_PKGSTATE_READER_DEFAULT <- list(installed = installed_default,
                                        selections = selections_default)

.pkgops_pkgstate_reader <- local({
    state <- new.env(parent = emptyenv())
    pkgstate_reader <- function() {
        if (is.null(state$reader)) {
            return(.PKGOPS_PKGSTATE_READER_DEFAULT)
        }
        merged <- .PKGOPS_PKGSTATE_READER_DEFAULT
        merged[names(state$reader)] <- state$reader
        merged
    }
    set_pkgstate_reader <- function(reader = NULL) {
        old <- state$reader
        state$reader <- reader
        invisible(old)
    }
    list(pkgstate_reader = pkgstate_reader,
         set_pkgstate_reader = set_pkgstate_reader)
})
pkgstate_reader <- .pkgops_pkgstate_reader$pkgstate_reader
set_pkgstate_reader <- .pkgops_pkgstate_reader$set_pkgstate_reader

## A scalar string from a decoded record field, or NA if absent/malformed. Robust
## to a non-list record (a malformed/hand-built preview): a non-list rec yields NA
## for every field, so the record is treated as malformed rather than erroring.
.rec_str <- function(rec, field) {
    if (!is.list(rec)) {
        return(NA_character_)
    }
    v <- rec[[field]]
    if (.is_scalar_str(v)) {
        v
    } else {
        NA_character_
    }
}

## Split a record's `package` into (package, architecture). A hold record carries
## no separate architecture field, so an arch-qualified target arrives inline as
## `pkg:arch` -- split it and match both, preserving target identity. An
## unqualified name has NA architecture (match by name across all its rows). A
## malformed value (no scalar, or not exactly one `pkg:arch` split) yields NA
## package, so the record fails as malformed rather than matching the wrong row.
.split_pkg_arch <- function(x) {
    if (!.is_scalar_str(x)) {
        list(package = NA_character_, architecture = NA_character_)
    } else if (grepl("^[^:]+:[^:]+$", x)) {
        list(package = sub(":.*$", "", x), architecture = sub("^[^:]+:", "", x))
    } else if (!grepl(":", x, fixed = TRUE)) {
        list(package = x, architecture = NA_character_)
    } else {
        list(package = NA_character_, architecture = NA_character_)
    }
}

## A reader frame must carry the columns the predicate reads; a frame that does
## not is malformed and stops (the outer belt in .verify() turns that into a
## verification FAILURE, never a wrong pass from a silently-absent column).
.require_cols <- function(df, cols, what) {
    if (!is.data.frame(df) || !all(cols %in% names(df))) {
        stop(sprintf("%s reader frame is missing required columns (need %s)",
                     what, paste(cols, collapse = ", ")))
    }
    invisible(df)
}

## Fold per-record failure messages into a (verified, detail) verdict: any
## failure -> verified FALSE with the joined reasons; none -> verified TRUE.
.verify_result <- function(fails) {
    if (length(fails) > 0L) {
        list(verified = FALSE, detail = paste(fails, collapse = "; "))
    } else {
        list(verified = TRUE, detail = NA_character_)
    }
}

## Check one transaction record's action against the installed row (0 or 1 row,
## package:architecture being unique in dpkg). dpkg has no "removed"/"purged"
## status word: removed-with-configs is `config-files`, purged is an absent row
## (or the `not-installed` stub), installed-and-configured is `installed`. The
## five actions are the complete set pkgexec emits (install/remove/purge/upgrade/
## downgrade; no configure/reinstall here).
.check_txn_state <- function(action, to_version, row) {
    present <- nrow(row) > 0L
    if (present) {
        status <- as.character(row$status[1L])
    } else {
        status <- NA_character_
    }
    if (present) {
        version <- as.character(row$version[1L])
    } else {
        version <- NA_character_
    }
    switch(action,
           install =,
           upgrade =,
           downgrade = {
        if (!present) {
            return(sprintf("absent, expected installed %s", to_version))
        }
        if (!identical(status, "installed")) {
            return(sprintf("status %s, expected installed", status))
        }
        if (!identical(version, to_version)) {
            return(sprintf("version %s, expected %s", version, to_version))
        }
        NA_character_
    },
           remove = {
        ## removed leaves config files (or drops the row); "installed" or any
        ## incomplete state means the removal did not take.
        if (present && !status %in% c("config-files", "not-installed")) {
            return(sprintf("status %s, expected removed", status))
        }
        NA_character_
    },
           purge = {
        ## purge deletes configs too: a surviving `config-files` row is a
        ## failed purge; only an absent row / `not-installed` stub passes.
        if (present && !identical(status, "not-installed")) {
            return(sprintf("status %s, expected purged", status))
        }
        NA_character_
    },
           sprintf("unrecognised action %s", action))
}

## install/remove/purge/upgrade/dist_upgrade -> transaction records, each checked
## by ITS OWN action (a verb pulls in dependency installs/removals/upgrades).
.verify_txn <- function(records, reader) {
    inst <- reader$installed()
    .require_cols(inst, c("package", "version", "architecture", "status"),
                  "installed")
    fails <- character(0)
    for (rec in records) {
        pkg <- .rec_str(rec, "package")
        arch <- .rec_str(rec, "architecture")
        action <- .rec_str(rec, "action")
        to_version <- .rec_str(rec, "to_version")
        if (is.na(pkg) || is.na(action)) {
            fails <- c(fails, "malformed transaction record")
            next
        }
        row <- inst[!is.na(inst$package) & inst$package == pkg &
            (is.na(arch) | inst$architecture == arch),, drop = FALSE]
        why <- .check_txn_state(action, to_version, row)
        if (!is.na(why)) {
            fails <- c(fails, sprintf("%s: %s", pkg, why))
        }
    }
    .verify_result(fails)
}

## configure -> each record's package must now be fully configured (dpkg status
## `installed`); the record's `state` is the PRE-state that needed configuring.
.verify_configure <- function(records, reader) {
    inst <- reader$installed()
    .require_cols(inst, c("package", "architecture", "status"), "installed")
    fails <- character(0)
    for (rec in records) {
        pkg <- .rec_str(rec, "package")
        arch <- .rec_str(rec, "architecture")
        if (is.na(pkg)) {
            fails <- c(fails, "malformed configure record")
            next
        }
        row <- inst[!is.na(inst$package) & inst$package == pkg &
            (is.na(arch) | inst$architecture == arch),, drop = FALSE]
        if (nrow(row) > 0L) {
            status <- as.character(row$status[1L])
        } else {
            status <- "absent"
        }
        if (!identical(status, "installed")) {
            fails <- c(fails, sprintf("%s: %s, expected fully configured",
                                      pkg, status))
        }
    }
    .verify_result(fails)
}

## hold/unhold -> each target must read back in the intended dpkg selection
## (`to_state` in {install, hold}). An arch-qualified target (`pkg:arch`) matches
## both package AND architecture, preserving its identity; an unqualified target
## is verified across ALL its selection rows (every row must agree -- fail
## closed). Comparisons are NA-safe: an NA selection is a mismatch, not an error.
.verify_hold <- function(records, reader) {
    parsed <- lapply(records, function(rec) {
        pa <- .split_pkg_arch(.rec_str(rec, "package"))
        list(package = pa$package, architecture = pa$architecture,
             want = .rec_str(rec, "to_state"))
    })
    pkgs <- unique(vapply(parsed, function(p) p$package, character(1)))
    sel <- reader$selections(pkgs[!is.na(pkgs)])
    .require_cols(sel, c("package", "architecture", "selection"), "selections")
    fails <- character(0)
    for (p in parsed) {
        if (is.na(p$package) || is.na(p$want)) {
            fails <- c(fails, "malformed hold record")
            next
        }
        hit <- !is.na(sel$package) & sel$package == p$package
        if (!is.na(p$architecture)) {
            hit <- hit & !is.na(sel$architecture) &
            sel$architecture == p$architecture
        }
        row <- sel[hit,, drop = FALSE]
        label <- if (is.na(p$architecture)) {
            p$package
        } else {
            paste0(p$package, ":", p$architecture)
        }
        if (nrow(row) == 0L) {
            fails <- c(fails,
                       sprintf("%s: no selection, expected %s", label, p$want))
        } else if (!all(!is.na(row$selection) & row$selection == p$want)) {
            fails <- c(fails, sprintf("%s: selection %s, expected %s", label,
                                      paste(unique(row$selection), collapse = "/"),
                                      p$want))
        }
    }
    .verify_result(fails)
}

## Verify a committed preview's resolved records against native ground truth,
## returning list(verified = TRUE/FALSE/NA, detail). verified is NA when there is
## nothing to check (an index refresh, or no records); FALSE when any record's
## post-state disagrees with the plan; TRUE when all agree. Independent of the
## helper's status by construction -- it reads only the plan and the ground truth.
.verify <- function(preview, reader = pkgstate_reader()) {
    fam <- .verify_family(preview$verb)
    if (is.null(fam) || identical(fam, "update")) {
        detail <- if (identical(fam, "update")) {
            "no post-state to verify (index refresh)"
        } else {
            sprintf("no verification for verb %s", preview$verb)
        }
        return(list(verified = NA, detail = detail))
    }
    records <- preview$records
    if (!is.list(records) || length(records) == 0L) {
        return(list(verified = NA, detail = "no resolved records to verify"))
    }
    ## Belt over the per-record fixes: any residual error from malformed reader
    ## frames or records is normalized to a verification FAILURE (never raised),
    ## so .verify's "never raises" contract holds against untrusted inputs. A
    ## post-state pkgops cannot read is not a pass -- it fails closed.
    tryCatch(
             switch(fam, txn = .verify_txn(records, reader),
                    configure = .verify_configure(records, reader),
                    hold = .verify_hold(records, reader)),
             error = function(e) {
        list(verified = FALSE,
             detail = paste0("verification error: ", conditionMessage(e)))
    })
}
