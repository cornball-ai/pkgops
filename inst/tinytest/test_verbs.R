# The fail-fast request validation that runs before any planner spawn:
# the Debian-name grammar (mirroring pkgexec name_ok) and per-verb arity.

vpn <- pkgops:::.valid_package_name

# --- valid names: lowercase start, name chars, optional :arch ---
expect_true(all(vpn(c("nginx", "lib6", "g++", "a.b-c", "foo:amd64", "x0",
                      "libc6:i386"))))

# --- invalid: uppercase, too short, leading punct, bad chars, bad arch ---
expect_false(any(vpn(c("A", "n", "-x", "x_y", "café", "foo:", "foo:-bad",
                       ":amd64", "UPPER", "foo:AMD64"))))

# --- length cap (> 256 bytes) ---
expect_false(vpn(strrep("a", 257L)))
expect_true(vpn(strrep("a", 256L)))

# --- NA is never valid ---
expect_false(vpn(NA_character_))

## ---- per-verb arity (.check_targets) --------------------------------------
ct <- pkgops:::.check_targets
vs_install <- pkgops:::.PKGOPS_VERBS$install
vs_update  <- pkgops:::.PKGOPS_VERBS$update

# a whole-system verb rejects any target, never silently drops it
e <- tryCatch(ct(vs_update, "nginx"), error = identity)
expect_inherits(e, "pkgops_bad_request")
expect_inherits(e, "pkgops_error")
expect_inherits(e, "runix_error")
expect_true(grepl("no packages", conditionMessage(e)))
# ... and accepts none
expect_equal(ct(vs_update, character(0)), character(0))

# a target verb requires a non-empty vector of valid, unique names
expect_error(ct(vs_install, character(0)), "non-empty")
expect_error(ct(vs_install, NA_character_), "non-NA")
expect_error(ct(vs_install, c("nginx", "nginx")), "duplicate")
expect_error(ct(vs_install, "Bad!"), "invalid package name")
expect_error(ct(vs_install, paste0("pkg", 1:257)), "too many")
expect_equal(ct(vs_install, c("nginx", "curl")), c("nginx", "curl"))

## ---- the verb table itself -----------------------------------------------
V <- pkgops:::.PKGOPS_VERBS
expect_equal(length(V), 9L)
# request verbs are the exact "apt.<verb>" tokens the planner accepts
expect_equal(V$dist_upgrade$request_verb, "apt.dist_upgrade")  # underscore, not hyphen
# only update and hold are autonomous (polkit non-interactive group)
auto <- vapply(V, function(v) isTRUE(v$autonomous), logical(1))
expect_equal(sort(names(auto)[auto]), c("hold", "update"))
# exactly the five target verbs take packages
tgt <- vapply(V, function(v) v$arity == "targets", logical(1))
expect_equal(sort(names(tgt)[tgt]),
             c("hold", "install", "purge", "remove", "unhold"))
