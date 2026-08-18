# pkgops 0.0.1

Initial release: the **preview half** of the unprivileged apt-mutation issuer
for the Runix framework.

* `apt_<verb>_preview()` for the nine apt verbs (`install`, `remove`, `purge`,
  `hold`, `unhold`, `update`, `upgrade`, `dist_upgrade`, `configure`). Each plans
  the change with the read-only `runix-apt-preview` helper (shipped by
  `pkgexec`) and returns an advisory `pkgops_preview` carrying the plan digest a
  later commit would bind, the verb-specific resolved records, and whether the
  verb is polkit-autonomous.
* Previews are **advisory only**: they open no broker intent, take no `dpkg`
  lock, and mint nothing. The authoritative resolution happens under the lock at
  commit time.
* The planner reply is strictly validated (schema, verb/packages echo, exit-code
  consistency, digest-present-iff-expected); anything untrustworthy fails closed
  as `runix_preview_failed`. Non-success plans raise typed conditions on the
  shared runix taxonomy: `runix_resolve_failed`, `runix_not_owned`,
  `runix_held`, `runix_protected`, `runix_dpkg_broken`, `runix_helper_internal`.
* The commit lifecycle (effect-session custody, polkit authorization, and
  `pkgstate` verification) is a later, separately reviewed slice; no
  mutation-capable code path exists in this release.
