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
* The planner reply is strictly validated: an exact top-level key set (no missing
  or extra field), integer-valued `schema_version` and `plan_schema` (a fractional
  `1.5` is refused, never truncated to `1`), actual JSON arrays for `packages` and
  `records` (a scalar is refused), an order-sensitive `packages` echo against the
  request, per-status digest presence (`plan_hash`/`plan_schema` present exactly
  for `ok` and the three policy refusals), and exit-code consistency. Anything
  untrustworthy fails closed as `runix_preview_failed`. Non-success plans raise
  typed conditions on the shared runix taxonomy: `runix_resolve_failed`,
  `runix_not_owned`, `runix_held`, `runix_protected`, `runix_dpkg_broken`,
  `runix_helper_internal`.
* Boundary: `records` is validated structurally (a JSON array of JSON objects),
  but the verb-specific field grammar within each record (transaction / hold /
  configure / update) is deliberately **not** validated in this preview slice.
  The schema-1 `plan_hash` is the integrity authority here and the records are
  advisory. The per-field record grammar is pinned in the commit slice, where
  records feed `pkgstate` verification and are exercised against real planner
  output in the disposable-VM gate.
* The commit lifecycle (effect-session custody, polkit authorization, and
  `pkgstate` verification) is a later, separately reviewed slice; no
  mutation-capable code path exists in this release.
