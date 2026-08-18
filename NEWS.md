# pkgops 0.0.1.2

Commit lifecycle (slice 3b), second increment: the **commit-result classifier**.
Still pure and hermetic -- no session call, no spawn, no broker, no polkit, no
`pkgstate`.

* `.classify_commit()` turns runix's already-parsed `runix_commit_result` (its C
  owns the JSON frame parse, the cid check, and the exit/status/delivery gates)
  into the `pkgops_outcome` to record, the runix condition to signal, and whether
  the intent must be left open -- applying the contract's close-vs-open rule
  (§4.6/§4.8). It **never raises and never does IO**, so the orchestration can
  write the outcome first and only then signal (outcome-closed-before-signal).
* The four runix `session_status` cases are handled per `effect_session.c`: `ok`
  (the helper's status + effect_issued rule, closed), `unauthorized` and
  `spawn_failed` (known no-effect, closed false), and `effect_unknown` (the
  effect is genuinely unknown, so the intent is **left open**). `effect_issued`
  is read from runix verbatim, never fabricated.
* Two design points flagged for review: the outcome now also carries the
  session-level statuses (which have no helper status), and `spawn_failed` maps
  to a pkgops-owned `pkgops_spawn_failed` (the contract's taxonomy did not name
  it).
* Still held: the actual `open`/`commit`/`write_outcome` orchestration, the
  polkit branch, and `pkgstate` verification are later increments of 3b.

# pkgops 0.0.1.1

Begins the commit lifecycle (slice 3b), first increment: the **commit-result
contract**. Pure and hermetic -- no effect, no spawn, no broker yet.

* The closed twelve-status commit vocabulary and each status's stable runix
  condition class (`runix_apt_locked`, `runix_no_intent`, `runix_not_applied`,
  `runix_operation_failed`, plus the six shared with the preview channel),
  pinned bytewise to shipped pkgexec v0.0.3 (`src/result.c`) with a drift test.
* `effect_issued` is carried as a strict tri-state, read as the helper's
  first-class boolean and never inferred from the status (`dpkg_broken` is TRUE
  when a commit broke dpkg, FALSE when a pre-existing broken state was found);
  `NA` is reserved for a result that cannot be trusted.
* cid-equality (a result is bound to its intent only when the correlation_id
  matches) and the versioned `pkgops_outcome` object (§6.2).
* `apt_locked` -- lock contention refused before the commit, so provably
  no-effect -- is registered retryable in the shared runix registry; generic
  transport/timeout is deliberately not.
* Still held: the effect-session wiring, polkit authorization, and `pkgstate`
  verification are later increments of 3b, each separately reviewed.

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
