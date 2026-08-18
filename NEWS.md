# pkgops 0.0.1.5

Commit lifecycle (slice 3b): **wire the polkit authorization into
`.commit_session`** (§4.3 step 2). The decision from the previous increment now
gates the commit, including the plain-intent terminal refusal path. Still
hermetic (the broker, `pkexec`/`pkcheck`, and dpkg are all behind seams) and
still internal -- pkgstate verification and the exported API remain.

* Step 2 runs `.authorize(verb_spec, interactive)` after the capability
  negotiation and before the effect intent is opened. **Interactive** proceeds to
  the effect intent (the `pkexec` prompt authenticates at the spawn); **machine
  mode** maps the `pkcheck` decision.
* A machine-mode refusal never opens an effect intent. `unauthorized` and
  `approval_required` open a **plain intent** (no receipt) via the generic broker
  sink and write the matching terminal outcome (`effect_issued = FALSE`) under one
  correlation id, then signal `runix_unauthorized` / `runix_approval_required` --
  the record is the close that precedes the signal, so a refused attempt is
  durably audited without minting an unused effect receipt.
* A check that could not be run at all (`check_failed`) fails closed with
  **nothing recorded** (`pkgops_polkit_check_failed`): there is no authoritative
  decision to persist. If the refusal record itself cannot be written, that error
  propagates -- either way no effect ran.
* `interactive` is a caller-supplied argument (runix exposes no TTY probe, so mode
  detection stays at the CLI layer); it defaults to `FALSE` (machine mode).
* Still deferred (their own later increments): `pkgstate` verification and the
  exported per-verb `apt_<verb>()` API.

# pkgops 0.0.1.4

Commit lifecycle (slice 3b), fourth increment: the **polkit authorization
decision** (the §4.3-step-2 decision layer). Pure decision + an injectable
`pkcheck` seam, no broker and no intent yet -- the next increment wires it into
`.commit_session`.

* `.authorize(verb_spec, interactive)` decides whether a commit may proceed.
  **Interactive mode** defers to the `pkexec` prompt at the entrypoint spawn and
  skips `pkcheck`; **machine mode** runs a native, non-interactive `pkcheck` for
  the verb's polkit action (`ai.cornball.runix.apt.<verb>`) against this
  process's race-safe `pid,start-time,uid` subject.
* The `pkcheck` exit code maps to a closed decision vocabulary, pinned to the
  tested canary matrix: `0` authorized, `1` unauthorized, `2`/`3`
  approval_required (a challenge that cannot be obtained non-interactively), and
  anything else `check_failed` (fail closed, never silently authorized).
* The `pkcheck` call is behind an injectable seam (`set_pkcheck()`), so the whole
  decision is hermetic. It is **not** a privilege boundary: polkit still enforces
  at the `pkexec` spawn inside runix's C, so a substituted check can only make
  pkgops proceed to a commit that `pkexec` then denies, or refuse one it would
  have allowed -- both degrade safely.
* The autonomous verbs (`apt.update`/`apt.hold`) need no special-casing: the
  `runix-apt-autonomous` polkit rule grants members `rc 0` through the same
  check, and a non-member falls through to a refusal like any other verb.
* Still deferred (their own later increments): wiring the decision into
  `.commit_session` with the plain-intent terminal-outcome path, `pkgstate`
  verification, and the exported per-verb `apt_<verb>()` API.

# pkgops 0.0.1.3

Commit lifecycle (slice 3b), third increment: the **effect-session
orchestration** -- the first IO-bearing increment. Still hermetic (the broker,
the pkexec entrypoint, and dpkg are all behind an injectable seam), and still
**no exported commit entrypoint**: polkit authorization and `pkgstate`
verification are later increments, so an issuer cannot yet authorize or verify
truthfully.

* `.commit_session()` (internal) drives the contract's branched commit lifecycle
  (§4.3): capability negotiation, open the effect-required intent, commit through
  the runix effect-session, classify the result, write the outcome, then signal.
  The **outcome is always written before the condition is signaled** (§4.8): a
  known failure closes the durable intent first, then raises; a genuinely
  effect-unknown result (a malformed helper reply, a raised commit, or a persist
  failure) leaves the intent open for reconciliation and never fabricates an
  `effect_issued:false`.
* The four runix effect-session R calls (`effect_capability`,
  `effect_session_open`/`_commit`/`_write_outcome`) are driven through an
  injectable seam (`session_ops()`), so the whole lifecycle is tested against
  fakes with no root, no broker, and no dpkg. Production always uses the real
  `runix::` calls; the privileged verb-to-entrypoint map stays a hard C constant
  inside runix, with no runtime seam.
* Two steps of the lifecycle are **deferred to their own later increments** and
  marked in the source: the polkit authorization branch (§4.3 step 2) and
  `pkgstate` verification (§4.3 step 6). Until they land, `.commit_session` stays
  internal and `verified` stays `NA`.
* Boundary: `.outcome_record()` is intentionally minimal (the audit fields pkgops
  owns before verification); the exact durable-record grammar and its alignment
  with the broker's record schema are pinned in the VM-gated increment.

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
