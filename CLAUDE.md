# pkgops — project notes

The unprivileged R **issuer** for authorized apt package-state mutations in the
Runix framework. Sibling packages: `runix` (common core), `pkgexec` (privileged
effectors + the `runix-apt-preview` planner), `pkgstate` (read-only dpkg/apt
state). All public.

## Scope boundary (read before adding code)

Slice **3a (preview)** is complete: `apt_<verb>_preview()` for the nine verbs → an
advisory `pkgops_preview`. Previews open no broker intent, take no dpkg lock, and
mint nothing.

Slice **3b (commit lifecycle)** is under way as a **draft PR, built in small
reviewed increments** — hold at each increment before the next.

- **Increment 1 (merged): the commit-result contract** (`R/outcome.R`) — the
  closed 12-status vocabulary + runix condition mapping (drift-pinned to pkgexec
  v0.0.3), the tri-state `effect_issued`, cid-equality, the `pkgops_outcome`
  object, and the `apt_locked` retryability registration. Pure and hermetic.
- **Increment 2 (merged): the commit-result classifier** (`R/classify.R`) —
  `.classify_commit()` maps a `runix_commit_result` (runix's C owns the frame
  parse + cid + delivery gates) to an outcome + condition + `leave_open`, per the
  §4.6/§4.8 close-vs-open rule. It never raises and never does IO. Also pure.
- **Increment 3 (merged): the effect-session orchestration** (`R/commit.R`,
  `R/session_ops.R`) — `.commit_session()` wires the §4.3 lifecycle steps 1,3,4,
  5,7,8 (capability → open → commit → classify → write_outcome → signal) with the
  outcome-closed-before-signal discipline (§4.8). The four runix effect-session R
  calls are driven through an injectable seam (`session_ops()`/`set_session_ops`,
  hermetic-test-only; production always uses the real `runix::` defaults, and the
  privileged verb→entrypoint map stays a hard C constant in runix). `.commit_session`
  is **internal** and gates on `advisory_verdict == "ok"` before any session op.
- **Increment 4a (merged): the polkit authorization decision** (`R/polkit.R`) —
  the §4.3-step-2 decision layer: the per-verb polkit action id
  (`ai.cornball.runix.apt.<verb>`), a native non-interactive `pkcheck` behind an
  injectable seam (`pkcheck_fn()`/`set_pkcheck`; hermetic-test-only, not a
  privilege boundary — polkit still enforces at the pkexec spawn in runix's C),
  the pkcheck exit-code→decision map (0 authorized / 1 unauthorized / 2,3
  approval_required / else check_failed, integer-valued-guarded), and
  `.authorize(verb_spec, interactive)` (interactive mode defers to the pkexec
  prompt and skips pkcheck).
- **Increment 4b (merged): wire authorization into `.commit_session`** — step 2
  runs `.authorize(verb_spec, interactive)`; authorized proceeds, a machine-mode
  refusal opens a **plain intent** via the seam's `refuse` op and writes the
  terminal outcome (only signaled as closed when `audit_persisted == TRUE` with a
  valid broker cid, `.valid_broker_cid`); `check_failed` fails closed with nothing
  recorded.
- **Increment 5a (merged): pkgstate verification predicates** (`R/verify.R`) —
  `.verify(preview, reader)` checks every **resolved record** of a committed
  preview against native ground truth, per verb (§6.3): transaction verbs by each
  record's `action` (install/upgrade/downgrade → installed at `to_version`; remove
  → `config-files`/`not-installed`/absent; purge → absent/`not-installed`, a
  surviving `config-files` is a *failed* purge) via `dpkg_installed()`; configure →
  fully `installed`; hold/unhold → the `dpkg_selections()` want reads back; update
  → `NA`. **Independent of the helper's status** (reads only the plan + ground
  truth); returns `(verified TRUE/FALSE/NA, detail)`. `architecture` is required by
  the txn/configure grammar (a missing arch fails, never wildcard-matches). pkgstate
  reads go through an injectable reader seam
  (`pkgstate_reader()`/`set_pkgstate_reader`, hermetic-test-only). **`pkgstate` is
  now an `Imports`** (the default reader uses it). Record grammar/post-state pinned
  to pkgexec 0.0.3 + pkgstate 0.0.1.9.
- **Increment 5b (merged): wire verification into `.commit_session` step 6** —
  after commit + classify, on the **success path only** (`is.null(condition)`: an
  `ok`/`no_op` that will be returned), `.verify_and_capture()` runs `.verify()` and
  captures `verified`/`verify_detail` onto the returned outcome. **Observational**:
  never raises, never changes close/open; a disagreeing post-state is
  `verified = FALSE` + a detail, not a signal, so the outcome is still written
  (step 7) and outcome-before-signal holds. A known failure / left-open effect is
  not verified. The reader stays behind the seam, so `.commit_session` is fully
  hermetic (fake session-ops + fake pkcheck + fake reader).
- **Increment 6 (draft PR #9, HELD): exported per-verb `apt_<verb>()` API** — the
  nine `apt_<verb>(preview, ...)` commit wrappers with the preview
  `{verb,resource,plan_hash}` match check; interactive defaults to
  `base::interactive()`. This makes pkgops **mutation-capable**. Held pending the
  VM proof (Part B) that the complete public path + durable record shape hold
  against a real broker/polkit.
- **VM-gate increment Part A (this): durable audit record grammar** — enrich the
  committed outcome with the broker `RECORD_SCHEMA` fields so the exported API
  writes a complete record. `.observe()` reads the resolved records' post-state
  into the record's `observed` object, keyed by `package:arch` (`{status,version}`
  for txn/configure, `{selection}` for hold -- one entry per matched arch, since an
  unqualified hold target can span arches); `.freeze_reader()` gives verdict +
  observe one shared post-read. `state_changed` is a real pre/post `.observe()` diff
  (D7 = S-B), `NA` when either side is unavailable, never inferred from
  `effect_issued`; `apt.update` observes nothing, so observed/changed/state_changed
  are all omitted.
  `.authorized_via()` records `pkexec`/`autonomous`/`pkcheck` at the authorization
  site (`.authorize()` now returns `list(decision, via)`). `.outcome_record()`
  maps onto the broker's 16-field allow-list (omitting `NA`/`NULL` optionals;
  `verified` → `changed` only when the post-state was read), and
  `.validate_record()` mirrors the broker guard (rejects non-allow-list field,
  reserved key, wrong type). Observation is **success-path only**; the failure-path
  `observed` shape stays deferred. Plan: `runix/docs/pkgops-vm-gate-plan.md`.
  - **Part B follow-up (the coarse `outcome`)**: `RECORD_SCHEMA` marks `operation`
    and `outcome` REQUIRED, so a record without `outcome` is `schema_invalid` at
    `write_outcome` — a Part B finding the hermetic fake broker could not surface.
    `.outcome_record()` now derives the coarse `outcome` from the closed status
    (`ok` for `ok`/`no_op`, `error` for every closed failure/refusal), keeping the
    detailed per-package result in `observed`. `.validate_record()` enforces the
    required pair locally (`.PKGOPS_RECORD_REQUIRED`). The R-level refuse path
    (`session_ops.R`) already carried `outcome` (`intent` + status); the native
    effect-session open_intent gained the field in runix (`effect_session.c`).
- **Still NOT started** (later increments, each its own review): **Part B** — the
  disposable-VM proof that pins the durable record grammar, the plain-intent
  refusal record grammar, and the exact pkcheck rc→outcome split against a real
  broker/polkit; then the `rctl apt.*` surface.

The authoritative design is `runix/docs/pkgops-plan.md` (the approved contract)
and `runix/docs/pkgops-implementation-plan.md` (rev 2, the build sequence).

## Wire contracts

The planner request/response, the nine statuses, and the record grammars are
pinned to shipped **pkgexec v0.0.3** source (`tools/preview.cc`, `src/request.c`,
`src/digest.h`) and quoted in the implementation plan's Appendix A. The verb
table (`R/verbs.R`) cites its source of truth per field. If pkgexec bumps the
plan schema or a record grammar, update both in lockstep.

## Conventions

tinyverse: `pkgKitten`, `tinyrox::document()`, `tinypkgr::install()`/`check()`,
`tinytest`, `rformat`. Version starts `0.0.1`. Conditions go through
`stop_pkgops()` → `runix::runix_abort()` so they inherit `runix_error`. The
runner is injectable (`set_runner()`), so the suite is hermetic (fake planner,
canned JSON) and never spawns the real binary.
