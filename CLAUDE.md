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
- **Increment 3 (this): the effect-session orchestration** (`R/commit.R`,
  `R/session_ops.R`) — `.commit_session()` wires the §4.3 lifecycle steps 1,3,4,
  5,7,8 (capability → open → commit → classify → write_outcome → signal) with the
  outcome-closed-before-signal discipline (§4.8). The four runix effect-session R
  calls are driven through an injectable seam (`session_ops()`/`set_session_ops`,
  hermetic-test-only; production always uses the real `runix::` defaults, and the
  privileged verb→entrypoint map stays a hard C constant in runix). `.commit_session`
  is **internal** — there is no exported per-verb `apt_<verb>()` commit entrypoint
  yet, because an issuer cannot authorize (polkit) or verify (pkgstate) truthfully
  until those increments land.
- **Still NOT started** (later increments, each its own review): the **polkit
  authorization branch** (§4.3 step 2 — machine-mode `pkcheck`, autonomous-verb
  handling, the plain-intent `approval_required`/`unauthorized` terminal
  outcome), **`pkgstate` verification** (§4.3 step 6 — `pkgstate` becomes an
  `Imports` only when that increment lands, not before, or it is an unused-Import
  NOTE; it also supplies the outcome record's `observed`/`changed` post-state
  fields), and then the **exported per-verb `apt_<verb>()` API** (with the
  preview `{verb,resource,plan_hash}` match check). The durable outcome-record
  grammar in `.outcome_record()` is intentionally minimal until it is pinned
  against a real broker in the VM-gated increment.

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
