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

- **Increment 1 (this): the commit-result contract** (`R/outcome.R`) — the closed
  12-status vocabulary + runix condition mapping (drift-pinned to pkgexec
  v0.0.3), the tri-state `effect_issued`, cid-equality, the `pkgops_outcome`
  object, and the `apt_locked` retryability registration. Pure and hermetic.
- **Still NOT started** (later increments, each its own review): the
  `runix::effect_session_*` custody + commit wiring, the polkit authorization
  branch, and `pkgstate` verification (`pkgstate` becomes an `Imports` only when
  that increment lands — not before, or it is an unused-Import NOTE). Do not add a
  mutation-capable path, effect-receipt handling, spawn, or a `pkgstate`
  dependency ahead of its increment.

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
