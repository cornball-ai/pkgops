# pkgops — project notes

The unprivileged R **issuer** for authorized apt package-state mutations in the
Runix framework. Sibling packages: `runix` (common core), `pkgexec` (privileged
effectors + the `runix-apt-preview` planner), `pkgstate` (read-only dpkg/apt
state). All public.

## Scope boundary (read before adding code)

This repo currently ships the **preview half only** (arc slice 3a):
`apt_<verb>_preview()` for the nine verbs → an advisory `pkgops_preview`. Previews
open no broker intent, take no dpkg lock, and mint nothing.

The **commit lifecycle is a later, separately reviewed slice (3b)** and is NOT
started: `runix::effect_session_*` custody, the polkit authorization branch, the
12-status commit mapping, and `pkgstate` verification. Do not add any
mutation-capable path, effect-receipt handling, or a `pkgstate` dependency until
that slice is opened as its own reviewed PR.

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
