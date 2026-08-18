# pkgops

The unprivileged R issuer for authorized **APT package-state mutations** in the
[Runix](https://github.com/cornball-ai/runix) system-administration framework.

This release ships the **preview** half only. A preview plans a change with the
read-only `runix-apt-preview` helper and hands back a typed, advisory object
carrying the plan digest that a later commit would bind. It opens no broker
intent, takes no `dpkg` lock, and mints nothing.

```r
p <- pkgops::apt_install_preview(c("nginx"))
p
#> <pkgops preview: apt.install [ok]>
#>   targets   : nginx
#>   resource  : nginx
#>   records   : 1
#>   digest    : 9f2c1a0b4e6d... (schema 1)
#>   autonomous: no (auth_admin)
#>   advisory only: opens no intent, mints nothing

p$plan_hash   # the schema-1 plan digest a commit would bind
p$records     # the verb-specific resolved records the digest covers
```

## The nine verbs

`apt_install_preview()`, `apt_remove_preview()`, `apt_purge_preview()`,
`apt_hold_preview()`, `apt_unhold_preview()` take a character vector of package
names. `apt_update_preview()`, `apt_upgrade_preview()`,
`apt_dist_upgrade_preview()`, `apt_configure_preview()` are whole-system and take
no targets.

A non-success plan raises a typed condition (all inheriting `pkgops_error` and
`runix_error`): `runix_resolve_failed`, `runix_not_owned`, `runix_held`,
`runix_protected`, `runix_dpkg_broken`, `runix_helper_internal`, or
`runix_preview_failed` for a malformed request or an untrustworthy reply.

## Where the pieces live

* **pkgops** (this package): the unprivileged issuer.
* [`pkgexec`](https://github.com/cornball-ai/pkgexec): the privileged effectors
  and the `runix-apt-preview` planner (shipped as a system package).
* [`pkgstate`](https://github.com/cornball-ai/pkgstate): read-only `dpkg`/`APT`
  state, used by the commit-time verification in a later slice.
* [`runix`](https://github.com/cornball-ai/runix): the common core (broker
  client, effect-session custody, condition taxonomy).

## Status

The commit lifecycle (effect-session custody, polkit authorization, and post-
state verification) is a later, separately reviewed slice. There is no
mutation-capable code path in this release.

## License

MIT © cornball.ai
