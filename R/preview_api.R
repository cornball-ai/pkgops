#' Preview an authorized apt package-state change
#'
#' Plan one of the nine apt operations with the unprivileged, read-only
#' \code{runix-apt-preview} helper and return a typed, \strong{advisory}
#' \code{pkgops_preview}. A preview resolves the change and computes the plan
#' digest a later commit would bind, but it opens no broker intent, takes no
#' \code{dpkg} lock, and mints nothing. The authoritative resolution happens
#' under the lock at commit time (a separate slice); a preview that later drifts
#' from that re-resolution is a safe refusal there, never a wrong mutation.
#'
#' The target-taking verbs (\code{install}, \code{remove}, \code{purge},
#' \code{hold}, \code{unhold}) require a non-empty character vector of strict
#' Debian package names (optionally \code{name:arch}), de-duplicated, at most
#' 256. The whole-system verbs (\code{update}, \code{upgrade},
#' \code{dist_upgrade}, \code{configure}) take no targets and reject any.
#'
#' On a non-success plan the call raises a typed condition, each inheriting
#' \code{pkgops_error} and \code{runix_error}: \code{runix_resolve_failed},
#' \code{runix_not_owned}, \code{runix_held}, \code{runix_protected},
#' \code{runix_dpkg_broken}, \code{runix_helper_internal}, or, for a malformed
#' request or an untrustworthy reply, \code{runix_preview_failed}. The three
#' policy refusals (\code{runix_not_owned}/\code{runix_held}/
#' \code{runix_protected}) carry the resolved \code{records} and \code{plan_hash}
#' in the condition's data.
#'
#' @param packages For the target-taking verbs, a non-empty character vector of
#'   package names. The whole-system verbs take no argument.
#' @return A \code{pkgops_preview}: a list with \code{schema_version},
#'   \code{verb}, \code{resource}, \code{plan_schema}, \code{plan_hash},
#'   \code{autonomous} (whether polkit may grant the verb non-interactively to
#'   the \code{runix-apt-autonomous} group), \code{packages} (the original
#'   validated targets), \code{records} (verb-specific, exactly as the digest
#'   bound them), \code{advisory_verdict} (\code{"ok"} or \code{"no_op"}), and
#'   \code{advisory_detail}. A \code{no_op} preview carries no digest. Raises a
#'   typed condition on any non-success plan.
#' @examples
#' \dontrun{
#' p <- apt_install_preview(c("nginx"))
#' p$plan_hash
#' apt_update_preview()
#' }
#' @rdname apt_preview
#' @export
apt_install_preview <- function(packages) .preview("install", packages)

#' @rdname apt_preview
#' @export
apt_remove_preview <- function(packages) .preview("remove", packages)

#' @rdname apt_preview
#' @export
apt_purge_preview <- function(packages) .preview("purge", packages)

#' @rdname apt_preview
#' @export
apt_hold_preview <- function(packages) .preview("hold", packages)

#' @rdname apt_preview
#' @export
apt_unhold_preview <- function(packages) .preview("unhold", packages)

#' @rdname apt_preview
#' @export
apt_update_preview <- function() .preview("update")

#' @rdname apt_preview
#' @export
apt_upgrade_preview <- function() .preview("upgrade")

#' @rdname apt_preview
#' @export
apt_dist_upgrade_preview <- function() .preview("dist_upgrade")

#' @rdname apt_preview
#' @export
apt_configure_preview <- function() .preview("configure")
