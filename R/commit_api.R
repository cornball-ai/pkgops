#' Commit an authorized apt package-state change
#'
#' Commit the exact change an \code{apt_<verb>_preview()} resolved. Each function
#' takes the \code{pkgops_preview} its preview twin produced and drives the
#' privileged commit lifecycle for it: it negotiates the effect-receipt
#' capability, authorizes the verb through polkit, opens an effect-bound intent,
#' commits through the runix effect-session, verifies the post-state against the
#' plan, and writes the durable outcome. Unlike the preview twin, this mutates the
#' system.
#'
#' A commit binds \strong{only} the preview it is handed. The \code{plan_hash} the
#' preview carries is what the privileged helper re-validates under the \code{dpkg}
#' lock, so a plan that has drifted since the preview is refused there, never
#' applied. Each \code{apt_<verb>()} refuses, before anything is opened, a preview
#' for a different verb (an \code{apt.remove} preview handed to
#' \code{apt_install()} is a \code{pkgops_bad_request}), a non-\code{ok} preview (a
#' \code{no_op} or a policy refusal is never committable), and anything that is not
#' a \code{pkgops_preview}.
#'
#' \strong{Authorization.} With \code{interactive = TRUE} the \code{pkexec} prompt
#' authenticates the change at the privileged spawn; with \code{interactive =
#' FALSE} (machine mode) a non-interactive \code{pkcheck} decides, and a denial or
#' an approval challenge becomes a durably-audited refusal, never a prompt. The
#' default follows \code{\link{interactive}()} -- an R console commits
#' interactively, a script or CI run commits in machine mode.
#'
#' On any refusal or failure the call signals a typed condition inheriting
#' \code{pkgops_error} and \code{runix_error} (for example \code{runix_unauthorized},
#' \code{runix_held}, \code{runix_apt_locked}, \code{runix_operation_failed},
#' \code{runix_dpkg_broken}). An effect whose outcome could not be determined
#' (\code{runix_helper_bad_result}) leaves the intent open for reconciliation and
#' is never reported as a clean failure.
#'
#' @param preview The \code{pkgops_preview} to commit, from the matching
#'   \code{apt_<verb>_preview()}.
#' @param lock_timeout Seconds the privileged helper waits for the \code{dpkg}
#'   lock before refusing with \code{runix_apt_locked} (\code{0} = do not wait).
#' @param deadline_ms Overall commit deadline, in milliseconds.
#' @param interactive Authorize through the interactive \code{pkexec} prompt
#'   (\code{TRUE}) or a non-interactive \code{pkcheck} (\code{FALSE}). Defaults to
#'   \code{\link{interactive}()}.
#' @param socket_path The broker's \code{AF_UNIX} socket.
#' @return A \code{pkgops_outcome} recording the committed change: its
#'   \code{effect_issued} and, for a verb with an observable post-state, its
#'   \code{verified} verdict and \code{verify_detail}. Signals a typed condition
#'   on any refusal or failure.
#' @examples
#' \dontrun{
#' p <- apt_install_preview(c("nginx"))
#' out <- apt_install(p, lock_timeout = 300)
#' out$verified
#' }
#' @rdname apt_commit
#' @export
apt_install <- function(preview, lock_timeout = 0L, deadline_ms = 120000L,
                        interactive = base::interactive(),
                        socket_path = .PKGOPS_BROKER_SOCKET) {
    .commit_verb("apt.install", preview, lock_timeout, deadline_ms,
                 interactive, socket_path)
}

#' @rdname apt_commit
#' @export
apt_remove <- function(preview, lock_timeout = 0L, deadline_ms = 120000L,
                       interactive = base::interactive(),
                       socket_path = .PKGOPS_BROKER_SOCKET) {
    .commit_verb("apt.remove", preview, lock_timeout, deadline_ms,
                 interactive, socket_path)
}

#' @rdname apt_commit
#' @export
apt_purge <- function(preview, lock_timeout = 0L, deadline_ms = 120000L,
                      interactive = base::interactive(),
                      socket_path = .PKGOPS_BROKER_SOCKET) {
    .commit_verb("apt.purge", preview, lock_timeout, deadline_ms,
                 interactive, socket_path)
}

#' @rdname apt_commit
#' @export
apt_hold <- function(preview, lock_timeout = 0L, deadline_ms = 120000L,
                     interactive = base::interactive(),
                     socket_path = .PKGOPS_BROKER_SOCKET) {
    .commit_verb("apt.hold", preview, lock_timeout, deadline_ms,
                 interactive, socket_path)
}

#' @rdname apt_commit
#' @export
apt_unhold <- function(preview, lock_timeout = 0L, deadline_ms = 120000L,
                       interactive = base::interactive(),
                       socket_path = .PKGOPS_BROKER_SOCKET) {
    .commit_verb("apt.unhold", preview, lock_timeout, deadline_ms,
                 interactive, socket_path)
}

#' @rdname apt_commit
#' @export
apt_update <- function(preview, lock_timeout = 0L, deadline_ms = 120000L,
                       interactive = base::interactive(),
                       socket_path = .PKGOPS_BROKER_SOCKET) {
    .commit_verb("apt.update", preview, lock_timeout, deadline_ms,
                 interactive, socket_path)
}

#' @rdname apt_commit
#' @export
apt_upgrade <- function(preview, lock_timeout = 0L, deadline_ms = 120000L,
                        interactive = base::interactive(),
                        socket_path = .PKGOPS_BROKER_SOCKET) {
    .commit_verb("apt.upgrade", preview, lock_timeout, deadline_ms,
                 interactive, socket_path)
}

#' @rdname apt_commit
#' @export
apt_dist_upgrade <- function(preview, lock_timeout = 0L,
                             deadline_ms = 120000L,
                             interactive = base::interactive(),
                             socket_path = .PKGOPS_BROKER_SOCKET) {
    .commit_verb("apt.dist_upgrade", preview, lock_timeout, deadline_ms,
                 interactive, socket_path)
}

#' @rdname apt_commit
#' @export
apt_configure <- function(preview, lock_timeout = 0L, deadline_ms = 120000L,
                          interactive = base::interactive(),
                          socket_path = .PKGOPS_BROKER_SOCKET) {
    .commit_verb("apt.configure", preview, lock_timeout, deadline_ms,
                 interactive, socket_path)
}
