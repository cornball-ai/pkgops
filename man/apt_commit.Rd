% tinyrox says don't edit this manually, but it can't stop you!
\name{apt_commit}
\alias{apt_install}
\alias{apt_remove}
\alias{apt_purge}
\alias{apt_hold}
\alias{apt_unhold}
\alias{apt_update}
\alias{apt_upgrade}
\alias{apt_dist_upgrade}
\alias{apt_configure}
\title{Commit an authorized apt package-state change}
\usage{
apt_install(
  preview,
  lock_timeout = 0L,
  deadline_ms = 120000L,
  interactive = base::interactive(),
  socket_path = .PKGOPS_BROKER_SOCKET
)

apt_remove(
  preview,
  lock_timeout = 0L,
  deadline_ms = 120000L,
  interactive = base::interactive(),
  socket_path = .PKGOPS_BROKER_SOCKET
)

apt_purge(
  preview,
  lock_timeout = 0L,
  deadline_ms = 120000L,
  interactive = base::interactive(),
  socket_path = .PKGOPS_BROKER_SOCKET
)

apt_hold(
  preview,
  lock_timeout = 0L,
  deadline_ms = 120000L,
  interactive = base::interactive(),
  socket_path = .PKGOPS_BROKER_SOCKET
)

apt_unhold(
  preview,
  lock_timeout = 0L,
  deadline_ms = 120000L,
  interactive = base::interactive(),
  socket_path = .PKGOPS_BROKER_SOCKET
)

apt_update(
  preview,
  lock_timeout = 0L,
  deadline_ms = 120000L,
  interactive = base::interactive(),
  socket_path = .PKGOPS_BROKER_SOCKET
)

apt_upgrade(
  preview,
  lock_timeout = 0L,
  deadline_ms = 120000L,
  interactive = base::interactive(),
  socket_path = .PKGOPS_BROKER_SOCKET
)

apt_dist_upgrade(
  preview,
  lock_timeout = 0L,
  deadline_ms = 120000L,
  interactive = base::interactive(),
  socket_path = .PKGOPS_BROKER_SOCKET
)

apt_configure(
  preview,
  lock_timeout = 0L,
  deadline_ms = 120000L,
  interactive = base::interactive(),
  socket_path = .PKGOPS_BROKER_SOCKET
)
}
\arguments{
\item{preview}{The \code{pkgops_preview} to commit, from the matching
\code{apt_<verb>_preview()}.}

\item{lock_timeout}{Seconds the privileged helper waits for the \code{dpkg}
lock before refusing with \code{runix_apt_locked} (\code{0} = do not wait).}

\item{deadline_ms}{Overall commit deadline, in milliseconds.}

\item{interactive}{Authorize through the interactive \code{pkexec} prompt
(\code{TRUE}) or a non-interactive \code{pkcheck} (\code{FALSE}). Defaults to
\code{\link{interactive}()}.}

\item{socket_path}{The broker's \code{AF_UNIX} socket.}
}
\value{
A \code{pkgops_outcome} recording the committed change: its
  \code{effect_issued} and, for a verb with an observable post-state, its
  \code{verified} verdict and \code{verify_detail}. Signals a typed condition
  on any refusal or failure.
}
\description{
Commit the exact change an \code{apt_<verb>_preview()} resolved. Each function
takes the \code{pkgops_preview} its preview twin produced and drives the
privileged commit lifecycle for it: it negotiates the effect-receipt
capability, authorizes the verb through polkit, opens an effect-bound intent,
commits through the runix effect-session, verifies the post-state against the
plan, and writes the durable outcome. Unlike the preview twin, this mutates the
system.
}
\details{
A commit binds \strong{only} the preview it is handed. The \code{plan_hash} the
preview carries is what the privileged helper re-validates under the \code{dpkg}
lock, so a plan that has drifted since the preview is refused there, never
applied. Each \code{apt_<verb>()} refuses, before anything is opened, a preview
for a different verb (an \code{apt.remove} preview handed to
\code{apt_install()} is a \code{pkgops_bad_request}), a non-\code{ok} preview (a
\code{no_op} or a policy refusal is never committable), and anything that is not
a \code{pkgops_preview}.

\strong{Authorization.} With \code{interactive = TRUE} the \code{pkexec} prompt
authenticates the change at the privileged spawn; with \code{interactive =
FALSE} (machine mode) a non-interactive \code{pkcheck} decides, and a denial or
an approval challenge becomes a durably-audited refusal, never a prompt. The
default follows \code{\link{interactive}()} -- an R console commits
interactively, a script or CI run commits in machine mode.

On any refusal or failure the call signals a typed condition inheriting
\code{pkgops_error} and \code{runix_error} (for example \code{runix_unauthorized},
\code{runix_held}, \code{runix_apt_locked}, \code{runix_operation_failed},
\code{runix_dpkg_broken}). An effect whose outcome could not be determined
(\code{runix_helper_bad_result}) leaves the intent open for reconciliation and
is never reported as a clean failure.

}
\examples{
\dontrun{
p <- apt_install_preview(c("nginx"))
out <- apt_install(p, lock_timeout = 300)
out$verified
}
}
