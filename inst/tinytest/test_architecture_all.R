# libapt's P.Arch() identifies the native cache slot for Architecture: all.
# dpkg's Architecture field remains "all". These independently specified frames
# reproduce the real canary mismatch without consulting or changing live dpkg.
local({
    verify <- pkgops:::.verify
    observe <- pkgops:::.observe
    reads <- 0L
    frame <- function(arch = "all", status = "installed", version = "1.1",
                      package = "canary-fixture") {
        data.frame(package = package, architecture = arch, status = status,
                   version = version, stringsAsFactors = FALSE)
    }
    reader <- function(df) list(installed = function() {
        reads <<- reads + 1L
        df
    })
    preview <- function(action, arch = "amd64") {
        list(verb = if (action == "configure") "apt.configure" else "apt.install",
             records = list(list(package = "canary-fixture", architecture = arch,
                 action = action, from_version = "1.0", to_version = "1.1",
                 current_version = "1.0", state = "half-configured")))
    }
    installed <- frame()
    absent <- installed[FALSE, ]
    for (action in c("install", "upgrade", "downgrade", "configure")) {
        p <- preview(action)
        expect_true(verify(p, reader(installed))$verified)
        got <- observe(p, reader(installed))
        expect_identical(got$state, list("canary-fixture:amd64" =
            list(status = "installed", version = "1.1")))
        expect_false(got$read_failed)
        expect_false(verify(p, reader(frame(status = "half-configured")))$verified)
        expect_false(verify(p, reader(frame(arch = "i386")))$verified)
        expect_false(verify(p, reader(frame(package = "another-fixture")))$verified)
    }
    p <- preview("install")
    expect_false(verify(p, reader(frame(version = "1.0")))$verified)
    expect_true(verify(preview("install", "all"), reader(installed))$verified)
    expect_false(verify(preview("install", "all"), reader(frame(arch = "amd64")))$verified)
    # Concrete multiarch rows remain distinct: i386's version cannot satisfy amd64.
    multi <- rbind(frame("amd64", version = "1.0"), frame("i386"))
    expect_false(verify(p, reader(multi))$verified)
    expect_true(verify(preview("install", "i386"), reader(multi))$verified)
    for (action in c("remove", "purge")) {
        p <- preview(action)
        expect_false(verify(p, reader(installed))$verified)
        expect_true(verify(p, reader(absent))$verified)
        before <- observe(p, reader(installed))
        after <- observe(p, reader(absent))
        expect_true(pkgops:::.state_changed(before, after))
    }
    expect_true(verify(preview("remove"), reader(frame(status = "config-files")))$verified)
    expect_false(verify(preview("purge"), reader(frame(status = "config-files")))$verified)
    # Never silently choose one row from contradictory or duplicate ground truth.
    for (df in list(rbind(installed, frame("amd64")), rbind(installed, installed))) {
        for (action in c("install", "configure")) {
            p <- preview(action)
            expect_false(verify(p, reader(df))$verified)
            got <- observe(p, reader(df))
            expect_true(got$read_failed)
            expect_null(got$state)
        }
    }
    expect_true(reads > 0L)
})
