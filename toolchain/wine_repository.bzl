"""Pinned upstream Wine PE binaries; no Linux host libraries enter the image."""

def _wine_impl(ctx):
    ctx.download(
        url = "https://dl.winehq.org/wine-builds/ubuntu/pool/main/w/wine/wine-stable-i386_11.0.0.0~noble-1_i386.deb",
        output = "wine.deb",
        sha256 = "b322b50f9e8bd59687840d9a7bad10d70b12ef9bdb873298e858ff93a6205e56",
    )
    dpkg = ctx.which("dpkg-deb")
    if not dpkg:
        fail("Extracting the WineHQ PE distribution requires dpkg-deb")
    result = ctx.execute([dpkg, "--extract", "wine.deb", "package"])
    if result.return_code:
        fail(result.stderr)
    ctx.symlink("package/opt/wine-stable/lib/wine/i386-windows", "pe")
    ctx.file("BUILD.bazel", 'exports_files(glob(["pe/*"]))\n')

wine_repository = repository_rule(implementation = _wine_impl)

def _wine_build_tools_impl(ctx):
    ctx.download(
        url = "https://archive.ubuntu.com/ubuntu/pool/main/f/flex/flex_2.6.4-8.2build1_amd64.deb",
        output = "flex.deb",
        sha256 = "c5604f55827b50e3f568b4731b7799f86b147454c867be02bc141d9d8ce561ff",
    )
    result = ctx.execute(["dpkg-deb", "--extract", "flex.deb", "."])
    if result.return_code:
        fail(result.stderr)
    ctx.file("BUILD.bazel", 'exports_files(["usr/bin/flex"])\n')

wine_build_tools_repository = repository_rule(implementation = _wine_build_tools_impl)
