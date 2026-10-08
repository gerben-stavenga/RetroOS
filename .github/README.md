# CI and releases

## Checks

`CI` runs on branch pushes and pull requests. Its reusable validation workflow
has independent jobs for lint/unit tests, personality/hardware integration, and
release-image packaging and BIOS/UEFI boot checks. Packaging runs for master
and versioned releases. Require the `Required checks` status in branch rules.
Integration logs remain available even when a test fails. KVM suites are
required when the runner exposes KVM; unavailable emulators or proprietary
assets follow the existing test runner's explicit skip rules.

## Numbered releases

1. Update `CHANGELOG.md` with `## [0.8.0] - YYYY-MM-DD` (use the new version).
   Describe changes, upgrade instructions and known limitations.
2. Commit the code and notes to master. Let CI pass.
3. Create and push an annotated version tag pointing at that commit:

   ```sh
   git tag -a v0.8.0 -m 'RetroOS 0.8.0'
   git push origin v0.8.0
   ```

The versioned release workflow validates the tag and notes, runs all checks on
that exact commit, downloads the checked release artifacts, verifies checksums,
and publishes a draft only after all checks succeed. Published versions are
never overwritten. A failed publish can be retried via the workflow's manual
`tag` input; it resumes an unpublished draft. Prerelease tags such as
`v0.9.0-rc.1` create GitHub prereleases and do not replace the latest release.
The existing public filenames stay consistent with installation instructions;
version numbers are recorded by tags, release titles and the kernel build ID.

`Publish rolling release` retains the legacy `retroos` download link. It now
requires a successful CI run and matching commit; it cannot build and publish
unchecked binaries. Numbered releases are the normal release history.
