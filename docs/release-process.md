# Release Process

This document records versioning conventions, the release checklist, and which repository security settings are enabled. It also records the release steps added by Issue #20 (plan Issue 19).

## Repository security settings enabled

| Setting | Status | Where it's controlled |
| --- | --- | --- |
| Secret scanning | ✅ Enabled | Settings → Code security (on by default for public repositories) |
| Secret scanning push protection | ✅ Enabled | Settings → Code security |
| Dependabot vulnerability alerts | ✅ Enabled | `PUT /repos/{owner}/{repo}/vulnerability-alerts` |
| Dependabot security updates | ✅ Enabled | Settings → Code security |
| Private vulnerability reporting | ✅ Enabled | Settings → Code security — this is what makes the reporting route in [`SECURITY.md`](../SECURITY.md) work |
| Branch protection on `main` | ✅ Enabled | Settings → Branches |

### Branch protection details for `main`

- Pull request required before merging.
- At least 1 approving review required.
- Required status checks (must pass before merge): `Build (strict warnings) and test`, `AddressSanitizer + UndefinedBehaviorSanitizer` (both from [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)), with branches required to be up to date (`strict` mode).
- Force pushes disallowed.
- Branch deletion disallowed.

These settings satisfy Issue #1's acceptance criteria: GitHub's Security tab shows `SECURITY.md` with private vulnerability reporting enabled, and every change to `main` now goes through a reviewed, CI-checked pull request.

## Security automation (what is actually in the repository)

| Item | Status |
| --- | --- |
| CodeQL for C/C++ | `.github/workflows/codeql.yml`. Runs on pull requests and `main`. Its only extra permission is `security-events: write` on that one job, needed to upload results; no secrets are used. |
| Dependabot | `.github/dependabot.yml`, GitHub Actions only (the project has no third-party libraries). |
| SBOM (Software Bill of Materials) | **Not provided.** The project has no external dependencies and distributes no binary; an SBOM would be an empty claim. Revisit if either changes. |
| `CODEOWNERS` | **Not added.** To be added once the team agrees who owns the security-sensitive paths. |
| `SECURITY-INSIGHTS.yml` | **Not added.** Only added once every practice it would declare is real. |

## Building a release from a clean clone

```sh
git clone https://github.com/ROHIT-JR/secure-proxy.git && cd secure-proxy
git checkout vX.Y.Z
make && make test && make demo-check
sha256sum bin/proxy bin/client > SHA256SUMS
```

Publish `SHA256SUMS` with the release. Release notes must link the exact tag, `SHA256SUMS`, and the matching `CHANGELOG.md` section.

## Versioning

This project has not yet made a tagged release. When it does, it will use [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`), starting at `v0.1.0` for the first Phase 1 (working concurrent proxy) milestone completion.

## Release checklist (for the first tagged release)

- [ ] All Phase 1 issues (#1–#9) closed and `make test` / `make sanitize` pass on a clean checkout.
- [ ] `CHANGELOG.md` updated with the release's changes.
- [ ] Tag created from `main` following semantic versioning, e.g. `git tag -a v0.1.0 -m "Phase 1: working concurrent proxy"`.
- [ ] Release notes on GitHub link to the tag, the relevant `CHANGELOG.md` section, and (once binaries are distributed) a checksum file and generated SBOM.
- [ ] Confirm CI is green on the tagged commit before publishing the release.

## Rollback

If a tagged release is found to be broken:

1. Do not delete the tag — leave it for traceability.
2. Fix forward with a new patch release, or revert the offending commit(s) on `main` via a reviewed pull request (never force-push over `main`, since branch protection now blocks this).
3. Mark the broken release as a pre-release or add a note to its release description pointing to the fixed version.
