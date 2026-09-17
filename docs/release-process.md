# Release Process

This document records versioning conventions, the release checklist, and which repository security settings are enabled. It will grow a full tagging/checksum/SBOM (Software Bill of Materials, a generated inventory of dependencies) process under Issue #20 (plan Issue 19), once the project actually distributes a binary. For now it captures the state established by Issue #1 (plan Issue 0).

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

## Versioning

This project has not yet made a tagged release. When it does, it will use [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`), starting at `v0.1.0` for the first Phase 1 (working concurrent proxy) milestone completion.

## Release checklist (for the first tagged release)

- [ ] All Phase 1 issues (#1–#9) closed and `make test` / `make sanitize` pass on a clean checkout.
- [ ] `CHANGELOG.md` updated with the release's changes (added under Issue #20).
- [ ] Tag created from `main` following semantic versioning, e.g. `git tag -a v0.1.0 -m "Phase 1: working concurrent proxy"`.
- [ ] Release notes on GitHub link to the tag, the relevant `CHANGELOG.md` section, and (once binaries are distributed) a checksum file and generated SBOM.
- [ ] Confirm CI is green on the tagged commit before publishing the release.

## Rollback

If a tagged release is found to be broken:

1. Do not delete the tag — leave it for traceability.
2. Fix forward with a new patch release, or revert the offending commit(s) on `main` via a reviewed pull request (never force-push over `main`, since branch protection now blocks this).
3. Mark the broken release as a pre-release or add a note to its release description pointing to the fixed version.
