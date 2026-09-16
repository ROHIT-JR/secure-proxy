# Support

SecureBrowse is an educational, security-aware forward proxy built as a university Operating Systems project. This page explains where to go for different kinds of help.

## I have a usage question

Use [GitHub Discussions](../../discussions) if enabled for this repository, or open a regular [GitHub Issue](../../issues/new/choose) using the "blank issue" or a discussion-style label if Discussions is not available. Please search existing issues and discussions first.

## I found a bug

Open a [bug report issue](../../issues/new/choose) using the bug report template. Please include:

- The exact command you ran and the output you saw.
- Your operating system and compiler version (for example, `gcc --version`).
- Whether the bug happens with `make sanitize` builds too.
- Logs, with any secrets or personal data removed.

## I found a security vulnerability

Do not open a public issue. Follow the private reporting process in [`SECURITY.md`](SECURITY.md).

## I want to request a feature

Open a [feature request issue](../../issues/new/choose) using the feature request template.

## What is not supported

- This is not a production secure web gateway. Do not deploy it to protect real, sensitive traffic.
- We do not provide guaranteed response times; this is a volunteer/student-maintained project.
- We do not support platforms other than Linux, or compilers other than `gcc`/`clang` with POSIX (Portable Operating System Interface) socket and `pthread` support.
- We do not provide live threat-intelligence API (Application Programming Interface) keys. The optional live threat-feed adapter (Issue 15 in the project plan) requires you to obtain and configure your own key.
