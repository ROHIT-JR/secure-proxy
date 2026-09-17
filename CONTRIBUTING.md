# Contributing to SecureBrowse

Thank you for considering a contribution. This guide is written for two kinds of readers: student teammates who are still learning C, sockets, and threads, and outside contributors who have never touched this repository before. Both are welcome.

## Setup

1. Clone the repository:
   ```sh
   git clone git@github.com:ROHIT-JR/secure-proxy.git
   cd secure-proxy
   ```
2. You need a Linux machine (or a Linux virtual machine/container) with `gcc` or `clang`, `make`, and POSIX (Portable Operating System Interface) threads support. Most mainstream Linux distributions have these by default.
3. Build the project:
   ```sh
   make
   ```
4. Run the test suite:
   ```sh
   make test
   ```
5. Run the sanitizer build (AddressSanitizer + UndefinedBehaviorSanitizer) before submitting networking or memory-related changes:
   ```sh
   make sanitize
   ```

## Branch naming

Use the pattern `type/short-description`, for example:

- `feat/url-parser`
- `fix/socket-leak-on-error`
- `docs/architecture-diagram`
- `test/concurrent-clients`

## Coding style

C and Markdown formatting follow the rules in [`.editorconfig`](.editorconfig) and [`.clang-format`](.clang-format). Run `clang-format` on changed `.c`/`.h` files before opening a pull request:

```sh
clang-format -i src/your_file.c
```

Compiler warnings are treated as errors (`-Wall -Wextra -Werror -pthread`). Code that does not compile warning-free will not be merged.

## How to open an issue

- Bug reports and feature requests use the templates under **Issues → New Issue**.
- If you think you found a security vulnerability, do **not** open a public issue. Follow [`SECURITY.md`](SECURITY.md) instead.
- Check existing issues first to avoid duplicates. Issues labelled `good-first-task` are a good starting point if you are new to the codebase.

## How to open a pull request

1. Create a branch from `main` using the naming convention above.
2. Make your change, add or update tests, and run `make test` and `make sanitize`.
3. Fill in the pull request template completely. This applies equally to human contributors and AI coding agents — a pull request is not complete without:
   - A **per-file breakdown**: every file created or changed, what changed, and why. Do not leave the reviewer to re-derive this from the raw diff.
   - **Test results**: the exact commands you ran (`make test`, `make sanitize`, or manual steps) and their actual outcome, not just a checked box.
   - The security/privacy impact and secrets checklist.
   - A closing `Closes #<issue>` line linking the issue the pull request resolves.
4. `main` is protected: a pull request with at least one approving review and passing CI is required before merge.

## Review expectations

- At least one maintainer review and a passing CI (Continuous Integration) run are required before merge.
- Reviewers will check: correctness, memory and socket ownership (every `malloc` freed once, every socket closed once), test coverage, and adherence to the project's safety rules below.
- Please respond to review comments within a reasonable time; if you are stuck, say so in the pull request — reviewers are happy to help.

## Safety rule: never submit secrets or real harmful URLs

This is a security-adjacent project, so this rule is non-negotiable:

- Never commit API (Application Programming Interface) keys, passwords, tokens, or other secrets. Use environment variables instead, and check `.gitignore` before committing.
- Never use real malicious, phishing, or harmful URLs (Uniform Resource Locators) in code, tests, commit messages, or issue reports. Use `example.com`, local test servers, or fake fixture data instead.
- Never commit real captured browsing data, personal data, or private URLs.

Pull requests that violate this rule will be closed and, if secrets were pushed, you will be asked to rotate them immediately.
