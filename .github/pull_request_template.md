## Summary

<!-- One or two sentences: what does this change do, and why does it need to happen now? -->

## Files created or changed

<!--
List every file this PR touches. For each one, state what changed and why.
This section is required for both human and AI-agent contributors — it lets a
reviewer understand the change without re-deriving it from the raw diff.

Example:

| File | Created / Changed | What & why |
| --- | --- | --- |
| `src/request_parser.c` | Created | Implements `parse_http_url()`; needed before the TCP server (Issue #5) can validate incoming requests. |
| `docs/architecture.md` | Changed | Added the parser's typed result struct to the module boundary table, so the doc matches the new code. |
-->

| File | Created / Changed | What & why |
| --- | --- | --- |
| | | |

## Test results

<!--
State exactly what you ran and what happened. Paste command + outcome, not just a checkbox.
Example:
  make test        -> all Phase 1 integration tests pass (12/12)
  make sanitize     -> clean, no AddressSanitizer/UndefinedBehaviorSanitizer reports
-->

- [ ] `make test` passes — result:
- [ ] `make sanitize` passes (AddressSanitizer + UndefinedBehaviorSanitizer), for changes touching sockets, threads, or memory — result:
- [ ] New behavior has new or updated tests

## Security and privacy impact

<!--
Does this change touch untrusted network input, DNS (Domain Name System) resolution,
private/loopback addresses, logging, caching, or a third-party provider?
Describe the impact, or state explicitly that there is none.
-->

## Documentation updated

- [ ] README, docs/, or code comments updated if behavior or setup changed
- [ ] Not applicable

## Secrets checklist

- [ ] I confirm this diff contains no API keys, passwords, tokens, real private URLs, or personal data.

## Closes

Closes #
