# Changelog

## 0.6.6 - Release preparation

- Require Hermes 0.23.0 and use its native `pre_llm_call` block directive to
  veto malicious or governance-denied prompts before inference.
- Detect prompt-veto support from the concrete host consumer contract before
  reporting `block_returned`; direct imports under older hosts remain
  observational.
- Register final-output transformation with `hold_stream=True`, intentionally
  buffering all enabled modes so Block replacements precede delivery while
  Shadow, Warn, benign, and fail-open content remain unchanged.
- Pin the published `silmaril-security-sdk` 0.8.2 release after direct-client
  compatibility coverage.
- Send SDK 0.8.2 typed governance with canonical agent `hermes`, agent
  resources at model boundaries, and trusted native tool-name resources at
  tool boundaries without inventing MCP server identity.
- Add loopback HTTP wire coverage for typed governance and opt-in native
  qualification against official Hermes v0.23.0 source commit
  `2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19`.
- Pin separate development and native-QA dependencies, keep the documented
  default suite runnable with runtime requirements and `unittest`, and require
  all eight native cases in GitHub CI.
- Reject dirty or mismatched Hermes qualification checkouts and verify that
  every imported host consumer module originates from the pinned checkout.

This entry describes source prepared for 0.6.6. It does not assert package or
GitHub publication, hosted propagation, deployment, or installed uptake.

## 0.6.5 - Release preparation

- Preserve the typed SDK governance decision and treat `governance.action=block`
  as a block candidate without changing the raw model prediction.
- Use the same model-or-governance candidate predicate for native decisions,
  cached results, local evidence decisions, and bounded log summaries.
- Show readable governance-policy denial copy for governance-only blocks.
- Pin the published `silmaril-security-sdk` 0.7.3 release.
- Retain the corrected mode guidance: explicit local Shadow, Warn, or Block
  wins; a mode-less response falls back to Shadow.

This entry describes source prepared for 0.6.5. It does not assert package or
GitHub publication, hosted propagation, deployment, or installed uptake.
