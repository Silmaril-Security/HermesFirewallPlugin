# Changelog

## 0.7.0 - Source candidate

- Move to `silmaril-security-sdk` 1.0.0, which calls `/v2/classify` and falls
  back to `/classify` on deployments without it. `SILMARIL_API_URL` and every
  other setting are unchanged.
- Decide every boundary on the typed SDK result: a block candidate is
  `result.blocked` (`action` other than `allow`). A block whose `source` is
  `governance` keeps policy-denial copy and a benign recorded prediction. The
  plugin no longer reads `prediction`, `score`, `threshold`,
  `primary_outcome`, or the score maps, which SDK 1.0 removed.
- Treat a result that is not the SDK's `BlockResult` as a classification
  failure: it is logged with its error type and recorded as `unavailable`
  instead of being read as an allow.
- Write the decision's `confidence` and `severity` to
  `LocalProtectionEventV1` when the Firewall reports a known value, and stop
  writing `modelScore` and `modelThreshold`. The schema version and every other
  field are unchanged; app versions that predate the new fields ignore them.
- Record `provenance.modelVersion` from the decision's model identifier and
  `provenance.policyVersion` from the governance decision's policy version
  when those are present. Both are stripped of control and format characters
  and cut to 128 UTF-8 bytes.
- Log `action` and `source` in `sdk_result` lines in place of `prediction`.
- Serve `/v2/classify` and `/classify` from the native acceptance classifier
  and relay each route to the matching customer route.

This entry describes source prepared for 0.7.0. It does not assert package or
GitHub publication, hosted propagation, deployment, or installed uptake.

## 0.6.7 - Source candidate

- Register stable Hermes 0.23.1 `pre_auxiliary_call` and
  `post_auxiliary_call` observers with bounded sanitized request/response
  classification and logical-request/per-attempt correlation.
- Forward validated tool-hook `conversation_id` independently from rotating
  transcript sessions and child-session identity, with explicit missing or
  invalid fallback.
- Keep auxiliary and lifecycle observers pass-through in every mode; Block
  candidates record native action unavailable without claiming prevention.
- Raise the host contract floor and source qualification pin to Hermes 0.23.1.

This entry describes source prepared for 0.6.7. It does not assert package or
GitHub publication, hosted propagation, deployment, or installed uptake.

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
