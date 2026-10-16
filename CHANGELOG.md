# Changelog

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
