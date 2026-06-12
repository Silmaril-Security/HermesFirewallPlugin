# Hermes Firewall Installed

This fail-open Silmaril SDK firewall plugin is enabled after Hermes restarts.

It classifies `pre_llm_call`, `pre_tool_call`, `post_tool_call`,
`transform_tool_result`, and `transform_llm_output` events with the Silmaril
Security SDK. SDK output is logged for each call without raw classified text.
SDK failures are logged and fail open. Default behavior does not block tools,
inject context, or rewrite tool results.

Optional enforcement is available only for Hermes `pre_tool_call`, the hook
that can veto execution:

```bash
HERMES_FIREWALL_BLOCK_MALICIOUS=true
```

Install the SDK in the Hermes Python environment:

```bash
pip install silmaril-security-sdk==0.4.2
```

Set `SILMARIL_API_KEY` and `SILMARIL_API_URL` in the Hermes environment before
restarting Hermes.

Restart Hermes to load the plugin:

```bash
hermes gateway restart
```
