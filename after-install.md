# Hermes Firewall Installed

This fail-open Silmaril SDK firewall plugin is enabled after Hermes restarts.

It classifies `pre_llm_call`, `pre_tool_call`, `post_tool_call`, and
`transform_tool_result` events with the Silmaril Security SDK. SDK output is
logged for each call. SDK failures are logged and do not block tools, inject
context, or rewrite tool results.

Install the SDK in the Hermes Python environment:

```bash
pip install silmaril-security-sdk==0.1.0
```

Set `SILMARIL_API_KEY` and `SILMARIL_API_URL` in the Hermes environment before
restarting Hermes.

Restart Hermes to load the plugin:

```bash
hermes gateway restart
```
