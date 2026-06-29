# Hermes Firewall Installed

This fail-open Silmaril SDK firewall plugin is enabled after Hermes restarts.

It classifies `pre_llm_call`, `pre_tool_call`, `post_tool_call`,
`transform_tool_result`, and `transform_llm_output` events with the Silmaril
Security SDK. SDK output is logged for each call without raw classified text.
SDK failures are logged and fail open. Default behavior does not block tools,
inject context, or rewrite tool results.

Optional enforcement is available at Hermes boundaries that can act on content:
`pre_tool_call` can veto execution, while `transform_tool_result` and
`transform_llm_output` can replace malicious content before downstream use:

```bash
HERMES_FIREWALL_BLOCK_MALICIOUS=true
```

Install the SDK in the Hermes Python environment:

```bash
pip install silmaril-security-sdk==0.4.2
```

Set `SILMARIL_API_KEY` and `SILMARIL_API_URL` in the Hermes environment before
restarting Hermes.

The repository includes `.env.example` with all required and optional settings.
Configuration is read from the Hermes process environment at hook execution
time. Do not commit real API keys.

Restart Hermes to load the plugin:

```bash
hermes gateway restart
```

To open the public Silmaril Firewall demo after configuring Hermes:

```bash
python scripts/open_playground.py --open
```

The launcher prints or opens `https://app.silmaril.dev/demo/setup-complete`,
supports `--route playground` and `--json`, and never prints `SILMARIL_API_KEY`.
