# Hermes Firewall Installed

This fail-open Silmaril SDK firewall plugin is enabled after Hermes restarts.

It classifies `pre_llm_call`, `pre_tool_call`, `post_tool_call`,
`transform_tool_result`, and `transform_llm_output` events with the Silmaril
Security SDK. SDK output is logged for each call without raw classified text.
SDK failures are logged and fail open. Default behavior does not block tools,
inject context, or rewrite tool results.

Hook decisions are also written as private, bounded `LocalProtectionEventV1`
records under `~/Library/Application Support/Silmaril/Evidence/incoming`.
These records contain redacted metadata only and never claim a real-world
outcome was verified. Set `SILMARIL_LOCAL_EVENT_DIR` only when the incoming
directory must be overridden.

Optional Block enforcement is available at `pre_tool_call`. Warn can add bounded
same-turn context at supported surfaces. Completed content is never replaced:

```bash
SILMARIL_MODE=block
```

Install the SDK in the Hermes Python environment:

```bash
pip install silmaril-security-sdk==0.6.0
```

Set `SILMARIL_API_KEY`, `SILMARIL_API_URL`, and the app-provided
`SILMARIL_ENDPOINT_ID` in the Hermes environment before
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
