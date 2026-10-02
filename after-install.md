# Hermes Firewall Installed

This fail-open Silmaril SDK firewall plugin, version 0.6.3, is enabled after Hermes restarts.

It classifies `pre_llm_call`, `pre_tool_call`, `post_tool_call`,
`transform_tool_result`, `transform_llm_output`, `subagent_start`, and
`subagent_stop` with the Silmaril Security SDK. SDK output is logged for each
call without raw classified text. SDK failures are logged and fail open. A
`FirewallBlockedException` that includes a classification result supplies that
result for the effective-mode decision and is not treated as an outage. When
neither mode override is set, the backend selects the effective mode. A
response without a mode stays in Shadow and does not block tools, inject
context, or rewrite results.

Hook decisions are also written as private, bounded `LocalProtectionEventV1`
records under `~/Library/Application Support/Silmaril/Evidence/incoming`.
These records contain redacted metadata only and never claim a real-world
outcome was verified. Set `SILMARIL_LOCAL_EVENT_DIR` only when the incoming
directory must be overridden.

`post_tool_call`, `subagent_start`, and `subagent_stop` are observe-only.
Block can veto `pre_tool_call`. At `transform_tool_result` and
`transform_llm_output`, Block replaces malicious tool results and assistant
output with fixed, content-free text. Warn returns bounded context from
`pre_llm_call` and appends that warning at `transform_tool_result`.

```bash
SILMARIL_MODE=block
```

Install the SDK in the Hermes Python environment:

```bash
pip install silmaril-security-sdk==0.6.0
```

Set required `SILMARIL_API_KEY` and `SILMARIL_API_URL` in the Hermes
environment before restarting Hermes. `SILMARIL_ENDPOINT_ID` is optional.

The repository includes `.env.example` for the required API settings and the
current optional overrides. The deprecated `HERMES_FIREWALL_BLOCK_MALICIOUS`
flag is documented in the README and is not listed in `.env.example`.
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
