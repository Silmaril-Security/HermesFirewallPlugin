# Hermes Firewall

A fail-open Hermes directory plugin that classifies firewall lifecycle events
with the Silmaril Security SDK. It defaults to shadow/pass-through mode without
injecting context, and can optionally block malicious pre-tool calls plus
replace malicious tool or final LLM output at Hermes transform boundaries.

## Install

Recommended install from GitHub:

```bash
hermes plugins install Silmaril-Security/HermesFirewallPlugin --enable
hermes gateway restart
```

The plugin requires the Silmaril Security SDK in the same Python environment
that runs Hermes:

```bash
pip install silmaril-security-sdk==0.5.0
```

Copy `.env.example` into your Hermes environment manager or shell profile and
replace placeholder values there. Do not commit real API keys.

Local development install on macOS/Linux:

```bash
git clone https://github.com/Silmaril-Security/HermesFirewallPlugin.git
cd HermesFirewallPlugin
hermes plugins install "file://$(pwd)" --force --enable
hermes gateway restart
```

Local development install on PowerShell:

```powershell
$uri = (Get-Item .).FullName.Replace('\', '/')
hermes plugins install "file:///$uri" --force --enable
hermes gateway restart
```

## Behavior

The plugin registers seven hooks:

- `pre_llm_call` classifies the user message with `HookLabel.USER_INPUT`.
- `pre_tool_call` classifies the tool name and arguments with `HookLabel.TOOL_CALL`. It returns `None` by default so the call is allowed, or `{"action": "block", "message": "..."}` when `HERMES_FIREWALL_BLOCK_MALICIOUS=true` and the classifier returns a malicious result.
- `post_tool_call` classifies the tool result with `HookLabel.TOOL_RESPONSE` and remains observe-only.
- `transform_tool_result` reuses the matching `post_tool_call` classification, then returns the original result by default or a safe replacement when blocking is enabled and the result is malicious.
- `transform_llm_output` classifies the final assistant response with `HookLabel.LLM_OUTPUT`, then returns the original response by default or a safe replacement when blocking is enabled and the output is malicious.
- `subagent_start` classifies the child goal with `HookLabel.USER_INPUT` for visibility.
- `subagent_stop` classifies the child summary with `HookLabel.LLM_OUTPUT` for visibility.

The SDK client is created with `shadow_mode=True`, so classification output is
logged without relying on SDK exceptions for control flow. SDK import,
configuration, network, API, malformed payload, empty payload, and classification
failures are logged and fail open.

Only the exact prediction `MALICIOUS` is enforceable. Scores, thresholds,
outcomes, missing predictions, and unknown predictions remain diagnostic. A
matching post/transform tool callback pair makes one SDK request, and changed
content receives a distinct content-sensitive identity. Child lifecycle events
use the child session as their conversation identity; other events use the
normal Hermes session. Large strings preserve both their head and tail when
sanitized for classification.

Each successful SDK call logs an `sdk_result` line containing event type, hook
label, tool name, tool call id when present, prediction, readable risk category,
and whether the SDK classified the event as blocked. Raw prompts, tool
arguments, tool outputs, assistant text, classifier scores, thresholds, detector
maps, and raw decision JSON are not emitted in structured logs or model-visible
context.

Every completed classification also writes one bounded `LocalProtectionEventV1` JSON
record to the private local evidence spool. The record contains only redacted
metadata, opaque request/session fingerprints, decision facts, native action,
and plugin provenance. It never contains raw prompts, arguments, results,
assistant output, credentials, detector maps, or error bodies. Events always
report `outcome=not_observed`. Allowed and monitored actions report
`evidenceTruth=plugin_reported`; returned Hermes blocks and replacements report
`evidenceTruth=native_response_returned`. Neither value claims the downstream
consequence was independently prevented.

Writes are synchronous, per-event, and atomic, with `0700` directory and `0600`
file permissions. Evidence failures log only the error type and never change
the Hermes hook return value. By default the plugin writes directly to:

```text
~/Library/Application Support/Silmaril/Evidence/incoming
```

Required environment variables:

- `SILMARIL_API_KEY`: API key for the Silmaril Firewall classify API.
- `SILMARIL_API_URL`: tenant `/classify` endpoint for the Silmaril Firewall API.

Optional environment variables:

- `HERMES_FIREWALL_SDK_TIMEOUT_SECONDS` controls the SDK request timeout. Default: `2.0`.
- `HERMES_FIREWALL_SDK_MAX_RETRIES` controls SDK retries. Default: `0`.
- `HERMES_FIREWALL_MAX_PAYLOAD_CHARS` caps large string fields. Default: `8000`.
- `HERMES_FIREWALL_BLOCK_MALICIOUS` enables optional blocking at supported pre-tool and transform boundaries. Default: `false`.
- `SILMARIL_LOCAL_EVENT_DIR` directly overrides the incoming evidence directory. It is primarily intended for testing and nonstandard installations.

Configuration precedence is Hermes-native and environment-based: the hook reads
the process environment used by Hermes at call time. There is no local config
file parser, credential service, or fallback that writes secrets into plugin
state.

## Enforcement

Hermes supports pre-execution vetoes through `pre_tool_call` and post-execution
replacement through `transform_tool_result` and `transform_llm_output`.
`post_tool_call`, `subagent_start`, and `subagent_stop` remain observe-only
because those Hermes hooks have no enforcement return channel. Unsafe delegation
is blocked at the nearest enforceable gate: the `delegate_task` tool call
(`DELEGATION_TOOL_NAME` in the plugin) is classified and vetoed by
`pre_tool_call` before the child agent starts. Child
agent prompts, tool calls, tool results, and final outputs are scanned through
the same normal hook path used for parent sessions.

Default behavior is pass-through:

```bash
HERMES_FIREWALL_BLOCK_MALICIOUS=false
```

To enable enforcement at supported boundaries:

```bash
HERMES_FIREWALL_BLOCK_MALICIOUS=true
```

When enabled, malicious `pre_tool_call` classifications return the Hermes veto
shape with readable copy:

```text
Silmaril Firewall blocked this tool call: Unsafe agent control attempt. Continue without using the blocked content.
```

Malicious transform-hook classifications return a safe replacement string with
surface, reason, action, and next step. The replacement does not include raw
classifier JSON, scores, thresholds, detector maps, original tool output, or
assistant text.

## Public Demo

The demo launcher opens the hosted Silmaril Firewall UI at
`https://app.silmaril.dev/demo/setup-complete`. It does not serve a local UI,
start a credential proxy, or put `SILMARIL_API_KEY` in the URL, terminal output,
or chat.

Run it from the repository root:

```bash
python scripts/open_playground.py
python scripts/open_playground.py --open
python scripts/open_playground.py --route playground --json
```

For preview validation, override the hosted base URL:

```bash
SILMARIL_DEMO_BASE_URL="http://localhost:3001" python scripts/open_playground.py
```

The JSON status output includes the configured API URL and a boolean
`hasApiKey`, but never the raw key.

## Development

```bash
python -m unittest discover -s tests -p 'test_*.py'
python -m py_compile firewall.py __init__.py
python -m py_compile scripts/open_playground.py
```

## Manage

```bash
hermes plugins update hermes-firewall
hermes plugins disable hermes-firewall
hermes plugins remove hermes-firewall
```

## License

This plugin is licensed under Apache-2.0. See `LICENSE` and `NOTICE`.
