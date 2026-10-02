# Hermes Firewall

A fail-open Hermes directory plugin that classifies firewall lifecycle events
with the Silmaril Security SDK. Shadow is silent. Warn adds one bounded warning
on supported same-turn surfaces. Block vetoes malicious `pre_tool_call` events.
`post_tool_call` is observe-only. `transform_tool_result` and
`transform_llm_output` replace malicious Block output with fixed, content-free
text. Hooks without an enforcement return leave completed content unchanged.

## Install

Recommended install from GitHub:

```bash
hermes plugins install Silmaril-Security/HermesFirewallPlugin --enable
hermes gateway restart
```

This plugin's manifest version is 0.6.3 (`plugin.yaml` and `PLUGIN_VERSION`
in `firewall.py`). It requires Silmaril Security SDK 0.6.0, the version pinned
in `requirements.txt`, in the same Python environment that runs Hermes:

```bash
pip install silmaril-security-sdk==0.6.0
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
- `pre_tool_call` classifies the tool name and arguments with `HookLabel.TOOL_CALL`. It returns `None` by default so the call is allowed, or `{"action": "block", "message": "..."}` when the effective mode is Block and the classifier returns a malicious result.
- `post_tool_call` classifies the tool result with `HookLabel.TOOL_RESPONSE` and remains observe-only.
- `transform_tool_result` reuses the matching `post_tool_call` classification. Warn appends bounded context; Block replaces the result before model reuse.
- `transform_llm_output` classifies the final assistant response with `HookLabel.LLM_OUTPUT` and replaces malicious Block output before delivery.
- `subagent_start` classifies the child goal with `HookLabel.USER_INPUT` for visibility.
- `subagent_stop` classifies the child summary with `HookLabel.LLM_OUTPUT` for visibility.

Each native Hermes event produces at most one classification. `pre_llm_call`
accepts the host's `conversation_history` argument for compatibility but ignores
it; conversation state is owned by the Firewall sequence cache.

Effective mode is chosen in this order: a valid `SILMARIL_MODE` of `shadow`,
`warn`, or `block`; otherwise `HERMES_FIREWALL_BLOCK_MALICIOUS` (`true` is
Block and `false` is Shadow); otherwise a `shadow`, `warn`, or `block` value
on the SDK result; otherwise Shadow. A valid `SILMARIL_MODE` wins over both
the legacy flag and a different mode on the result. An invalid `SILMARIL_MODE`
is logged and ignored, and it does not fall through to the legacy flag. When
neither override is set, the SDK client omits `mode` and the backend selects
the effective mode. During a mixed-version backend response, a configured mode
stays authoritative, and a mode-less result stays Shadow.

SDK import failure, missing `SILMARIL_API_KEY` or `SILMARIL_API_URL`, network
and API errors, empty payloads, and other classification errors are logged
with the error type and fail open. If the SDK raises `FirewallBlockedException`
and the exception carries a classification result, the plugin uses that result.
The hook still applies effective mode and the exact `MALICIOUS` prediction. An
exception without a result fails open.

Only the exact prediction `MALICIOUS` is enforceable. Scores, thresholds,
outcomes, missing predictions, and unknown predictions remain diagnostic. A
successful `post_tool_call` classification is reused by the matching
`transform_tool_result` when the session, task, tool call id, tool name, and
content match, so that pair makes one SDK request. A failed observation is not
cached. Changed content receives a distinct content-sensitive identity. Child
lifecycle events use the child session as their conversation identity; other
events use the normal Hermes session. Large strings preserve both their head
and tail when sanitized for classification.

Each successful SDK call logs an `sdk_result` line containing event type, hook
label, tool name, tool call id when present, prediction, readable risk category,
and whether the SDK classified the event as blocked. Raw prompts, tool
arguments, tool outputs, assistant text, classifier scores, thresholds, detector
maps, and raw decision JSON are not emitted in structured logs or model-visible
context.

Every hook invocation also attempts to write one bounded `LocalProtectionEventV1` JSON
record to the private local evidence spool, including fail-open results. The
record contains redacted metadata, opaque request/session fingerprints,
decision facts, native action, and plugin provenance. Unit-interval scores and
thresholds may be stored as `modelScore` and `modelThreshold`. It never
contains raw prompts, arguments, results, assistant output, credentials,
detector maps, or error bodies. Events always report `outcome=not_observed`.
A returned Hermes native veto (`nativeAction=block_returned`) reports
`evidenceTruth=native_response_returned`. Every other native action, including
Warn and transform replacement (`nativeAction=content_replaced`), reports
`evidenceTruth=plugin_reported`. Neither value claims the downstream
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

- `SILMARIL_ENDPOINT_ID` is the canonical UUID v4 supplied by the Silmaril endpoint app.
- `HERMES_FIREWALL_SDK_TIMEOUT_SECONDS` controls the SDK request timeout. Default: `2.0`.
- `HERMES_FIREWALL_SDK_MAX_RETRIES` controls SDK retries. Default: `0`.
- `HERMES_FIREWALL_MAX_PAYLOAD_CHARS` caps large string fields. Default: `8000`.
- `SILMARIL_MODE` optionally overrides the backend with `shadow`, `warn`, or `block`.
- `HERMES_FIREWALL_BLOCK_MALICIOUS` is the deprecated legacy mapping; true maps to Block and false maps to Shadow.
- `SILMARIL_LOCAL_EVENT_DIR` directly overrides the incoming evidence directory. It is primarily intended for testing and nonstandard installations.

Configuration precedence is Hermes-native and environment-based: the hook reads
the process environment used by Hermes at call time. There is no local config
file parser, credential service, or fallback that writes secrets into plugin
state.

Every classifier request carries plugin-owned `metadata.silmaril` with
`integration` `hermes-firewall`, `version` `0.6.3`, and `provenance`.
Provenance always includes `schema_version` 1 and `harness` `hermes`. A valid
UUID v4 `SILMARIL_ENDPOINT_ID` adds `endpoint_id`; an invalid value is omitted
with a warning. On macOS, a successful ComputerName lookup can add
`device_name`. Classification continues when either value is absent.
`device_name` is not written into local evidence.

## Enforcement

`pre_tool_call` is the pre-execution veto. In Block mode a malicious result
returns `{"action": "block", "message": "..."}`. `post_tool_call` is
observe-only and returns `None` in every mode, including Block.
`transform_tool_result` and `transform_llm_output` are the native replacement
hooks: a malicious Block decision replaces the completed tool result or
assistant output with fixed, content-free text. Warn context is returned from
`pre_llm_call`. `transform_tool_result` keeps the original tool result and
appends the same warning. `transform_llm_output` returns the original
assistant text in Warn mode. `subagent_start` and `subagent_stop` remain
observe-only because those Hermes hooks have no enforcement return channel.
Unsafe delegation is blocked at the nearest enforceable gate: the
`delegate_task` tool call (`DELEGATION_TOOL_NAME` in the plugin) is classified
and vetoed by `pre_tool_call` before the child agent starts. Child agent
prompts, tool calls, tool results, and final outputs are scanned through the
same normal hook path used for parent sessions.

By default, neither mode variable is set and the backend selects the effective mode.

To enable enforcement at supported boundaries:

```bash
SILMARIL_MODE=block
```

When enabled, malicious `pre_tool_call` classifications return the Hermes veto
shape with readable copy:

```text
Silmaril Firewall blocked this tool call: Unsafe agent control attempt. Continue without using the blocked content.
```

Malicious Block decisions at the transform hooks use the same fixed shape.
For a `control_abuse` or `prompt_injection` result the replacements are:

```text
Silmaril Firewall blocked this tool result: Unsafe agent control attempt. Continue without using the blocked content.
Silmaril Firewall blocked this assistant output: Unsafe agent control attempt. Continue without using the blocked content.
```

The warning string is fixed. It does not include raw prompts, arguments,
secrets, scores, thresholds, detector maps, or hidden policy.

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
