# Hermes Firewall

A fail-open Hermes directory plugin that classifies firewall lifecycle events
with the Silmaril Security SDK. It defaults to shadow/pass-through mode without
rewriting or injecting context, and can optionally block malicious pre-tool
execution events where Hermes supports blocking.

## Install

Recommended install from GitHub:

```bash
hermes plugins install Silmaril-Security/HermesFirewallPlugin --enable
hermes gateway restart
```

The plugin requires the Silmaril Security SDK in the same Python environment
that runs Hermes:

```bash
pip install silmaril-security-sdk==0.4.2
```

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

The plugin registers five hooks:

- `pre_llm_call` classifies the user message with `HookLabel.USER_INPUT`.
- `pre_tool_call` classifies the tool name and arguments with `HookLabel.TOOL_CALL`. It returns `None` by default so the call is allowed, or `{"action": "block", "message": "..."}` when `HERMES_FIREWALL_BLOCK_MALICIOUS=true` and the classifier returns a malicious result.
- `post_tool_call` classifies the tool result with `HookLabel.TOOL_RESPONSE`.
- `transform_tool_result` classifies the tool result with `HookLabel.TOOL_RESPONSE`, then returns the original result unchanged.
- `transform_llm_output` classifies the final assistant response with `HookLabel.LLM_OUTPUT`, then returns the original response unchanged.

The SDK client is created with `shadow_mode=True`, so classification output is
logged without relying on SDK exceptions for control flow. SDK import,
configuration, network, API, malformed payload, empty payload, and classification
failures are logged and fail open.

Each successful SDK call logs an `sdk_result` line containing event type, hook
label, tool name, tool call id when present, `prediction`, `score`, `threshold`,
computed `blocked`, `primary_outcome`, `outcome_scores`, `detector_scores`, and
`detector_counts`. Raw prompts, tool arguments, tool outputs, and assistant text
are not emitted in structured logs or model-visible context.

Required environment variables:

- `SILMARIL_API_KEY`: API key for the Silmaril Firewall classify API.
- `SILMARIL_API_URL`: tenant `/classify` endpoint for the Silmaril Firewall API.

Optional environment variables:

- `HERMES_FIREWALL_SDK_TIMEOUT_SECONDS` controls the SDK request timeout. Default: `2.0`.
- `HERMES_FIREWALL_SDK_MAX_RETRIES` controls SDK retries. Default: `0`.
- `HERMES_FIREWALL_MAX_PAYLOAD_CHARS` caps large string fields. Default: `8000`.
- `HERMES_FIREWALL_BLOCK_MALICIOUS` enables optional `pre_tool_call` blocking. Default: `false`.

## Enforcement

Hermes currently supports blocking through `pre_tool_call` only. This plugin
therefore never blocks `pre_llm_call`, `post_tool_call`, `transform_tool_result`,
or `transform_llm_output`, even when the classifier result is malicious.

Default behavior is pass-through:

```bash
HERMES_FIREWALL_BLOCK_MALICIOUS=false
```

To enable pre-tool enforcement:

```bash
HERMES_FIREWALL_BLOCK_MALICIOUS=true
```

When enabled, malicious `pre_tool_call` classifications return the Hermes veto
shape:

```json
{
  "action": "block",
  "message": "Silmaril Firewall classified this tool call as malicious; primary_outcome=control_abuse; score=0.99; threshold=0.5"
}
```

## Development

```bash
python -m unittest discover -s tests -p 'test_*.py'
python -m py_compile firewall.py __init__.py
```

## Manage

```bash
hermes plugins update hermes-firewall
hermes plugins disable hermes-firewall
hermes plugins remove hermes-firewall
```
