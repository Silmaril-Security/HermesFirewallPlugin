# Hermes Firewall

A pass-through Hermes directory plugin that classifies firewall lifecycle events
with the Silmaril Security SDK without blocking, rewriting, or injecting context.

## Install

Recommended install from GitHub:

```bash
hermes plugins install Silmaril-Security/HermesFirewallPlugin --enable
hermes gateway restart
```

The plugin requires the Silmaril Security SDK in the same Python environment
that runs Hermes:

```bash
pip install silmaril-security-sdk==0.1.0
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

The plugin registers four hooks:

- `pre_llm_call` classifies the user message with `HookLabel.USER_INPUT`.
- `pre_tool_call` classifies the tool name and arguments with `HookLabel.TOOL_CALL`, then returns `None` so the call is allowed.
- `post_tool_call` classifies the tool result with `HookLabel.TOOL_RESPONSE`.
- `transform_tool_result` classifies the tool result with `HookLabel.TOOL_RESPONSE`, then returns the original result unchanged.

The SDK client is created with `shadow_mode=True`, so classification output is
logged but never blocks Hermes. SDK import, configuration, network, API, and
classification failures are logged and fail open.

Each successful SDK call logs an `sdk_result` line containing the SDK output:
`prediction`, `score`, `threshold`, computed `blocked`, `primary_outcome`, and
`outcome_scores`.

Required environment variables:

- `SILMARIL_API_KEY`: API key for the Silmaril Firewall classify API.
- `SILMARIL_API_URL`: tenant `/classify` endpoint for the Silmaril Firewall API.

Optional environment variables:

- `HERMES_FIREWALL_SDK_TIMEOUT_SECONDS` controls the SDK request timeout. Default: `2.0`.
- `HERMES_FIREWALL_SDK_THRESHOLD` controls the SDK threshold sent to the API. Default: `0.5`.
- `HERMES_FIREWALL_SDK_MAX_RETRIES` controls SDK retries. Default: `0`.
- `HERMES_FIREWALL_MAX_PAYLOAD_CHARS` caps large string fields. Default: `8000`.

## Manage

```bash
hermes plugins update hermes-firewall
hermes plugins disable hermes-firewall
hermes plugins remove hermes-firewall
```
