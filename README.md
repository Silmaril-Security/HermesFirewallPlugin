# Hermes Firewall

A pass-through Hermes directory plugin that logs firewall lifecycle events
without blocking, rewriting, injecting context, or calling external services.

## Install

Recommended install from GitHub:

```bash
hermes plugins install Silmaril-Security/HermesFirewallPlugin --enable
hermes gateway restart
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

- `pre_llm_call` logs the session, platform, model, turn flag, and message/history sizes.
- `pre_tool_call` logs the tool name and argument keys, then returns `None` so the call is allowed.
- `post_tool_call` logs the tool name, result size, and duration when Hermes provides it.
- `transform_tool_result` logs the transform hook and returns the original result unchanged.

No API key is required for this pass-through version.

## Manage

```bash
hermes plugins update hermes-firewall
hermes plugins disable hermes-firewall
hermes plugins remove hermes-firewall
```
