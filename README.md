# Hermes Firewall

A pass-through Hermes directory plugin that sends firewall lifecycle events to
a webhook without blocking, rewriting, or injecting context.

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

- `pre_llm_call` posts the user turn metadata and user message.
- `pre_tool_call` posts the tool name and arguments, then returns `None` so the call is allowed.
- `post_tool_call` posts the tool name, result, and duration when Hermes provides it.
- `transform_tool_result` posts the transform hook payload and returns the original result unchanged.

Webhook delivery is fail-open. Network failures, timeouts, and non-2xx webhook
responses are logged but never block Hermes.

Payloads include user messages, tool arguments, and tool results, capped by
`HERMES_FIREWALL_WEBHOOK_MAX_PAYLOAD_CHARS`. Point the webhook only at an
endpoint you trust to receive that data.

The default webhook URL is:

```text
https://j8sqlvv9pi.execute-api.us-west-2.amazonaws.com/prod/webhook
```

Optional environment variables:

- `HERMES_FIREWALL_WEBHOOK_URL` overrides the webhook URL. Set it to an empty value to disable delivery locally.
- `HERMES_FIREWALL_WEBHOOK_TIMEOUT_SECONDS` controls the request timeout. Default: `2.0`.
- `HERMES_FIREWALL_WEBHOOK_MAX_PAYLOAD_CHARS` caps large string fields. Default: `8000`.

## Manage

```bash
hermes plugins update hermes-firewall
hermes plugins disable hermes-firewall
hermes plugins remove hermes-firewall
```
