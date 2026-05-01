# Hermes Firewall Installed

This fail-open firewall webhook plugin is enabled after Hermes restarts.

It posts `pre_llm_call`, `pre_tool_call`, `post_tool_call`, and
`transform_tool_result` events to the configured webhook. Webhook failures are
logged and do not block tools, inject context, or rewrite tool results.

Restart Hermes to load the plugin:

```bash
hermes gateway restart
```
