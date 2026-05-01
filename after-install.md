# Hermes Firewall Installed

This pass-through firewall plugin is enabled after Hermes restarts.

It logs `pre_llm_call`, `pre_tool_call`, `post_tool_call`, and
`transform_tool_result` events. It does not block tools, inject context,
rewrite tool results, or call external services.

Restart Hermes to load the plugin:

```bash
hermes gateway restart
```
