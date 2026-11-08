# Hermes Firewall

A fail-open Hermes directory plugin that classifies firewall lifecycle events
with the Silmaril Security SDK. Shadow is silent. Warn adds one bounded warning
on supported same-turn surfaces. On Hermes 0.23+, Block vetoes `pre_llm_call`
before inference and `pre_tool_call` before execution when the model predicts
`MALICIOUS` or governance returns `action=block`.
`post_tool_call` is observe-only. `transform_tool_result` and
`transform_llm_output` replace Block candidates with fixed, content-free text.
Final assistant output is held until `transform_llm_output` completes, so a
replacement is applied before any assistant text is delivered.

## Install

Release [v0.6.6](https://github.com/Silmaril-Security/HermesFirewallPlugin/releases/tag/v0.6.6)
is available. For a reproducible installation on macOS/Linux, check out that
release and use Hermes's existing local `file://` installer:

```bash
git clone --branch v0.6.6 --depth 1 https://github.com/Silmaril-Security/HermesFirewallPlugin.git
cd HermesFirewallPlugin
hermes plugins install "file://$(pwd)" --force --enable
hermes gateway restart
```

Plugin version 0.6.6 requires Hermes 0.23.0 or newer with the capable
`hold_stream` output-transform path described below, and the published Silmaril
Security SDK 0.8.2, the version pinned in `requirements.txt`, in the same Python
environment that runs Hermes:

```bash
pip install silmaril-security-sdk==0.8.2
```

Copy `.env.example` into your Hermes environment manager or shell profile and
replace placeholder values there. Do not commit real API keys.

To install current source from GitHub instead:

```bash
hermes plugins install Silmaril-Security/HermesFirewallPlugin --enable
hermes gateway restart
```

Reproducible local install from an existing v0.6.6 checkout on PowerShell:

```powershell
$uri = (Get-Item .).FullName.Replace('\', '/')
hermes plugins install "file:///$uri" --force --enable
hermes gateway restart
```

## Behavior

The plugin registers seven hooks:

- `pre_llm_call` classifies the user message with `HookLabel.USER_INPUT`. Warn returns bounded context. On a host with the native v0.23 veto consumer, Block returns a fixed veto before inference.
- `pre_tool_call` classifies the tool name and arguments with `HookLabel.TOOL_CALL`. It returns `None` by default so the call is allowed, or `{"action": "block", "message": "..."}` when the effective mode is Block and the result is a block candidate.
- `post_tool_call` classifies the tool result with `HookLabel.TOOL_RESPONSE` and remains observe-only.
- `transform_tool_result` reuses the matching `post_tool_call` classification. Warn appends bounded context; Block replaces the result before model reuse.
- `transform_llm_output` is registered with `hold_stream=True`, classifies the held final assistant response with `HookLabel.LLM_OUTPUT`, and replaces Block-candidate output before delivery.
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
neither override is set, the SDK client omits `mode`. Current classify responses
also omit mode, so the plugin falls back to Shadow; select Warn or Block
explicitly when intended. A valid legacy response mode remains compatible. During a mixed-version backend response, a configured mode
stays authoritative, and a mode-less result stays Shadow.

SDK import failure, missing `SILMARIL_API_KEY` or `SILMARIL_API_URL`, network
and API errors, empty payloads, and other classification errors are logged
with the error type and fail open. If the SDK raises `FirewallBlockedException`
and the exception carries a classification result, the plugin uses that result.
The hook still applies effective mode and the shared block-candidate predicate.
An exception without a result fails open.

The shared block-candidate predicate is an exact `MALICIOUS` prediction or a
typed SDK `GovernanceDecision` with `action=block`. Governance `action=allow`,
absent governance, scores, thresholds, outcomes, missing predictions, and
unknown predictions do not create a candidate. A governance-only denial keeps
the model prediction `BENIGN`; it is not relabeled as malicious. A successful
`post_tool_call` classification is reused by the matching
`transform_tool_result` when the session, task, tool call id, tool name, and
content match, so that pair makes one SDK request. A failed observation is not
cached. Changed content receives a distinct content-sensitive identity. Child
lifecycle events use the child session as their conversation identity; other
events use the normal Hermes session.

Every SDK submission, including serialized structured tool arguments, is
strictly limited by `HERMES_FIREWALL_MAX_PAYLOAD_CHARS`. Oversized text samples
the head and tail with a short omission marker included in the character limit;
very small positive limits use a deterministic prefix. Invalid and nonpositive
values use the default. Request identity, tool-result cache identity, local
protection evidence, and content returned to Hermes remain based on the
original full event text.

This sampling omits the middle of oversized content. A result therefore covers
only the submitted sample and is not proof that the full input was classified.
Payload overflow does not itself create an enforcement decision.

Each successful SDK call logs an `sdk_result` line containing event type, hook
label, tool name, tool call id when present, prediction, readable risk category,
and whether the result is a block candidate. Raw governance objects, prompts, tool
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
For `pre_llm_call`, `block_returned` is emitted only when capability detection
finds both the native block exit reason and the `blocks` consumer parameter.
It is never inferred from a Hermes version string.

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
- `HERMES_FIREWALL_MAX_PAYLOAD_CHARS` strictly caps each complete text submitted to the SDK, including serialized tool arguments. Default: `8000`.
- `SILMARIL_MODE` selects local handling with `shadow`, `warn`, or `block`.
- `HERMES_FIREWALL_BLOCK_MALICIOUS` is the deprecated legacy mapping; true maps to Block and false maps to Shadow.
- `SILMARIL_LOCAL_EVENT_DIR` directly overrides the incoming evidence directory. It is primarily intended for testing and nonstandard installations.

Configuration precedence is Hermes-native and environment-based: the hook reads
the process environment used by Hermes at call time. There is no local config
file parser, credential service, or fallback that writes secrets into plugin
state.

Every classifier request carries plugin-owned `metadata.silmaril` with
`integration` `hermes-firewall`, `version` `0.6.6`, and `provenance`.
Provenance always includes `schema_version` 1 and `harness` `hermes`. A valid
UUID v4 `SILMARIL_ENDPOINT_ID` adds `endpoint_id`; an invalid value is omitted
with a warning. On macOS, a successful ComputerName lookup can add
`device_name`. Classification continues when either value is absent.
`device_name` is not written into local evidence.

Requests also use the SDK 0.8.2 typed governance fields. Every request sets the
canonical agent to `hermes`. Model/user boundaries use an `agent` resource with
id `hermes`; tool-call and tool-response boundaries use a `tool` resource whose
id is the trusted native `tool_name`. Hermes 0.23 does not provide a trusted MCP
server identity to these hooks, so an encoded tool name is not reinterpreted as
an MCP server. Metadata remains attribution and is not used as a substitute for
the typed resource.

## Enforcement

`pre_llm_call` is the pre-inference veto on Hermes 0.23+. In Block mode a block
candidate returns fixed, content-free text. `pre_tool_call` is the
pre-execution veto. In Block mode a block candidate
returns `{"action": "block", "message": "..."}`. `post_tool_call` is
observe-only and returns `None` in every mode, including Block.
`transform_tool_result` and `transform_llm_output` are the native replacement
hooks: a Block decision replaces the completed tool result or
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

Supported local modes are exactly `shadow`, `warn`, and `block`. By default,
neither mode variable is set. Current classify responses omit mode, so the
plugin falls back to Shadow. Select Warn or Block explicitly when intended.
Warn uses only the existing same-turn warning-context surfaces. Block uses the
native prompt/tool vetoes and transform replacements. Observe-only hooks remain
observe-only in every mode.

While this plugin is enabled on the supported API, assistant streaming is
buffered in every mode, including Shadow and Warn. Benign, Shadow, Warn, and
classifier-error paths return the original final content unchanged; buffering
ensures a Block replacement is selected before any original assistant token is
delivered. Classification errors remain fail open.

The manifest requires Hermes `>=0.23.0`. If the module is imported directly by
an older host that bypasses the manifest gate, it safely falls back to
observation for `pre_llm_call`, registers the old output-transform API without
claiming held streaming, and does not emit prompt-veto `block_returned`
evidence. Older hosts therefore cannot guarantee pre-inference prompt vetoes or
pre-delivery final-output replacement.

Native qualification is pinned to the official Hermes v0.23.0 source commit
`2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19`. The opt-in test executes this
plugin through that checkout's real plugin manager, conversation loop, stream
delivery, and finalizer with loopback-only model traffic:

```bash
HERMES_023_SOURCE=/path/to/hermes-agent-v0.23.0 \
  python -m unittest -v tests.test_hermes_023_native
```

The qualification rejects a different revision, any tracked or untracked
checkout changes, and any imported Hermes consumer module whose origin is
outside that checkout. It clears the inherited environment before importing
Hermes, uses isolated `HOME`, `HERMES_HOME`, and temporary directories, and
allows only loopback model traffic during the cases. This qualification is
separate from the default unit command, which explicitly reports eight skipped
native cases when `HERMES_023_SOURCE` is unset; skipped cases are not a native
qualification result. GitHub CI supplies the pinned source and requires all
eight cases to run.

To enable enforcement at supported boundaries:

```bash
SILMARIL_MODE=block
```

When enabled, block-candidate `pre_tool_call` classifications return the Hermes
veto shape with readable copy:

```text
Silmaril Firewall blocked this tool call: Unsafe agent control attempt. Continue without using the blocked content.
```

Malicious Block decisions use the same fixed shape. For a `control_abuse` or
`prompt_injection` result, prompt and transform outputs are:

```text
Silmaril Firewall blocked this user prompt: Unsafe agent control attempt. Continue without using the blocked content.
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

The default suite requires only the runtime dependency and remains runnable
with the standard library test runner in a clean environment:

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
```

Install the pinned development tools for pytest and focused lint:

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q tests
.venv/bin/ruff check --select E4,E7,E9,F firewall.py local_evidence.py scripts tests
```

Native Hermes qualification has a separate pinned dependency set and source
checkout. Its host-runtime pins mirror the corresponding v0.23.0 upstream
direct pins used by this focused harness:

```bash
HERMES_COMMIT=2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19
HERMES_SOURCE=/tmp/hermes-agent-v0.23.0
git init "$HERMES_SOURCE"
git -C "$HERMES_SOURCE" remote add origin https://github.com/NousResearch/hermes-agent.git
git -C "$HERMES_SOURCE" fetch --depth=1 origin "$HERMES_COMMIT"
git -C "$HERMES_SOURCE" checkout --detach "$HERMES_COMMIT"
python -m venv .venv-native
.venv-native/bin/python -m pip install -r requirements-native.txt
HERMES_023_SOURCE="$HERMES_SOURCE" \
  .venv-native/bin/python -m unittest -v tests.test_hermes_023_native
```

A qualifying run executes exactly eight tests. It makes no paid inference
calls and does not install or configure Hermes in the user's profile.

Additional syntax checks:

```bash
.venv/bin/python -m py_compile firewall.py local_evidence.py __init__.py
.venv/bin/python -m py_compile scripts/open_playground.py tests/test_hermes_023_native.py
```

## Manage

```bash
hermes plugins update hermes-firewall
hermes plugins disable hermes-firewall
hermes plugins remove hermes-firewall
```

## License

This plugin is licensed under Apache-2.0. See `LICENSE` and `NOTICE`.
