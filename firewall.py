"""Fail-open Silmaril Firewall SDK hooks for Hermes.

This plugin classifies Hermes hook payloads with the Silmaril Security SDK.
It defaults to shadow/pass-through mode. SDK errors are logged without raw
payloads and fail open. Optional blocking applies to pre_tool_call and to
Hermes transform hooks that can replace post-execution tool or final LLM output
before downstream use.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Mapping


LOGGER = logging.getLogger("hermes.plugins.firewall")
PLUGIN_NAME = "hermes-firewall"
PLUGIN_VERSION = "0.4.0"
DEFAULT_SDK_TIMEOUT_SECONDS = 2.0
DEFAULT_SDK_MAX_RETRIES = 0
DEFAULT_MAX_PAYLOAD_CHARS = 8000
DEFAULT_MAX_COLLECTION_ITEMS = 50
DELEGATION_TOOL_NAME = "delegate_task"
_SDK_CLIENT: Any | None = None
_SDK_CONFIG: tuple[str, str, float, int] | None = None


def _safe_len(value: Any) -> int:
    try:
        return len(value)  # type: ignore[arg-type]
    except TypeError:
        return 0


def _keys(value: Any) -> str:
    if isinstance(value, Mapping):
        return ",".join(sorted(str(key) for key in value.keys())) or "-"
    return "-"


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if not value:
        return default
    try:
        parsed = float(value)
    except ValueError:
        LOGGER.warning("[%s] invalid %s=%r; using %s", PLUGIN_NAME, name, value, default)
        return default
    return max(0.1, parsed)


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError:
        LOGGER.warning("[%s] invalid %s=%r; using %s", PLUGIN_NAME, name, value, default)
        return default
    return max(128, parsed)


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    LOGGER.warning("[%s] invalid %s=%r; using %s", PLUGIN_NAME, name, value, default)
    return default


def _max_payload_chars() -> int:
    return _int_env("HERMES_FIREWALL_MAX_PAYLOAD_CHARS", DEFAULT_MAX_PAYLOAD_CHARS)


def _json_safe(value: Any, *, depth: int = 0) -> Any:
    if depth > 6:
        return repr(value)

    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        max_chars = _max_payload_chars()
        if len(value) <= max_chars:
            return value
        omitted = len(value) - max_chars
        return f"{value[:max_chars]}...[truncated {omitted} chars]"

    if isinstance(value, bytes):
        return _json_safe(value.decode("utf-8", errors="replace"), depth=depth + 1)

    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        items = list(value.items())
        for key, item_value in items[:DEFAULT_MAX_COLLECTION_ITEMS]:
            safe[str(key)] = _json_safe(item_value, depth=depth + 1)
        if len(items) > DEFAULT_MAX_COLLECTION_ITEMS:
            safe["_truncated_items"] = len(items) - DEFAULT_MAX_COLLECTION_ITEMS
        return safe

    if isinstance(value, (list, tuple, set)):
        values = list(value)
        safe_values = [
            _json_safe(item, depth=depth + 1)
            for item in values[:DEFAULT_MAX_COLLECTION_ITEMS]
        ]
        if len(values) > DEFAULT_MAX_COLLECTION_ITEMS:
            safe_values.append({"_truncated_items": len(values) - DEFAULT_MAX_COLLECTION_ITEMS})
        return safe_values

    return repr(value)


def _sdk_timeout() -> float:
    return _float_env("HERMES_FIREWALL_SDK_TIMEOUT_SECONDS", DEFAULT_SDK_TIMEOUT_SECONDS)


def _sdk_max_retries() -> int:
    value = os.getenv("HERMES_FIREWALL_SDK_MAX_RETRIES")
    if not value:
        return DEFAULT_SDK_MAX_RETRIES
    try:
        parsed = int(value)
    except ValueError:
        LOGGER.warning(
            "[%s] invalid HERMES_FIREWALL_SDK_MAX_RETRIES=%r; using %s",
            PLUGIN_NAME,
            value,
            DEFAULT_SDK_MAX_RETRIES,
        )
        return DEFAULT_SDK_MAX_RETRIES
    return max(0, parsed)


def _block_malicious() -> bool:
    return _bool_env("HERMES_FIREWALL_BLOCK_MALICIOUS", False)


def _sdk_symbols() -> tuple[Any, Any]:
    try:
        from silmaril_security.sdk import Firewall, HookLabel
    except Exception as exc:
        raise RuntimeError(
            "silmaril-security-sdk is not installed or could not be imported"
        ) from exc
    return Firewall, HookLabel


def _firewall_client() -> Any:
    global _SDK_CLIENT, _SDK_CONFIG

    api_key = os.getenv("SILMARIL_API_KEY", "").strip()
    api_url = os.getenv("SILMARIL_API_URL", "").strip()
    if not api_key:
        raise RuntimeError("SILMARIL_API_KEY is not configured")
    if not api_url:
        raise RuntimeError("SILMARIL_API_URL is not configured")

    timeout = _sdk_timeout()
    max_retries = _sdk_max_retries()
    config = (api_key, api_url, timeout, max_retries)
    if _SDK_CLIENT is not None and _SDK_CONFIG == config:
        return _SDK_CLIENT

    Firewall, _ = _sdk_symbols()
    _SDK_CLIENT = Firewall(
        api_key=api_key,
        api_url=api_url,
        timeout=timeout,
        shadow_mode=True,
        max_retries=max_retries,
    )
    _SDK_CONFIG = config
    return _SDK_CLIENT


def _log(event: str, **fields: Any) -> None:
    details = " ".join(f"{key}={value}" for key, value in fields.items())
    LOGGER.info("[%s] %s %s", PLUGIN_NAME, event, details)


def _result_dict(result: Any) -> dict[str, Any]:
    score = getattr(result, "score", None)
    threshold = getattr(result, "threshold", None)
    blocked = None
    if isinstance(score, (int, float)) and isinstance(threshold, (int, float)):
        blocked = score >= threshold
    return {
        "prediction": getattr(result, "prediction", None),
        "score": score,
        "threshold": threshold,
        "blocked": blocked,
        "primary_outcome": getattr(result, "primary_outcome", None),
        "outcome_scores": getattr(result, "outcome_scores", None),
        "detector_scores": getattr(result, "detector_scores", None),
        "detector_counts": getattr(result, "detector_counts", None),
    }


def _text_for_classification(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(_json_safe(value), ensure_ascii=False, sort_keys=True)


def _metadata_value(value: Any) -> Any:
    return None if value in {"", "-"} else value


def _metadata(event: str, fields: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "silmaril": {
            "integration": PLUGIN_NAME,
            "version": PLUGIN_VERSION,
        },
        "hermesHookEvent": event,
        "sessionId": _metadata_value(fields.get("session_id")),
        "taskId": _metadata_value(fields.get("task_id")),
        "toolCallId": _metadata_value(fields.get("tool_call_id")),
        "toolName": _metadata_value(fields.get("tool_name")),
        "model": _metadata_value(fields.get("model")),
        "platform": _metadata_value(fields.get("platform")),
        "childSessionId": _metadata_value(fields.get("child_session_id")),
        "childSubagentId": _metadata_value(fields.get("child_subagent_id")),
        "childRole": _metadata_value(fields.get("child_role")),
        "parentTurnId": _metadata_value(fields.get("parent_turn_id")),
    }


def _classify(
    event: str,
    hook_name: str,
    text: str,
    tool_name: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    if not text or not text.strip():
        _log("classify_skipped", hook_event=event, hook=hook_name, reason="empty_text")
        return None

    try:
        client = _firewall_client()
        _, HookLabel = _sdk_symbols()
        hook = getattr(HookLabel, hook_name)
        result = client.classify(
            text,
            hook=hook,
            tool_name=tool_name,
            metadata=metadata,
            shadow_mode=True,
        )
        result_dict = _result_dict(result)
        LOGGER.info(
            "[%s] sdk_result event=%s hook=%s tool_name=%s tool_call_id=%s prediction=%s risk=%s blocked=%s",
            PLUGIN_NAME,
            event,
            hook.value,
            tool_name or "-",
            (metadata or {}).get("toolCallId") or "-",
            result_dict.get("prediction"),
            _risk_label(result_dict),
            result_dict.get("blocked"),
        )
        return result_dict
    except Exception as exc:
        LOGGER.warning(
            "[%s] SDK classification failed open event=%s hook=%s tool_name=%s error_type=%s",
            PLUGIN_NAME,
            event,
            hook_name,
            tool_name or "-",
            type(exc).__name__,
        )
        LOGGER.debug("[%s] SDK classification traceback", PLUGIN_NAME, exc_info=True)
        return None


def _observe(
    event: str,
    fields: Mapping[str, Any],
    hook_name: str,
    text: str,
    tool_name: str | None = None,
) -> dict[str, Any] | None:
    _log(event, **fields)
    return _classify(
        event,
        hook_name,
        text,
        tool_name=tool_name,
        metadata=_metadata(event, fields),
    )


def _is_malicious(result: Mapping[str, Any] | None) -> bool:
    if result is None:
        return False
    prediction = result.get("prediction")
    if isinstance(prediction, str):
        normalized_prediction = prediction.lower()
        if normalized_prediction == "benign":
            return False
    else:
        normalized_prediction = ""
    score = result.get("score")
    threshold = result.get("threshold")
    if isinstance(score, (int, float)) and isinstance(threshold, (int, float)):
        return score >= threshold
    if normalized_prediction == "malicious":
        return True
    blocked = result.get("blocked")
    return bool(blocked) if isinstance(blocked, bool) else False


def _block_message(result: Mapping[str, Any], subject: str) -> str:
    risk = _risk_label(result)
    return (
        f"Silmaril Firewall blocked this {subject}: {risk}. "
        "Continue without using the blocked content."
    )


def _risk_label(result: Mapping[str, Any]) -> str:
    outcome = result.get("primary_outcome")
    normalized = outcome.strip().lower() if isinstance(outcome, str) else ""
    normalized = normalized.replace("-", "_").replace(" ", "_")
    if not normalized:
        return "Unsafe content" if _is_malicious(result) else "No flagged risk"
    if normalized == "benign":
        return "Unexpected classification conflict" if _is_malicious(result) else "No flagged risk"
    labels = {
        "prompt_injection": "Unsafe agent control attempt",
        "control_abuse": "Unsafe agent control attempt",
        "information_disclosure": "Sensitive information exposure",
        "secret_exposure": "Sensitive information exposure",
        "system_compromise": "Potential system compromise",
        "service_disruption": "Service disruption risk",
        "data_exfiltration": "Sensitive data exfiltration risk",
    }
    label = labels.get(normalized)
    if label is None:
        LOGGER.debug(
            "[%s] unknown primary_outcome=%r; using generic risk label",
            PLUGIN_NAME,
            outcome,
        )
        return "Unsafe content"
    return label


def _surface_label(event: str, fields: Mapping[str, Any], hook_name: str) -> str:
    tool_name = fields.get("tool_name")
    tool_part = f" ({tool_name})" if isinstance(tool_name, str) and tool_name not in {"", "-"} else ""
    if event in {"pre_llm_call"}:
        return "parent or child prompt"
    if event == "pre_tool_call":
        return f"tool call{tool_part}"
    if event in {"post_tool_call", "transform_tool_result"}:
        return f"tool result{tool_part}"
    if event == "transform_llm_output":
        return "final assistant output"
    if event == "subagent_start":
        return "subagent start request"
    if event == "subagent_stop":
        return "subagent final output"
    return hook_name.lower().replace("_", " ")


def _block_output(result: Mapping[str, Any]) -> dict[str, str]:
    return {
        "action": "block",
        "message": _block_message(result, "tool call"),
    }


def _blocked_replacement(
    event: str,
    fields: Mapping[str, Any],
    hook_name: str,
    result: Mapping[str, Any],
) -> str:
    surface = _surface_label(event, fields, hook_name)
    risk = _risk_label(result)
    lines = [
        "Silmaril Firewall blocked unsafe content.",
        "",
        f"Surface: {surface}.",
        f"Reason: {risk}.",
        "Action: The unsafe content was replaced before downstream model consumption.",
        "Next step: Continue without using or repeating the blocked content.",
    ]
    return "\n".join(lines)


def pre_llm_call(
    session_id: str = "",
    user_message: str = "",
    conversation_history: list[Any] | None = None,
    is_first_turn: bool = False,
    model: str = "",
    platform: str = "",
    **kwargs: Any,
) -> None:
    """Observe a user turn before the LLM loop. Return None to pass through."""
    fields = {
        "session_id": session_id or "-",
        "platform": platform or "-",
        "model": model or "-",
        "first_turn": is_first_turn,
        "user_chars": _safe_len(user_message),
        "history_len": _safe_len(conversation_history or []),
    }
    _observe(
        "pre_llm_call",
        fields,
        "USER_INPUT",
        user_message,
    )
    return None


def pre_tool_call(
    tool_name: str = "",
    args: dict[str, Any] | None = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **kwargs: Any,
) -> dict[str, str] | None:
    """Observe a tool call before execution. Return None to allow it.

    Hermes currently exposes child-agent delegation as the delegate_task tool.
    Because this hook scans every tool call, that delegation path is covered
    here before subagent_start's observer-only visibility hook fires.
    """
    fields = {
        "session_id": session_id or "-",
        "task_id": task_id or "-",
        "tool_call_id": tool_call_id or "-",
        "tool_name": tool_name or "-",
        "arg_keys": _keys(args or {}),
    }
    result = _observe(
        "pre_tool_call",
        fields,
        "TOOL_CALL",
        _text_for_classification({"tool_name": tool_name, "args": args or {}}),
        tool_name=tool_name or None,
    )
    if _block_malicious() and _is_malicious(result):
        return _block_output(result)
    return None


def post_tool_call(
    tool_name: str = "",
    args: dict[str, Any] | None = None,
    result: str = "",
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    duration_ms: int | None = None,
    **kwargs: Any,
) -> None:
    """Observe a tool result after execution. Return None to pass through."""
    fields = {
        "session_id": session_id or "-",
        "task_id": task_id or "-",
        "tool_call_id": tool_call_id or "-",
        "tool_name": tool_name or "-",
        "duration_ms": duration_ms if duration_ms is not None else "-",
        "result_chars": _safe_len(result),
    }
    _observe(
        "post_tool_call",
        fields,
        "TOOL_RESPONSE",
        result,
        tool_name=tool_name or None,
    )
    return None


def transform_tool_result(
    tool_name: str = "",
    args: dict[str, Any] | None = None,
    result: str = "",
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    duration_ms: int | None = None,
    **kwargs: Any,
) -> str:
    """Observe a transform hook and return the result or a safe replacement."""
    fields = {
        "session_id": session_id or "-",
        "task_id": task_id or "-",
        "tool_call_id": tool_call_id or "-",
        "tool_name": tool_name or "-",
        "duration_ms": duration_ms if duration_ms is not None else "-",
        "result_chars": _safe_len(result),
    }
    observed = _observe(
        "transform_tool_result",
        fields,
        "TOOL_RESPONSE",
        result,
        tool_name=tool_name or None,
    )
    if _block_malicious() and _is_malicious(observed):
        return _blocked_replacement(
            "transform_tool_result",
            fields,
            "TOOL_RESPONSE",
            observed,
        )
    return result


def transform_llm_output(
    response_text: str = "",
    session_id: str = "",
    task_id: str = "",
    model: str = "",
    platform: str = "",
    **kwargs: Any,
) -> str:
    """Observe final assistant output and return it or a safe replacement."""
    fields = {
        "session_id": session_id or "-",
        "task_id": task_id or "-",
        "model": model or "-",
        "platform": platform or "-",
        "response_chars": _safe_len(response_text),
    }
    observed = _observe(
        "transform_llm_output",
        fields,
        "LLM_OUTPUT",
        response_text,
    )
    if _block_malicious() and _is_malicious(observed):
        return _blocked_replacement(
            "transform_llm_output",
            fields,
            "LLM_OUTPUT",
            observed,
        )
    return response_text


def subagent_start(
    parent_session_id: str = "",
    child_session_id: str = "",
    child_subagent_id: str = "",
    child_role: str = "",
    child_goal: str = "",
    parent_turn_id: str = "",
    **kwargs: Any,
) -> None:
    """Observe subagent launches. Hermes treats this hook as visibility-only."""
    fields = {
        "session_id": parent_session_id or "-",
        "child_session_id": child_session_id or "-",
        "child_subagent_id": child_subagent_id or "-",
        "child_role": child_role or "-",
        "parent_turn_id": parent_turn_id or "-",
        "goal_chars": _safe_len(child_goal),
    }
    _observe(
        "subagent_start",
        fields,
        "USER_INPUT",
        child_goal,
    )
    return None


def subagent_stop(
    parent_session_id: str = "",
    child_session_id: str = "",
    child_subagent_id: str = "",
    child_role: str = "",
    child_summary: str = "",
    child_status: str = "",
    parent_turn_id: str = "",
    **kwargs: Any,
) -> None:
    """Observe subagent completion. Enforcement stays in normal child hooks."""
    fields = {
        "session_id": parent_session_id or "-",
        "child_session_id": child_session_id or "-",
        "child_subagent_id": child_subagent_id or "-",
        "child_role": child_role or "-",
        "child_status": child_status or "-",
        "parent_turn_id": parent_turn_id or "-",
        "summary_chars": _safe_len(child_summary),
    }
    _observe(
        "subagent_stop",
        fields,
        "LLM_OUTPUT",
        child_summary,
    )
    return None


def register(ctx: Any) -> None:
    """Register pass-through firewall hooks with Hermes."""
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("transform_tool_result", transform_tool_result)
    ctx.register_hook("transform_llm_output", transform_llm_output)
    ctx.register_hook("subagent_start", subagent_start)
    ctx.register_hook("subagent_stop", subagent_stop)
    LOGGER.info("[%s] registered pass-through hooks", PLUGIN_NAME)
