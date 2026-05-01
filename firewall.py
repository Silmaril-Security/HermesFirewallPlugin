"""Pass-through Silmaril Firewall SDK hooks for Hermes.

This plugin classifies Hermes hook payloads with the Silmaril Security SDK.
It fails open: SDK errors are logged but never block or rewrite Hermes
operations.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Mapping


LOGGER = logging.getLogger("hermes.plugins.firewall")
PLUGIN_NAME = "hermes-firewall"
PLUGIN_VERSION = "0.3.0"
DEFAULT_SDK_TIMEOUT_SECONDS = 2.0
DEFAULT_SDK_THRESHOLD = 0.5
DEFAULT_SDK_MAX_RETRIES = 0
DEFAULT_MAX_PAYLOAD_CHARS = 8000
DEFAULT_MAX_COLLECTION_ITEMS = 50
_SDK_CLIENT: Any | None = None
_SDK_CONFIG: tuple[str, str, float, float, int] | None = None


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


def _sdk_threshold() -> float:
    value = _float_env("HERMES_FIREWALL_SDK_THRESHOLD", DEFAULT_SDK_THRESHOLD)
    if value > 1.0:
        LOGGER.warning(
            "[%s] HERMES_FIREWALL_SDK_THRESHOLD=%s is above 1.0; using 1.0",
            PLUGIN_NAME,
            value,
        )
        return 1.0
    return value


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
    threshold = _sdk_threshold()
    max_retries = _sdk_max_retries()
    config = (api_key, api_url, threshold, timeout, max_retries)
    if _SDK_CLIENT is not None and _SDK_CONFIG == config:
        return _SDK_CLIENT

    Firewall, _ = _sdk_symbols()
    _SDK_CLIENT = Firewall(
        api_key=api_key,
        api_url=api_url,
        threshold=threshold,
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
    }


def _text_for_classification(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(_json_safe(value), ensure_ascii=False, sort_keys=True)


def _classify(event: str, hook_name: str, text: str, tool_name: str | None = None) -> None:
    try:
        client = _firewall_client()
        _, HookLabel = _sdk_symbols()
        hook = getattr(HookLabel, hook_name)
        result = client.classify(text, hook=hook, tool_name=tool_name, shadow_mode=True)
        LOGGER.info(
            "[%s] sdk_result event=%s hook=%s tool_name=%s output=%s",
            PLUGIN_NAME,
            event,
            hook.value,
            tool_name or "-",
            json.dumps(_result_dict(result), ensure_ascii=False, sort_keys=True),
        )
    except Exception as exc:
        LOGGER.warning(
            "[%s] SDK classification failed open event=%s hook=%s tool_name=%s error=%s",
            PLUGIN_NAME,
            event,
            hook_name,
            tool_name or "-",
            exc,
        )
        LOGGER.debug("[%s] SDK classification traceback", PLUGIN_NAME, exc_info=True)


def _observe(
    event: str,
    fields: Mapping[str, Any],
    hook_name: str,
    text: str,
    tool_name: str | None = None,
) -> None:
    _log(event, **fields)
    _classify(event, hook_name, text, tool_name=tool_name)


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
) -> None:
    """Observe a tool call before execution. Return None to allow it."""
    fields = {
        "session_id": session_id or "-",
        "task_id": task_id or "-",
        "tool_call_id": tool_call_id or "-",
        "tool_name": tool_name or "-",
        "arg_keys": _keys(args or {}),
    }
    _observe(
        "pre_tool_call",
        fields,
        "TOOL_CALL",
        _text_for_classification({"tool_name": tool_name, "args": args or {}}),
        tool_name=tool_name or None,
    )
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
    """Observe a transform hook and return the original result unchanged."""
    fields = {
        "session_id": session_id or "-",
        "task_id": task_id or "-",
        "tool_call_id": tool_call_id or "-",
        "tool_name": tool_name or "-",
        "duration_ms": duration_ms if duration_ms is not None else "-",
        "result_chars": _safe_len(result),
    }
    _observe(
        "transform_tool_result",
        fields,
        "TOOL_RESPONSE",
        result,
        tool_name=tool_name or None,
    )
    return result


def register(ctx: Any) -> None:
    """Register pass-through firewall hooks with Hermes."""
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("transform_tool_result", transform_tool_result)
    LOGGER.info("[%s] registered pass-through hooks", PLUGIN_NAME)
