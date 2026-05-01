"""Pass-through firewall hooks for Hermes.

This plugin calls a webhook for hook visibility. It fails open: webhook
delivery errors are logged but never block or rewrite Hermes operations.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Mapping
from urllib import error as urllib_error
from urllib import request as urllib_request

try:
    import requests
except Exception:  # pragma: no cover - depends on the Hermes environment.
    requests = None  # type: ignore[assignment]


LOGGER = logging.getLogger("hermes.plugins.firewall")
PLUGIN_NAME = "hermes-firewall"
PLUGIN_VERSION = "0.2.0"
DEFAULT_WEBHOOK_URL = (
    "https://j8sqlvv9pi.execute-api.us-west-2.amazonaws.com/prod/webhook"
)
DEFAULT_WEBHOOK_TIMEOUT_SECONDS = 2.0
DEFAULT_MAX_PAYLOAD_CHARS = 8000
DEFAULT_MAX_COLLECTION_ITEMS = 50


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


def _webhook_url() -> str:
    return os.getenv("HERMES_FIREWALL_WEBHOOK_URL", DEFAULT_WEBHOOK_URL).strip()


def _webhook_timeout() -> float:
    return _float_env("HERMES_FIREWALL_WEBHOOK_TIMEOUT_SECONDS", DEFAULT_WEBHOOK_TIMEOUT_SECONDS)


def _max_payload_chars() -> int:
    return _int_env("HERMES_FIREWALL_WEBHOOK_MAX_PAYLOAD_CHARS", DEFAULT_MAX_PAYLOAD_CHARS)


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


def _webhook_payload(event: str, fields: Mapping[str, Any], data: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "plugin": PLUGIN_NAME,
        "plugin_version": PLUGIN_VERSION,
        "event": event,
        "timestamp": time.time(),
        "fields": _json_safe(fields),
        "data": _json_safe(data),
    }


def _post_with_requests(url: str, payload: dict[str, Any], timeout: float) -> tuple[int, str]:
    response = requests.post(url, json=payload, timeout=timeout)  # type: ignore[union-attr]
    try:
        body = response.json()
    except ValueError:
        body = response.text
    return response.status_code, json.dumps(_json_safe(body), ensure_ascii=False)


def _post_with_urllib(url: str, payload: dict[str, Any], timeout: float) -> tuple[int, str]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib_request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib_request.urlopen(req, timeout=timeout) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            return response.status, response_body
    except urllib_error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        return exc.code, response_body


def _send_webhook(event: str, fields: Mapping[str, Any], data: Mapping[str, Any]) -> None:
    url = _webhook_url()
    if not url:
        LOGGER.info("[%s] webhook disabled event=%s", PLUGIN_NAME, event)
        return

    payload = _webhook_payload(event, fields, data)
    timeout = _webhook_timeout()

    try:
        if requests is not None:
            status_code, response_body = _post_with_requests(url, payload, timeout)
        else:
            status_code, response_body = _post_with_urllib(url, payload, timeout)

        if status_code >= 400:
            LOGGER.warning(
                "[%s] webhook returned error event=%s status=%s body=%s",
                PLUGIN_NAME,
                event,
                status_code,
                _json_safe(response_body),
            )
            return

        LOGGER.info("[%s] webhook delivered event=%s status=%s", PLUGIN_NAME, event, status_code)
    except Exception as exc:
        LOGGER.warning(
            "[%s] webhook delivery failed open event=%s error=%s",
            PLUGIN_NAME,
            event,
            exc,
        )
        LOGGER.debug("[%s] webhook delivery traceback", PLUGIN_NAME, exc_info=True)


def _log(event: str, **fields: Any) -> None:
    details = " ".join(f"{key}={value}" for key, value in fields.items())
    LOGGER.info("[%s] %s %s", PLUGIN_NAME, event, details)


def _observe(event: str, fields: Mapping[str, Any], data: Mapping[str, Any] | None = None) -> None:
    _log(event, **fields)
    _send_webhook(event, fields, data or {})


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
        {
            "user_message": user_message,
            "conversation_history_len": _safe_len(conversation_history or []),
            "kwargs": kwargs,
        },
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
        {
            "args": args or {},
            "kwargs": kwargs,
        },
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
        {
            "args": args or {},
            "result": result,
            "kwargs": kwargs,
        },
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
        {
            "args": args or {},
            "result": result,
            "kwargs": kwargs,
        },
    )
    return result


def register(ctx: Any) -> None:
    """Register pass-through firewall hooks with Hermes."""
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("transform_tool_result", transform_tool_result)
    LOGGER.info("[%s] registered pass-through hooks", PLUGIN_NAME)
