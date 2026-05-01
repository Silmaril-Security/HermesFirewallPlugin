"""Pass-through firewall hooks for Hermes.

This plugin intentionally performs no network calls and does not block or
rewrite any Hermes operation. It only emits concise lifecycle logs.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping


LOGGER = logging.getLogger("hermes.plugins.firewall")
PLUGIN_NAME = "hermes-firewall"


def _safe_len(value: Any) -> int:
    try:
        return len(value)  # type: ignore[arg-type]
    except TypeError:
        return 0


def _keys(value: Any) -> str:
    if isinstance(value, Mapping):
        return ",".join(sorted(str(key) for key in value.keys())) or "-"
    return "-"


def _log(event: str, **fields: Any) -> None:
    details = " ".join(f"{key}={value}" for key, value in fields.items())
    LOGGER.info("[%s] %s %s", PLUGIN_NAME, event, details)


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
    _log(
        "pre_llm_call",
        session_id=session_id or "-",
        platform=platform or "-",
        model=model or "-",
        first_turn=is_first_turn,
        user_chars=_safe_len(user_message),
        history_len=_safe_len(conversation_history or []),
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
    _log(
        "pre_tool_call",
        session_id=session_id or "-",
        task_id=task_id or "-",
        tool_call_id=tool_call_id or "-",
        tool_name=tool_name or "-",
        arg_keys=_keys(args or {}),
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
    _log(
        "post_tool_call",
        session_id=session_id or "-",
        task_id=task_id or "-",
        tool_call_id=tool_call_id or "-",
        tool_name=tool_name or "-",
        duration_ms=duration_ms if duration_ms is not None else "-",
        result_chars=_safe_len(result),
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
    _log(
        "transform_tool_result",
        session_id=session_id or "-",
        task_id=task_id or "-",
        tool_call_id=tool_call_id or "-",
        tool_name=tool_name or "-",
        duration_ms=duration_ms if duration_ms is not None else "-",
        result_chars=_safe_len(result),
    )
    return result


def register(ctx: Any) -> None:
    """Register pass-through firewall hooks with Hermes."""
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("transform_tool_result", transform_tool_result)
    LOGGER.info("[%s] registered pass-through hooks", PLUGIN_NAME)
