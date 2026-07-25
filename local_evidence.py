"""Private, bounded LocalProtectionEventV1 evidence for Hermes hooks.

This module deliberately receives enough hook data to derive opaque
correlations, but serializes only the frozen LocalProtectionEventV1 allowlist.
It never serializes raw prompts, arguments, tool results, or model output.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


LOCAL_PROTECTION_EVENT_SCHEMA_VERSION = 1
PROVENANCE_SCHEMA_VERSION = 1
MAX_LOCAL_PROTECTION_EVENT_BYTES = 16 * 1024
MAX_SUMMARY_LENGTH = 280
DEFAULT_EVENT_DIRECTORY_COMPONENTS = (
    "Library",
    "Application Support",
    "Silmaril",
    "Evidence",
    "incoming",
)

_SAFE_TOOL_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9._:/-]{0,63}$")
_RUNTIME_CHECK_MARKER = re.compile(
    r"\bsilmaril-runtime-check:[A-Za-z0-9-]{16,128}\b"
)
_SENSITIVE_TOOL_NAME = re.compile(
    r"(?:secret|token|credential|password|api[_-]?key|"
    r"sk-[a-z0-9_-]{8,}|akia[0-9a-z]{12,})",
    re.IGNORECASE,
)

_CONSEQUENCE_SUMMARIES = {
    "credential_exposure": "A credential or secret could be exposed.",
    "sensitive_data_exposure": "Sensitive data could be exposed.",
    "code_execution": "The action could lead to unsafe code execution.",
    "destructive_change": (
        "The action could disrupt service or cause a destructive change."
    ),
    "external_communication": (
        "The action could communicate with an external destination."
    ),
    "privilege_change": "The action could change privileges.",
    "unsafe_agent_control": "The action could take unsafe control of an AI agent.",
    "other": "The action could cause an unsafe consequence.",
    "unknown": "No specific harmful consequence was identified by the plugin.",
}


def build_local_protection_event(
    *,
    event: str,
    hook: str,
    mode: str,
    raw_text: str,
    fields: Mapping[str, Any],
    classification: Mapping[str, Any] | None,
    policy_decision: str,
    native_action: str,
    plugin_name: str,
    plugin_version: str,
    occurred_at: datetime | None = None,
) -> dict[str, Any]:
    """Build the frozen LocalProtectionEventV1 JSON shape."""

    observed_at = _iso8601_utc(occurred_at or datetime.now(timezone.utc))
    result = classification or {}
    prediction = _normalize_prediction(result.get("prediction"))
    consequence = _attempted_consequence(result, prediction)
    request_identity = _request_identity(event, fields)
    session_identity = _session_identity(fields)
    request_fingerprint = _request_fingerprint(
        event,
        request_identity,
        raw_text,
    )
    session_fingerprint = _fingerprint("session", session_identity)
    tool_display_name = _safe_tool_display_name(fields.get("tool_name"))

    event_id = _stable_contract_id(
        "protection-event",
        (
            "hermes",
            hook,
            request_fingerprint or "",
            session_fingerprint or "",
            observed_at,
        ),
    )

    local_event: dict[str, Any] = {
        "schemaVersion": LOCAL_PROTECTION_EVENT_SCHEMA_VERSION,
        "id": event_id,
        "occurredAt": observed_at,
        "host": "hermes",
        "hook": hook,
        "mode": mode,
        "attemptedConsequence": consequence,
        "prediction": prediction,
        "policyDecision": policy_decision,
        "nativeAction": native_action,
        "outcome": "not_observed",
        "evidenceTruth": (
            "native_response_returned"
            if native_action in {"block_returned", "content_replaced"}
            else "plugin_reported"
        ),
        "evidenceCompleteness": "partial",
        "provenance": {
            "schemaVersion": PROVENANCE_SCHEMA_VERSION,
            "producer": _bounded_identifier(plugin_name, 128)
            or "hermes-firewall-plugin",
            "producerVersion": _bounded_identifier(plugin_version, 128)
            or "unknown",
            "pluginVersion": _bounded_identifier(plugin_version, 128)
            or "unknown",
            "observedAt": observed_at,
        },
    }

    optional_fields = {
        "requestFingerprint": request_fingerprint,
        "sessionFingerprint": session_fingerprint,
        "toolDisplayName": tool_display_name,
        "riskClass": consequence["category"],
        "modelScore": _unit_interval(result.get("score")),
        "modelThreshold": _unit_interval(result.get("threshold")),
    }
    local_event.update(
        {
            key: value
            for key, value in optional_fields.items()
            if value is not None
        }
    )
    return local_event


def write_local_protection_event(
    event: Mapping[str, Any],
    environment: Mapping[str, str] | None = None,
    *,
    home_directory: str | os.PathLike[str] | None = None,
) -> Path:
    """Atomically write one private event file to the local incoming spool."""

    directory = resolve_local_event_directory(
        environment,
        home_directory=home_directory,
    )
    serialized = (
        json.dumps(
            event,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(serialized) > MAX_LOCAL_PROTECTION_EVENT_BYTES:
        raise ValueError("Local protection event exceeds the bounded event size")

    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory_stat = directory.lstat()
    if not stat.S_ISDIR(directory_stat.st_mode) or directory.is_symlink():
        raise OSError("Local evidence directory must be a real directory")
    directory.chmod(0o700)

    event_digest = hashlib.sha256(str(event.get("id", "")).encode("utf-8")).hexdigest()
    destination = directory / f"event-{event_digest}.json"
    temporary = directory / (
        f".event-{event_digest}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    descriptor: int | None = None

    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        destination.chmod(0o600)
        directory_descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        return destination
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except Exception:
            pass
        raise


def resolve_local_event_directory(
    environment: Mapping[str, str] | None = None,
    *,
    home_directory: str | os.PathLike[str] | None = None,
) -> Path:
    """Resolve the direct override or the shared macOS Application Support path."""

    active_environment = os.environ if environment is None else environment
    configured = active_environment.get("SILMARIL_LOCAL_EVENT_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()

    if home_directory is not None:
        home = Path(home_directory)
    else:
        configured_home = active_environment.get("HOME", "").strip()
        home = Path(configured_home).expanduser() if configured_home else Path.home()
    return home.joinpath(*DEFAULT_EVENT_DIRECTORY_COMPONENTS)


def _iso8601_utc(value: datetime) -> str:
    aware = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return (
        aware.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _normalize_prediction(value: Any) -> str:
    if value == "MALICIOUS":
        return "malicious"
    if value == "BENIGN":
        return "benign"
    if value is None:
        return "unavailable"
    return "unknown"


def _attempted_consequence(
    result: Mapping[str, Any],
    prediction: str,
) -> dict[str, str]:
    raw_outcome = result.get("primary_outcome")
    normalized = (
        raw_outcome.strip().lower().replace("-", "_").replace(" ", "_")
        if isinstance(raw_outcome, str)
        else ""
    )
    categories = {
        "secret_exposure": "credential_exposure",
        "information_disclosure": "sensitive_data_exposure",
        "data_exfiltration": "sensitive_data_exposure",
        "system_compromise": "code_execution",
        "service_disruption": "destructive_change",
        "external_communication": "external_communication",
        "privilege_change": "privilege_change",
        "control_abuse": "unsafe_agent_control",
        "prompt_injection": "unsafe_agent_control",
    }
    if normalized == "benign":
        category = "unknown"
    elif normalized in categories:
        category = categories[normalized]
    elif prediction == "malicious":
        category = "other"
    else:
        category = "unknown"
    return {
        "category": category,
        "summary": _bounded_summary(_CONSEQUENCE_SUMMARIES[category]),
    }


def _request_identity(event: str, fields: Mapping[str, Any]) -> str | None:
    for name in (
        "tool_call_id",
        "task_id",
        "parent_turn_id",
        "child_subagent_id",
    ):
        value = _present_string(fields.get(name))
        if value:
            return f"{event}:{name}:{value}"
    return None


def _session_identity(fields: Mapping[str, Any]) -> str | None:
    return _present_string(fields.get("child_session_id")) or _present_string(
        fields.get("session_id")
    )


def _request_fingerprint(
    event: str,
    request_identity: str | None,
    raw_text: str,
) -> str:
    runtime_check = _RUNTIME_CHECK_MARKER.search(raw_text)
    if runtime_check:
        return hashlib.sha256(
            runtime_check.group(0).encode("utf-8")
        ).hexdigest()
    content_digest = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    return _fingerprint(
        "request",
        f"{event}|{request_identity or ''}|sha256:{content_digest}",
    ) or ""


def _fingerprint(namespace: str, value: str | None) -> str | None:
    if not value:
        return None
    digest = hashlib.sha256(_frame((namespace, value))).hexdigest()
    return f"sha256:{digest}"


def _stable_contract_id(namespace: str, components: tuple[str, ...]) -> str:
    digest = hashlib.sha256(_frame((namespace, *components))).hexdigest()
    return f"{namespace}:{digest}"


def _frame(components: tuple[str, ...]) -> bytes:
    return "|".join(
        f"{len(component.encode('utf-8'))}:{component}"
        for component in components
    ).encode("utf-8")


def _unit_interval(value: Any) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        return None
    if not math.isfinite(value) or not 0 <= value <= 1:
        return None
    return value


def _safe_tool_display_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = _bounded_identifier(value, 256)
    if not normalized:
        return None
    if not _SAFE_TOOL_NAME.fullmatch(normalized):
        return "redacted_tool"
    if _SENSITIVE_TOOL_NAME.search(normalized):
        return "redacted_tool"
    return normalized


def _bounded_summary(value: str) -> str:
    return _normalize_whitespace(value)[:MAX_SUMMARY_LENGTH]


def _bounded_identifier(value: Any, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = _normalize_whitespace(value)
    return normalized[:maximum] or None


def _normalize_whitespace(value: str) -> str:
    return " ".join(
        re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", value).split()
    )


def _present_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return None if not stripped or stripped == "-" else stripped
