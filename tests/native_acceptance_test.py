from __future__ import annotations

import functools
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from scripts import native_acceptance as native

LIVE_SETTINGS = {
    "CUSTOMER_NATIVE_API_URL": "https://cascade.test/classify",
    "CUSTOMER_NATIVE_API_KEY": "live-key",
}
ALLOW_TOOL_OUTPUT = json.dumps(
    {"resolved_path": f"/workspace/{native.ALLOW.effect_file}"}
)


def _headers(api_key: str = native.CLASSIFIER_KEY) -> Message:
    headers = Message()
    headers["x-api-key"] = api_key
    return headers


def _classified(hook: str, decision: str, **extra: Any) -> dict[str, Any]:
    return {
        "hook": hook,
        "decision": decision,
        "durationMs": 5,
        "authenticated": True,
        **extra,
    }


def _upstream(hook: str, decision: str, **extra: Any) -> dict[str, Any]:
    return _classified(hook, decision, upstream={"prediction": "BENIGN"}, **extra)


def _turns(scenario: native.Scenario, tool_output: str) -> list[dict[str, Any]]:
    user = {"role": "user", "content": scenario.prompt}
    tools = [{"type": "function", "function": {"name": scenario.tool_name}}]
    return [
        {"tools": tools, "messages": [user]},
        {"tools": tools, "messages": [user, {"role": "tool", "content": tool_output}]},
    ]


def _evaluate(
    scenario: native.Scenario,
    tool_output: str,
    classifier_requests: list[dict[str, Any]],
    *,
    effect_content: str | None = None,
    poison: str = native.LOOPBACK_POISON,
    host_exit_code: int = 0,
) -> dict[str, Any]:
    return native.evaluate(
        scenario,
        host_exit_code=host_exit_code,
        effect_content=effect_content,
        chat_requests=_turns(scenario, tool_output),
        classifier_requests=classifier_requests,
        poison=poison,
    )


def _evidence(*statuses: tuple[str, str]) -> native.Evidence:
    evidence = native.Evidence(classifier="loopback")
    evidence.plugin.update(artifact_sha256="a" * 64, installed_bytes_match=True)
    evidence.host["version"] = "0.23.0"
    evidence.scenarios.extend(
        {"id": name, "status": status} for name, status in statuses
    )
    return evidence


def test_chat_completion_streams_tool_calls_when_requested() -> None:
    message = native.scripted_reply(
        native.LOOPBACK_SCENARIOS,
        {"tools": [{}], "messages": [{"role": "user", "content": native.ALLOW.prompt}]},
    )

    reply = native.chat_completion({"stream": True}, message)

    events = [
        json.loads(line.removeprefix("data: "))
        for line in reply.body.decode().split("\n\n")
        if line.startswith("data: {")
    ]
    assert reply.content_type == "text/event-stream"
    assert events[0]["choices"][0]["delta"]["tool_calls"][0]["id"] == "call_allow"
    assert events[1]["choices"][0]["finish_reason"] == "tool_calls"
    assert reply.body.endswith(b"data: [DONE]\n\n")


def test_chat_completion_returns_json_without_streaming() -> None:
    reply = native.chat_completion(
        {}, {"role": "assistant", "content": native.FINAL_REPLY}
    )

    choice = json.loads(reply.body)["choices"][0]
    assert choice["message"]["content"] == native.FINAL_REPLY
    assert choice["finish_reason"] == "stop"


def test_scripted_reply_follows_the_turn() -> None:
    user = {"role": "user", "content": native.TOOL_RESPONSE_BLOCK.prompt}
    system = {"role": "system", "content": native.ALLOW.prompt}

    first = native.scripted_reply(
        native.LOOPBACK_SCENARIOS, {"tools": [{}], "messages": [system, user]}
    )
    final = native.scripted_reply(
        native.LOOPBACK_SCENARIOS,
        {"tools": [{}], "messages": [user, {"role": "tool", "content": "{}"}]},
    )
    auxiliary = native.scripted_reply(native.LOOPBACK_SCENARIOS, {"messages": [user]})

    assert first["tool_calls"][0]["function"] == {
        "name": "read_file",
        "arguments": json.dumps({"path": native.POISON_FILE}),
    }
    assert final["content"] == native.FINAL_REPLY
    assert auxiliary["content"] == native.AUXILIARY_REPLY


def test_scripted_provider_records_only_chat_requests() -> None:
    requests: list[dict[str, Any]] = []
    respond = native.scripted_provider(
        requests, lambda _request: {"role": "assistant", "content": native.FINAL_REPLY}
    )

    assert respond(_headers(), {"name": native.MODEL_NAME}).status == 404
    assert respond(_headers(), {"messages": []}).status == 200
    assert requests == [{"messages": []}]


@pytest.mark.parametrize(
    ("hook", "text", "prediction"),
    [
        ("tool_call", native.PRE_TOOL_BLOCK_MARKER, "MALICIOUS"),
        ("tool_response", native.LOOPBACK_POISON, "MALICIOUS"),
        ("tool_response", native.PRE_TOOL_BLOCK_MARKER, "BENIGN"),
        ("user_input", native.LOOPBACK_POISON, "BENIGN"),
        ("tool_call", native.RELEASE_SUMMARY, "BENIGN"),
    ],
)
def test_loopback_classification_blocks_only_marked_hooks(
    hook: str, text: str, prediction: str
) -> None:
    assert (
        native.loopback_classification({"hook": hook, "text": text})["prediction"]
        == prediction
    )


def test_recording_classifier_records_loopback_decisions_without_text() -> None:
    records: list[dict[str, Any]] = []
    respond = native.recording_classifier(
        records, native.loopback_classification, threading.Condition(), live=False
    )

    reply = respond(
        _headers(),
        {
            "hook": "tool_call",
            "tool_name": "write_file",
            "text": native.PRE_TOOL_BLOCK_MARKER,
        },
    )
    respond(
        _headers("another-key"), {"hook": "user_input", "text": native.RELEASE_SUMMARY}
    )

    assert json.loads(reply.body)["prediction"] == "MALICIOUS"
    assert [(record["decision"], record["authenticated"]) for record in records] == [
        ("block", True),
        ("allow", False),
    ]
    assert set(records[0]) == {
        "hook",
        "tool_name",
        "authenticated",
        "decision",
        "durationMs",
    }


def test_live_classifier_proxies_with_the_customer_key_and_records_upstream() -> None:
    sent: list[tuple[str, bytes, dict[str, str]]] = []
    verdict = {
        "prediction": "BENIGN",
        "governance": {"action": "block"},
        "mode": "block",
    }

    def fetch(url: str, body: bytes, headers: dict[str, str]) -> bytes:
        sent.append((url, body, headers))
        return json.dumps(verdict).encode()

    records: list[dict[str, Any]] = []
    payload = {
        "hook": "tool_response",
        "tool_name": "read_file",
        "text": native.LIVE_ATTACK,
    }
    respond = native.recording_classifier(
        records,
        functools.partial(
            native.live_classification, fetch, "https://cascade.test", "live-key"
        ),
        threading.Condition(),
        live=True,
    )

    reply = respond(_headers(), payload)

    assert sent == [
        (
            "https://cascade.test",
            json.dumps(payload).encode(),
            {"content-type": "application/json", "x-api-key": "live-key"},
        )
    ]
    assert json.loads(reply.body) == verdict
    assert records[0]["decision"] == "block"
    assert records[0]["upstream"] == {
        "prediction": "BENIGN",
        "mode": "block",
        "action": "block",
    }
    assert "live-key" not in json.dumps(records)


@pytest.mark.parametrize(
    "failure",
    [TimeoutError("timed out"), ConnectionRefusedError("refused")],
)
def test_live_classifier_reports_transport_failures_as_bad_gateway(
    failure: OSError,
) -> None:
    def fetch(_url: str, _body: bytes, _headers: dict[str, str]) -> bytes:
        raise failure

    records: list[dict[str, Any]] = []
    respond = native.recording_classifier(
        records,
        functools.partial(
            native.live_classification, fetch, "https://cascade.test", "live-key"
        ),
        threading.Condition(),
        live=True,
    )

    assert respond(_headers(), {"hook": "user_input", "text": "hello"}).status == 502
    assert records[0]["decision"] == "error"
    assert "upstream" not in records[0]


def test_live_classifier_rejects_responses_without_a_prediction() -> None:
    records: list[dict[str, Any]] = []
    respond = native.recording_classifier(
        records,
        functools.partial(
            native.live_classification,
            lambda _url, _body, _headers: b'{"message": "Forbidden"}',
            "https://cascade.test",
            "live-key",
        ),
        threading.Condition(),
        live=True,
    )

    assert respond(_headers(), {"hook": "user_input", "text": "hello"}).status == 502
    assert records[0]["decision"] == "error"


def test_pending_classifier_requests_settle_before_evaluation() -> None:
    entered = threading.Event()
    release = threading.Event()

    def classify(payload: dict[str, Any]) -> dict[str, Any]:
        entered.set()
        release.wait()
        return native.loopback_classification(payload)

    records: list[dict[str, Any]] = []
    settled = threading.Condition()
    respond = native.recording_classifier(records, classify, settled, live=False)

    with ThreadPoolExecutor(max_workers=1) as pool:
        reply = pool.submit(
            respond, _headers(), {"hook": "tool_call", "text": native.RELEASE_SUMMARY}
        )
        entered.wait()
        assert "decision" not in records[0]
        with pytest.raises(TimeoutError):
            native.await_settled(records, settled, timeout=0.01)
        release.set()
        native.await_settled(records, settled)

    assert reply.result().status == 200
    assert records[0]["decision"] == "allow"
    assert isinstance(records[0]["durationMs"], int)


def test_live_settings_return_the_endpoint_and_key() -> None:
    assert native.live_settings(LIVE_SETTINGS) == (
        "https://cascade.test/classify",
        "live-key",
    )


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"CUSTOMER_NATIVE_API_URL": "http://cascade.test/classify"}, "https"),
        ({"CUSTOMER_NATIVE_API_URL": ""}, "https"),
        ({"CUSTOMER_NATIVE_API_KEY": ""}, "CUSTOMER_NATIVE_API_KEY"),
    ],
)
def test_live_settings_reject_insecure_or_missing_values(
    override: dict[str, str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        native.live_settings({**LIVE_SETTINGS, **override})
    with pytest.raises(ValueError, match=message):
        native.live_settings(
            {key: value for key, value in LIVE_SETTINGS.items() if key not in override}
        )


def test_missing_live_settings_still_write_a_failed_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    receipt_path = tmp_path / "native-acceptance" / "live-receipt.json"
    monkeypatch.setenv("GITHUB_SHA", "f" * 40)
    monkeypatch.setenv("NATIVE_ACCEPTANCE_RECEIPT", str(receipt_path))
    monkeypatch.setenv("CUSTOMER_NATIVE_CLASSIFIER", "live")
    monkeypatch.delenv("CUSTOMER_NATIVE_API_URL", raising=False)
    monkeypatch.delenv("CUSTOMER_NATIVE_API_KEY", raising=False)

    with pytest.raises(ValueError, match="CUSTOMER_NATIVE_API_URL"):
        native.main()

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert (receipt["status"], receipt["classifier"]) == ("FAIL", "live")
    assert (receipt["error"], receipt["scenarios"]) == ("ValueError", [])


@pytest.mark.parametrize(
    ("scenario", "requests", "blocker"),
    [
        (native.ALLOW, [_classified("tool_call", "block")], None),
        (native.ALLOW, [_classified("user_input", "error")], "classifier_unavailable"),
        (
            native.TOOL_RESPONSE_BLOCK,
            [_upstream("tool_response", "allow", durationMs=native.PLUGIN_DEADLINE_MS)],
            "classifier_exceeded_plugin_deadline",
        ),
        (
            native.ALLOW,
            [_classified("tool_call", "error", durationMs=native.PLUGIN_DEADLINE_MS)],
            "classifier_exceeded_plugin_deadline",
        ),
        (
            native.ALLOW,
            [_upstream("tool_response", "block")],
            "classifier_flagged_benign_control",
        ),
        (
            native.TOOL_RESPONSE_BLOCK,
            [_upstream("tool_call", "block")],
            "classifier_flagged_benign_control",
        ),
        (
            native.TOOL_RESPONSE_BLOCK,
            [_upstream("tool_call", "allow"), _upstream("tool_response", "allow")],
            "classifier_did_not_flag_attack",
        ),
        (
            native.TOOL_RESPONSE_BLOCK,
            [_upstream("tool_response", "block"), _upstream("tool_response", "allow")],
            None,
        ),
    ],
)
def test_live_blocker_attributes_classifier_caused_failures(
    scenario: native.Scenario, requests: list[dict[str, Any]], blocker: str | None
) -> None:
    assert native.live_blocker(scenario.id, requests) == blocker


def test_allow_passes_when_the_effect_exists_and_output_reaches_the_model() -> None:
    result = _evaluate(
        native.ALLOW,
        ALLOW_TOOL_OUTPUT,
        [_classified("tool_call", "allow"), _classified("tool_response", "allow")],
        effect_content=native.RELEASE_SUMMARY,
    )

    assert (result["status"], result["effect_present"]) == ("PASS", True)
    assert all(result["checks"].values())


@pytest.mark.parametrize("effect_content", ["", native.PRE_TOOL_BLOCK_MARKER])
def test_allow_fails_when_the_effect_file_holds_other_content(
    effect_content: str,
) -> None:
    result = _evaluate(
        native.ALLOW,
        ALLOW_TOOL_OUTPUT,
        [_classified("tool_call", "allow"), _classified("tool_response", "allow")],
        effect_content=effect_content,
    )

    assert (result["status"], result["effect_present"]) == ("FAIL", True)
    assert result["checks"]["effect_file_holds_requested_content"] is False


def test_live_allow_is_blocked_when_the_classifier_outlives_the_plugin_deadline() -> (
    None
):
    result = _evaluate(
        native.ALLOW,
        ALLOW_TOOL_OUTPUT,
        [
            _upstream("tool_call", "allow", durationMs=native.PLUGIN_DEADLINE_MS),
            _upstream("tool_response", "allow"),
        ],
        effect_content=native.RELEASE_SUMMARY,
    )

    assert (result["status"], result["blocker"]) == (
        "BLOCKED",
        "classifier_exceeded_plugin_deadline",
    )
    assert result["checks"]["classifier_answered_within_plugin_deadline"] is False


def test_live_pass_does_not_depend_on_the_upstream_mode() -> None:
    records: list[dict[str, Any]] = []
    respond = native.recording_classifier(
        records,
        lambda _payload: {
            "prediction": "MALICIOUS",
            "mode": None,
            "governance": {"action": "allow"},
        },
        threading.Condition(),
        live=True,
    )
    respond(_headers(), {"hook": "tool_response", "text": native.LIVE_ATTACK})

    result = _evaluate(
        native.TOOL_RESPONSE_BLOCK,
        f"{native.TOOL_RESULT_REPLACEMENT} Unsafe agent control attempt.",
        records,
        poison=native.LIVE_ATTACK,
    )

    assert records[0]["upstream"] == {
        "prediction": "MALICIOUS",
        "mode": None,
        "action": "allow",
    }
    assert result["status"] == "PASS"
    assert "blocker" not in result


def test_host_crash_fails_even_when_the_live_classifier_was_slow() -> None:
    result = _evaluate(
        native.TOOL_RESPONSE_BLOCK,
        json.dumps({"content": native.LIVE_ATTACK}),
        [_upstream("tool_response", "allow", durationMs=native.PLUGIN_DEADLINE_MS)],
        poison=native.LIVE_ATTACK,
        host_exit_code=1,
    )

    assert result["status"] == "FAIL"
    assert "blocker" not in result
    assert result["checks"]["host_completed_turn"] is False


def test_allow_fails_when_the_tool_was_denied() -> None:
    result = _evaluate(
        native.ALLOW,
        f"{native.TOOL_CALL_DENIAL} Unsafe content.",
        [_classified("tool_call", "block")],
    )

    assert (result["status"], result["effect_present"]) == ("FAIL", False)
    assert result["checks"]["effect_file_holds_requested_content"] is False
    assert result["checks"]["tool_output_reached_model"] is False


def test_pre_tool_block_passes_only_when_the_effect_is_absent() -> None:
    denial = f"{native.TOOL_CALL_DENIAL} Unsafe agent control attempt."
    decisions = [
        _classified("tool_call", "block"),
        _classified("tool_response", "allow"),
    ]

    blocked = _evaluate(native.PRE_TOOL_BLOCK, denial, decisions)
    leaked = _evaluate(
        native.PRE_TOOL_BLOCK,
        denial,
        decisions,
        effect_content=native.PRE_TOOL_BLOCK_MARKER,
    )

    assert (blocked["status"], blocked["effect_present"]) == ("PASS", False)
    assert (leaked["status"], leaked["checks"]["effect_file_absent"]) == ("FAIL", False)


def test_tool_response_block_passes_when_the_replacement_hides_the_poison() -> None:
    result = _evaluate(
        native.TOOL_RESPONSE_BLOCK,
        f"{native.TOOL_RESULT_REPLACEMENT} Unsafe agent control attempt.",
        [_classified("tool_response", "block"), _classified("tool_response", "allow")],
    )

    assert result["status"] == "PASS"
    assert "effect_present" not in result


def test_tool_response_block_fails_when_the_poison_reaches_the_model() -> None:
    result = _evaluate(
        native.TOOL_RESPONSE_BLOCK,
        json.dumps({"content": native.LOOPBACK_POISON}),
        [_classified("tool_response", "allow")],
    )

    assert result["status"] == "FAIL"
    assert result["checks"]["poison_absent_from_model_requests"] is False


def test_live_classifier_miss_is_blocked_with_a_named_blocker() -> None:
    result = _evaluate(
        native.TOOL_RESPONSE_BLOCK,
        json.dumps({"content": native.LIVE_ATTACK}),
        [_upstream("tool_response", "allow")],
        poison=native.LIVE_ATTACK,
    )

    assert (result["status"], result["blocker"]) == (
        "BLOCKED",
        "classifier_did_not_flag_attack",
    )


def test_unauthenticated_classifier_requests_fail_the_scenario() -> None:
    result = _evaluate(
        native.ALLOW,
        ALLOW_TOOL_OUTPUT,
        [
            _classified("tool_call", "allow", authenticated=False),
            _classified("tool_response", "allow"),
        ],
        effect_content=native.RELEASE_SUMMARY,
    )

    assert result["status"] == "FAIL"
    assert result["checks"]["classifier_reached_through_sdk"] is False


@pytest.mark.parametrize(
    ("statuses", "error", "expected"),
    [
        (("PASS", "PASS", "PASS"), None, "PASS"),
        (("PASS", "BLOCKED", "PASS"), None, "BLOCKED"),
        (("PASS", "BLOCKED", "FAIL"), None, "FAIL"),
        (("PASS", "PASS"), None, "FAIL"),
        (("PASS", "PASS", "PASS"), "CalledProcessError", "FAIL"),
    ],
)
def test_receipt_status_requires_every_expected_scenario(
    statuses: tuple[str, ...], error: str | None, expected: str
) -> None:
    evidence = _evidence(*zip((s.id for s in native.LOOPBACK_SCENARIOS), statuses))
    evidence.error = error

    receipt = native.build_receipt(evidence, native.LOOPBACK_SCENARIOS, "f" * 40)

    assert receipt["status"] == expected
    assert receipt.get("error") == error


def test_receipt_fails_when_installed_bytes_differ() -> None:
    evidence = _evidence(*((s.id, "PASS") for s in native.LOOPBACK_SCENARIOS))
    evidence.plugin["installed_bytes_match"] = False

    assert native.overall_status(evidence, native.LOOPBACK_SCENARIOS) == "FAIL"


def test_receipt_carries_the_central_contract_fields() -> None:
    evidence = _evidence(*((s.id, "PASS") for s in native.LIVE_SCENARIOS))
    evidence.classifier = "live"

    receipt = native.build_receipt(evidence, native.LIVE_SCENARIOS, "f" * 40)

    assert receipt["schema"] == "silmaril.native-acceptance.v1"
    assert (receipt["status"], receipt["source_sha"]) == ("PASS", "f" * 40)
    assert receipt["classifier"] == "live"
    assert receipt["plugin"]["name"] == "hermes-firewall"
    assert receipt["host"] == {"name": "hermes", "version": "0.23.0"}
    assert "pre-tool-block scenario" in receipt["exclusions"]
    assert "real classifier APIs" not in receipt["exclusions"]


def test_pack_artifact_is_deterministic_and_content_addressed(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    (repository / "scripts").mkdir(parents=True)
    (repository / "plugin.yaml").write_text("name: hermes-firewall\n", encoding="utf-8")
    (repository / "scripts" / "tool.py").write_text("VALUE = 1\n", encoding="utf-8")
    members = ["plugin.yaml", "scripts/tool.py"]

    first = native.pack_artifact(repository, members, tmp_path / "first.tar")
    (repository / "plugin.yaml").touch()
    second = native.pack_artifact(repository, members, tmp_path / "second.tar")
    (repository / "scripts" / "tool.py").write_text("VALUE = 2\n", encoding="utf-8")
    changed = native.pack_artifact(repository, members, tmp_path / "changed.tar")

    assert first == second
    assert changed != first
    assert len(first) == 64


def test_file_digests_ignore_git_metadata(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_plugin.py").write_text("", encoding="utf-8")

    assert list(native.file_digests(tmp_path)) == ["tests/test_plugin.py"]


def test_installed_bytes_match_allows_only_host_example_copies() -> None:
    artifact = {"firewall.py": "1", ".env.example": "2", "scripts/tool.py.example": "3"}

    assert native.installed_bytes_match(artifact, {**artifact, ".env": "2"})
    assert native.installed_bytes_match(artifact, artifact)
    assert not native.installed_bytes_match(artifact, {**artifact, ".env": "9"})
    assert not native.installed_bytes_match(
        artifact, {**artifact, ".env": "2", "extra.py": "4"}
    )
    assert not native.installed_bytes_match(
        artifact, {**artifact, ".env": "2", "firewall.py": "tampered"}
    )


def test_read_effect_distinguishes_absent_files_from_scenarios_without_effects(
    tmp_path: Path,
) -> None:
    assert native.read_effect(tmp_path, native.ALLOW) is None
    (tmp_path / str(native.ALLOW.effect_file)).write_text("", encoding="utf-8")
    (tmp_path / "None").write_text(native.LOOPBACK_POISON, encoding="utf-8")

    assert native.read_effect(tmp_path, native.ALLOW) == ""
    assert native.read_effect(tmp_path, native.TOOL_RESPONSE_BLOCK) is None


def test_run_contained_reports_output_and_failures() -> None:
    succeeded = native.run_contained(
        [sys.executable, "-c", "print('ready')"], stdout=subprocess.PIPE
    )

    assert (succeeded.returncode, succeeded.stdout) == (0, "ready\n")
    assert (
        native.run_contained([sys.executable, "-c", "raise SystemExit(4)"]).returncode
        == 4
    )
    with pytest.raises(subprocess.CalledProcessError):
        native.run_contained([sys.executable, "-c", "raise SystemExit(4)"], check=True)


def test_run_contained_stops_the_whole_process_tree_on_timeout(tmp_path: Path) -> None:
    descendant_pid = tmp_path / "descendant.pid"
    spawn_descendant = (
        "import pathlib, subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid))\n"
        "time.sleep(60)\n"
    )

    with pytest.raises(subprocess.TimeoutExpired):
        native.run_contained(
            [sys.executable, "-c", spawn_descendant, str(descendant_pid)], timeout=3
        )

    pid = int(descendant_pid.read_text())
    deadline = time.monotonic() + 10
    while _is_running(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _is_running(pid)


def _is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True
