from __future__ import annotations

import importlib.metadata
import json
import os
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from email.message import Message
from typing import Any
from unittest import mock

import requests
from silmaril_security.sdk import (
    BlockResult,
    Firewall,
    FirewallBlockedException,
    GovernanceDecision,
    HookLabel,
)

import firewall
from scripts import native_acceptance as native


GOVERNANCE = {
    "action": "block",
    "policy_version": "synthetic-policy-v1",
    "rule_id": "synthetic-rule",
}
GOVERNANCE_BLOCK_VERSION_2 = {
    "results": [
        {
            "action": "block",
            "source": "governance",
            "governance": GOVERNANCE,
            "model_id": "synthetic-model",
        }
    ]
}
GOVERNANCE_BLOCK_VERSION_1 = {
    "prediction": "BENIGN",
    "score": 0.01,
    "threshold": 0.5,
    "mode": "shadow",
    "primary_outcome": "benign",
    "governance": GOVERNANCE,
    "model_id": "synthetic-model",
}
DEPLOYMENTS = {
    "version 2 route": {},
    "version 1 route only": {"serves_version_2": False},
    "version 2 route answering a version 1 body": {"body_route": native.V1_ROUTE},
}
ATTACK = {"content": native.PRE_TOOL_BLOCK_MARKER}


class StandInSession:
    def post(self, _url: str, **_options: Any) -> None:
        raise requests.Timeout("synthetic timeout")


def loopback_classifier(
    requests_seen: list[tuple[str, dict[str, Any]]],
    *,
    serves_version_2: bool = True,
    body_route: str | None = None,
    body: dict[str, Any] | None = None,
) -> native.Responder:
    def respond(path: str, _headers: Message, payload: dict[str, Any]) -> native.Reply:
        requests_seen.append((path, payload))
        if path == native.V2_ROUTE and not serves_version_2:
            return native.Reply(b'{"message": "Not Found"}', status=404)
        return native.Reply(
            json.dumps(
                body or native.loopback_classification(body_route or path, payload)
            ).encode()
        )

    return respond


class Sdk100IntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence_directory = tempfile.TemporaryDirectory()
        self.environment = mock.patch.dict(
            os.environ,
            {
                "SILMARIL_API_KEY": "synthetic-key",
                "SILMARIL_API_URL": "https://local.invalid/classify",
                "SILMARIL_MODE": "block",
                "SILMARIL_LOCAL_EVENT_DIR": self.evidence_directory.name,
            },
        )
        self.environment.start()
        self.evidence: list[dict[str, Any]] = []
        self.emitter = mock.patch.object(
            firewall,
            "_LOCAL_EVIDENCE_EMITTER",
            side_effect=self.evidence.append,
        )
        self.emitter.start()
        self._reset_plugin()

    def tearDown(self) -> None:
        self._reset_plugin()
        self.emitter.stop()
        self.environment.stop()
        self.evidence_directory.cleanup()

    def _reset_plugin(self) -> None:
        firewall._SDK_CLIENT = None
        firewall._SDK_CONFIG = None
        firewall._TOOL_RESULT_CACHE.clear()
        firewall._reset_mac_device_name_lookup_for_tests(platform="linux")

    @contextmanager
    def _deployment(self, **options: Any) -> Iterator[list[tuple[str, dict[str, Any]]]]:
        requests_seen: list[tuple[str, dict[str, Any]]] = []
        with native.loopback_server(loopback_classifier(requests_seen, **options)) as url:
            os.environ["SILMARIL_API_URL"] = f"{url}/classify"
            self._reset_plugin()
            self.evidence.clear()
            yield requests_seen

    def test_installed_sdk_is_100(self) -> None:
        self.assertEqual(importlib.metadata.version("silmaril-security-sdk"), "1.0.0")

    def test_sdk_raises_its_typed_block_result_for_both_response_versions(self) -> None:
        for name, options in DEPLOYMENTS.items():
            with self.subTest(deployment=name), self._deployment(**options):
                client = Firewall(
                    api_key="synthetic-key",
                    api_url=os.environ["SILMARIL_API_URL"],
                    mode="block",
                    max_retries=0,
                )

                with self.assertRaises(FirewallBlockedException) as raised:
                    client.classify(native.PRE_TOOL_BLOCK_MARKER, hook=HookLabel.TOOL_CALL)

                result = raised.exception.result
                self.assertIsInstance(result, BlockResult)
                self.assertTrue(result.blocked)
                self.assertEqual((result.action, result.source), ("block", "model"))

    def test_block_is_enforced_on_every_deployment_generation(self) -> None:
        expected_routes = {
            "version 2 route": [native.V2_ROUTE, native.V2_ROUTE],
            "version 1 route only": [native.V2_ROUTE, native.V1_ROUTE, native.V1_ROUTE],
            "version 2 route answering a version 1 body": [native.V2_ROUTE, native.V2_ROUTE],
        }
        for name, options in DEPLOYMENTS.items():
            with self.subTest(deployment=name), self._deployment(**options) as seen:
                blocked = firewall.pre_tool_call(tool_name="write_file", args=ATTACK)
                replaced = firewall.transform_tool_result(
                    tool_name="read_file",
                    result=native.LOOPBACK_POISON,
                )

                self.assertEqual(blocked["action"], "block")
                self.assertIn(native.TOOL_CALL_DENIAL, blocked["message"])
                self.assertIn(native.TOOL_RESULT_REPLACEMENT, replaced)
                self.assertNotIn(native.LOOPBACK_POISON, replaced)
                self.assertEqual([path for path, _ in seen], expected_routes[name])
                self.assertEqual(
                    [event["policyDecision"] for event in self.evidence],
                    ["block", "block"],
                )
                self.assertEqual(
                    [event["prediction"] for event in self.evidence],
                    ["malicious", "malicious"],
                )

    def test_allow_passes_on_every_deployment_generation(self) -> None:
        for name, options in DEPLOYMENTS.items():
            with self.subTest(deployment=name), self._deployment(**options):
                self.assertIsNone(
                    firewall.pre_tool_call(
                        tool_name="write_file",
                        args={"content": native.RELEASE_SUMMARY},
                    )
                )
                self.assertEqual(
                    firewall.transform_tool_result(
                        tool_name="read_file",
                        result=native.RELEASE_SUMMARY,
                    ),
                    native.RELEASE_SUMMARY,
                )
                self.assertEqual(
                    [event["policyDecision"] for event in self.evidence],
                    ["allow", "allow"],
                )

    def test_receipt_carries_confidence_and_severity_only_from_version_2(self) -> None:
        expected = {
            "version 2 route": {"confidence": "very_high", "severity": "high"},
            "version 1 route only": {},
            "version 2 route answering a version 1 body": {},
        }
        for name, options in DEPLOYMENTS.items():
            with self.subTest(deployment=name), self._deployment(**options):
                firewall.pre_tool_call(tool_name="write_file", args=ATTACK)

                (event,) = self.evidence
                self.assertEqual(event["schemaVersion"], 1)
                self.assertEqual(
                    {
                        key: event[key]
                        for key in ("confidence", "severity", "modelScore", "modelThreshold")
                        if key in event
                    },
                    expected[name],
                )

    def test_governance_block_is_enforced_and_named_for_both_response_versions(self) -> None:
        deployments = {
            "version 2 body": {"body": GOVERNANCE_BLOCK_VERSION_2},
            "version 1 body": {"body": GOVERNANCE_BLOCK_VERSION_1, "serves_version_2": False},
        }
        for name, options in deployments.items():
            with self.subTest(deployment=name), self._deployment(**options):
                blocked = firewall.pre_tool_call(
                    tool_name="terminal",
                    args={"command": "synthetic command"},
                )

                self.assertEqual(blocked["action"], "block")
                self.assertIn("Governance policy denied this action", blocked["message"])
                (event,) = self.evidence
                self.assertEqual(event["prediction"], "benign")
                self.assertEqual(event["policyDecision"], "block")
                self.assertEqual(event["nativeAction"], "block_returned")

    def test_model_and_policy_versions_reach_the_receipt_on_every_deployment_generation(
        self,
    ) -> None:
        deployments = {
            "version 2 body": {"body": GOVERNANCE_BLOCK_VERSION_2},
            "/classify fallback": {
                "body": GOVERNANCE_BLOCK_VERSION_1,
                "serves_version_2": False,
            },
            "version 1 body on /v2/classify": {"body": GOVERNANCE_BLOCK_VERSION_1},
        }
        for name, options in deployments.items():
            with self.subTest(deployment=name), self._deployment(**options):
                firewall.pre_tool_call(
                    tool_name="terminal",
                    args={"command": "synthetic command"},
                )

                (event,) = self.evidence
                self.assertEqual(
                    event["provenance"]["policyVersion"],
                    GOVERNANCE["policy_version"],
                )
                self.assertEqual(event["provenance"]["modelVersion"], "synthetic-model")

        with self._deployment():
            firewall.pre_tool_call(
                tool_name="write_file",
                args={"content": native.RELEASE_SUMMARY},
            )

            (event,) = self.evidence
            self.assertNotIn("policyVersion", event["provenance"])
            self.assertNotIn("modelVersion", event["provenance"])

    def test_real_block_results_drive_the_plugin_decision(self) -> None:
        governance = GovernanceDecision(**GOVERNANCE)
        cases = (
            (BlockResult(action="block", source="model", outcome="secret_exposure"), "block"),
            (BlockResult(action="block", source="governance", governance=governance), "block"),
            (BlockResult(action="block"), "block"),
            (BlockResult(action="allow"), "allow"),
            (BlockResult(action="allow", governance=governance), "allow"),
        )
        for result, expected in cases:
            with self.subTest(result=result):
                self.assertEqual(result.blocked, expected == "block")
                self.assertEqual(
                    firewall._local_evidence_decision(result, block_action="block_returned")[1:3],
                    (expected, "block_returned" if expected == "block" else "none"),
                )

    def test_transport_error_fails_open_as_unavailable(self) -> None:
        client = Firewall(
            api_key="synthetic-key",
            api_url="https://local.invalid/classify",
            mode="block",
            max_retries=0,
            session=StandInSession(),
        )

        with (
            mock.patch.object(firewall, "_firewall_client", return_value=client),
            self.assertLogs("hermes.plugins.firewall", level="WARNING"),
        ):
            decision = firewall.pre_tool_call(
                tool_name="terminal",
                args={"command": "synthetic command"},
            )

        self.assertIsNone(decision)
        self.assertEqual(self.evidence[0]["policyDecision"], "unavailable")

    def test_server_error_on_version_2_fails_open_without_a_fallback(self) -> None:
        seen: list[str] = []

        def respond(path: str, _headers: Message, _payload: dict[str, Any]) -> native.Reply:
            seen.append(path)
            return native.Reply(b"{}", status=500)

        with native.loopback_server(respond) as url:
            os.environ["SILMARIL_API_URL"] = f"{url}/classify"
            self._reset_plugin()
            with self.assertLogs("hermes.plugins.firewall", level="WARNING") as logs:
                decision = firewall.pre_tool_call(tool_name="write_file", args=ATTACK)

        self.assertIsNone(decision)
        self.assertEqual(seen, [native.V2_ROUTE])
        self.assertIn("error_type=SilmarilApiError", "\n".join(logs.output))
        self.assertEqual(self.evidence[0]["policyDecision"], "unavailable")

    def test_plugin_sends_typed_agent_and_ordinary_tool_governance_over_http(self) -> None:
        with self._deployment() as seen:
            self.assertIsNone(
                firewall.pre_llm_call(
                    user_message="synthetic prompt",
                    session_id="session-1",
                )
            )
            self.assertIsNone(
                firewall.pre_tool_call(
                    tool_name="terminal",
                    args={"command": "synthetic command"},
                    session_id="session-1",
                    tool_call_id="tool-1",
                )
            )

        (_, agent_request), (_, tool_request) = seen
        self.assertEqual(
            agent_request["resource"],
            {"kind": "agent", "id": "hermes"},
        )
        self.assertEqual(
            agent_request["metadata"]["silmaril"]["governance"],
            {
                "agent": "hermes",
                "resource": {"kind": "agent", "id": "hermes"},
            },
        )
        self.assertEqual(
            tool_request["resource"],
            {"kind": "tool", "id": "terminal"},
        )
        self.assertEqual(
            tool_request["metadata"]["silmaril"]["governance"],
            {
                "agent": "hermes",
                "resource": {"kind": "tool", "id": "terminal"},
            },
        )
        self.assertEqual(
            tool_request["metadata"]["silmaril"]["integration"],
            "hermes-firewall",
        )
        self.assertNotIn("parent_id", tool_request["resource"])
        self.assertEqual(tool_request["tool_name"], "terminal")


if __name__ == "__main__":
    unittest.main()
