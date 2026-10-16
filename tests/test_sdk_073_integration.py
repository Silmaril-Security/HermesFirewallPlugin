from __future__ import annotations

import importlib.metadata
import json
import os
import tempfile
import unittest
from typing import Any
from unittest import mock

import requests
from silmaril_security.sdk import (
    Firewall as SdkFirewall,
    FirewallBlockedException as SdkFirewallBlockedException,
    HookLabel as SdkHookLabel,
)

import firewall


class StandInResponse:
    status_code = 200
    reason = "OK"

    def __init__(self, body: dict[str, Any]) -> None:
        self.body = body

    def json(self) -> dict[str, Any]:
        return self.body


class StandInSession:
    def __init__(
        self,
        response: dict[str, Any] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.requests: list[dict[str, Any]] = []

    def post(self, _url: str, **options: Any) -> StandInResponse:
        self.requests.append(json.loads(options["data"]))
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return StandInResponse(self.response)


def governance_response(*, response_mode: str = "shadow") -> dict[str, Any]:
    return {
        "prediction": "BENIGN",
        "score": 0.01,
        "threshold": 0.5,
        "mode": response_mode,
        "primary_outcome": "benign",
        "governance": {
            "action": "block",
            "policy_version": "synthetic-policy-v1",
            "rule_id": "synthetic-rule",
        },
    }


class PublishedSdk073IntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = mock.patch.dict(
            os.environ,
            {
                "SILMARIL_API_KEY": "synthetic-key",
                "SILMARIL_API_URL": "https://local.invalid/classify",
                "SILMARIL_MODE": "block",
            },
            clear=False,
        )
        self.environment.start()
        self.evidence_directory = tempfile.TemporaryDirectory()
        os.environ["SILMARIL_LOCAL_EVENT_DIR"] = self.evidence_directory.name
        firewall._SDK_CLIENT = None
        firewall._SDK_CONFIG = None
        firewall._TOOL_RESULT_CACHE.clear()
        firewall._reset_mac_device_name_lookup_for_tests(platform="linux")

    def tearDown(self) -> None:
        firewall._SDK_CLIENT = None
        firewall._SDK_CONFIG = None
        firewall._TOOL_RESULT_CACHE.clear()
        firewall._reset_mac_device_name_lookup_for_tests(platform="linux")
        self.environment.stop()
        self.evidence_directory.cleanup()

    def test_actual_073_parser_raises_typed_governance_block_exception(self) -> None:
        self.assertEqual(
            importlib.metadata.version("silmaril-security-sdk"),
            "0.7.3",
        )
        session = StandInSession(governance_response())
        client = SdkFirewall(
            api_key="synthetic-key",
            api_url="https://local.invalid/classify",
            mode="block",
            max_retries=0,
            session=session,
        )

        with self.assertRaises(SdkFirewallBlockedException) as raised:
            client.classify("synthetic input", hook=SdkHookLabel.TOOL_CALL)

        result = raised.exception.result
        assert result is not None
        self.assertEqual(result.prediction, "BENIGN")
        self.assertEqual(result.mode, "block")
        self.assertEqual(result.governance.action, "block")
        self.assertEqual(result.governance.policy_version, "synthetic-policy-v1")
        self.assertEqual(result.governance.rule_id, "synthetic-rule")
        self.assertEqual(session.requests[0]["mode"], "block")

    def test_plugin_recovers_073_exception_and_local_mode_wins_response_mode(self) -> None:
        session = StandInSession(governance_response(response_mode="shadow"))
        client = SdkFirewall(
            api_key="synthetic-key",
            api_url="https://local.invalid/classify",
            mode="block",
            max_retries=0,
            session=session,
        )
        evidence: list[dict[str, Any]] = []

        with (
            mock.patch.object(firewall, "_firewall_client", return_value=client),
            mock.patch.object(
                firewall,
                "_sdk_symbols",
                return_value=(SdkFirewall, SdkHookLabel, SdkFirewallBlockedException),
            ),
            mock.patch.object(
                firewall,
                "_LOCAL_EVIDENCE_EMITTER",
                side_effect=evidence.append,
            ),
        ):
            blocked = firewall.pre_tool_call(
                tool_name="terminal",
                args={"command": "synthetic command"},
            )

        self.assertEqual(blocked["action"], "block")
        self.assertIn("Governance policy denied this action", blocked["message"])
        self.assertEqual(evidence[0]["prediction"], "benign")
        self.assertEqual(evidence[0]["policyDecision"], "block")
        self.assertEqual(evidence[0]["nativeAction"], "block_returned")

    def test_actual_073_transport_error_fails_open(self) -> None:
        session = StandInSession(error=requests.Timeout("synthetic timeout"))
        client = SdkFirewall(
            api_key="synthetic-key",
            api_url="https://local.invalid/classify",
            mode="block",
            max_retries=0,
            session=session,
        )

        with (
            mock.patch.object(firewall, "_firewall_client", return_value=client),
            mock.patch.object(
                firewall,
                "_sdk_symbols",
                return_value=(SdkFirewall, SdkHookLabel, SdkFirewallBlockedException),
            ),
        ):
            with self.assertLogs("hermes.plugins.firewall", level="WARNING"):
                decision = firewall.pre_tool_call(
                    tool_name="terminal",
                    args={"command": "synthetic command"},
                )

        self.assertIsNone(decision)


if __name__ == "__main__":
    unittest.main()
