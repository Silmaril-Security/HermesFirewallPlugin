from __future__ import annotations

import json
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import local_evidence


class LocalEvidenceTests(unittest.TestCase):
    def test_builds_frozen_schema_with_bounded_redacted_metadata(self) -> None:
        raw_secret = "RAW-PAYLOAD secret-password-123"
        session_secret = "customer-session-secret-456"
        detector_secret = "detector-debug-secret-789"

        event = local_evidence.build_local_protection_event(
            event="pre_tool_call",
            hook="pre_tool",
            mode="block",
            raw_text=raw_secret,
            fields={
                "session_id": session_secret,
                "task_id": "task-123",
                "tool_call_id": "tool-call-456",
                "tool_name": "api_key=secret-value",
            },
            classification={
                "prediction": "MALICIOUS",
                "score": 0.97,
                "threshold": 0.8,
                "primary_outcome": "secret_exposure",
                "detector_scores": {"raw": detector_secret},
            },
            policy_decision="block",
            native_action="block_returned",
            plugin_name="hermes-firewall",
            plugin_version="0.5.0",
            occurred_at=datetime(2026, 7, 24, 12, 34, 56, tzinfo=timezone.utc),
        )

        self.assertEqual(
            set(event),
            {
                "schemaVersion",
                "id",
                "occurredAt",
                "host",
                "hook",
                "mode",
                "requestFingerprint",
                "sessionFingerprint",
                "toolDisplayName",
                "riskClass",
                "attemptedConsequence",
                "prediction",
                "modelScore",
                "modelThreshold",
                "policyDecision",
                "nativeAction",
                "outcome",
                "evidenceTruth",
                "evidenceCompleteness",
                "provenance",
            },
        )
        self.assertEqual(event["schemaVersion"], 1)
        self.assertRegex(event["id"], r"^protection-event:[a-f0-9]{64}$")
        self.assertEqual(event["occurredAt"], "2026-07-24T12:34:56.000000Z")
        self.assertEqual(event["host"], "hermes")
        self.assertEqual(event["hook"], "pre_tool")
        self.assertEqual(event["mode"], "block")
        self.assertRegex(event["requestFingerprint"], r"^sha256:[a-f0-9]{64}$")
        self.assertRegex(event["sessionFingerprint"], r"^sha256:[a-f0-9]{64}$")
        self.assertEqual(event["toolDisplayName"], "redacted_tool")
        self.assertEqual(event["riskClass"], "credential_exposure")
        self.assertEqual(event["attemptedConsequence"], {
            "category": "credential_exposure",
            "summary": "A credential or secret could be exposed.",
        })
        self.assertEqual(event["prediction"], "malicious")
        self.assertEqual(event["modelScore"], 0.97)
        self.assertEqual(event["modelThreshold"], 0.8)
        self.assertEqual(event["policyDecision"], "block")
        self.assertEqual(event["nativeAction"], "block_returned")
        self.assertEqual(event["outcome"], "not_observed")
        self.assertEqual(event["evidenceTruth"], "plugin_reported")
        self.assertEqual(event["evidenceCompleteness"], "partial")
        self.assertEqual(event["provenance"], {
            "schemaVersion": 1,
            "producer": "hermes-firewall",
            "producerVersion": "0.5.0",
            "pluginVersion": "0.5.0",
            "observedAt": "2026-07-24T12:34:56.000000Z",
        })

        serialized = json.dumps(event, sort_keys=True)
        for secret in (
            raw_secret,
            session_secret,
            "task-123",
            "tool-call-456",
            "secret-value",
            detector_secret,
        ):
            self.assertNotIn(secret, serialized)
        self.assertLess(
            len(serialized.encode("utf-8")),
            local_evidence.MAX_LOCAL_PROTECTION_EVENT_BYTES,
        )

    def test_prediction_scores_and_unknown_consequences_are_conservative(self) -> None:
        event = local_evidence.build_local_protection_event(
            event="transform_llm_output",
            hook="llm_output",
            mode="shadow",
            raw_text="safe output",
            fields={},
            classification={
                "prediction": "BENIGN",
                "score": float("nan"),
                "threshold": 2,
                "primary_outcome": "server_future_value",
            },
            policy_decision="allow",
            native_action="allowed",
            plugin_name="hermes-firewall",
            plugin_version="0.5.0",
            occurred_at=datetime(2026, 7, 24, tzinfo=timezone.utc),
        )

        self.assertEqual(event["prediction"], "benign")
        self.assertEqual(event["riskClass"], "unknown")
        self.assertNotIn("modelScore", event)
        self.assertNotIn("modelThreshold", event)
        self.assertNotIn("server_future_value", json.dumps(event))

    def test_override_and_application_support_default_are_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            override = root / "custom-incoming"

            self.assertEqual(
                local_evidence.resolve_local_event_directory({
                    "SILMARIL_LOCAL_EVENT_DIR": f"  {override}  ",
                }),
                override,
            )
            self.assertEqual(
                local_evidence.resolve_local_event_directory(
                    {},
                    home_directory=root / "home",
                ),
                root
                / "home"
                / "Library"
                / "Application Support"
                / "Silmaril"
                / "Evidence"
                / "incoming",
            )

    def test_atomic_writer_creates_private_complete_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "incoming"
            event = self._event()

            destination = local_evidence.write_local_protection_event(
                event,
                {"SILMARIL_LOCAL_EVENT_DIR": str(directory)},
            )

            self.assertEqual(json.loads(destination.read_text()), event)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(
                [path.name for path in directory.iterdir()],
                [destination.name],
            )

    def test_atomic_writer_cleans_temporary_file_when_replace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "incoming"

            with mock.patch(
                "local_evidence.os.replace",
                side_effect=OSError("simulated rename failure"),
            ):
                with self.assertRaises(OSError):
                    local_evidence.write_local_protection_event(
                        self._event(),
                        {"SILMARIL_LOCAL_EVENT_DIR": str(directory)},
                    )

            self.assertEqual(list(directory.iterdir()), [])

    def _event(self) -> dict[str, object]:
        return local_evidence.build_local_protection_event(
            event="pre_tool_call",
            hook="pre_tool",
            mode="shadow",
            raw_text="bounded input",
            fields={"tool_call_id": "call-1", "tool_name": "terminal"},
            classification={
                "prediction": "BENIGN",
                "score": 0.01,
                "threshold": 0.5,
                "primary_outcome": "benign",
            },
            policy_decision="allow",
            native_action="allowed",
            plugin_name="hermes-firewall",
            plugin_version="0.5.0",
            occurred_at=datetime(2026, 7, 24, tzinfo=timezone.utc),
        )


if __name__ == "__main__":
    unittest.main()
