"""Qualification against the actual Hermes v0.23.0 host source.

Run explicitly with::

    HERMES_023_SOURCE=/path/to/hermes-agent-v0.23.0 \
      python -m unittest -v tests.test_hermes_023_native

The source checkout must be the pinned upstream commit below. The test uses the
official plugin manager, conversation loop, stream delivery, and turn finalizer;
only the model and Firewall classification results are inert local fakes.
"""

from __future__ import annotations

import importlib
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import firewall


HERMES_023_COMMIT = "2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19"
MALICIOUS_TOKEN = "NATIVE-MALICIOUS-TOKEN"


class _Provider(BaseHTTPRequestHandler):
    chat_requests: list[dict] = []

    def do_POST(self) -> None:
        request = json.loads(
            self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        )
        if "messages" in request:
            type(self).chat_requests.append(request)
        if request.get("stream") is True:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            chunks = (
                ({"role": "assistant", "content": MALICIOUS_TOKEN}, None),
                ({}, "stop"),
            )
            for delta, finish_reason in chunks:
                body = {
                    "id": "loopback",
                    "choices": [
                        {
                            "index": 0,
                            "delta": delta,
                            "finish_reason": finish_reason,
                        }
                    ],
                }
                self.wfile.write(f"data: {json.dumps(body)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
            return
        body = json.dumps(
            {
                "id": "loopback",
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 1,
                    "total_tokens": 11,
                },
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": MALICIOUS_TOKEN,
                        },
                        "finish_reason": "stop",
                    }
                ],
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        del args


def _decision(*, malicious: bool = False, governance: bool = False) -> dict:
    return {
        "prediction": "MALICIOUS" if malicious else "BENIGN",
        "score": 0.99 if malicious else 0.01,
        "threshold": 0.5,
        "mode": os.environ["SILMARIL_MODE"],
        "governance": (
            {
                "action": "block",
                "policy_version": "native-test",
                "rule_id": "native-test-rule",
            }
            if governance
            else None
        ),
        "primary_outcome": "prompt_injection" if malicious else "benign",
        "blocked": malicious or governance,
    }


def _agent(provider_url: str):
    from run_agent import AIAgent

    return AIAgent(
        api_key="synthetic-key",
        base_url=provider_url,
        provider="openai-compat",
        model="test-model",
        max_iterations=2,
        enabled_toolsets=[],
        quiet_mode=True,
        skip_context_files=True,
        skip_memory=True,
        save_trajectories=False,
        platform="cli",
    )


@unittest.skipUnless(
    os.environ.get("HERMES_023_SOURCE"),
    "native qualification requires HERMES_023_SOURCE",
)
class Hermes023NativeQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configured = os.environ["HERMES_023_SOURCE"]
        cls.source = Path(configured).resolve()
        cls._temp = tempfile.TemporaryDirectory(prefix="hermes-023-native-")
        cls.addClassCleanup(cls._temp.cleanup)
        cls.temp_root = Path(cls._temp.name)
        home = cls.temp_root / "home"
        hermes_home = cls.temp_root / "hermes"
        tmp_dir = cls.temp_root / "tmp"
        for directory in (home, hermes_home, tmp_dir):
            directory.mkdir()
        (hermes_home / "config.yaml").write_text(
            "updates:\n"
            "  check: false\n"
            "models_dev:\n"
            "  url: http://127.0.0.1:9/api.json\n"
            "skills:\n"
            "  creation_nudge_interval: 0\n"
            "memory:\n"
            "  nudge_interval: 0\n"
            "telemetry:\n"
            "  shared_metrics:\n"
            "    enabled: false\n"
            "    send: false\n",
            encoding="utf-8",
        )

        git = shutil.which("git")
        if git is None:
            raise RuntimeError("git is required for native source verification")
        cls._environment = mock.patch.dict(
            os.environ,
            {
                "HOME": str(home),
                "HERMES_HOME": str(hermes_home),
                "HERMES_023_SOURCE": str(cls.source),
                "HERMES_ENABLE_PROJECT_PLUGINS": "0",
                "HERMES_BUNDLED_PLUGINS": str(cls.temp_root / "no-bundled"),
                "LANG": "C.UTF-8",
                "PATH": os.environ.get("PATH", os.defpath),
                "SILMARIL_MODE": "block",
                "TMPDIR": str(tmp_dir),
            },
            clear=True,
        )
        cls._environment.start()
        cls.addClassCleanup(cls._environment.stop)

        revision = cls._git(git, "rev-parse", "HEAD")
        if revision != HERMES_023_COMMIT:
            raise AssertionError(
                f"Hermes source revision {revision} != {HERMES_023_COMMIT}"
            )
        dirty = cls._git(git, "status", "--porcelain=v1", "--untracked-files=all")
        if dirty:
            raise AssertionError(f"Hermes source checkout is not clean:\n{dirty}")

        sys.path.insert(0, str(cls.source))
        cls.addClassCleanup(cls._remove_source_path)
        modules = (
            "agent.turn_context",
            "agent.conversation_loop",
            "agent.stream_delivery",
            "agent.turn_finalizer",
            "hermes_cli.plugins",
            "hermes_cli.plugins_dispatch",
            "run_agent",
        )
        origins = {
            name: Path(inspect.getfile(importlib.import_module(name))).resolve()
            for name in modules
        }
        outside = {
            name: origin
            for name, origin in origins.items()
            if not cls._is_within(origin, cls.source)
        }
        if outside:
            raise AssertionError(
                "Hermes modules were not imported from the pinned checkout: "
                f"{outside}"
            )
        # Match the upstream test harness: do not launch the detached hourly
        # scratch-prune child from this short-lived, isolated qualification.
        hermes_constants = importlib.import_module("hermes_constants")
        hermes_constants._scratch_pruned_once = True

    @classmethod
    def _remove_source_path(cls) -> None:
        source = str(cls.source)
        if source in sys.path:
            sys.path.remove(source)

    @classmethod
    def _git(cls, executable: str, *args: str) -> str:
        return subprocess.run(
            [executable, *args],
            cwd=cls.source,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    @staticmethod
    def _is_within(path: Path, directory: Path) -> bool:
        try:
            path.relative_to(directory)
        except ValueError:
            return False
        return True

    def setUp(self) -> None:
        from hermes_cli import plugins
        from hermes_cli.plugins import PluginContext, PluginManifest

        plugins._reset_plugin_managers_for_tests()
        manager = plugins.get_plugin_manager()
        context = PluginContext(
            PluginManifest(name="hermes-firewall", version=firewall.PLUGIN_VERSION),
            manager,
        )
        firewall.register(context)

        self.server = HTTPServer(("127.0.0.1", 0), _Provider)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()
        _Provider.chat_requests = []
        self.provider_url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def tearDown(self) -> None:
        from hermes_cli import plugins

        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        plugins._reset_plugin_managers_for_tests()
        os.environ["SILMARIL_MODE"] = "block"

    def _assert_prompt_veto(
        self,
        *,
        malicious: bool = False,
        governance: bool = False,
    ) -> None:
        def observe(event: str, *_args: object, **_kwargs: object) -> dict:
            if event == "pre_llm_call":
                return _decision(malicious=malicious, governance=governance)
            return _decision()

        with mock.patch.object(firewall, "_observe", side_effect=observe):
            result = _agent(self.provider_url).run_conversation(
                "synthetic blocked prompt"
            )

        self.assertEqual(_Provider.chat_requests, [])
        self.assertEqual(
            result["turn_exit_reason"],
            firewall.PRE_LLM_BLOCK_EXIT_REASON,
        )
        self.assertEqual(result["api_calls"], 0)
        self.assertTrue(
            result["final_response"].startswith(
                "Silmaril Firewall blocked this user prompt:"
            )
        )

    def _assert_held_output(
        self,
        *,
        mode: str,
        output_decision: str,
        expect_replaced: bool,
    ) -> None:
        os.environ["SILMARIL_MODE"] = mode

        def observe(event: str, *_args: object, **_kwargs: object):
            if event == "pre_llm_call":
                return _decision()
            if output_decision == "error":
                return None
            return _decision(
                malicious=output_decision == "malicious",
                governance=output_decision == "governance",
            )

        shown: list[str] = []
        with mock.patch.object(firewall, "_observe", side_effect=observe):
            agent = _agent(self.provider_url)
            agent.stream_delta_callback = shown.append
            result = agent.run_conversation("synthetic allowed prompt")

        self.assertTrue(_Provider.chat_requests)
        self.assertTrue(
            all(request.get("stream") is True for request in _Provider.chat_requests)
        )
        self.assertFalse([text for text in shown if text])
        if expect_replaced:
            self.assertNotIn(MALICIOUS_TOKEN, result["final_response"])
            self.assertTrue(
                result["final_response"].startswith(
                    "Silmaril Firewall blocked this assistant output:"
                )
            )
            self.assertIsNone(result["pre_transform_response"])
        else:
            self.assertEqual(result["final_response"], MALICIOUS_TOKEN)

    def test_native_prompt_veto_precedes_inference_for_malicious_input(self) -> None:
        self._assert_prompt_veto(malicious=True)

    def test_native_prompt_veto_precedes_inference_for_governance_denial(self) -> None:
        self._assert_prompt_veto(governance=True)

    def test_native_held_output_replaces_malicious_block(self) -> None:
        self._assert_held_output(
            mode="block",
            output_decision="malicious",
            expect_replaced=True,
        )

    def test_native_held_output_replaces_governance_block(self) -> None:
        self._assert_held_output(
            mode="block",
            output_decision="governance",
            expect_replaced=True,
        )

    def test_native_held_output_preserves_shadow_content(self) -> None:
        self._assert_held_output(
            mode="shadow",
            output_decision="malicious",
            expect_replaced=False,
        )

    def test_native_held_output_preserves_warn_content(self) -> None:
        self._assert_held_output(
            mode="warn",
            output_decision="malicious",
            expect_replaced=False,
        )

    def test_native_held_output_preserves_classifier_error_content(self) -> None:
        self._assert_held_output(
            mode="block",
            output_decision="error",
            expect_replaced=False,
        )

    def test_native_held_output_preserves_benign_content(self) -> None:
        self._assert_held_output(
            mode="block",
            output_decision="benign",
            expect_replaced=False,
        )


if __name__ == "__main__":
    unittest.main()
