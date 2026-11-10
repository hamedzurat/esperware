#!/usr/bin/env python3
"""Exercise the container's MCP stdio transport through a harness-style client."""

import json
import os
import pathlib
import shutil
import selectors
import subprocess
import tempfile
import time
import unittest
import urllib.request


TOOLS = {
    "program_session",
    "inspect_function",
    "search_pseudocode",
    "search_types",
    "edit_function",
    "save_program",
    "revert_last_edit",
}


class McpContainer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        engine = os.environ.get("CONTAINER_ENGINE", "podman")
        image = os.environ.get("MCP_IMAGE", "ghidra-mcp:local")
        cls.repo = pathlib.Path(__file__).resolve().parents[1]
        cls.data_dir = pathlib.Path(tempfile.mkdtemp(prefix="ghidra-mcp-test-"))
        (cls.data_dir / "projects").mkdir()
        fixture = cls.repo / "build/fixtures/readability-fixture.elf"
        subprocess.run([str(cls.repo / "fixtures/build-fixture.sh")], check=True)
        subprocess.run(
            [
                engine, "run", "--rm",
                "-v", f"{cls.data_dir}:/data",
                "-v", f"{fixture}:/input/readability-fixture.elf:ro",
                "-v", f"{cls.repo / 'fixtures'}:/scripts:ro",
                "--entrypoint", "/opt/ghidra/support/analyzeHeadless", image,
                "/data/projects", "DockerMcp",
                "-import", "/input/readability-fixture.elf", "-overwrite",
                "-scriptPath", "/scripts", "-postScript", "McpToolsProbeSetup.java",
            ],
            check=True,
        )
        cls.stderr_file = (cls.data_dir / "mcp-stderr.log").open("wb")
        cls.process = subprocess.Popen(
            [
                engine, "run", "--rm", "-i",
                "--name", f"ghidra-mcp-test-{os.getpid()}",
                "-e", "GHIDRA_MCP_HISTORY_HOST=0.0.0.0",
                "-p", "127.0.0.1::8765",
                "-v", f"{cls.data_dir}:/data", image,
                "/data/projects/DockerMcp.gpr:/readability-fixture.elf",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=cls.stderr_file,
            bufsize=0,
        )
        cls.selector = selectors.DefaultSelector()
        cls.selector.register(cls.process.stdout, selectors.EVENT_READ)
        cls.buffer = bytearray()
        cls.next_id = 1

        try:
            init = cls.request(
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "docker-mcp-integration-test", "version": "1"},
                },
            )
        except Exception:
            cls.stderr_file.flush()
            details = (cls.data_dir / "mcp-stderr.log").read_text(errors="replace")
            name = f"ghidra-mcp-test-{os.getpid()}"
            app_log = subprocess.run(
                [engine, "exec", "--workdir", "/", name, "cat",
                 "/root/.config/ghidra/ghidra_12.2_PUBLIC/application.log"],
                capture_output=True, text=True,
            ).stdout
            subprocess.run([engine, "stop", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([engine, "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cls.process.kill()
            raise AssertionError(f"MCP initialization failed. stderr:\n{details}\nGhidra log:\n{app_log}")
        if "result" not in init:
            raise AssertionError(f"initialize failed: {init}")
        cls.notify("notifications/initialized", {})
        time.sleep(5)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "process"):
            cls.process.terminate()
            try:
                cls.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cls.process.kill()
                cls.process.wait()
            engine = os.environ.get("CONTAINER_ENGINE", "podman")
            name = f"ghidra-mcp-test-{os.getpid()}"
            subprocess.run([engine, "stop", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([engine, "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if hasattr(cls, "data_dir"):
            shutil.rmtree(cls.data_dir)

    @classmethod
    def request(cls, method, params):
        request_id = cls.next_id
        cls.next_id += 1
        cls.write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            response = cls.read_message()
            if response.get("id") == request_id:
                return response

    @classmethod
    def notify(cls, method, params):
        cls.write({"jsonrpc": "2.0", "method": method, "params": params})

    @classmethod
    def write(cls, message):
        cls.process.stdin.write((json.dumps(message) + "\n").encode())
        cls.process.stdin.flush()

    @classmethod
    def read_message(cls):
        while b"\n" not in cls.buffer:
            if not cls.selector.select(timeout=90):
                raise TimeoutError("MCP container did not respond within 90 seconds")
            chunk = os.read(cls.process.stdout.fileno(), 65536)
            if not chunk:
                raise AssertionError(f"MCP container exited with {cls.process.poll()}")
            cls.buffer.extend(chunk)
        line, _, rest = cls.buffer.partition(b"\n")
        cls.buffer = bytearray(rest)
        return json.loads(line)

    def call_tool(self, name, arguments):
        response = self.request("tools/call", {"name": name, "arguments": arguments})
        self.assertIn("result", response, response)
        content = response["result"].get("content", [])
        self.assertTrue(content, response)
        return response["result"], json.loads(content[0]["text"])

    def test_stdio_initializes_and_registers_all_tools(self):
        response = self.request("tools/list", {})
        self.assertIn("result", response, response)
        names = {tool["name"] for tool in response["result"]["tools"]}
        self.assertEqual(names, TOOLS)

    def test_every_tool_against_fixture(self):
        _, status = self.call_tool("program_session", {"contract_version": 1, "action": "status"})
        self.assertTrue(status["ok"], status)
        _, opened = self.call_tool("program_session", {
            "contract_version": 1, "action": "open", "program": "/readability-fixture.elf"
        })
        self.assertTrue(opened["ok"], opened)
        identity = {
            "contract_version": 1,
            "session_id": opened["session_id"],
            "generation": opened["generation"],
            "expected_revision": opened["revision"],
        }

        _, search = self.call_tool("search_pseudocode", {
            **identity, "query": "probe_state", "match_in": "all"
        })
        function = search["matches"][0]
        address = function["entry_address"]

        _, types = self.call_tool("search_types", {**identity, "query": "ProbeState"})
        self.assertTrue(
            any("ProbeState" in item["data_type_path"] for item in types["types"]), types
        )

        _, inspection = self.call_tool("inspect_function", {
            **identity, "function_address": address
        })
        self.assertEqual(inspection["function"]["entry_address"], address)

        status_args = {
            "contract_version": 1,
            "action": "status",
            "session_id": identity["session_id"],
            "generation": identity["generation"],
        }
        previous_revision = None
        stable_reads = 0
        for _ in range(30):
            _, status = self.call_tool("program_session", status_args)
            current_revision = status["revision"]
            stable_reads = stable_reads + 1 if current_revision == previous_revision else 0
            if stable_reads >= 2:
                break
            previous_revision = current_revision
            time.sleep(1)
        self.assertGreaterEqual(stable_reads, 2, "Ghidra analysis kept changing the program")

        _, edit = self.call_tool("edit_function", {
            **identity,
            "target": {"kind": "function", "function_address": address},
            "change": {"kind": "comment", "value": "Docker MCP integration test"},
        })
        self.assertTrue(edit["ok"], edit)
        self.assertEqual(edit["decompile_status"], "complete", edit)
        self.assertEqual(edit["history_status"], "recorded", edit)
        _, updated = self.call_tool("inspect_function", {
            **identity, "expected_revision": edit["revision"], "function_address": address
        })
        self.assertIn("Docker MCP integration test", updated["pseudocode"], updated)
        _, reverted = self.call_tool("revert_last_edit", {
            **identity,
            "expected_revision": edit["revision"],
            "edit_id": edit["edit_id"],
        })
        self.assertTrue(reverted["ok"], reverted)
        self.assertEqual(reverted["history_status"], "recorded", reverted)
        engine = os.environ.get("CONTAINER_ENGINE", "podman")
        mapping = subprocess.check_output([engine, "port", f"ghidra-mcp-test-{os.getpid()}", "8765/tcp"], text=True).strip()
        port = int(mapping.rsplit(":", 1)[1])
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/edits") as response:
            history = json.load(response)["edits"]
        self.assertEqual([entry["operation"] for entry in history], ["edit", "revert"])
        self.assertIn("Docker MCP integration test", history[0]["after_code"])
        self.assertNotIn("Docker MCP integration test", history[1]["after_code"])
        _, saved = self.call_tool("save_program", {
            **identity, "expected_revision": reverted["revision"]
        })
        self.assertTrue(saved["ok"], saved)

        _, closed = self.call_tool("program_session", {
            **identity, "expected_revision": saved["revision"], "action": "close"
        })
        self.assertTrue(closed["session_closed"], closed)


if __name__ == "__main__":
    unittest.main()
