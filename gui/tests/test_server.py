"""Tests for the local launcher (command building, safety checks, run listing)."""

from __future__ import annotations

import http.client
import json
import socket
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from gui import server
from gui.server import LOCAL, Jobs, build_command, list_runs, make_handler, resolve_run, run_dir_name

OUT = Path("/tmp/out")
BOXES = ["eval-web-vuln", "eval-db-exposed"]


def cmd(**spec):
    base = {"target": "eval-web-vuln", "engine": "fake"}
    return build_command({**base, **spec}, BOXES, out_dir=OUT, platform="linux", python="py")


class BuildCommandTests(unittest.TestCase):
    def test_container_run_maps_options_to_flags(self) -> None:
        c = cmd(v2=True, banner=True, osv=True, nvd=True, check_versions=True)
        self.assertEqual(c[0], "py")
        self.assertIn("run_full_scan.py", c[1])
        for flag in ("--v2", "--banner-candidates", "--osv-discovery", "--nvd-discovery", "--check-versions"):
            self.assertIn(flag, c)
        self.assertEqual(c[c.index("--container") + 1], "eval-web-vuln")
        self.assertEqual(c[c.index("--engine") + 1], "fake")

    def test_limits_only_apply_to_the_ai_engine(self) -> None:
        self.assertNotIn("--max-calls", cmd(engine="fake", max_calls=5))
        c = cmd(engine="claude", max_calls=5, max_cost_usd=1.5)
        self.assertEqual(c[c.index("--max-calls") + 1], "5")
        self.assertEqual(c[c.index("--max-cost-usd") + 1], "1.5")

    def test_default_limits_are_the_cli_defaults(self) -> None:
        c = cmd(engine="claude")
        self.assertEqual(c[c.index("--max-calls") + 1], str(server.DEFAULT_MAX_CALLS))

    def test_unknown_or_unsafe_target_is_refused(self) -> None:
        for bad in ("nope", "eval-web-vuln; rm -rf /", "--help", "", None, 5, "../x"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                cmd(target=bad)

    def test_unknown_engine_is_refused(self) -> None:
        for bad in ("openai", "", None):
            with self.assertRaises(ValueError):
                cmd(engine=bad)

    def test_banner_needs_the_full_pipeline(self) -> None:
        with self.assertRaises(ValueError):
            cmd(banner=True, v2=False)

    def test_limits_are_range_checked(self) -> None:
        for kw in ({"max_calls": -1}, {"max_calls": 501}, {"max_cost_usd": 51}, {"max_calls": "x"}):
            with self.assertRaises(ValueError, msg=str(kw)):
                cmd(engine="claude", **kw)

    def test_this_machine_runs_the_local_script_on_linux_only(self) -> None:
        c = build_command({"target": LOCAL, "engine": "claude", "check_versions": True}, [], out_dir=OUT,
                          platform="linux")
        self.assertEqual(c[0], "bash")
        self.assertIn("scan-local-host.sh", c[1])
        self.assertIn("--engine=claude", c)
        self.assertIn("--check-versions", c)
        with self.assertRaises(ValueError):
            build_command({"target": LOCAL, "engine": "fake"}, [], out_dir=OUT, platform="win32")

    def test_output_folder_name_is_safe(self) -> None:
        self.assertRegex(run_dir_name("eval-web-vuln"), r"^eval-web-vuln-\d{8}_\d{6}$")
        self.assertRegex(run_dir_name(LOCAL), r"^this-machine-\d{8}_\d{6}$")


class RunListingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "scan-results"
        self.root.mkdir()

    def _run(self, name: str, with_report: bool = False) -> None:
        d = self.root / name
        d.mkdir()
        (d / "verdicts.json").write_text(json.dumps({"verdicts": []}), encoding="utf-8")
        if with_report:
            (d / "report.html").write_text("<p>hi</p>", encoding="utf-8")

    def test_only_folders_with_verdicts_are_runs(self) -> None:
        self._run("a")
        (self.root / "empty").mkdir()
        self.assertEqual(list_runs(self.root), ["scan-results/a"])

    def test_missing_root_is_fine(self) -> None:
        self.assertEqual(list_runs(self.root / "nope"), [])

    def test_ids_outside_the_listing_resolve_to_nothing(self) -> None:
        self._run("a")
        for bad in ("scan-results/../a", "../scan-results/a", "scan-results/nope", "", "a", "x/a"):
            self.assertIsNone(resolve_run((self.root,), bad), bad)
        self.assertEqual(resolve_run((self.root,), "scan-results/a"), self.root / "a")


class HttpTests(unittest.TestCase):
    TOKEN = "tok123"

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "scan-results"
        self.root.mkdir()
        self.jobs = Jobs()
        with socket.socket() as s:  # the handler must know its port, so pick a free one first
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", self.port),
            make_handler(self.TOKEN, self.port, (self.root,), self.jobs, self.root))
        self.addCleanup(self.server.server_close)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        patcher = mock.patch.object(server, "list_containers", return_value=(BOXES, ""))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = dict(headers or {})
        c.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def test_page_carries_the_token(self) -> None:
        status, body = self._req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(self.TOKEN.encode(), body)
        self.assertNotIn(b"__TOKEN__", body)

    def test_foreign_host_header_is_refused(self) -> None:
        for method in ("GET", "POST"):
            status, _ = self._req(method, "/api/runs", headers={"Host": "evil.example"})
            self.assertEqual(status, 403, method)

    def test_post_without_the_token_is_refused(self) -> None:
        for headers in ({}, {"X-Token": "wrong"}):
            status, _ = self._req("POST", "/api/run", {"target": "eval-web-vuln", "engine": "fake"}, headers)
            self.assertEqual(status, 403)

    def test_bad_spec_with_token_is_400_and_starts_nothing(self) -> None:
        status, body = self._req("POST", "/api/run", {"target": "nope", "engine": "fake"},
                                 {"X-Token": self.TOKEN})
        self.assertEqual(status, 400)
        self.assertIn("container", json.loads(body)["error"])
        self.assertFalse(self.jobs.running())

    def test_valid_run_is_started_with_the_built_command(self) -> None:
        started = {}
        self.jobs.start = lambda c, out, rid: started.update(cmd=c, out=out, rid=rid)
        status, body = self._req("POST", "/api/run", {"target": "eval-web-vuln", "engine": "fake", "v2": True},
                                 {"X-Token": self.TOKEN})
        self.assertEqual(status, 200)
        self.assertIn("--v2", started["cmd"])
        self.assertTrue(started["rid"].startswith("scan-results/eval-web-vuln-"))

    def test_second_run_while_busy_is_409(self) -> None:
        def busy(*a):
            raise RuntimeError("a run is already in progress")
        self.jobs.start = busy
        status, _ = self._req("POST", "/api/run", {"target": "eval-web-vuln", "engine": "fake"},
                              {"X-Token": self.TOKEN})
        self.assertEqual(status, 409)

    def test_stop_with_nothing_running(self) -> None:
        status, body = self._req("POST", "/api/stop", {}, {"X-Token": self.TOKEN})
        self.assertEqual((status, json.loads(body)), (200, {"stopped": False}))

    def test_idle_job_status(self) -> None:
        status, body = self._req("GET", "/api/job")
        self.assertEqual((status, json.loads(body)["state"]), (200, "idle"))

    def test_unknown_run_and_traversal_are_404(self) -> None:
        for path in ("/api/run/nope", "/api/run/..%2F..%2Fetc", "/report/..%2Fx", "/report/scan-results/nope"):
            self.assertEqual(self._req("GET", path)[0], 404, path)

    def test_report_is_served_with_a_locked_down_csp(self) -> None:
        d = self.root / "r1"
        d.mkdir()
        (d / "verdicts.json").write_text("{}", encoding="utf-8")
        (d / "report.html").write_text("<script>alert(1)</script>", encoding="utf-8")
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", "/report/scan-results/r1")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 200)
        self.assertIn("default-src 'none'", r.getheader("Content-Security-Policy"))
        c.close()


class JobsTests(unittest.TestCase):
    def test_runs_a_process_and_captures_its_log(self) -> None:
        import sys
        import time
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Jobs()
            jobs.start([sys.executable, "-c", "print('héllo — ok')"], Path(tmp) / "o", "x/y")
            for _ in range(100):
                if not jobs.running():
                    break
                time.sleep(0.05)
            s = jobs.status()
            self.assertEqual(s["state"], "done")
            self.assertIn("héllo — ok", s["log"])

    def test_failed_exit_code_is_reported(self) -> None:
        import sys
        import time
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Jobs()
            jobs.start([sys.executable, "-c", "raise SystemExit(3)"], Path(tmp) / "o", "x/y")
            for _ in range(100):
                if not jobs.running():
                    break
                time.sleep(0.05)
            self.assertEqual((jobs.status()["state"], jobs.status()["exit_code"]), ("failed", 3))


if __name__ == "__main__":
    unittest.main()
