"""Integration tests against servers started on 127.0.0.1 only.

No external host is ever contacted, so this suite is deterministic and safe on
an isolated CI runner. Anything that would need the real internet is asserted
via its *failure* path instead.
"""

import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.base import IsolatedHomeCase, ROOT


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _Handler(BaseHTTPRequestHandler):
    """Answers a small, predictable set of routes."""

    server_version = "ReaperTest/1.0"

    def log_message(self, *args):  # silence the test output
        pass

    def _send(self, code: int, body: bytes, ctype: str = "text/html",
              extra: dict = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/":
            self._send(200, b"<html><head><title>Reaper Test</title></head>"
                            b"<body><h1>ok</h1></body></html>")
        elif self.path == "/missing-header":
            # Deliberately no CSP / X-Frame-Options so the audit has findings.
            self._send(200, b"<html><body>bare</body></html>")
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/cookie":
            self._send(200, b"<html><body>c</body></html>",
                       extra={"Set-Cookie": "sid=abc; Path=/"})
        else:
            self._send(404, b"not found", "text/plain")

    do_HEAD = do_GET


class LocalServerCase(unittest.TestCase):
    """Boots one HTTP server per test class."""

    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.server = ThreadingHTTPServer(("127.0.0.1", cls.port), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)


class TestHttpFetch(LocalServerCase):
    def test_get_returns_status_and_body(self):
        from core import net
        res = net.http_request(self.url + "/")
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], 200)
        self.assertIn("Reaper Test", res["body"])

    def test_head_request(self):
        from core import net
        res = net.http_request(self.url + "/", method="HEAD")
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], 200)

    def test_404_is_not_an_exception(self):
        from core import net
        res = net.http_request(self.url + "/definitely-missing")
        self.assertEqual(res["status"], 404)

    def test_connection_refused_is_reported(self):
        from core import net
        dead = _free_port()
        res = net.http_request(f"http://127.0.0.1:{dead}/", timeout=1.0)
        self.assertFalse(res["ok"])
        self.assertTrue(res["error"])

    def test_redirect_followed(self):
        from core import net
        res = net.http_request(self.url + "/redirect")
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], 200)


class TestTcpPrimitives(LocalServerCase):
    def test_connect_to_open_port(self):
        from core import net
        elapsed = net.tcp_connect("127.0.0.1", self.port, timeout=2.0)
        self.assertIsNotNone(elapsed)
        self.assertGreaterEqual(elapsed, 0)

    def test_connect_to_closed_port(self):
        from core import net
        dead = _free_port()
        self.assertIsNone(net.tcp_connect("127.0.0.1", dead, timeout=0.5))

    def test_connect_to_unresolvable_host(self):
        from core import net
        self.assertIsNone(net.tcp_connect("no-such-host.invalid", 80, timeout=1.0))


class TestPortScan(LocalServerCase):
    def test_finds_open_port_with_authorization(self):
        from modules.reconnaissance import port_scan
        res = port_scan.run("127.0.0.1", ports=[self.port], timeout=2.0, threads=2,
                            authorized=True)
        self.assertTrue(res["ok"])
        self.assertGreaterEqual(len(res["open_ports"]), 1)
        self.assertEqual(res["open_ports"][0]["port"], self.port)

    def test_requires_authorization(self):
        from modules.reconnaissance import port_scan
        res = port_scan.run("127.0.0.1", ports=[80])
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "authorization_required")

    def test_invalid_port_spec_is_rejected(self):
        from modules.reconnaissance import port_scan
        res = port_scan.run("127.0.0.1", ports="not-a-port", authorized=True)
        self.assertFalse(res["ok"])
        self.assertTrue(res["message"])

    def test_closed_port_not_reported(self):
        from modules.reconnaissance import port_scan
        dead = _free_port()
        res = port_scan.run("127.0.0.1", ports=[dead], timeout=0.4, authorized=True)
        self.assertTrue(res["ok"])
        self.assertEqual(res["open_ports"], [])


class TestWebAssessment(LocalServerCase):
    def test_detects_missing_headers(self):
        from modules.web_security import web_assess
        res = web_assess.run(self.url + "/missing-header")
        self.assertTrue(res["ok"])
        titles = " ".join(f["title"].lower() for f in res["findings"])
        self.assertTrue("content-security-policy" in titles or "csp" in titles)
        self.assertGreaterEqual(len(res["findings"]), 1)

    def test_server_header_detected(self):
        from modules.web_security import web_assess
        res = web_assess.run(self.url + "/")
        self.assertIn("ReaperTest", json.dumps(res))

    def test_cookie_without_flags_flagged(self):
        from modules.web_security import web_assess
        res = web_assess.run(self.url + "/cookie")
        self.assertTrue(res["ok"])
        self.assertIn("cookie", json.dumps(res).lower())

    def test_unreachable_target_degrades(self):
        from modules.web_security import web_assess
        dead = _free_port()
        res = web_assess.run(f"http://127.0.0.1:{dead}/", timeout=1.0)
        self.assertFalse(res["ok"])
        self.assertTrue(res["message"])

    def test_bad_scheme_rejected(self):
        from modules.web_security import web_assess
        res = web_assess.run("ftp://example.com")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "unsupported_scheme")


class TestFingerprint(LocalServerCase):
    def test_identifies_server(self):
        from modules.reconnaissance import fingerprint
        res = fingerprint.run(self.url)
        self.assertTrue(res["ok"])
        self.assertIn("ReaperTest", json.dumps(res))


class TestTls(LocalServerCase):
    """TLS tests need openssl; they are skipped when it is unavailable."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import shutil
        if not shutil.which("openssl"):
            raise unittest.SkipTest("openssl not installed")

    def _tls_server(self, certfile, keyfile):
        import shutil
        work = os.path.join(os.environ["HOME"], f"tls-{time.time_ns()}")
        os.makedirs(work, exist_ok=True)
        cert = os.path.join(work, "cert.pem")
        key = os.path.join(work, "key.pem")
        proc = shutil.which("openssl")
        subprocess.run(
            [proc, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", "1",
             "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True, timeout=60,
        )
        port = _free_port()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        def stop():
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

        return port, stop

    def test_self_signed_cert_is_analysed(self):
        from modules.reconnaissance import ssl_audit
        port, stop = self._tls_server(None, None)
        try:
            res = ssl_audit.run(f"https://127.0.0.1:{port}")
        finally:
            stop()
        self.assertTrue(res["ok"])
        joined = json.dumps(res).lower()
        self.assertIn("localhost", joined)
        # A self-signed leaf must be reported, not silently accepted.
        self.assertGreaterEqual(len(res["findings"]), 1)

    def test_unreachable_tls_reports_cleanly(self):
        from modules.reconnaissance import ssl_audit
        dead = _free_port()
        res = ssl_audit.run(f"https://127.0.0.1:{dead}", timeout=1.0)
        self.assertFalse(res["ok"])
        self.assertTrue(res["error"])


class TestGeoIpOffline(LocalServerCase):
    def test_private_ip_is_flagged_without_network(self):
        from modules.location_intelligence import geo_ip
        res = geo_ip.run("192.168.1.10")
        self.assertTrue(res["ok"])
        self.assertIn("private", json.dumps(res).lower())

    def test_invalid_ip_rejected(self):
        from modules.location_intelligence import geo_ip
        res = geo_ip.run("not-an-ip")
        self.assertFalse(res["ok"])


class TestCliSmoke(unittest.TestCase):
    """Runs the real entry point as a subprocess, exactly as a user would."""

    def run_cli(self, *args, timeout=90):
        env = dict(os.environ)
        env.update({
            "REAPER_ACCEPT_TERMS": "1",
            "REAPER_NONINTERACTIVE": "1",
            "NO_COLOR": "1",
            "PYTHONPATH": ROOT,
        })
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "main.py"), *args],
            capture_output=True, text=True, timeout=timeout, env=env, cwd=ROOT,
        )

    def test_version(self):
        from core.config import VERSION

        out = self.run_cli("--version")
        self.assertEqual(out.returncode, 0)
        self.assertIn(VERSION, out.stdout + out.stderr)

    def test_help_lists_every_command(self):
        out = self.run_cli("--help")
        self.assertEqual(out.returncode, 0)
        text = out.stdout + out.stderr
        for cmd in ("phone", "whatsapp", "geoip", "location", "domain",
                    "subdomains", "ssl", "ports", "fingerprint", "webscan",
                    "deps", "username", "threat", "history", "status",
                    "tools", "doctor", "dashboard", "config"):
            self.assertIn(cmd, text, cmd)

    def test_status_runs(self):
        from core.config import VERSION

        out = self.run_cli("status")
        self.assertEqual(out.returncode, 0)
        self.assertIn(VERSION, out.stdout)

    def test_tools_lists_modules(self):
        out = self.run_cli("tools")
        self.assertEqual(out.returncode, 0)
        self.assertIn("phone", out.stdout)

    def test_doctor_runs_without_traceback(self):
        out = self.run_cli("doctor")
        self.assertNotIn("Traceback", out.stdout + out.stderr)
        self.assertIn(out.returncode, (0, 1))

    def test_selftest_runs(self):
        out = self.run_cli("selftest", timeout=180)
        self.assertNotIn("Traceback", out.stdout + out.stderr)

    def test_phone_json_global_position(self):
        out = self.run_cli("--json", "phone", "+966501234567")
        self.assertEqual(out.returncode, 0)
        data = json.loads(out.stdout)
        self.assertEqual(data["e164"], "+966501234567")

    def test_phone_json_subcommand_position(self):
        out = self.run_cli("phone", "+966501234567", "--json")
        self.assertEqual(out.returncode, 0)
        data = json.loads(out.stdout)
        self.assertEqual(data["e164"], "+966501234567")

    def test_ports_json_refuses_without_authorization(self):
        out = self.run_cli("ports", "127.0.0.1", "--json")
        data = json.loads(out.stdout)
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "authorization_required")
        self.assertNotEqual(out.returncode, 0)

    def test_history_runs(self):
        out = self.run_cli("history")
        self.assertEqual(out.returncode, 0)

    def test_config_shows_no_secret_values(self):
        out = self.run_cli("config")
        self.assertEqual(out.returncode, 0)
        self.assertNotIn("sk-", out.stdout)

    def test_unknown_command_exits_two(self):
        out = self.run_cli("not-a-command")
        self.assertEqual(out.returncode, 2)

    def test_bad_target_has_no_traceback(self):
        out = self.run_cli("domain", "not a domain")
        self.assertNotIn("Traceback", out.stdout + out.stderr)


class TestDashboard(IsolatedHomeCase):
    def test_starts_serves_and_refuses_public_bind(self):
        import urllib.request
        from dashboard import server as dash

        port = _free_port()
        server = dash.create_server(host="127.0.0.1", port=port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                try:
                    with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/healthz", timeout=2) as r:
                        if r.status == 200:
                            break
                except OSError:
                    time.sleep(0.1)
            for route in ("/", "/healthz", "/api/system", "/api/history",
                          "/api/stats", "/api/providers", "/api/audit"):
                with urllib.request.urlopen(f"http://127.0.0.1:{port}{route}",
                                            timeout=5) as resp:
                    self.assertEqual(resp.status, 200, route)
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/nope", timeout=5)
            self.assertEqual(ctx.exception.code, 404)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_public_bind_rejected(self):
        from dashboard import server as dash
        with self.assertRaises(ValueError):
            dash.create_server(host="0.0.0.0", port=_free_port())


if __name__ == "__main__":
    unittest.main()
