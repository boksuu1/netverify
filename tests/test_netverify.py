import contextlib
import io
import json
import os
import socket
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from netverify import cli, core, dnscheck, httpcheck, report, tlscheck


def reply(txid, name, ips, rcode=0):
    header = struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, len(ips), 0, 0)
    question = dnscheck.build_query(name, txid)[12:]
    answers = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip) for ip in ips)
    return header + question + answers


def cert(host, issuer, valid=True):
    return {"host": host, "valid": valid, "issuer": issuer, "error": ""}


class DnsTests(unittest.TestCase):
    def verdict(self, got, ref, outcome="valid"):
        with mock.patch.object(dnscheck, "probe", return_value=outcome):
            return dnscheck.judge("example.com", set(got), set(ref), 1)[0]

    def test_query_layout(self):
        query = dnscheck.build_query("example.com", 0x1234)
        self.assertEqual(query[:2], b"\x12\x34")
        self.assertTrue(query.endswith(b"\x00\x00\x01\x00\x01"))

    def test_parse_reply(self):
        parsed = dnscheck.parse_response(reply(7, "example.com", ["1.2.3.4", "5.6.7.8"]))
        self.assertEqual(parsed, (7, 0, {"1.2.3.4", "5.6.7.8"}))

    def test_parse_nxdomain(self):
        _, rcode, ips = dnscheck.parse_response(reply(1, "x.example.com", [], rcode=3))
        self.assertEqual((rcode, ips), (3, set()))

    def test_bogus_addresses(self):
        self.assertTrue(dnscheck.is_bogus("10.0.0.1"))
        self.assertTrue(dnscheck.is_bogus("127.0.0.1"))
        self.assertFalse(dnscheck.is_bogus("8.8.8.8"))

    def test_matching_answers(self):
        self.assertEqual(self.verdict(["1.1.1.1"], ["1.1.1.1", "2.2.2.2"]), "ok")

    def test_other_address_with_valid_certificate(self):
        self.assertEqual(self.verdict(["140.82.113.4"], ["140.82.121.3"], "valid"), "ok")

    def test_other_address_with_invalid_certificate(self):
        self.assertEqual(self.verdict(["6.6.6.6"], ["140.82.121.3"], "invalid"), "fail")

    def test_other_address_unreachable(self):
        self.assertEqual(self.verdict(["6.6.6.6"], ["140.82.121.3"], "unreachable"), "warn")

    def test_private_address(self):
        self.assertEqual(self.verdict(["192.168.1.1"], ["93.184.216.34"]), "fail")

    def test_empty_answer(self):
        self.assertEqual(self.verdict([], ["93.184.216.34"]), "fail")

    def test_compare_without_data(self):
        self.assertEqual(dnscheck.compare("x", None, {"1.1.1.1"}, 1)["status"], "skip")
        self.assertEqual(dnscheck.compare("x", {"1.1.1.1"}, set(), 1)["status"], "skip")


class TlsTests(unittest.TestCase):
    def test_distinct_issuers(self):
        results = [cert("a", "DigiCert"), cert("b", "Let's Encrypt"), cert("c", "Google Trust Services")]
        self.assertEqual(tlscheck.judge(results)[0], "ok")

    def test_same_issuer_everywhere(self):
        results = [cert("a", "Proxy CA"), cert("b", "Proxy CA"), cert("c", "Proxy CA")]
        self.assertEqual(tlscheck.judge(results)[0], "fail")

    def test_two_failures(self):
        results = [cert("a", "", False), cert("b", "", False), cert("c", "X")]
        self.assertEqual(tlscheck.judge(results)[0], "fail")

    def test_single_failure(self):
        results = [cert("a", "", False), cert("b", "X"), cert("c", "Y")]
        self.assertEqual(tlscheck.judge(results)[0], "warn")

    def test_unreachable_sites(self):
        results = [cert("a", "", None), cert("b", "", None), cert("c", "X")]
        self.assertEqual(tlscheck.judge(results)[0], "skip")


class HttpTests(unittest.TestCase):
    def test_portal_expected(self):
        self.assertEqual(httpcheck.judge_portal(204, b"", 204, b"")[0], "ok")
        self.assertEqual(httpcheck.judge_portal(200, b"success\n", 200, b"success")[0], "ok")

    def test_portal_redirect(self):
        self.assertEqual(httpcheck.judge_portal(302, b"", 204, b"")[0], "fail")

    def test_portal_login_page(self):
        self.assertEqual(httpcheck.judge_portal(200, b"<html>login</html>", 204, b"")[0], "fail")

    def test_portal_server_error(self):
        self.assertEqual(httpcheck.judge_portal(503, b"", 204, b"")[0], "warn")

    def test_identical_pages(self):
        plain = (200, {}, b"<html> hi </html>")
        secure = (200, {}, b"<html>\nhi\n</html>")
        self.assertEqual(httpcheck.judge_injection(plain, secure)[0], "ok")

    def test_injected_script(self):
        plain = (200, {}, b"<html>hi<script src=x></script></html>")
        secure = (200, {}, b"<html>hi</html>")
        self.assertEqual(httpcheck.judge_injection(plain, secure)[0], "fail")

    def test_different_pages(self):
        self.assertEqual(httpcheck.judge_injection((200, {}, b"a"), (200, {}, b"b"))[0], "warn")

    def test_upgrade_redirect(self):
        plain = (301, {"location": "https://example.com/"}, b"")
        self.assertEqual(httpcheck.judge_injection(plain, (200, {}, b"x"))[0], "ok")

    def test_foreign_redirect(self):
        plain = (302, {"location": "http://portal.hotel.net/login"}, b"")
        self.assertEqual(httpcheck.judge_injection(plain, (200, {}, b"x"))[0], "fail")


class ReportTests(unittest.TestCase):
    def test_verdicts(self):
        ok, skip, fail = (core.finding("a", status, "x") for status in ("ok", "skip", "fail"))
        self.assertEqual(report.verdict([ok, ok]), "ok")
        self.assertEqual(report.verdict([ok, skip, skip]), "skip")
        self.assertEqual(report.verdict([skip, skip, fail]), "fail")
        self.assertEqual(report.EXIT[report.verdict([ok, fail])], 2)

    def test_json(self):
        data = json.loads(report.render_json([core.finding("a", "ok", "x")]))
        self.assertEqual(data["verdict"], "ok")

    def test_text(self):
        self.assertIn("HONEST", report.render_text([core.finding("a", "ok", "x")], False))


class CliTests(unittest.TestCase):
    def run_cli(self, args, checks):
        with mock.patch.dict(cli.CHECKS, checks), contextlib.redirect_stdout(io.StringIO()):
            return cli.main(args)

    def test_exit_code_follows_verdict(self):
        checks = {
            "dns": lambda timeout: [core.finding("a", "fail", "x")],
            "tls": lambda timeout: [],
            "http": lambda timeout: [],
        }
        self.assertEqual(self.run_cli(["--json"], checks), 2)

    def test_flag_selects_checks(self):
        checks = {
            "dns": lambda timeout: [core.finding("a", "ok", "x")],
            "tls": lambda timeout: [core.finding("b", "fail", "x")],
            "http": lambda timeout: [],
        }
        self.assertEqual(self.run_cli(["--dns"], checks), 0)


if __name__ == "__main__":
    unittest.main()
