"""Automated tests. Run from the project folder with:

    python -m unittest discover -s tests -v        (Windows)
    python3 -m unittest discover -s tests -v       (Mac / Linux)
"""

import ast
import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import phishing_checker as pc  # noqa: E402


def run_session(inputs):
    """Run main() with scripted keyboard input; return everything it printed."""
    buffer = io.StringIO()
    with patch("builtins.input", side_effect=inputs), redirect_stdout(buffer):
        pc.main()
    return buffer.getvalue()


class MandatoryWorkbookTests(unittest.TestCase):
    def test_1_clean_url(self):
        self.assertEqual(pc.inspect_url("https://www.example.com/login"), [pc.MSG_NO_WARNINGS])

    def test_2_ip_and_http(self):
        self.assertEqual(pc.inspect_url("http://192.0.2.10/account"), [pc.MSG_IP_HOST, pc.MSG_HTTP])

    def test_3_at_and_http(self):
        self.assertEqual(
            pc.inspect_url("http://example.com@sample.invalid/login"),
            [pc.MSG_AT_SYMBOL, pc.MSG_HTTP],
        )

    def test_4_many_segments(self):
        self.assertEqual(
            pc.inspect_url("https://a.b.c.d.e.example.invalid/path"), [pc.MSG_MANY_SEGMENTS]
        )

    def test_5_punycode(self):
        self.assertEqual(pc.inspect_url("https://xn--example.invalid/"), [pc.MSG_PUNYCODE])


class RuleBoundaryTests(unittest.TestCase):
    def test_length_exactly_100_not_flagged(self):
        url = "https://www.example.com/" + "a" * (100 - len("https://www.example.com/"))
        self.assertEqual(len(url), 100)
        self.assertNotIn(pc.MSG_LONG_URL, pc.inspect_url(url))

    def test_length_101_flagged(self):
        url = "https://www.example.com/" + "a" * (101 - len("https://www.example.com/"))
        self.assertEqual(len(url), 101)
        self.assertIn(pc.MSG_LONG_URL, pc.inspect_url(url))

    def test_four_segments_not_flagged_five_flagged(self):
        self.assertNotIn(pc.MSG_MANY_SEGMENTS, pc.inspect_url("https://a.b.example.invalid/"))
        self.assertIn(pc.MSG_MANY_SEGMENTS, pc.inspect_url("https://a.b.c.example.invalid/"))

    def test_https_ip_flags_ip_only(self):
        self.assertEqual(pc.inspect_url("https://192.0.2.10/"), [pc.MSG_IP_HOST])

    def test_uppercase_scheme_and_host(self):
        self.assertEqual(pc.inspect_url("HTTP://EXAMPLE.INVALID/"), [pc.MSG_HTTP])

    def test_userinfo_hides_ip_host(self):
        result = pc.inspect_url("https://example.com@192.0.2.10/")
        self.assertIn(pc.MSG_AT_SYMBOL, result)
        self.assertIn(pc.MSG_IP_HOST, result)

    def test_port_is_not_part_of_hostname(self):
        self.assertEqual(pc.inspect_url("https://www.example.com:8443/x"), [pc.MSG_NO_WARNINGS])

    def test_multiple_warnings(self):
        url = "http://x@a.b.c.d.xn--e.invalid/" + "p" * 90
        self.assertEqual(
            pc.inspect_url(url),
            [pc.MSG_AT_SYMBOL, pc.MSG_LONG_URL, pc.MSG_MANY_SEGMENTS, pc.MSG_PUNYCODE, pc.MSG_HTTP],
        )

    def test_clean_https_url(self):
        self.assertEqual(pc.inspect_url("https://docs.example.org/guide/start"), [pc.MSG_NO_WARNINGS])


class InputHandlingTests(unittest.TestCase):
    def test_empty_and_spaces(self):
        self.assertEqual(pc.inspect_url(""), [pc.MSG_EMPTY])
        self.assertEqual(pc.inspect_url("    "), [pc.MSG_EMPTY])

    def test_missing_scheme_assumes_http(self):
        self.assertEqual(pc.inspect_url("www.example.com"), [pc.MSG_HTTP])

    def test_malformed_ipv6(self):
        self.assertEqual(pc.inspect_url("http://[bad"), [pc.MSG_INVALID_FORMAT])

    def test_valid_ipv6_does_not_crash(self):
        self.assertEqual(pc.inspect_url("https://[::1]/"), [pc.MSG_NO_WARNINGS])

    def test_bad_port(self):
        self.assertEqual(pc.inspect_url("http://example.com:99999999/"), [pc.MSG_INVALID_FORMAT])
        self.assertEqual(pc.inspect_url("http://example.com:abc/"), [pc.MSG_INVALID_FORMAT])

    def test_invalid_hostnames(self):
        self.assertEqual(pc.inspect_url("http://exa..mple.com/"), [pc.MSG_INVALID_HOST])
        self.assertEqual(pc.inspect_url("http://.example.com/"), [pc.MSG_INVALID_HOST])

    def test_no_hostname(self):
        self.assertEqual(pc.inspect_url("http:///path"), [pc.MSG_NO_HOST])

    def test_unsupported_schemes(self):
        for text in ("ftp://example.com/file", "javascript:alert(1)", "mailto:a@example.com",
                     "http:example.com", "://example.com"):
            self.assertEqual(pc.inspect_url(text), [pc.MSG_UNSUPPORTED_SCHEME], text)

    def test_spaces_inside_url(self):
        self.assertEqual(pc.inspect_url("http://exa mple.com"), [pc.MSG_INVALID_FORMAT])

    def test_non_string_input(self):
        self.assertEqual(pc.inspect_url(None), [pc.MSG_INVALID_FORMAT])

    def test_host_with_port_but_no_scheme(self):
        self.assertEqual(pc.inspect_url("example.com:8080/x"), [pc.MSG_HTTP])

    def test_weird_inputs_never_raise(self):
        for text in ("http://[", "http://]", "https://", "////", "http://@", "http://:80",
                     "http://[::1", "\x00", "http://a@b@c", "%%%", "http://xn--"):
            result = pc.inspect_url(text)
            self.assertIsInstance(result, list)
            self.assertTrue(result)


class InterfaceTests(unittest.TestCase):
    def test_every_warning_has_explanation(self):
        for message in (pc.MSG_AT_SYMBOL, pc.MSG_LONG_URL, pc.MSG_IP_HOST,
                        pc.MSG_MANY_SEGMENTS, pc.MSG_PUNYCODE, pc.MSG_HTTP):
            self.assertTrue(pc.WARNING_EXPLANATIONS[message])

    def test_has_warnings_helper(self):
        self.assertTrue(pc.has_warnings([pc.MSG_HTTP]))
        self.assertFalse(pc.has_warnings([pc.MSG_NO_WARNINGS]))
        self.assertFalse(pc.has_warnings([pc.MSG_EMPTY]))

    def test_summary_line(self):
        report = pc.format_report("http://192.0.2.10/account")
        self.assertIn("REVIEW CAREFULLY: 2 warning sign(s) found.", report)
        self.assertIn("1. " + pc.MSG_IP_HOST, report)
        self.assertIn("2. " + pc.MSG_HTTP, report)

    def test_no_summary_without_warnings(self):
        report = pc.format_report("https://www.example.com/login")
        self.assertNotIn("REVIEW CAREFULLY", report)
        self.assertIn("does NOT prove safety", report)

    def test_repeated_analysis_then_quit(self):
        output = run_session(["http://192.0.2.10/account", "https://www.example.com/login", "q"])
        self.assertEqual(output.count("RESULT"), 2)
        self.assertIn("Goodbye", output)

    def test_all_quit_commands(self):
        for command in ("q", "quit", "exit", "  QUIT  "):
            self.assertIn("Goodbye", run_session([command]))

    def test_empty_input_keeps_program_running(self):
        output = run_session(["", "q"])
        self.assertIn(pc.MSG_EMPTY, output)
        self.assertIn("Goodbye", output)

    def test_malformed_input_keeps_program_running(self):
        output = run_session(["http://[bad", "q"])
        self.assertIn(pc.MSG_INVALID_FORMAT, output)
        self.assertIn("Goodbye", output)

    def test_end_of_input_exits_cleanly(self):
        self.assertIn("Goodbye", run_session(EOFError()))


class ExtraHintTests(unittest.TestCase):
    def messages(self, url):
        return [message for message, _ in pc.find_extra_hints(url)]

    def test_mandatory_samples_get_no_extra_hints(self):
        for url in ("https://www.example.com/login", "http://192.0.2.10/account",
                    "http://example.com@sample.invalid/login",
                    "https://a.b.c.d.e.example.invalid/path", "https://xn--example.invalid/"):
            self.assertEqual(pc.find_extra_hints(url), [], url)

    def test_lookalike_brand(self):
        self.assertTrue(any("look-alike of 'amazon'" in m
                            for m in self.messages("http://amayon-login.example")))

    def test_digit_swap_lookalike(self):
        self.assertTrue(any("'paypal'" in m for m in self.messages("https://paypa1.example")))

    def test_real_brand_domain_not_flagged_as_brand(self):
        for url in ("https://www.amazon.com/", "https://www.amazon.co.uk/", "https://docs.google.com/"):
            self.assertFalse(any("brand" in m or "look-alike" in m for m in self.messages(url)), url)

    def test_brand_in_foreign_domain(self):
        self.assertTrue(any("brand name 'paypal'" in m
                            for m in self.messages("https://paypal.sample-site.example")))

    def test_dynamic_dns_and_tld(self):
        self.assertTrue(any("dynamic-DNS" in m for m in self.messages("https://sample.duckdns.org/")))
        self.assertTrue(any(".xyz" in m for m in self.messages("https://sample.xyz/")))

    def test_hyphens_and_digits(self):
        result = self.messages("https://secure-transaction-id-8294.invalid")
        self.assertTrue(any("hyphens" in m for m in result))
        self.assertTrue(any("digits" in m for m in result))

    def test_bad_input_and_ip_give_no_hints(self):
        for url in ("", "http://[bad", "ftp://x.example", "http://192.0.2.10/secure-login", "https://[::1]/"):
            self.assertEqual(pc.find_extra_hints(url), [], url)

    def test_overall_levels(self):
        self.assertEqual(pc.overall_assessment(0, 0), "")
        self.assertIn("Some clues", pc.overall_assessment(1, 1))
        self.assertIn("MANY SUSPICIOUS PATTERNS", pc.overall_assessment(1, 2))

    def test_report_is_cautious_not_a_verdict(self):
        report = pc.format_report("http://amayon-security-update.example")
        self.assertIn("MANY SUSPICIOUS PATTERNS", report)
        self.assertIn("not a confirmed verdict", report)
        self.assertNotIn("is malicious", report)

    def test_clean_url_report_unchanged(self):
        report = pc.format_report("https://www.example.com/login")
        self.assertNotIn("OVERALL", report)
        self.assertNotIn("Additional hints", report)


class OfflineGuaranteeTest(unittest.TestCase):
    def test_only_allowed_imports(self):
        """The program may import only these standard-library modules."""
        path = os.path.join(os.path.dirname(__file__), "..", "phishing_checker.py")
        with open(path, encoding="utf-8") as source_file:
            tree = ast.parse(source_file.read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        self.assertEqual(imported, {"ipaddress", "re", "urllib.parse"})


if __name__ == "__main__":
    unittest.main()
