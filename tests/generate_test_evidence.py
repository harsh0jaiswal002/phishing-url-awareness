"""Run the real program for each manual test case and write tests/test_samples.md.

Usage (from the project folder):
    python tests/generate_test_evidence.py       (Windows)
    python3 tests/generate_test_evidence.py      (Mac / Linux)

Each case starts phishing_checker.py as a separate process, types the input
for it, and records what was REALLY printed. PASS/FAIL is decided by comparing
that output with the expectation, never written by hand.
"""

import datetime
import os
import platform
import re
import subprocess
import sys

PROJECT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PROGRAM = os.path.join(PROJECT_DIR, "phishing_checker.py")
OUTPUT_FILE = os.path.join(PROJECT_DIR, "tests", "test_samples.md")

# (name, [typed lines], expected description, [required text], expected warning count, observation)
CASES = [
    ("1", ["https://www.example.com/login"], "No listed warning signs",
     ["No listed warning signs found"], 0, "Mandatory. Not a safety guarantee."),
    ("2", ["http://192.0.2.10/account"], "IP address + HTTP",
     ["Uses an IP address", "Uses HTTP"], 2, "Mandatory."),
    ("3", ["http://example.com@sample.invalid/login"], "@ symbol + HTTP",
     ["Contains an @ symbol", "Uses HTTP"], 2, "Mandatory."),
    ("4", ["https://a.b.c.d.e.example.invalid/path"], "Many hostname segments",
     ["many hostname segments"], 1, "Mandatory. Hostname has 7 parts."),
    ("5", ["https://xn--example.invalid/"], "Punycode-style hostname",
     ["punycode-style hostname"], 1, "Mandatory."),
    ("6", [""], "Friendly message, no crash",
     ["No URL entered."], 0, "Extra: empty input."),
    ("7", ["https://www.example.com/" + "a" * 90], "Long URL warning (114 chars)",
     ["Unusually long URL"], 1, "Extra: URL over 100 characters."),
    ("8", ["www.example.com"], "HTTP assumed + note about missing scheme",
     ["Uses HTTP", "no scheme was typed"], 1, "Extra: URL without a scheme."),
    ("9", ["http://[bad"], "Friendly message, no crash",
     ["not a valid URL format"], 0, "Extra: malformed IPv6 text."),
    ("10", ["http://x@a.b.c.d.xn--e.invalid/" + "p" * 90], "5 warnings + summary",
     ["Contains an @ symbol", "Unusually long URL", "many hostname segments",
      "punycode-style", "Uses HTTP", "REVIEW CAREFULLY: 5 warning sign(s) found."], 5,
     "Extra: many warnings in one URL."),
    ("11", ["http://192.0.2.10/account", "https://www.example.com/login"],
     "Two results in one session",
     ["Uses an IP address", "No listed warning signs found"], 2, "Extra: repeated analysis."),
    ("12", [], "Program says goodbye and stops",
     ["Goodbye"], 0, "Extra: quit command ('exit' typed)."),
    ("13", ["https://docs.example.org/guide/start"], "No listed warning signs",
     ["No listed warning signs found"], 0, "Extra: clean URL. Not a safety guarantee."),
    ("14", ["ftp://example.com/file"], "Unsupported scheme message",
     ["Unsupported or incomplete URL scheme"], 0, "Extra: unsupported scheme."),
    ("15", ["http://exa..mple.com/"], "Invalid hostname message",
     ["hostname is not valid"], 0, "Extra: invalid hostname."),
    ("16", ["http://amayon-security-update.example"], "HTTP + look-alike/word/hyphen hints, overall high",
     ["Uses HTTP", "look-alike of 'amazon'", "official-sounding words", "several hyphens",
      "MANY SUSPICIOUS PATTERNS (4 clues)", "not a confirmed verdict"], 1,
     "Extra feature: additional hints. Reserved .example name used."),
    ("17", ["https://secure-transaction-id-8294.invalid"], "No core warnings, but 3 extra hints",
     ["No listed warning signs found", "official-sounding words", "long run of digits",
      "MANY SUSPICIOUS PATTERNS (3 clues)"], 0,
     "Extra feature: core rules find nothing, hints still raise the overall level."),
    ("18", ["https://sample-name.duckdns.org/page"], "Dynamic-DNS hint only",
     ["free dynamic-DNS", "Some clues found (1)"], 0, "Extra feature: free dynamic-DNS domain."),
]



def run_case(typed_lines):
    """Start the program, type the lines (then 'exit'), return its output."""
    stdin_text = "\n".join(typed_lines + ["exit"]) + "\n"
    done = subprocess.run([sys.executable, PROGRAM], input=stdin_text,
                          capture_output=True, text=True, timeout=30)
    return done.stdout, done.returncode


def summarise(output):
    """Pull the result lines out of the real output (short form)."""
    parts = []
    for line in output.splitlines():
        text = line.strip()
        if re.match(r"(H?\d+\. )", text) or text.startswith("- ") or text.startswith("OVERALL") or text.startswith("REVIEW") \
                or text.startswith("Note:"):
            parts.append(text.replace("|", "/"))
    if "Goodbye" in output and not parts:
        parts.append("Goodbye! Stay alert online.")
    return "<br>".join(parts)


def main():
    rows, passed = [], 0
    for name, typed, expected, required, count, note in CASES:
        output, code = run_case(typed)
        found = len(re.findall(r"^\s+\d+\. ", output, re.MULTILINE))
        ok = code == 0 and all(t in output for t in required) and found == count
        passed += ok
        shown = " then ".join(f"`{t}`" if t else "(empty line)" for t in typed) or "`exit`"
        shown = shown.replace("|", "/")
        if len(shown) > 70:
            shown = shown[:67] + "..."
        rows.append(f"| {name} | {shown} | {expected} | {summarise(output)} | "
                    f"{'PASS' if ok else 'FAIL'} | {note} |")

    header = (
        "# Test Results\n\n"
        f"Python version used: {platform.python_version()} | "
        f"Operating system: {platform.system()} {platform.release()} | "
        f"Date: {datetime.date.today().isoformat()}\n\n"
        "These results were produced by running `phishing_checker.py` as a real process for each "
        "case (`python tests/generate_test_evidence.py`). Tests 1-5 are the mandatory workbook "
        "cases; 6-18 are extra.\n\n"
        "| # | Input | Expected result | Actual result | Pass/Fail | Observations |\n"
        "|---|-------|-----------------|---------------|-----------|--------------|\n"
    )
    footer = f"\n**Summary: {passed} of {len(CASES)} manual cases passed.**\n"
    with open(OUTPUT_FILE, "w", encoding="utf-8") as handle:
        handle.write(header + "\n".join(rows) + "\n" + footer)
    print(f"Wrote {OUTPUT_FILE}: {passed}/{len(CASES)} passed")


if __name__ == "__main__":
    main()
