# Phishing URL Awareness Checker

An offline, beginner-friendly Python command-line tool that reads the **text** of a URL and points out a few visible warning signs often seen in phishing links. Built for the **EWB Edutech Cybersecurity Internship** mini project.

> **Important:** This is an educational tool. It never opens a URL, scans a website or checks any reputation service. "No listed warning signs found" does **not** mean a URL is safe, and a warning does **not** mean a URL is malicious.

## 1. Overview: phishing and URL warning signs

Phishing is a trick in which an attacker sends a fake link or message to make a person share a password, card number or OTP. The fake link often imitates a real one. Some tricks leave visible clues in the URL text itself, such as a hidden destination, a bare IP address or an unencrypted connection. This tool checks six such clues. They are **clues, not proof**: honest links can show them, and dangerous links can show none (for example a name with a slightly wrong spelling).

## 2. Objectives

- Understand the parts of a URL (scheme, hostname, path).
- Practise Python functions, string handling, regular expressions and exception handling.
- Test a program honestly and document the real results.
- Publish a clean, understandable project on GitHub.

## 3. Features

- Six mandatory detection rules (see section 8)
- **Additional hints (extra feature):** hostname-only clues such as look-alike brand names, official-sounding words, free dynamic-DNS domains, often-abused endings, many hyphens and long digit runs, with a cautious overall level (see section 9)
- Plain-English explanation for every warning
- Numbered findings and a cautious summary line
- Loop for checking many URLs in one session (`q`, `quit`, `exit`)
- Safe handling of empty, malformed and unsupported input
- Works fully offline: no network access, no files read or written during analysis
- 47 automated unit tests plus 18 recorded manual test cases

## 4. Technology stack

Python 3.10+ and the standard library only: `urllib.parse`, `re`, `ipaddress` (and `unittest` for tests). No Flask, Django, machine learning, APIs, databases or third-party packages.

## 5. Requirements

Python 3.10 or later. No packages to install (`requirements.txt` only contains a comment).

## 6. Installation

```bash
git clone https://github.com/harsh0jaiswal002/phishing-url-awareness.git
cd phishing-url-awareness
```

## 7. How to run

| System | Command |
|---|---|
| Windows | `python phishing_checker.py` (or `py phishing_checker.py`) |
| macOS | `python3 phishing_checker.py` |
| Linux | `python3 phishing_checker.py` |

Run it from an open terminal inside the project folder (do not double-click the file). Type a sample URL and press Enter. Type `q`, `quit` or `exit` to stop.

## 8. The six detection rules

| # | Rule | What is checked | Why it matters | Possible false positives / limits |
|---|------|-----------------|----------------|-----------------------------------|
| 1 | **@ symbol** | An `@` anywhere in the URL text | In `example.com@sample.invalid` the browser treats `example.com` as "user information" and connects to `sample.invalid`. A quick glance shows the wrong name. | `@` also appears legitimately in paths or query strings (e.g. an email address in a parameter). The tool does not separate those cases. |
| 2 | **Long URL** | More than 100 characters | Long links can push the real destination or suspicious parts out of view. | Many honest links (tracking, search, login redirects) are long. Exactly 100 characters is not flagged. |
| 3 | **IP address hostname** | Hostname looks like four groups of 1-3 digits, e.g. `192.0.2.10` | Real services normally use readable names; a bare number hides ownership. | Routers and internal tools use IPs legitimately. The check is pattern-only, so `999.999.999.999` is also flagged. IPv6 and other numeric forms (hex, decimal) are **not** detected. |
| 4 | **Many hostname segments** | Five or more dot-separated parts | Stacking names (`a.b.c.d.e.example.invalid`) can make a link look official. The real domain is at the right-hand end. | Large organisations sometimes use deep subdomains. Counting parts does not tell which part is the registered domain. |
| 5 | **Punycode marker** | `xn--` in the hostname | Internationalized domain names (IDNs) are stored as `xn--...`. Attackers can register look-alike characters (a *homograph attack*). | Many genuine international sites use punycode. A raw non-ASCII hostname typed directly is not flagged. |
| 6 | **HTTP scheme** | Scheme is `http` | HTTP is not encrypted, so data can be read in transit. HTTPS encrypts the connection. | **HTTPS is not proof of legitimacy**; attackers can use HTTPS too. If no scheme is typed, `http://` is assumed (a note is printed). |

### Additional hints (extra feature, not part of the six rules)

After the six rules, the program also reads the hostname text for weaker clues. They are shown separately as `H1`, `H2`, ... and do **not** change the `REVIEW CAREFULLY: N warning sign(s)` count, which counts only the six core rules.

| Hint | What it looks for | Possible false positives |
|---|---|---|
| Brand look-alike | A well-known brand name in a domain that is not that brand's own, or a name one letter off (`amayon`, `paypa1`) | Fan sites, resellers and unrelated names that happen to be similar |
| Official-sounding words | `secure`, `verify`, `account`, `update`, `login` ... in the hostname | Honest sites such as `accounts.google.com` also contain them |
| Free dynamic-DNS domain | e.g. `duckdns.org`, `no-ip.com`, `servebbs.org` | Hobby and testing use is common |
| Often-abused ending | e.g. `.xyz`, `.top`, `.click` | Many honest sites use them |
| Many hyphens | Two or more hyphens in the main domain name | Some honest names are hyphenated |
| Long digit run | Four or more digits in a row in the hostname | Honest names such as `web3000` |

**Overall level:** 1-2 clues in total (core warnings + hints) gives "Some clues found, review carefully". 3 or more gives "MANY SUSPICIOUS PATTERNS ... do not open it or enter any details", followed by a statement that this is a text-based opinion, **not a confirmed verdict**. The tool never says a site *is* phishing or malicious, because an offline text check cannot know that. The brand list and word lists are short and hand-written, so many real tricks will still be missed.

## 9. Example terminal output

Real output from one run (the sample name uses the reserved `.example` ending, so it is not a real site; what follows each prompt is what the user typed):

```text
============================================================
  EWB Phishing URL Awareness Checker
============================================================
Text checks only - this program does not open URLs.
Use sample strings only. Type q, quit or exit to stop.

Enter a sample URL (or q to quit): http://amayon-security-update.example
------------------------------------------------------------
RESULT
------------------------------------------------------------
  1. Uses HTTP. HTTPS alone does not prove trust.
     Why it matters: HTTP is not encrypted, so data can be read on the way. Note that HTTPS only means the connection is encrypted; it does not prove the site is honest.

Additional hints (extra checks on the hostname text):
  H1. 'amayon' looks like a misspelling or look-alike of 'amazon'.
      Why it matters: Attackers register names that imitate well-known brands. Check the main domain (the part just before the ending, like .com) carefully.
  H2. Hostname contains official-sounding words: security, update.
      Why it matters: Words like 'secure' or 'verify' are used to sound official. Real brands use them too, so this is only a weak clue.
  H3. The main domain name contains several hyphens.
      Why it matters: Names stuffed with hyphens (like word-word-word.com) are common in imitation sites. Some honest sites do this too.

REVIEW CAREFULLY: 1 warning sign(s) found.
(The count is only a rough clue, not the chance of phishing.)

OVERALL: MANY SUSPICIOUS PATTERNS (4 clues). This link resembles common phishing patterns. Do not open it or enter any details.
This is a text-based opinion only, not a confirmed verdict: the tool cannot know whether the site is really malicious.

Never enter passwords from unexpected links.

Enter a sample URL (or q to quit): q
Goodbye! Stay alert online.
```

## 10. Testing

Two kinds of evidence are included:

1. **Manual cases** (`tests/test_samples.md`): 18 cases (the 5 mandatory workbook cases plus 13 extra) run through the real program. The table records the Python version, operating system, date, input, expected result, actual result and PASS/FAIL. It is generated by `tests/generate_test_evidence.py`, so results are observed, not typed by hand.
2. **Automated unit tests** (`tests/test_checker.py`): 47 tests covering the rules, the additional hints, boundary values (100 vs 101 characters, 4 vs 5 segments), malformed input, the loop, quit commands and an import check that the program uses only `re`, `ipaddress` and `urllib.parse`.

```bash
python3 -m unittest discover -s tests -v     # automated tests
python3 tests/generate_test_evidence.py      # re-run manual cases, rewrite test_samples.md
```

**Results on the development run** (Python 3.12.3, Linux): 47/47 unit tests passed and 18/18 manual cases passed. Re-run both on your own machine to get evidence for your own operating system. Passing tests only shows the rules behave as designed; it does not measure how well the tool detects real phishing.

## 11. Improvements implemented

| ID | Improvement | What changed and how it was tested |
|----|-------------|-------------------------------------|
| A | Repeated analysis | `main()` uses a `while True` loop; `q`, `quit`, `exit` stop it. Tested with scripted multi-URL sessions. |
| B | Warning summary | Prints `REVIEW CAREFULLY: N warning sign(s) found.` with a reminder that the count is not a probability. Helper `has_warnings()` separates warnings from information messages. |
| C | Malformed input handling | `try/except ValueError` around parsing; also handles empty input, spaces, bad ports, invalid hostnames, malformed IPv6 and unsupported schemes (`ftp://`, `javascript:`, `mailto:`). A test feeds many odd strings and checks nothing raises. |
| D | Warning explanations | Dictionary `WARNING_EXPLANATIONS` gives a short reason for each warning. A test checks every warning has one. |
| F | Additional hints and overall level (extra) | `find_extra_hints()` and `overall_assessment()` add hostname-only clues and a cautious overall line without changing the six rules. Tested for look-alikes, real brand domains (no false hint), dynamic DNS, TLDs, hyphens, digits, bad input and IP hosts. |
| E | Terminal interface | Banner, headings, numbered findings, spacing and instructions. |

All five workbook tests were re-run after each improvement. The six warning messages keep the workbook's exact wording.

## 12. Screenshots

![Sample run](screenshots/sample_run.png)
![Test results](screenshots/test_results.png)

## 13. Known limitations and false positives

- Reads text only: no DNS, no page content, no reputation data, no malware scanning.
- The six core rules and the extra hints are the only clues checked, and the hint lists are short and hand-written. Lookalike spellings (e.g. a slightly misspelled brand), misleading path words, URL shorteners and many other tricks are **not** detected.
- Honest URLs can trigger warnings (long tracking links, deep subdomains, IP-based internal tools, international domains).
- Missing-scheme input is treated as `http://`, so it shows the HTTP warning.
- IPv4 detection is pattern-based; IPv6 literals, hex/decimal IP forms are not flagged.
- - The warning count and overall level are not validated scores or probabilities, and were not measured against real phishing data.

## 14. Ethical use

Defensive learning only. Use sample strings (such as `example.com`, `.invalid` names and documentation IP `192.0.2.x`). Do not test with real suspicious links, collect credentials, or probe websites or networks without written permission. Do not present this tool's output as a definitive safe/malicious verdict.

## 15. Future improvements

Suspicious keywords in the path, detection of look-alike brand names, IPv6 and alternate IP formats, URL-shortener awareness, and configurable thresholds, all still text-only and offline.

## 16. Project structure

```text
phishing-url-awareness/
├── phishing_checker.py
├── README.md
├── requirements.txt
├── .gitignore
├── tests/
│   ├── test_samples.md
│   ├── test_checker.py
│   └── generate_test_evidence.py
└── screenshots/
    ├── sample_run.png
    └── test_results.png
```

## 17. Author

- **Name:** Harsh Jaiswal
- **Course:** B.Tech Computer Science and Engineering (Cyber Security)
- **University:** Gautam Buddha University
- **Internship:** EWB Edutech Cybersecurity Internship
- **GitHub:** https://github.com/harsh0jaiswal002
