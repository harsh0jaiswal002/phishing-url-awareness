"""Phishing URL Awareness Checker.

A small, offline, educational command-line tool. It reads URL *text* and
points out a few visible warning signs often seen in phishing links.

What it does NOT do:
- It never opens a URL, makes a network request, or scans a website.
- It cannot prove that a URL is safe or malicious. These are clues only.

Only Python's standard library is used.

Besides the six core workbook rules, an extra "additional hints" feature looks
at the hostname text only (look-alike brand names, official-sounding words,
free dynamic-DNS domains, often-abused TLDs, and similar clues). It is a
rough pattern check, not a verdict.
"""

import ipaddress
import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Settings (kept in one place so they are easy to explain and change)
# ---------------------------------------------------------------------------
MAX_URL_LENGTH = 100           # Rule 2: more than this many characters is flagged
MANY_SEGMENTS_THRESHOLD = 5    # Rule 4: this many hostname parts or more is flagged
QUIT_COMMANDS = ("q", "quit", "exit")
IPV4_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"   # four groups of 1-3 digits

# ---------------------------------------------------------------------------
# Messages. The six warning texts match the EWB workbook exactly.
# ---------------------------------------------------------------------------
MSG_AT_SYMBOL = "Contains an @ symbol; inspect carefully."
MSG_LONG_URL = "Unusually long URL (over 100 characters)."
MSG_IP_HOST = "Uses an IP address instead of a familiar domain."
MSG_MANY_SEGMENTS = "Contains many hostname segments/subdomains."
MSG_PUNYCODE = "Contains a punycode-style hostname."
MSG_HTTP = "Uses HTTP. HTTPS alone does not prove trust."

# Information / error messages (these are NOT warning signs)
MSG_NO_WARNINGS = "No listed warning signs found. This does NOT prove safety."
MSG_EMPTY = "No URL entered."
MSG_NO_HOST = "Could not identify a hostname."
MSG_INVALID_FORMAT = "This text is not a valid URL format."
MSG_INVALID_HOST = "The hostname is not valid (for example, empty parts or bad characters)."
MSG_UNSUPPORTED_SCHEME = (
    "Unsupported or incomplete URL scheme. Only http:// and https:// are analyzed."
)

ERROR_MESSAGES = (
    MSG_EMPTY,
    MSG_NO_HOST,
    MSG_INVALID_FORMAT,
    MSG_INVALID_HOST,
    MSG_UNSUPPORTED_SCHEME,
)

# Improvement D: a short, beginner-friendly reason for every warning.
WARNING_EXPLANATIONS = {
    MSG_AT_SYMBOL: (
        "Browsers ignore the text before @ (it is 'user information'). "
        "A link can look like one site but really go to the host after the @."
    ),
    MSG_LONG_URL: (
        "Long links can push the important part out of sight. "
        "Many honest links are long too."
    ),
    MSG_IP_HOST: (
        "Real services usually use readable names. A bare number hides who owns "
        "the site, though some internal tools legitimately use IPs."
    ),
    MSG_MANY_SEGMENTS: (
        "Stacking many names (a.b.c.d.e...) can make a link look official. "
        "Read the hostname from right to left to find the real domain."
    ),
    MSG_PUNYCODE: (
        "'xn--' marks an internationalized name written in plain letters. "
        "Attackers can use look-alike characters, but many real international "
        "sites use it too."
    ),
    MSG_HTTP: (
        "HTTP is not encrypted, so data can be read on the way. Note that "
        "HTTPS only means the connection is encrypted; it does not prove the "
        "site is honest."
    ),
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def has_warnings(findings):
    """Return True if the list contains at least one real warning sign."""
    return any(item in WARNING_EXPLANATIONS for item in findings)


def get_explicit_scheme(url):
    """Return the scheme the user typed (lowercase), or None if there is none.

    'ftp://x' -> 'ftp'; 'mailto:a@b.c' -> 'mailto'; 'example.com:8080' -> None
    because a colon followed by a digit looks like a port, not a scheme.
    """
    if "://" in url:
        return url.split("://", 1)[0].lower()
    match = re.match(r"([a-z][a-z0-9+.\-]*):", url, re.IGNORECASE)
    if match and not url[match.end():match.end() + 1].isdigit():
        return match.group(1).lower()
    return None


def is_valid_hostname(host):
    """Basic sanity check of a hostname (not a full DNS validator)."""
    if ":" in host:  # IPv6 literal such as ::1 (urlparse removes the brackets)
        try:
            ipaddress.IPv6Address(host)
            return True
        except ValueError:
            return False
    name = host[:-1] if host.endswith(".") else host  # one trailing dot is legal
    if not name or len(name) > 253:
        return False
    for label in name.split("."):
        if not label or len(label) > 63 or not re.fullmatch(r"[\w-]+", label):
            return False
    return True


def scheme_was_assumed(url):
    """True if the user typed no scheme, so the program added http:// itself."""
    url = url.strip()
    return bool(url) and "://" not in url and get_explicit_scheme(url) is None


# ---------------------------------------------------------------------------
# Core detection (no input() or print() here, so it is easy to test)
# ---------------------------------------------------------------------------
def inspect_url(raw_url):
    """Check visible URL text for selected warning signs.

    Returns a list of message strings. The list holds either warning
    messages, MSG_NO_WARNINGS, or a single error message for bad input.
    The text is only parsed; nothing is ever opened or sent anywhere.
    """
    if not isinstance(raw_url, str):
        return [MSG_INVALID_FORMAT]

    url = raw_url.strip()
    if not url:
        return [MSG_EMPTY]
    if re.search(r"\s", url):  # spaces/tabs inside the text
        return [MSG_INVALID_FORMAT]

    # Unsupported scheme handling (ftp://, javascript:, mailto:, http:x ...)
    scheme_typed = get_explicit_scheme(url)
    if scheme_typed is not None:
        if "://" not in url or scheme_typed not in ("http", "https"):
            return [MSG_UNSUPPORTED_SCHEME]

    # If no scheme was typed, assume http:// so the hostname can be found.
    candidate = url if "://" in url else "http://" + url

    # Improvement C: malformed input (e.g. 'http://[bad' or a bad port)
    try:
        parsed = urlparse(candidate)
        parsed.port  # touching .port raises ValueError for an invalid port
        host = (parsed.hostname or "").lower()
    except ValueError:
        return [MSG_INVALID_FORMAT]

    if not host:
        return [MSG_NO_HOST]
    if not is_valid_hostname(host):
        return [MSG_INVALID_HOST]

    findings = []

    # Rule 1: @ symbol
    if "@" in candidate:
        findings.append(MSG_AT_SYMBOL)

    # Rule 2: long URL
    if len(url) > MAX_URL_LENGTH:
        findings.append(MSG_LONG_URL)

    # Rule 3: IPv4-style hostname (pattern only: four groups of 1-3 digits)
    if re.fullmatch(IPV4_PATTERN, host):
        findings.append(MSG_IP_HOST)

    # Rule 4: five or more dot-separated hostname segments
    labels = [part for part in host.split(".") if part]
    if len(labels) >= MANY_SEGMENTS_THRESHOLD:
        findings.append(MSG_MANY_SEGMENTS)

    # Rule 5: punycode marker
    if "xn--" in host:
        findings.append(MSG_PUNYCODE)

    # Rule 6: plain HTTP
    if parsed.scheme.lower() == "http":
        findings.append(MSG_HTTP)

    if not findings:
        findings.append(MSG_NO_WARNINGS)
    return findings


# ---------------------------------------------------------------------------
# Additional hints (EXTRA, beyond the six workbook rules)
# These look only at the hostname text. They are rough clues, not proof.
# ---------------------------------------------------------------------------
KNOWN_BRANDS = (
    "amazon", "paypal", "google", "microsoft", "apple", "facebook", "instagram",
    "netflix", "whatsapp", "linkedin", "flipkart", "paytm", "hdfcbank", "icicibank",
)
FUZZY_MIN_LENGTH = 6          # only longer brand names get the "one letter off" check
OFFICIAL_SOUNDING_WORDS = (
    "login", "signin", "secure", "security", "verify", "verification", "account",
    "update", "confirm", "banking", "wallet", "password", "billing", "support",
    "recover", "unlock", "suspend", "alert", "transaction", "payment", "invoice",
    "refund", "reward", "prize",
)
FREE_DYNAMIC_DNS_DOMAINS = (
    "servebbs.org", "serveftp.com", "no-ip.com", "no-ip.org", "ddns.net",
    "duckdns.org", "hopto.org", "zapto.org", "myftp.org", "dyndns.org",
    "ngrok.io", "ngrok-free.app", "000webhostapp.com",
)
OFTEN_ABUSED_TLDS = (
    "xyz", "top", "click", "zip", "tk", "ml", "ga", "cf", "gq", "icu", "buzz", "rest",
)
SECOND_LEVEL_LABELS = ("co", "com", "org", "net", "gov", "ac", "edu")  # amazon.co.uk
LOOKALIKE_DIGITS = str.maketrans("0135", "oles")   # 0->o, 1->l, 3->e, 5->s

HINT_EXPLANATIONS = {
    "brand": (
        "Attackers register names that imitate well-known brands. Check the main "
        "domain (the part just before the ending, like .com) carefully."
    ),
    "words": (
        "Words like 'secure' or 'verify' are used to sound official. Real brands "
        "use them too, so this is only a weak clue."
    ),
    "dyndns": (
        "Free dynamic-DNS services let anyone create a name cheaply. Many are used "
        "for hobby or testing, but attackers like them too."
    ),
    "tld": (
        "Some endings are cheap or free and are often misused. Many honest sites "
        "use them as well."
    ),
    "hyphens": (
        "Names stuffed with hyphens (like word-word-word.com) are common in "
        "imitation sites. Some honest sites do this too."
    ),
    "digits": (
        "Long number strings can look like ticket or transaction IDs and add "
        "false 'official' detail."
    ),
}


def edit_distance(first, second):
    """Number of single-letter changes needed to turn one word into another."""
    previous = list(range(len(second) + 1))
    for row, letter_a in enumerate(first, start=1):
        current = [row]
        for col, letter_b in enumerate(second, start=1):
            current.append(min(previous[col] + 1,
                               current[col - 1] + 1,
                               previous[col - 1] + (letter_a != letter_b)))
        previous = current
    return previous[-1]


def find_extra_hints(raw_url):
    """Return a list of (message, explanation) pairs from the hostname text.

    Returns an empty list for bad input, IP-address hosts and IPv6 hosts.
    """
    if any(item in ERROR_MESSAGES for item in inspect_url(raw_url)):
        return []
    url = raw_url.strip()
    candidate = url if "://" in url else "http://" + url
    host = (urlparse(candidate).hostname or "").lower().rstrip(".")
    if not host or ":" in host or re.fullmatch(IPV4_PATTERN, host):
        return []
    labels = host.split(".")
    if len(labels) < 2:
        return []

    index = -3 if len(labels) >= 3 and labels[-2] in SECOND_LEVEL_LABELS else -2
    main_label = labels[index]            # e.g. 'amazon' in www.amazon.co.uk
    hints = []

    # Brand names: exact brand in a foreign domain, or a one-letter-off look-alike
    seen_brands = set()
    for token in (t for t in re.split(r"[^a-z0-9]+", host) if len(t) >= 4):
        cleaned = token.translate(LOOKALIKE_DIGITS)
        for brand in KNOWN_BRANDS:
            if brand in seen_brands or main_label == brand:
                continue
            if token == brand:
                seen_brands.add(brand)
                hints.append((f"Uses the brand name '{brand}', but the main domain is "
                              f"'{main_label}'.", HINT_EXPLANATIONS["brand"]))
            elif (len(brand) >= FUZZY_MIN_LENGTH and abs(len(cleaned) - len(brand)) <= 1
                  and edit_distance(cleaned, brand) <= 1):
                seen_brands.add(brand)
                hints.append((f"'{token}' looks like a misspelling or look-alike of "
                              f"'{brand}'.", HINT_EXPLANATIONS["brand"]))

    words = [w for w in OFFICIAL_SOUNDING_WORDS if w in host]
    if words:
        hints.append((f"Hostname contains official-sounding words: {', '.join(words[:4])}.",
                      HINT_EXPLANATIONS["words"]))

    if any(host == d or host.endswith("." + d) for d in FREE_DYNAMIC_DNS_DOMAINS):
        hints.append(("Uses a free dynamic-DNS / free hosting domain.",
                      HINT_EXPLANATIONS["dyndns"]))

    if labels[-1] in OFTEN_ABUSED_TLDS:
        hints.append((f"Uses the '.{labels[-1]}' ending, which is cheap and often misused.",
                      HINT_EXPLANATIONS["tld"]))

    if main_label.removeprefix("xn--").count("-") >= 2:
        hints.append(("The main domain name contains several hyphens.",
                      HINT_EXPLANATIONS["hyphens"]))

    if re.search(r"\d{4,}", host):
        hints.append(("Hostname contains a long run of digits.",
                      HINT_EXPLANATIONS["digits"]))
    return hints


def overall_assessment(warning_count, hint_count):
    """Return a cautious overall line, or '' when no clue was found."""
    total = warning_count + hint_count
    if total == 0:
        return ""
    if total >= 3:
        return (f"OVERALL: MANY SUSPICIOUS PATTERNS ({total} clues). This link resembles "
                "common phishing patterns. Do not open it or enter any details.\n"
                "This is a text-based opinion only, not a confirmed verdict: the tool "
                "cannot know whether the site is really malicious.")
    return (f"OVERALL: Some clues found ({total}). Review carefully before trusting "
            "this link.")


# ---------------------------------------------------------------------------
# Output formatting and terminal interface
# ---------------------------------------------------------------------------
def format_report(raw_url):
    """Return the full text report for one URL (Improvements B, D and E)."""
    findings = inspect_url(raw_url)
    hints = find_extra_hints(raw_url)
    warning_count = len(findings) if has_warnings(findings) else 0
    lines = ["", "-" * 60, "RESULT", "-" * 60]

    if has_warnings(findings):
        for number, item in enumerate(findings, start=1):
            lines.append(f"  {number}. {item}")
            lines.append(f"     Why it matters: {WARNING_EXPLANATIONS[item]}")
    else:
        for item in findings:
            lines.append(f"  - {item}")

    if hints:
        lines.append("")
        lines.append("Additional hints (extra checks on the hostname text):")
        for number, (message, reason) in enumerate(hints, start=1):
            lines.append(f"  H{number}. {message}")
            lines.append(f"      Why it matters: {reason}")

    if warning_count:
        lines.append("")
        lines.append(f"REVIEW CAREFULLY: {warning_count} warning sign(s) found.")
        lines.append("(The count is only a rough clue, not the chance of phishing.)")
    overall = overall_assessment(warning_count, len(hints))
    if overall:
        lines.append("")
        lines.append(overall)

    if scheme_was_assumed(str(raw_url)) and not any(i in ERROR_MESSAGES for i in findings):
        lines.append("")
        lines.append("Note: no scheme was typed, so http:// was assumed for this check.")

    lines.append("")
    lines.append("Never enter passwords from unexpected links.")
    return "\n".join(lines)


def print_banner():
    """Show the title and short instructions."""
    print("=" * 60)
    print("  EWB Phishing URL Awareness Checker")
    print("=" * 60)
    print("Text checks only - this program does not open URLs.")
    print("Use sample strings only. Type q, quit or exit to stop.")


def main():
    """Ask for URLs in a loop until the user quits."""
    print_banner()
    while True:
        try:
            raw_url = input("\nEnter a sample URL (or q to quit): ")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye! Stay alert online.")
            break
        if raw_url.strip().lower() in QUIT_COMMANDS:
            print("Goodbye! Stay alert online.")
            break
        print(format_report(raw_url))


if __name__ == "__main__":
    main()
