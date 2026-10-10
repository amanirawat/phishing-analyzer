"""Rule-based phishing indicators.

Each check is a small function that looks at one signal and returns zero or more
Indicators. Keeping checks independent makes them easy to test, tune, and explain.
Weights reflect how strongly a signal predicts phishing on its own.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from .models import Indicator, ParsedEmail

# Brands most often impersonated in credential phishing, mapped to their real domains.
BRANDS = {
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com"],
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk"],
    "google": ["google.com", "gmail.com"],
    "netflix": ["netflix.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "linkedin": ["linkedin.com"],
    "chase": ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
    "dhl": ["dhl.com"],
    "irs": ["irs.gov"],
    "coinbase": ["coinbase.com"],
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc"}

RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf",
              "ga", "work", "support", "rest", "cam", "icu", "buzz", "monster", "lol"}

DANGEROUS_EXT = {"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "hta",
                 "msi", "iso", "img", "lnk", "jar", "wsf", "html", "htm", "svg"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlsb"}

URGENCY = [r"urgent", r"immediately", r"within \d+ (hours|hrs|minutes)", r"act now",
           r"final (notice|warning)", r"expires? (today|soon)", r"last chance",
           r"as soon as possible", r"asap", r"right away", r"time.sensitive"]
THREATS = [r"(account|mailbox|access).{0,30}(suspended|locked|disabled|terminated|closed|deactivated)",
           r"unusual (sign.in|activity|login)", r"unauthori[sz]ed (access|transaction|login)",
           r"legal action", r"permanently (deleted|removed)", r"verify your (identity|account)"]
CREDENTIALS = [r"(confirm|verify|update|validate|re-?enter).{0,25}(password|credentials|login|account details)",
               r"(password|passcode|pin).{0,20}(expire|reset|update)",
               r"social security", r"\bssn\b", r"one.time (code|passcode)", r"\bmfa code\b",
               r"(credit|debit) card (number|details)", r"(send|provide|confirm) (us )?your bank (account|details)"]
PAYMENT = [r"gift ?cards?", r"wire (transfer|the funds)", r"bitcoin|crypto(currency)? wallet",
           r"(bank|banking|payment) (details|information|account) (have|has) changed",
           r"new (bank|banking|payment) (details|information|account)",
           r"outstanding (invoice|payment)", r"zelle|venmo|cash ?app"]
SECRECY = [r"keep (this|it) (between us|confidential|quiet|to yourself)", r"don'?t (tell|mention|share) (this|anyone)",
           r"(it'?s|this is) a surprise"]
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com",
            "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com"}
AUTHORITY_TITLES = r"\b(dean|ceo|cfo|president|director|chair|manager|hr|human resources|payroll|it support|help ?desk|admin(istrator)?|security team|professor|dr\.?)\b"
GENERIC_GREETING =r"^\s*(dear|hello|hi)\s+(customer|user|client|member|valued \w+|account holder|sir/madam|sir or madam)"


def _find(patterns: list[str], text: str) -> list[str]:
    hits = []
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            hits.append(m.group(0))
    return hits


def _host(url: str) -> str:
    try:
        host = (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def _registrable(host: str) -> str:
    """Rough registrable domain (last two labels; three for co.uk-style suffixes)."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "@": "a"})


def _is_official(domain: str) -> bool:
    return any(domain == d or domain.endswith("." + d) for ds in BRANDS.values() for d in ds)


def lookalike_brand(domain: str) -> str | None:
    """Return the brand a domain is imitating, or None. Catches typos, digit swaps, and brand-in-domain tricks."""
    if not domain or _is_official(domain):
        return None
    reg = _registrable(domain)
    label = reg.split(".")[0]
    normalized = label.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    for brand, real_domains in BRANDS.items():
        key = brand.replace(" ", "")
        for real in real_domains:
            real_label = real.split(".")[0]
            if normalized == real_label and label != real_label:
                return brand                                  # paypa1.com, micros0ft.com
            if len(real_label) >= 5 and 0 < _levenshtein(label, real_label) <= 1:
                return brand                                  # paypai.com, amazom.com
        if len(key) >= 5 and key in normalized.replace("-", ""):
            return brand                                      # microsoft-support-team.com
        if len(key) >= 5 and key in domain.replace("-", "").replace(".", "") and reg not in real_domains:
            return brand                                      # paypal.com.secure-login.net
    return None


# ---------------------------------------------------------------- checks

def check_sender(email: ParsedEmail) -> list[Indicator]:
    out = []
    domain = email.from_domain
    name = email.from_name.lower()

    brand = lookalike_brand(domain)
    if brand:
        out.append(Indicator("lookalike_sender", "Sender domain imitates a known brand", "sender", 30,
                             f"'{domain}' looks like {brand.title()}, but it is not an official {brand.title()} domain.",
                             f"Do not trust this email. If you have a {brand.title()} account, sign in by typing the address yourself."))

    for b, real in BRANDS.items():
        if re.search(rf"\b{re.escape(b)}\b", name) and domain and not any(domain == d or domain.endswith("." + d) for d in real):
            if not brand:
                out.append(Indicator("display_name_spoof", "Display name doesn't match sender address", "sender", 20,
                                     f"Shows as '{email.from_name}' but was sent from '{email.from_address}'.",
                                     "Always check the actual email address, not just the name shown."))
            break

    if domain in FREEMAIL and re.search(AUTHORITY_TITLES, f"{name} {email.from_address}", re.IGNORECASE):
        out.append(Indicator("freemail_authority", "Authority figure writing from a personal email", "sender", 15,
                             f"'{email.from_name or email.from_address}' claims an official role but uses a free {domain} account.",
                             "Executives and staff use their organization's email. Confirm with them through official channels."))

    if email.reply_to and domain and _registrable(email.reply_to.rsplit("@", 1)[-1]) != _registrable(domain):
        out.append(Indicator("reply_to_mismatch", "Replies go to a different address", "sender", 15,
                             f"Sent from '{email.from_address}' but replies go to '{email.reply_to}'.",
                             "Do not reply. Your answer would go to someone other than the apparent sender."))
    return out


def check_authentication(email: ParsedEmail) -> list[Indicator]:
    res = email.auth_results.lower()
    if not res:
        return []
    failed = [m for m in ("spf", "dkim", "dmarc") if re.search(rf"\b{m}=(fail|softfail|permerror|none)", res)]
    if not failed:
        return []
    weight = 25 if "dmarc" in failed else 15
    return [Indicator("auth_fail", "Email failed sender verification", "authentication", weight,
                      f"Failed checks: {', '.join(f.upper() for f in failed)}. The sending server may not be authorized to send for this domain.",
                      "Treat this as unverified. Report it to IT or your email provider.")]


def check_content(email: ParsedEmail) -> list[Indicator]:
    text = f"{email.subject}\n{email.body_text}"
    out = []
    if hits := _find(URGENCY, text):
        out.append(Indicator("urgency", "Pressure to act quickly", "content", 10,
                             f"Urgent language: {', '.join(repr(h) for h in hits[:3])}.",
                             "Slow down. Real organizations rarely demand action within minutes."))
    if hits := _find(THREATS, text):
        out.append(Indicator("threat", "Threatens account loss or problems", "content", 10,
                             f"Threatening language: {', '.join(repr(h) for h in hits[:3])}.",
                             "Check your account status by visiting the official website directly, not through this email."))
    if hits := _find(CREDENTIALS, text):
        out.append(Indicator("credential_request", "Asks for passwords or sensitive information", "content", 25,
                             f"Requests sensitive data: {', '.join(repr(h) for h in hits[:3])}.",
                             "Never enter passwords, codes, or financial details from an email link."))
    if hits := _find(PAYMENT, text):
        out.append(Indicator("payment_request", "Unusual payment request", "content", 20,
                             f"Payment language: {', '.join(repr(h) for h in hits[:3])}.",
                             "Verify any payment or bank-detail change by phone, using a number you already know."))
    if hits := _find(SECRECY, text):
        out.append(Indicator("secrecy", "Asks you to keep it secret", "content", 15,
                             f"Secrecy request: {', '.join(repr(h) for h in hits[:2])}.",
                             "Requests for secrecy are a manipulation tactic. Tell a colleague or IT before acting."))
    if re.search(GENERIC_GREETING, email.body_text, re.IGNORECASE | re.MULTILINE):
        out.append(Indicator("generic_greeting", "Generic greeting", "content", 5,
                             "Doesn't address you by name.",
                             "Companies you do business with usually use your name."))
    return out


def check_links(email: ParsedEmail) -> list[Indicator]:
    out = []
    mismatches, ip_links, shorteners, risky_tld, punycode, lookalikes, insecure = [], [], [], [], [], [], []
    for link in email.links:
        url, text = link["url"], link["text"]
        if url.lower().startswith("mailto:"):
            continue
        host = _host(url)
        if not host:
            continue
        shown = _host(text) if re.match(r"^(https?://)?[\w-]+(\.[\w-]+)+(/\S*)?$", text.strip()) else ""
        if shown and _registrable(shown) != _registrable(host):
            mismatches.append(f"shows '{shown}' → goes to '{host}'")
        try:
            ipaddress.ip_address(host)
            ip_links.append(host)
        except ValueError:
            pass
        if host in SHORTENERS:
            shorteners.append(host)
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            risky_tld.append(host)
        if "xn--" in host:
            punycode.append(host)
        if (b := lookalike_brand(host)):
            lookalikes.append(f"{host} (imitates {b.title()})")
        if url.lower().startswith("http://"):
            insecure.append(host)

    if mismatches:
        out.append(Indicator("link_mismatch", "Link text hides a different destination", "links", 30,
                             "; ".join(mismatches[:3]),
                             "Hover over links before clicking. The real destination doesn't match what's shown."))
    if lookalikes:
        out.append(Indicator("lookalike_link", "Link points to a fake brand website", "links", 30,
                             ", ".join(sorted(set(lookalikes))[:3]),
                             "Don't click. This site is built to look like a real company's login page."))
    if ip_links:
        out.append(Indicator("ip_link", "Link uses a raw IP address", "links", 20,
                             ", ".join(sorted(set(ip_links))[:3]),
                             "Legitimate companies use named websites, not numeric addresses."))
    if punycode:
        out.append(Indicator("punycode", "Link uses look-alike international characters", "links", 20,
                             ", ".join(sorted(set(punycode))[:3]),
                             "This domain may use foreign letters that look identical to English ones."))
    if shorteners:
        out.append(Indicator("shortener", "Link hidden behind a URL shortener", "links", 10,
                             ", ".join(sorted(set(shorteners))),
                             "Shortened links hide where they go. Don't click unless you trust the sender."))
    if risky_tld:
        out.append(Indicator("risky_tld", "Link uses a domain ending common in abuse", "links", 10,
                             ", ".join(sorted(set(risky_tld))[:3]),
                             "Be extra cautious with unfamiliar domain endings."))
    if insecure and (out or len(insecure) == len(email.links)):
        out.append(Indicator("no_https", "Link is not encrypted (http://)", "links", 5,
                             ", ".join(sorted(set(insecure))[:3]),
                             "Never enter information on a page without https://."))
    return out


def check_attachments(email: ParsedEmail) -> list[Indicator]:
    out = []
    for name in email.attachments:
        parts = name.lower().split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if len(parts) > 2 and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"} and ext in DANGEROUS_EXT | {"zip", "rar", "7z"}:
            out.append(Indicator("double_extension", "Attachment disguises its file type", "attachments", 35,
                                 f"'{name}' pretends to be .{parts[-2]} but is really .{ext}.",
                                 "Do not open. This is a classic way to deliver malware."))
        elif ext in DANGEROUS_EXT:
            out.append(Indicator("dangerous_attachment", "Dangerous attachment type", "attachments", 30,
                                 f"'{name}' is a .{ext} file, which can run code or open a fake login page.",
                                 "Do not open. Report the email to IT."))
        elif ext in MACRO_EXT:
            out.append(Indicator("macro_attachment", "Office file with macros", "attachments", 25,
                                 f"'{name}' can contain macros that install malware.",
                                 "Do not open or click 'Enable Content'."))
        elif ext in {"zip", "rar", "7z"}:
            out.append(Indicator("archive_attachment", "Compressed attachment", "attachments", 10,
                                 f"'{name}' may hide other files inside.",
                                 "Only open archives you were expecting from someone you know."))
    return out


ALL_CHECKS = [check_sender, check_authentication, check_content, check_links, check_attachments]


def run_all(email: ParsedEmail) -> list[Indicator]:
    found: list[Indicator] = []
    for check in ALL_CHECKS:
        found.extend(check(email))
    return sorted(found, key=lambda i: i.weight, reverse=True)
