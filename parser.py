"""Turn raw email input (.eml or pasted text) into a ParsedEmail."""
from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from html.parser import HTMLParser

from .models import ParsedEmail

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


class _LinkExtractor(HTMLParser):
    """Collects visible text plus (anchor text, href) pairs from HTML bodies."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[dict] = []
        self.text_parts: list[str] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor_text = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append({"text": " ".join(self._anchor_text).strip(), "url": self._href.strip()})
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._anchor_text.append(data.strip())


def _html_to_text_and_links(html: str) -> tuple[str, list[dict]]:
    extractor = _LinkExtractor()
    extractor.feed(html)
    text = re.sub(r"\s+", " ", " ".join(extractor.text_parts)).strip()
    return text, extractor.links


def _plain_links(text: str) -> list[dict]:
    return [{"text": "", "url": u.rstrip(".,;")} for u in URL_RE.findall(text)]


def parse_eml(raw: bytes) -> ParsedEmail:
    """Parse a full RFC 822 message (what you get from 'Download original' / .eml)."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    name, addr = parseaddr(str(msg.get("From", "")))
    email = ParsedEmail(
        subject=str(msg.get("Subject", "")),
        from_name=name,
        from_address=addr.lower(),
        reply_to=parseaddr(str(msg.get("Reply-To", "")))[1].lower(),
        return_path=parseaddr(str(msg.get("Return-Path", "")))[1].lower(),
        auth_results=" ".join(str(v) for v in msg.get_all("Authentication-Results", [])),
    )

    texts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            email.attachments.append(filename or "unnamed-attachment")
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:  # malformed encodings shouldn't crash analysis
            continue
        if ctype == "text/html":
            text, links = _html_to_text_and_links(content)
            texts.append(text)
            email.links.extend(links)
        elif ctype == "text/plain":
            texts.append(content)
            email.links.extend(_plain_links(content))

    email.body_text = "\n".join(texts).strip()
    email.links = _dedupe(email.links)
    return email


def parse_text(text: str) -> ParsedEmail:
    """Parse pasted email content. Header lines (From:, Subject:, Reply-To:) are used if present."""
    if re.search(r"^(From|Subject|Received|Return-Path):", text, re.MULTILINE | re.IGNORECASE) and "\n\n" in text:
        # Looks like raw headers + body: let the real parser handle it.
        msg = Parser(policy=policy.default).parsestr(text)
        if msg.get("From"):
            return parse_eml(text.encode("utf-8", "replace"))

    email = ParsedEmail()
    body_lines = []
    for line in text.splitlines():
        m = re.match(r"^(from|subject|reply-to):\s*(.*)$", line.strip(), re.IGNORECASE)
        if m:
            key, value = m.group(1).lower(), m.group(2)
            if key == "from":
                name, addr = parseaddr(value)
                email.from_name, email.from_address = name, addr.lower()
            elif key == "subject":
                email.subject = value
            else:
                email.reply_to = parseaddr(value)[1].lower()
        else:
            body_lines.append(line)

    body = "\n".join(body_lines).strip()
    if re.search(r"<a\s|<html|<body|<p>", body, re.IGNORECASE):
        body, links = _html_to_text_and_links(body)
        email.links = links
    else:
        email.links = _plain_links(body)
    email.body_text = body
    email.links = _dedupe(email.links)
    return email


def _dedupe(links: list[dict]) -> list[dict]:
    seen, out = set(), []
    for link in links:
        key = (link["text"], link["url"])
        if link["url"] and key not in seen:
            seen.add(key)
            out.append(link)
    return out
