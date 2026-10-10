from pathlib import Path

import pytest

from phishing_analyzer import analyze, analyze_eml
from phishing_analyzer.ai import _validate
from phishing_analyzer.parser import parse_text
from phishing_analyzer.rules import lookalike_brand, run_all
from phishing_analyzer.scoring import level_for

SAMPLES = Path(__file__).parent.parent / "samples"


def ids(report):
    return {i.id for i in report.indicators}


# ---------- end-to-end on sample emails

def test_credential_phish_is_critical():
    r = analyze_eml((SAMPLES / "credential_phish.eml").read_bytes())
    assert r.level == "Critical"
    assert {"lookalike_sender", "link_mismatch", "auth_fail", "credential_request", "reply_to_mismatch"} <= ids(r)


def test_malware_invoice_flags_double_extension():
    r = analyze_eml((SAMPLES / "invoice_malware.eml").read_bytes())
    assert "double_extension" in ids(r)
    assert "payment_request" in ids(r)
    assert r.level in {"High", "Critical"}


def test_gift_card_scam_is_high():
    r = analyze((SAMPLES / "gift_card_scam.txt").read_text())
    assert {"payment_request", "freemail_authority", "secrecy"} <= ids(r)
    assert r.level == "High"


def test_legitimate_email_is_low():
    r = analyze_eml((SAMPLES / "legitimate.eml").read_bytes())
    assert r.level == "Low"
    assert r.indicators == []


# ---------- individual rules

@pytest.mark.parametrize("domain,brand", [
    ("paypa1.com", "paypal"),
    ("micros0ft.com", "microsoft"),
    ("arnazon.com", "amazon"),
    ("paypal.com.account-verify.net", "paypal"),
    ("microsoft-support-team.com", "microsoft"),
])
def test_lookalike_domains_detected(domain, brand):
    assert lookalike_brand(domain) == brand


@pytest.mark.parametrize("domain", ["paypal.com", "login.microsoftonline.com", "vt.edu", "example.com", "upstart.com"])
def test_real_domains_not_flagged(domain):
    assert lookalike_brand(domain) is None


def test_ip_address_link():
    r = analyze('From: a@b.com\n\nLog in here: http://192.168.4.20/login')
    assert "ip_link" in ids(r)


def test_shortener_link():
    r = analyze("Check this out https://bit.ly/3xyz")
    assert "shortener" in ids(r)


def test_html_link_text_mismatch():
    r = analyze('<p>Visit <a href="https://evil-site.top/x">www.chase.com</a></p>')
    assert "link_mismatch" in ids(r)
    assert "risky_tld" in ids(r)


def test_display_name_spoof():
    email = parse_text('From: "PayPal Support" <service@randomshop.example>\n\nHello')
    assert "display_name_spoof" in {i.id for i in run_all(email)}


def test_macro_attachment():
    raw = (b"From: a@example.com\nSubject: doc\nMIME-Version: 1.0\n"
           b"Content-Type: multipart/mixed; boundary=X\n\n--X\nContent-Type: text/plain\n\nsee attached\n"
           b"--X\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"report.docm\"\n\nAAAA\n--X--\n")
    assert "macro_attachment" in ids(analyze_eml(raw))


# ---------- scoring

@pytest.mark.parametrize("score,level", [(0, "Low"), (24, "Low"), (25, "Medium"), (50, "High"), (75, "Critical"), (100, "Critical")])
def test_levels(score, level):
    assert level_for(score) == level


def test_score_capped_at_100():
    r = analyze_eml((SAMPLES / "credential_phish.eml").read_bytes())
    assert r.score == 100


# ---------- AI output validation (no API call needed)

def test_ai_validator_accepts_good_json():
    out = _validate('{"summary": "This is a scam.", "actions": ["Report it", "Delete it"], "injection_attempt": false}')
    assert out and out["actions"] == ["Report it", "Delete it"]


def test_ai_validator_rejects_malformed():
    assert _validate("Sure! Here's my analysis...") is None
    assert _validate('{"summary": "", "actions": []}') is None


def test_ai_validator_strips_unsafe_advice():
    out = _validate('{"summary": "x", "actions": ["Click the link to verify", "Report to IT"]}')
    assert out["actions"] == ["Report to IT"]


def test_ai_disabled_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    r = analyze((SAMPLES / "gift_card_scam.txt").read_text(), use_ai=True)
    assert r.ai_used is False
