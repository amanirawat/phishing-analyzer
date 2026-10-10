"""AI Phishing Email Analyzer: score suspicious emails and explain what to do in plain language."""
from __future__ import annotations

from .ai import enhance_with_ai
from .models import Indicator, ParsedEmail, Report
from .parser import parse_eml, parse_text
from .rules import run_all
from .scoring import build_report

__version__ = "0.1.0"
__all__ = ["analyze", "analyze_eml", "Report", "Indicator", "ParsedEmail"]


def _finish(email: ParsedEmail, use_ai: bool) -> Report:
    report = build_report(email, run_all(email))
    if use_ai:
        text = f"From: {email.from_name} <{email.from_address}>\nSubject: {email.subject}\n\n{email.body_text}"
        report = enhance_with_ai(report, text)
    return report


def analyze(text: str, use_ai: bool = False) -> Report:
    """Analyze pasted email text (headers optional)."""
    return _finish(parse_text(text), use_ai)


def analyze_eml(raw: bytes, use_ai: bool = False) -> Report:
    """Analyze a raw .eml file."""
    return _finish(parse_eml(raw), use_ai)
