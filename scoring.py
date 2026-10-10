"""Combine indicators into a 0-100 risk score, a risk level, and next steps."""
from __future__ import annotations

from .models import Indicator, ParsedEmail, Report

LEVELS = [(75, "Critical"), (50, "High"), (25, "Medium"), (0, "Low")]

LEVEL_ACTIONS = {
    "Critical": ["Do not click any links, open attachments, or reply.",
                 "Report it with your email's 'Report phishing' button or forward it to your IT/security team.",
                 "Delete the email after reporting.",
                 "If you already clicked or entered information, change that password now and contact IT."],
    "High": ["Do not click links or open attachments.",
             "Contact the sender through a channel you already trust (official website or known phone number).",
             "Report the email to IT or your provider."],
    "Medium": ["Be cautious. Verify the request with the sender through another channel before acting.",
               "Hover over links to check where they really go."],
    "Low": ["No strong phishing signs found. Still verify anything involving money or passwords."],
}


def score(indicators: list[Indicator]) -> int:
    # Diminishing returns: one category can't max the score alone, but stacked categories escalate fast.
    total = sum(i.weight for i in indicators)
    categories = {i.category for i in indicators}
    if len(categories) >= 3:
        total += 10
    return min(100, total)


def level_for(value: int) -> str:
    return next(name for threshold, name in LEVELS if value >= threshold)


def build_report(email: ParsedEmail, indicators: list[Indicator]) -> Report:
    value = score(indicators)
    level = level_for(value)
    if indicators:
        top = ", ".join(i.title.lower() for i in indicators[:3])
        summary = f"{level} risk ({value}/100). Main concerns: {top}."
    else:
        summary = "Low risk (0/100). No common phishing indicators were detected."

    actions = list(LEVEL_ACTIONS[level])
    for ind in indicators[:3]:
        if ind.advice not in actions:
            actions.append(ind.advice)
    return Report(score=value, level=level, indicators=indicators, summary=summary, actions=actions)
