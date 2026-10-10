"""Data models shared across the analyzer."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class ParsedEmail:
    """A normalized view of an email, whether it came from a .eml file or pasted text."""
    subject: str = ""
    from_name: str = ""
    from_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    auth_results: str = ""
    body_text: str = ""
    links: list[dict] = field(default_factory=list)   # {"text": ..., "url": ...}
    attachments: list[str] = field(default_factory=list)

    @property
    def from_domain(self) -> str:
        return self.from_address.rsplit("@", 1)[-1].lower() if "@" in self.from_address else ""


@dataclass
class Indicator:
    """One phishing signal found in the email."""
    id: str
    title: str
    category: str          # sender | content | links | attachments | authentication
    weight: int            # contribution to the 0-100 risk score
    evidence: str          # exactly what triggered it, shown to the user
    advice: str            # plain-language action for a non-technical user


@dataclass
class Report:
    score: int
    level: str             # Low | Medium | High | Critical
    indicators: list[Indicator]
    summary: str
    actions: list[str]
    ai_used: bool = False

    def to_dict(self) -> dict:
        return asdict(self)
