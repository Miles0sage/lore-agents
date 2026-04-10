"""Intent classification for dangerous agent actions.

Two-layer detection system:
1. Pattern matching — fast regex/glob for known attack patterns (SQL injection,
   privilege escalation, prompt injection, data exfiltration)
2. Semantic classifier — lightweight rule-based intent scoring for actions
   that evade pattern matching

Covers OWASP Agentic Top 10 detection categories.
No ML dependencies — pure Python pattern matching for <0.1ms.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence

from phalanx.governance.types import IntentCategory


# Pre-compiled regex patterns for dangerous actions
_SQL_INJECTION_PATTERNS = [
    re.compile(r"(?i)(drop|alter|truncate|delete\s+from|insert\s+into|update\s+\w+\s+set)\s"),
    re.compile(r"(?i)(union\s+select|or\s+1\s*=\s*1|;\s*--)"),
    re.compile(r"(?i)(exec|execute|xp_cmdshell|sp_executesql)"),
]

_PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)(ignore\s+(previous|all|above)\s+(instructions|prompts|rules))"),
    re.compile(r"(?i)(you\s+are\s+now|new\s+instructions|forget\s+(everything|all))"),
    re.compile(r"(?i)(system\s*prompt|override\s+policy|bypass\s+(filter|guard|safety))"),
    re.compile(r"(?i)(jailbreak|DAN|do\s+anything\s+now)"),
]

_DATA_EXFILTRATION_PATTERNS = [
    re.compile(r"(?i)(send|post|upload|transmit|exfil)\s.*(to|via)\s.*(http|ftp|email|webhook)"),
    re.compile(r"(?i)(curl|wget|requests\.post|fetch)\s.*https?://"),
    re.compile(r"(?i)(base64|encode|compress)\s.*(secret|key|password|token|credential)"),
]

_PRIVILEGE_ESCALATION_PATTERNS = [
    re.compile(r"(?i)(sudo|su\s+root|chmod\s+777|chown\s+root)"),
    re.compile(r"(?i)(grant\s+all|revoke|alter\s+role|create\s+user)"),
    re.compile(r"(?i)(admin|root|superuser|elevated|escalat)"),
]

_RESOURCE_EXHAUSTION_PATTERNS = [
    re.compile(r"(?i)(while\s+true|infinite\s+loop|fork\s+bomb)"),
    re.compile(r"(?i)(rm\s+-rf\s+/|format\s+c:|del\s+/s\s+/q)"),
    re.compile(r"(?i)(:()\{\s*:\|:&\s*\};:)"),  # Fork bomb
]


@dataclass(frozen=True)
class IntentSignal:
    """A detected intent signal from pattern analysis."""

    category: IntentCategory
    confidence: float  # 0.0 to 1.0
    pattern: str       # Which pattern matched
    evidence: str      # The matching text


@dataclass(frozen=True)
class IntentResult:
    """Result of intent classification on an action."""

    category: IntentCategory
    confidence: float
    signals: tuple[IntentSignal, ...] = ()
    is_dangerous: bool = False

    def __repr__(self) -> str:
        return (
            f"<IntentResult category={self.category.value} "
            f"confidence={self.confidence:.2f} dangerous={self.is_dangerous}>"
        )


class IntentClassifier:
    """Two-layer intent classifier for agent actions.

    Layer 1: Regex pattern matching against known attack signatures.
    Layer 2: Keyword-based semantic scoring for ambiguous actions.

    Usage:
        classifier = IntentClassifier()
        result = classifier.classify("DROP TABLE users;")
        if result.is_dangerous:
            block_action()
    """

    def __init__(
        self,
        danger_threshold: float = 0.5,
        extra_patterns: dict[IntentCategory, list[re.Pattern[str]]] | None = None,
    ) -> None:
        self._threshold = danger_threshold
        self._patterns: dict[IntentCategory, list[re.Pattern[str]]] = {
            IntentCategory.DESTRUCTIVE_DATA: list(_SQL_INJECTION_PATTERNS),
            IntentCategory.PROMPT_INJECTION: list(_PROMPT_INJECTION_PATTERNS),
            IntentCategory.DATA_EXFILTRATION: list(_DATA_EXFILTRATION_PATTERNS),
            IntentCategory.PRIVILEGE_ESCALATION: list(_PRIVILEGE_ESCALATION_PATTERNS),
            IntentCategory.RESOURCE_EXHAUSTION: list(_RESOURCE_EXHAUSTION_PATTERNS),
        }
        if extra_patterns:
            for cat, pats in extra_patterns.items():
                self._patterns.setdefault(cat, []).extend(pats)

    def classify(self, text: str) -> IntentResult:
        """Classify text for dangerous intent.

        Checks action name, parameters, and any embedded content.
        Returns the highest-confidence dangerous category found.
        """
        signals: list[IntentSignal] = []

        # Layer 1: Pattern matching
        for category, patterns in self._patterns.items():
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    signals.append(IntentSignal(
                        category=category,
                        confidence=0.8,  # High confidence for regex match
                        pattern=pattern.pattern,
                        evidence=match.group(0),
                    ))

        # Layer 2: Keyword scoring
        keyword_signals = self._keyword_score(text)
        signals.extend(keyword_signals)

        if not signals:
            return IntentResult(
                category=IntentCategory.SAFE,
                confidence=1.0,
                is_dangerous=False,
            )

        # Pick highest confidence signal
        best = max(signals, key=lambda s: s.confidence)
        is_dangerous = best.confidence >= self._threshold

        return IntentResult(
            category=best.category,
            confidence=best.confidence,
            signals=tuple(signals),
            is_dangerous=is_dangerous,
        )

    def classify_action(self, action: str, params: dict | None = None) -> IntentResult:
        """Classify an action + params combination."""
        parts = [action]
        if params:
            for v in params.values():
                if isinstance(v, str):
                    parts.append(v)
        combined = " ".join(parts)
        return self.classify(combined)

    def _keyword_score(self, text: str) -> list[IntentSignal]:
        """Layer 2: Lightweight keyword-based scoring."""
        signals: list[IntentSignal] = []
        text_lower = text.lower()

        dangerous_keywords: dict[IntentCategory, list[tuple[str, float]]] = {
            IntentCategory.DESTRUCTIVE_DATA: [
                ("delete", 0.4), ("drop", 0.6), ("truncate", 0.7),
                ("destroy", 0.6), ("wipe", 0.5), ("purge", 0.5),
            ],
            IntentCategory.DATA_EXFILTRATION: [
                ("exfiltrate", 0.8), ("leak", 0.5), ("steal", 0.7),
                ("harvest", 0.4), ("scrape", 0.3), ("dump", 0.4),
            ],
            IntentCategory.PRIVILEGE_ESCALATION: [
                ("escalate", 0.6), ("elevate", 0.5), ("bypass", 0.6),
                ("override", 0.5), ("impersonate", 0.7),
            ],
            IntentCategory.RESOURCE_EXHAUSTION: [
                ("infinite", 0.6), ("exhaust", 0.5), ("flood", 0.6),
                ("ddos", 0.9), ("spam", 0.5),
            ],
        }

        for category, keywords in dangerous_keywords.items():
            for keyword, weight in keywords:
                if keyword in text_lower:
                    signals.append(IntentSignal(
                        category=category,
                        confidence=weight,
                        pattern=f"keyword:{keyword}",
                        evidence=keyword,
                    ))

        return signals
