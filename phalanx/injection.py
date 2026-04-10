"""phalanx.injection — Zero-dep prompt injection detector + canary tokens.

Based on the Rebuff pattern (protectai/rebuff, Apache-2.0).
No LLM calls. Sub-millisecond. Drop-in pre-execution gate.
"""
import re
import secrets
import unicodedata
from difflib import SequenceMatcher
from typing import Tuple

# Combinatorial keyword matrix
OVERRIDE_PREFIXES = [
    "Ignore", "Disregard", "Skip", "Forget", "Bypass",
    "Override", "Neglect", "Dismiss",
]
TARGETS = [
    "instructions", "directives", "commands", "previous",
    "above", "rules", "constraints", "guidelines",
]

# Pre-build all combinatorial phrase pairs for fast matching
_COMBO_PHRASES: list[Tuple[str, str]] = [
    (prefix, target) for prefix in OVERRIDE_PREFIXES for target in TARGETS
]

# Role-play jailbreaks
ROLEPLAY_PATTERNS = [
    r"act as\b",
    r"pretend (you are|to be)\b",
    r"you are now\b",
    r"from now on\b.{0,30}(you|act)",
    r"DAN\b",
    r"jailbreak",
    r"ignore (all |your )?(previous |prior )?(instructions?|rules?)",
]
_COMPILED_ROLEPLAY = [re.compile(p, re.IGNORECASE) for p in ROLEPLAY_PATTERNS]

# Base64-like: long runs of alphanum without spaces (>=20 chars)
_B64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _score_combinatorial(text: str) -> float:
    """Score 0.3 if any (prefix, target) pair matches via SequenceMatcher ratio > 0.8."""
    text_lower = text.lower()
    # Slide a window over the text to find candidate snippets
    words = text_lower.split()
    for i in range(len(words)):
        # Check windows of 2–4 words for a prefix+target combo
        window = " ".join(words[i : i + 4])
        for prefix, target in _COMBO_PHRASES:
            candidate = f"{prefix.lower()} {target.lower()}"
            ratio = SequenceMatcher(None, candidate, window[: len(candidate) + 8]).ratio()
            if ratio > 0.8:
                return 0.3
    return 0.0


def _score_roleplay(text: str) -> float:
    """Score 0.4 if any role-play jailbreak pattern matches."""
    for pattern in _COMPILED_ROLEPLAY:
        if pattern.search(text):
            return 0.4
    return 0.0


def _score_repetition(text: str) -> float:
    """Score 0.3 if the same phrase (3+ consecutive words) appears 3+ times."""
    words = text.lower().split()
    if len(words) < 9:
        return 0.0
    # Build trigrams and count occurrences
    trigrams: dict[str, int] = {}
    for i in range(len(words) - 2):
        trigram = " ".join(words[i : i + 3])
        trigrams[trigram] = trigrams.get(trigram, 0) + 1
    if any(count >= 3 for count in trigrams.values()):
        return 0.3
    return 0.0


def _score_base64(text: str) -> float:
    """Score 0.2 if text contains long alphanum blocks resembling base64/encoded payloads."""
    if _B64_PATTERN.search(text):
        return 0.2
    return 0.0


def detect_injection(text: str) -> Tuple[bool, float]:
    """Return (is_injection, confidence 0.0-1.0).

    Scores are additive across heuristics, capped at 1.0.
    is_injection is True when confidence > 0.5.
    """
    # Normalize unicode to catch homoglyph tricks
    text = unicodedata.normalize("NFKC", text)

    confidence = 0.0
    confidence += _score_combinatorial(text)
    confidence += _score_roleplay(text)
    confidence += _score_repetition(text)
    confidence += _score_base64(text)

    confidence = min(confidence, 1.0)
    is_injection = confidence > 0.5
    return is_injection, confidence


def inject_canary(system_prompt: str) -> Tuple[str, str]:
    """Embed a secret canary token in the system prompt.

    Returns (modified_prompt, canary_token).
    The canary is appended as a hidden system reference marker.
    """
    canary = secrets.token_hex(8)
    marker = f"\n[sys-ref:{canary}]"
    return system_prompt + marker, canary


def check_canary_leak(output: str, canary: str) -> bool:
    """Return True if the model leaked the canary token in its output."""
    return canary in output
