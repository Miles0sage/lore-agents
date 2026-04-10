"""Darwin Failure Capture — the moat.

Captures agent failures, hashes root causes, clusters them to find
novel attack patterns, and generates learned policies.

This is what Microsoft AGT and Asqav CANNOT do:
- They enforce rules humans write
- Phalanx learns rules from failures

Pipeline: failure → root_cause_hash → cluster → pattern → DynamicPolicy

No ML dependencies — uses locality-sensitive hashing and density-based
clustering in pure Python for zero-dependency deployment.
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

from phalanx.governance.types import (
    ActionVerdict,
    AgentIdentity,
    ExecutionContext,
    ExecutionRing,
    IntentCategory,
    PolicyResult,
)


def _normalize_error_msg(msg: str) -> str:
    """Strip variable content (numbers, paths) to get the error template."""
    msg = re.sub(r'\b\d+\b', 'N', msg)           # 404 → N
    msg = re.sub(r'/[\w./\-]+', 'PATH', msg)     # /tmp/file.json → PATH
    msg = re.sub(r'\b[0-9a-f]{8,64}\b', 'HEX', msg)  # hex IDs → HEX (bounded, no ReDoS)
    return msg.lower().strip()[:200]


@dataclass(frozen=True)
class FailureRecord:
    """A captured failure event for Darwin analysis."""

    root_cause_hash: str
    agent_id: str
    action: str
    params_hash: str
    ring: ExecutionRing
    trust_score: int
    verdict: ActionVerdict
    intent_category: IntentCategory
    error_type: str
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FailureCluster:
    """A cluster of related failures — a pattern."""

    cluster_id: str
    root_cause_hash: str
    count: int
    first_seen: float
    last_seen: float
    agent_ids: frozenset[str]
    sample_actions: tuple[str, ...]
    error_type: str
    intent_category: IntentCategory
    confidence: float  # 0.0-1.0 how confident we are this is a real pattern

    @property
    def is_novel(self) -> bool:
        """A cluster is novel if it's seen across multiple agents."""
        return len(self.agent_ids) >= 2

    @property
    def age_seconds(self) -> float:
        return time.time() - self.first_seen


@dataclass(frozen=True)
class LearnedRule:
    """A rule generated from failure analysis."""

    rule_id: str
    source_cluster_id: str
    action_pattern: str  # Glob pattern for matching
    intent_category: IntentCategory
    confidence: float
    created_at: float = field(default_factory=time.time)
    description: str = ""


class DarwinFailureCapture:
    """Captures and clusters agent failures to discover patterns.

    Usage:
        darwin = DarwinFailureCapture()

        # After a hypervisor deny:
        darwin.capture(ctx, result)

        # Periodically analyze for patterns:
        clusters = darwin.analyze()
        for cluster in clusters:
            if cluster.is_novel:
                rules = darwin.generate_rules(cluster)
    """

    def __init__(
        self,
        min_cluster_size: int = 3,
        max_buffer_size: int = 10000,
        cluster_window_seconds: float = 3600.0,
    ) -> None:
        self._min_cluster_size = min_cluster_size
        self._max_buffer = max_buffer_size
        self._window = cluster_window_seconds
        self._buffer: list[FailureRecord] = []
        self._clusters: dict[str, FailureCluster] = {}
        self._learned_rules: list[LearnedRule] = []

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)

    @property
    def clusters(self) -> dict[str, FailureCluster]:
        return dict(self._clusters)

    @property
    def learned_rules(self) -> list[LearnedRule]:
        return list(self._learned_rules)

    def generate_root_cause_hash(
        self,
        ctx: ExecutionContext,
        error_type: str = "policy_deny",
        intent: IntentCategory = IntentCategory.SAFE,
        error_message: str = "",
    ) -> str:
        """Generate a deterministic hash for a failure root cause.

        Hash components:
        - action name (normalized)
        - execution ring at time of failure
        - error type classification
        - intent category
        - normalized error message (strips variable content like numbers/paths)
        """
        components = [
            ctx.action.split(":")[0] if ":" in ctx.action else ctx.action,
            str(ctx.ring.value),
            error_type,
            intent.value,
            _normalize_error_msg(error_message),
        ]
        raw = "|".join(components)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def capture(
        self,
        ctx: ExecutionContext,
        result: PolicyResult | None = None,
        error_type: str = "policy_deny",
        intent: IntentCategory = IntentCategory.SAFE,
        metadata: dict[str, Any] | None = None,
        error_message: str = "",
    ) -> FailureRecord:
        """Capture a failure event into the buffer."""
        root_hash = self.generate_root_cause_hash(ctx, error_type, intent, error_message)

        # Hash params for deduplication (don't store raw params)
        params_str = str(sorted(ctx.params.items())) if ctx.params else ""
        params_hash = hashlib.sha256(params_str.encode()).hexdigest()[:12]

        record = FailureRecord(
            root_cause_hash=root_hash,
            agent_id=ctx.agent.agent_id,
            action=ctx.action,
            params_hash=params_hash,
            ring=ctx.ring,
            trust_score=ctx.agent.trust_score,
            verdict=result.verdict if result else ActionVerdict.DENY,
            intent_category=intent,
            error_type=error_type,
            metadata=metadata or {},
        )

        self._buffer.append(record)

        # Evict oldest if buffer full
        if len(self._buffer) > self._max_buffer:
            self._buffer = self._buffer[-self._max_buffer:]

        return record

    def analyze(self) -> list[FailureCluster]:
        """Analyze the failure buffer for patterns.

        Groups failures by root_cause_hash (density-based clustering).
        Returns clusters that meet the minimum size threshold.
        """
        now = time.time()
        cutoff = now - self._window

        # Filter to window
        recent = [r for r in self._buffer if r.timestamp > cutoff]

        # Group by root cause hash
        groups: dict[str, list[FailureRecord]] = defaultdict(list)
        for record in recent:
            groups[record.root_cause_hash].append(record)

        # Build clusters from groups meeting threshold
        new_clusters: list[FailureCluster] = []
        for root_hash, records in groups.items():
            if len(records) < self._min_cluster_size:
                continue

            agent_ids = frozenset(r.agent_id for r in records)
            actions = tuple(dict.fromkeys(r.action for r in records))[:10]
            timestamps = [r.timestamp for r in records]

            # Confidence based on density and cross-agent spread
            density_score = min(1.0, len(records) / (self._min_cluster_size * 3))
            spread_score = min(1.0, len(agent_ids) / 3)
            confidence = (density_score + spread_score) / 2

            cluster = FailureCluster(
                cluster_id=f"cl_{root_hash[:8]}_{int(now)}",
                root_cause_hash=root_hash,
                count=len(records),
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                agent_ids=agent_ids,
                sample_actions=actions,
                error_type=records[0].error_type,
                intent_category=records[0].intent_category,
                confidence=confidence,
            )

            self._clusters[cluster.cluster_id] = cluster
            new_clusters.append(cluster)

        return new_clusters

    def generate_rules(
        self,
        cluster: FailureCluster,
        min_confidence: float = 0.5,
    ) -> list[LearnedRule]:
        """Generate learned rules from a failure cluster.

        Extracts action patterns from the cluster's sample actions
        and creates glob-based deny rules.

        Only emits rules where cluster confidence >= min_confidence to
        avoid generating rules from weak or noisy clusters.
        """
        if cluster.confidence < min_confidence:
            return []

        rules: list[LearnedRule] = []

        # Find common action prefixes
        prefixes = self._extract_common_prefixes(list(cluster.sample_actions))

        for prefix in prefixes:
            rule = LearnedRule(
                rule_id=f"lr_{cluster.cluster_id}_{len(rules)}",
                source_cluster_id=cluster.cluster_id,
                action_pattern=f"{prefix}*",
                intent_category=cluster.intent_category,
                confidence=cluster.confidence,
                description=(
                    f"Auto-learned from {cluster.count} failures across "
                    f"{len(cluster.agent_ids)} agents. "
                    f"Error type: {cluster.error_type}"
                ),
            )
            rules.append(rule)
            self._learned_rules.append(rule)

        return rules

    def get_stats(self) -> dict[str, Any]:
        """Get Darwin engine statistics."""
        return {
            "buffer_size": len(self._buffer),
            "clusters": len(self._clusters),
            "learned_rules": len(self._learned_rules),
            "novel_clusters": sum(
                1 for c in self._clusters.values() if c.is_novel
            ),
        }

    def _extract_common_prefixes(self, actions: list[str]) -> list[str]:
        """Extract common action prefixes for glob pattern generation.

        Skips patterns that are too broad: those shorter than 10 characters
        (e.g. "tool:" or "a:") would match a large fraction of normal agent
        actions and act as an accidental wildcard block.

        O(n) single-pass: zip the first action's segments against all others
        rather than building a set per segment index.
        """
        if not actions:
            return []

        # Split actions by delimiter and find common prefixes
        split_actions = [a.split(":") for a in actions]

        if len(split_actions) == 1:
            # Single action — use the full action as prefix
            candidate = actions[0] + ":"
            return [candidate] if len(candidate) >= 10 else []

        # Single-pass O(n): use the first action as the reference and compare
        # each subsequent action's segments against it, stopping at first mismatch.
        reference = split_actions[0]
        common_depth = len(reference)
        for parts in split_actions[1:]:
            # Walk segments pairwise until they diverge
            depth = 0
            for seg_a, seg_b in zip(reference, parts):
                if seg_a == seg_b:
                    depth += 1
                else:
                    break
            common_depth = min(common_depth, depth)

        prefixes: list[str] = []
        if common_depth > 0:
            prefix = ":".join(reference[:common_depth]) + ":"
            prefixes = [prefix]
        else:
            # No common prefix — use most frequent first segment (single Counter pass)
            first_segments = [parts[0] for parts in split_actions]
            most_common = Counter(first_segments).most_common(1)
            if most_common:
                prefixes = [most_common[0][0] + ":"]

        # Filter out patterns that are too broad (< 10 chars would match too
        # many normal actions, effectively a wildcard block on everything)
        return [p for p in prefixes if len(p) >= 10]
