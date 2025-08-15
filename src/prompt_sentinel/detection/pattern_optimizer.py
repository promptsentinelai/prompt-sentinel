# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

"""Pattern optimization and performance tracking for heuristic detection.

This module provides advanced pattern matching optimization including:
- Pattern performance profiling
- Hit rate tracking and statistics
- Adaptive pattern reordering
- Dynamic pattern compilation
- Low-value pattern pruning
"""

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from re import Pattern
from typing import Any

import structlog

from prompt_sentinel.cache.cache_manager import CacheManager

logger = structlog.get_logger()


@dataclass
class PatternStats:
    """Statistics for individual pattern performance."""

    pattern_id: str
    pattern_str: str
    category: str
    total_checks: int = 0
    total_hits: int = 0
    total_time_ms: float = 0.0
    recent_hits: deque = field(default_factory=lambda: deque(maxlen=100))
    false_positive_count: int = 0
    true_positive_count: int = 0
    last_hit_time: float = 0.0

    @property
    def hit_rate(self) -> float:
        """Calculate hit rate percentage."""
        return (self.total_hits / self.total_checks * 100) if self.total_checks > 0 else 0.0

    @property
    def avg_time_ms(self) -> float:
        """Calculate average processing time."""
        return self.total_time_ms / self.total_checks if self.total_checks > 0 else 0.0

    @property
    def recent_hit_rate(self) -> float:
        """Calculate recent hit rate from last 100 checks."""
        if len(self.recent_hits) == 0:
            return 0.0
        return sum(self.recent_hits) / len(self.recent_hits) * 100

    @property
    def effectiveness_score(self) -> float:
        """Calculate overall effectiveness score."""
        # Factors: hit rate, true positive rate, recency, performance
        hit_score = self.hit_rate / 100

        # True positive rate (if we have feedback)
        total_positives = self.true_positive_count + self.false_positive_count
        tp_rate = self.true_positive_count / total_positives if total_positives > 0 else 0.5

        # Recency factor (patterns used recently are more valuable)
        recency_factor = 1.0 if (time.time() - self.last_hit_time) < 3600 else 0.8

        # Performance factor (faster patterns are better)
        perf_factor = (
            1.0
            if self.avg_time_ms < 0.1
            else (0.1 / self.avg_time_ms if self.avg_time_ms > 0 else 0.5)
        )

        # Weighted score
        return hit_score * 0.3 + tp_rate * 0.4 + recency_factor * 0.2 + perf_factor * 0.1


class PatternOptimizer:
    """Optimizes pattern matching performance through adaptive algorithms."""

    def __init__(self, cache_manager: CacheManager | None = None):
        """Initialize pattern optimizer.

        Args:
            cache_manager: Optional cache for storing pattern stats
        """
        self.cache = cache_manager
        self.pattern_stats: dict[str, PatternStats] = {}
        self.compiled_patterns: dict[str, Pattern] = {}
        self.pattern_order: list[str] = []
        self.reorder_threshold = 1000  # Reorder after N checks
        self.checks_since_reorder = 0
        self.pruning_threshold = 0.01  # Prune patterns with < 1% effectiveness

        # Pattern categories with metadata
        self.pattern_registry = self._initialize_patterns()
        self._compile_all_patterns()

    def _initialize_patterns(self) -> dict[str, list[tuple[str, str, float, str]]]:
        """Initialize pattern registry with categories."""
        return {
            "injection": [
                ("inj_001", r"ignore (all )?(previous|prior|above)", 0.9, "Instruction override"),
                (
                    "inj_002",
                    r"disregard (all )?(previous|prior|above|your training)",
                    0.9,
                    "Instruction override",
                ),
                ("inj_003", r"forget (everything|all|previous)", 0.85, "Memory manipulation"),
                (
                    "inj_004",
                    r"new (instructions?|commands?|rules?):",
                    0.8,
                    "New instruction injection",
                ),
                ("inj_005", r"(you are|you're) now", 0.75, "Role manipulation"),
                ("inj_006", r"act as if you (are|were)", 0.75, "Role manipulation"),
                ("inj_007", r"pretend (you are|to be)", 0.7, "Role pretending"),
                ("inj_008", r"from now on", 0.7, "Context switching"),
                (
                    "inj_009",
                    r"override (your|all|the) (instructions?|rules?|training)",
                    0.85,
                    "Override attempt",
                ),
                ("inj_010", r"stop following (your|the) (rules?|guidelines?)", 0.85, "Rule bypass"),
            ],
            "jailbreak": [
                ("jail_001", r"(DAN|dan) mode", 0.95, "DAN jailbreak"),
                ("jail_002", r"developer mode", 0.9, "Developer mode attempt"),
                (
                    "jail_003",
                    r"(disable|bypass|ignore) (safety|filters?|restrictions?)",
                    0.9,
                    "Safety bypass",
                ),
                ("jail_004", r"unlimited power", 0.85, "Unrestricted mode"),
                ("jail_005", r"no (restrictions?|limits?|rules?)", 0.8, "Restriction removal"),
                ("jail_006", r"jailbreak", 0.95, "Direct jailbreak"),
                (
                    "jail_007",
                    r"(remove|lift) all (restrictions?|limitations?)",
                    0.9,
                    "Limitation removal",
                ),
                ("jail_008", r"god mode", 0.85, "God mode attempt"),
            ],
            "data_extraction": [
                (
                    "data_001",
                    r"(show|reveal|display) (your )?(system )?(prompt|instructions?)",
                    0.9,
                    "System prompt extraction",
                ),
                (
                    "data_002",
                    r"what are your (instructions?|rules?|guidelines?)",
                    0.85,
                    "Instruction fishing",
                ),
                (
                    "data_003",
                    r"repeat (your |the )?(first|initial|original)",
                    0.8,
                    "Context extraction",
                ),
                (
                    "data_004",
                    r"(list|show) all (your )?capabilities",
                    0.75,
                    "Capability enumeration",
                ),
                (
                    "data_005",
                    r"tell me (about )?your (training|dataset|model)",
                    0.8,
                    "Model information",
                ),
                (
                    "data_006",
                    r"(print|output|echo) (your|the) (prompt|instructions?)",
                    0.85,
                    "Direct extraction",
                ),
            ],
            "encoding": [
                ("enc_001", r"base64|base32|hex|binary", 0.7, "Encoding detected"),
                ("enc_002", r"rot13|caesar|cipher", 0.75, "Cipher detected"),
                ("enc_003", r"[A-Za-z0-9+/]{50,}={0,2}", 0.6, "Possible base64"),
                ("enc_004", r"\\x[0-9a-fA-F]{2}", 0.65, "Hex encoding"),
            ],
        }

    def _compile_all_patterns(self) -> None:
        """Compile all patterns and initialize statistics."""
        for category, patterns in self.pattern_registry.items():
            for pattern_id, pattern_str, _confidence, _description in patterns:
                try:
                    # Compile pattern
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                    self.compiled_patterns[pattern_id] = compiled

                    # Initialize stats
                    self.pattern_stats[pattern_id] = PatternStats(
                        pattern_id=pattern_id,
                        pattern_str=pattern_str,
                        category=category,
                    )

                    # Initial order (by confidence)
                    self.pattern_order.append(pattern_id)

                except re.error as e:
                    logger.error(f"Failed to compile pattern {pattern_id}: {e}")

        # Sort initial order by confidence
        self._reorder_patterns()
        logger.info(f"Compiled {len(self.compiled_patterns)} patterns")

    def check_patterns(
        self, text: str, category: str | None = None
    ) -> list[tuple[str, float, str]]:
        """Check text against patterns and collect statistics.

        Args:
            text: Text to check
            category: Optional category to limit checking

        Returns:
            List of (pattern_id, confidence, description) for matches
        """
        matches = []
        self.checks_since_reorder += 1

        # Determine patterns to check
        patterns_to_check = self.pattern_order
        if category:
            patterns_to_check = [
                pid for pid in self.pattern_order if self.pattern_stats[pid].category == category
            ]

        for pattern_id in patterns_to_check:
            if pattern_id not in self.compiled_patterns:
                continue

            pattern = self.compiled_patterns[pattern_id]
            stats = self.pattern_stats[pattern_id]

            # Time the pattern check
            start = time.perf_counter()
            match = pattern.search(text)
            elapsed_ms = (time.perf_counter() - start) * 1000

            # Update statistics
            stats.total_checks += 1
            stats.total_time_ms += elapsed_ms

            if match:
                stats.total_hits += 1
                stats.recent_hits.append(1)
                stats.last_hit_time = time.time()

                # Get pattern metadata
                for _cat, patterns in self.pattern_registry.items():
                    for pid, _, conf, desc in patterns:
                        if pid == pattern_id:
                            matches.append((pattern_id, conf, desc))
                            break
            else:
                stats.recent_hits.append(0)

        # Reorder patterns periodically
        if self.checks_since_reorder >= self.reorder_threshold:
            self._reorder_patterns()
            self.checks_since_reorder = 0

        return matches

    def _reorder_patterns(self) -> None:
        """Reorder patterns based on effectiveness scores."""
        # Calculate effectiveness scores
        pattern_scores = []
        for pattern_id, stats in self.pattern_stats.items():
            if stats.total_checks > 10:  # Need minimum data
                score = stats.effectiveness_score
                pattern_scores.append((score, pattern_id))

        # Sort by score (highest first)
        pattern_scores.sort(reverse=True)

        # Update pattern order
        new_order = [pid for _, pid in pattern_scores]

        # Add any patterns without enough data at the end
        for pattern_id in self.compiled_patterns:
            if pattern_id not in new_order:
                new_order.append(pattern_id)

        self.pattern_order = new_order
        logger.debug(f"Reordered patterns, top 3: {self.pattern_order[:3]}")

    def prune_patterns(self) -> list[str]:
        """Identify and remove low-value patterns.

        Returns:
            List of pruned pattern IDs
        """
        pruned = []

        for pattern_id, stats in self.pattern_stats.items():
            # Need sufficient data
            if stats.total_checks < 100:
                continue

            # Check effectiveness
            if stats.effectiveness_score < self.pruning_threshold:
                pruned.append(pattern_id)
                logger.info(
                    f"Pruning pattern {pattern_id}: "
                    f"effectiveness={stats.effectiveness_score:.3f}, "
                    f"hit_rate={stats.hit_rate:.1f}%"
                )

        # Remove pruned patterns
        for pattern_id in pruned:
            if pattern_id in self.compiled_patterns:
                del self.compiled_patterns[pattern_id]
            if pattern_id in self.pattern_order:
                self.pattern_order.remove(pattern_id)

        return pruned

    def add_feedback(self, pattern_id: str, is_true_positive: bool) -> None:
        """Add feedback about pattern match quality.

        Args:
            pattern_id: Pattern that matched
            is_true_positive: Whether the match was a true positive
        """
        if pattern_id in self.pattern_stats:
            stats = self.pattern_stats[pattern_id]
            if is_true_positive:
                stats.true_positive_count += 1
            else:
                stats.false_positive_count += 1

    def get_statistics(self) -> dict[str, Any]:
        """Get comprehensive pattern statistics.

        Returns:
            Dictionary with pattern performance metrics
        """
        total_checks = sum(s.total_checks for s in self.pattern_stats.values())
        total_hits = sum(s.total_hits for s in self.pattern_stats.values())
        total_time = sum(s.total_time_ms for s in self.pattern_stats.values())

        # Top performers
        top_patterns = sorted(
            self.pattern_stats.items(), key=lambda x: x[1].effectiveness_score, reverse=True
        )[:5]

        # Worst performers
        worst_patterns = sorted(self.pattern_stats.items(), key=lambda x: x[1].effectiveness_score)[
            :5
        ]

        return {
            "total_patterns": len(self.compiled_patterns),
            "total_checks": total_checks,
            "total_hits": total_hits,
            "overall_hit_rate": (total_hits / total_checks * 100) if total_checks > 0 else 0,
            "total_time_ms": total_time,
            "avg_time_per_check_ms": total_time / total_checks if total_checks > 0 else 0,
            "top_performers": [
                {
                    "id": pid,
                    "category": stats.category,
                    "hit_rate": stats.hit_rate,
                    "effectiveness": stats.effectiveness_score,
                    "avg_time_ms": stats.avg_time_ms,
                }
                for pid, stats in top_patterns
            ],
            "worst_performers": [
                {
                    "id": pid,
                    "category": stats.category,
                    "hit_rate": stats.hit_rate,
                    "effectiveness": stats.effectiveness_score,
                    "avg_time_ms": stats.avg_time_ms,
                }
                for pid, stats in worst_patterns
            ],
            "pattern_order": self.pattern_order[:10],  # Top 10 in current order
        }

    def export_optimized_patterns(self) -> dict[str, list[tuple[str, float, str]]]:
        """Export optimized pattern set for production use.

        Returns:
            Optimized patterns organized by category
        """
        optimized = defaultdict(list)

        # Group by category and sort by effectiveness
        for pattern_id in self.pattern_order:
            if pattern_id not in self.pattern_stats:
                continue

            stats = self.pattern_stats[pattern_id]

            # Skip low-effectiveness patterns
            if stats.effectiveness_score < self.pruning_threshold:
                continue

            # Find pattern details
            for category, patterns in self.pattern_registry.items():
                for pid, pattern_str, confidence, description in patterns:
                    if pid == pattern_id:
                        # Adjust confidence based on effectiveness
                        adjusted_conf = confidence * stats.effectiveness_score
                        optimized[category].append((pattern_str, adjusted_conf, description))
                        break

        return dict(optimized)


class AdaptivePatternMatcher:
    """Adaptive pattern matcher that learns from usage patterns."""

    def __init__(self, optimizer: PatternOptimizer):
        """Initialize adaptive matcher.

        Args:
            optimizer: Pattern optimizer instance
        """
        self.optimizer = optimizer
        self.context_patterns: dict[str, list[str]] = defaultdict(list)
        self.pattern_cache: dict[int, list[tuple[str, float, str]]] = {}
        self.cache_hits = 0
        self.cache_misses = 0

    def match(self, text: str, context: str | None = None) -> list[tuple[str, float, str]]:
        """Match text against patterns with context awareness.

        Args:
            text: Text to match
            context: Optional context hint (e.g., "api_call", "chat", "code")

        Returns:
            List of matches with pattern info
        """
        # Check cache first
        text_hash = hash(text)
        if text_hash in self.pattern_cache:
            self.cache_hits += 1
            return self.pattern_cache[text_hash]

        self.cache_misses += 1

        # Use context-specific patterns if available
        if context and context in self.context_patterns:
            # Check context-specific patterns first
            matches = self.optimizer.check_patterns(text, category=None)
        else:
            # Check all patterns
            matches = self.optimizer.check_patterns(text)

        # Cache result
        self.pattern_cache[text_hash] = matches

        # Limit cache size
        if len(self.pattern_cache) > 10000:
            # Remove oldest entries (simple FIFO)
            oldest = list(self.pattern_cache.keys())[:1000]
            for key in oldest:
                del self.pattern_cache[key]

        return matches

    def learn_context(self, context: str, pattern_ids: list[str]) -> None:
        """Learn which patterns are effective for specific contexts.

        Args:
            context: Context identifier
            pattern_ids: Patterns that were effective in this context
        """
        for pattern_id in pattern_ids:
            if pattern_id not in self.context_patterns[context]:
                self.context_patterns[context].append(pattern_id)

        # Keep only top patterns per context
        if len(self.context_patterns[context]) > 20:
            # Sort by effectiveness
            sorted_patterns = sorted(
                self.context_patterns[context],
                key=lambda pid: self.optimizer.pattern_stats.get(
                    pid, PatternStats("", "", "")
                ).effectiveness_score,
                reverse=True,
            )
            self.context_patterns[context] = sorted_patterns[:20]

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics.

        Returns:
            Cache performance metrics
        """
        total = self.cache_hits + self.cache_misses
        return {
            "cache_size": len(self.pattern_cache),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate": (self.cache_hits / total * 100) if total > 0 else 0,
            "context_patterns": {k: len(v) for k, v in self.context_patterns.items()},
        }
