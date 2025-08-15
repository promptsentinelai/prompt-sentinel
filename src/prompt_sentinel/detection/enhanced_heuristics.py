# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

"""Enhanced heuristic detection with adaptive pattern optimization.

This module provides an improved heuristic detector that uses:
- Pattern performance tracking and optimization
- Adaptive pattern ordering based on effectiveness
- Context-aware pattern matching
- Automatic low-value pattern pruning
"""

import time
from typing import Any

import structlog

from prompt_sentinel.cache.cache_manager import CacheManager
from prompt_sentinel.detection.pattern_optimizer import (
    AdaptivePatternMatcher,
    PatternOptimizer,
)
from prompt_sentinel.models.schemas import (
    DetectionCategory,
    DetectionReason,
    Message,
    Verdict,
)

logger = structlog.get_logger()


class EnhancedHeuristicDetector:
    """Enhanced heuristic detector with adaptive pattern optimization."""

    def __init__(
        self,
        detection_mode: str = "moderate",
        cache_manager: CacheManager | None = None,
        enable_optimization: bool = True,
        enable_pruning: bool = True,
    ):
        """Initialize enhanced heuristic detector.

        Args:
            detection_mode: Detection sensitivity (strict/moderate/permissive)
            cache_manager: Optional cache manager for pattern stats
            enable_optimization: Whether to enable pattern optimization
            enable_pruning: Whether to enable automatic pattern pruning
        """
        self.detection_mode = detection_mode
        self.cache_manager = cache_manager
        self.enable_optimization = enable_optimization
        self.enable_pruning = enable_pruning

        # Initialize pattern optimizer
        self.optimizer = PatternOptimizer(cache_manager)
        self.matcher = AdaptivePatternMatcher(self.optimizer)

        # Detection statistics
        self.total_detections = 0
        self.detection_times: list[float] = []
        self.pruning_interval = 1000  # Prune after N detections

        logger.info(
            "Enhanced heuristic detector initialized",
            mode=detection_mode,
            optimization=enable_optimization,
            pruning=enable_pruning,
            patterns=len(self.optimizer.compiled_patterns),
        )

    def detect(
        self,
        messages: list[Message],
        context: str | None = None,
    ) -> tuple[Verdict, list[DetectionReason], float]:
        """Detect potential threats using optimized pattern matching.

        Args:
            messages: Messages to analyze
            context: Optional context hint for pattern selection

        Returns:
            Tuple of (verdict, reasons, confidence)
        """
        start_time = time.perf_counter()
        self.total_detections += 1

        # Combine message content
        combined_text = " ".join(msg.content for msg in messages)

        # Detect context if not provided
        if not context:
            context = self._detect_context(messages)

        # Use adaptive matcher for pattern matching
        if self.enable_optimization:
            matches = self.matcher.match(combined_text, context)
        else:
            # Fallback to basic pattern checking
            matches = self.optimizer.check_patterns(combined_text)

        # Process matches
        reasons = []
        max_confidence = 0.0
        matched_patterns = []

        for pattern_id, confidence, description in matches:
            # Adjust confidence based on detection mode
            adjusted_confidence = self._adjust_confidence(confidence)
            max_confidence = max(max_confidence, adjusted_confidence)

            # Determine category from pattern
            category = self._get_category_for_pattern(pattern_id)

            reasons.append(
                DetectionReason(
                    category=category,
                    description=description,
                    confidence=adjusted_confidence,
                    source="heuristic",
                    patterns_matched=[pattern_id],
                )
            )

            matched_patterns.append(pattern_id)

        # Learn from this detection if optimization is enabled
        if self.enable_optimization and matched_patterns:
            self.matcher.learn_context(context, matched_patterns)

        # Determine verdict
        verdict = self._determine_verdict(max_confidence)

        # Track detection time
        detection_time = (time.perf_counter() - start_time) * 1000
        self.detection_times.append(detection_time)

        # Prune patterns periodically if enabled
        if self.enable_pruning and self.total_detections % self.pruning_interval == 0:
            self._perform_pruning()

        # Log detection
        if matched_patterns:
            logger.debug(
                "Enhanced detection found threats",
                patterns=len(matched_patterns),
                verdict=verdict.value,
                confidence=max_confidence,
                time_ms=detection_time,
            )

        return verdict, reasons, max_confidence

    def _detect_context(self, messages: list[Message]) -> str:
        """Detect context from message patterns.

        Args:
            messages: Messages to analyze

        Returns:
            Context identifier
        """
        # Simple context detection based on content patterns
        combined = " ".join(msg.content.lower() for msg in messages)

        if any(keyword in combined for keyword in ["api", "endpoint", "request", "response"]):
            return "api_call"
        elif any(keyword in combined for keyword in ["code", "function", "class", "import"]):
            return "code"
        elif any(keyword in combined for keyword in ["chat", "conversation", "tell me", "how do"]):
            return "chat"
        elif len(messages) > 1:
            return "conversation"
        else:
            return "general"

    def _adjust_confidence(self, base_confidence: float) -> float:
        """Adjust confidence based on detection mode.

        Args:
            base_confidence: Base confidence value

        Returns:
            Adjusted confidence
        """
        if self.detection_mode == "strict":
            # Increase confidence for strict mode
            return min(base_confidence * 1.2, 1.0)
        elif self.detection_mode == "permissive":
            # Decrease confidence for permissive mode
            return base_confidence * 0.8
        else:
            # Moderate mode - no adjustment
            return base_confidence

    def _determine_verdict(self, confidence: float) -> Verdict:
        """Determine verdict based on confidence and mode.

        Args:
            confidence: Detection confidence

        Returns:
            Detection verdict
        """
        if self.detection_mode == "strict":
            # Lower thresholds for strict mode
            if confidence >= 0.6:
                return Verdict.BLOCK
            elif confidence >= 0.3:
                return Verdict.FLAG
            else:
                return Verdict.ALLOW
        elif self.detection_mode == "permissive":
            # Higher thresholds for permissive mode
            if confidence >= 0.8:
                return Verdict.BLOCK
            elif confidence >= 0.5:
                return Verdict.FLAG
            else:
                return Verdict.ALLOW
        else:
            # Moderate mode - balanced thresholds
            if confidence >= 0.7:
                return Verdict.BLOCK
            elif confidence >= 0.4:
                return Verdict.FLAG
            else:
                return Verdict.ALLOW

    def _get_category_for_pattern(self, pattern_id: str) -> DetectionCategory:
        """Get detection category for a pattern.

        Args:
            pattern_id: Pattern identifier

        Returns:
            Detection category
        """
        if pattern_id in self.optimizer.pattern_stats:
            category_str = self.optimizer.pattern_stats[pattern_id].category

            mapping = {
                "injection": DetectionCategory.DIRECT_INJECTION,
                "jailbreak": DetectionCategory.JAILBREAK,
                "data_extraction": DetectionCategory.PROMPT_LEAK,
                "encoding": DetectionCategory.ENCODING_ATTACK,
            }

            return mapping.get(category_str, DetectionCategory.BENIGN)

        return DetectionCategory.BENIGN

    def _perform_pruning(self) -> None:
        """Perform pattern pruning to remove low-value patterns."""
        logger.info("Performing pattern pruning")

        pruned = self.optimizer.prune_patterns()

        if pruned:
            logger.info(
                "Pruned low-value patterns",
                count=len(pruned),
                remaining=len(self.optimizer.compiled_patterns),
            )

    def add_feedback(self, pattern_ids: list[str], is_true_positive: bool) -> None:
        """Add feedback about detection quality.

        Args:
            pattern_ids: Patterns that matched
            is_true_positive: Whether the detection was correct
        """
        for pattern_id in pattern_ids:
            self.optimizer.add_feedback(pattern_id, is_true_positive)

    def get_statistics(self) -> dict:
        """Get comprehensive detection statistics.

        Returns:
            Dictionary with performance metrics
        """
        # Calculate average detection time
        avg_time = (
            sum(self.detection_times) / len(self.detection_times) if self.detection_times else 0
        )

        stats: dict[str, Any] = {
            "total_detections": self.total_detections,
            "average_detection_time_ms": avg_time,
            "detection_mode": self.detection_mode,
            "optimization_enabled": self.enable_optimization,
            "pruning_enabled": self.enable_pruning,
        }

        # Add pattern optimizer statistics
        optimizer_stats = self.optimizer.get_statistics()
        stats["pattern_stats"] = optimizer_stats

        # Add matcher cache statistics
        if self.enable_optimization:
            cache_stats = self.matcher.get_cache_stats()
            stats["cache_stats"] = cache_stats

        return stats

    def export_optimized_patterns(self) -> dict:
        """Export the optimized pattern set.

        Returns:
            Optimized patterns ready for production use
        """
        return self.optimizer.export_optimized_patterns()

    def reset_statistics(self) -> None:
        """Reset all statistics and pattern ordering."""
        # Reset optimizer stats
        for stats in self.optimizer.pattern_stats.values():
            stats.total_checks = 0
            stats.total_hits = 0
            stats.total_time_ms = 0
            stats.recent_hits.clear()
            stats.false_positive_count = 0
            stats.true_positive_count = 0

        # Reset matcher cache
        self.matcher.pattern_cache.clear()
        self.matcher.cache_hits = 0
        self.matcher.cache_misses = 0
        self.matcher.context_patterns.clear()

        # Reset detector stats
        self.total_detections = 0
        self.detection_times.clear()

        # Recompile patterns in original order
        self.optimizer._reorder_patterns()

        logger.info("Statistics reset")
