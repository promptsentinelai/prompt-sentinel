# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""ML-enhanced heuristic detector that incorporates discovered patterns."""

import structlog

from prompt_sentinel.detection.heuristics import HeuristicDetector
from prompt_sentinel.ml.manager import PatternManager
from prompt_sentinel.ml.patterns import ExtractedPattern
from prompt_sentinel.models.schemas import DetectionCategory, DetectionReason, Message, Verdict

logger = structlog.get_logger()


class MLEnhancedHeuristicDetector(HeuristicDetector):
    """Heuristic detector enhanced with ML-discovered patterns."""

    def __init__(
        self, detection_mode: str = "strict", pattern_manager: PatternManager | None = None
    ):
        """Initialize ML-enhanced detector.

        Args:
            detection_mode: One of "strict", "moderate", "permissive"
            pattern_manager: Pattern manager for ML patterns
        """
        super().__init__(detection_mode)
        self.pattern_manager = pattern_manager
        self._ml_patterns: list[ExtractedPattern] = []
        self._last_pattern_refresh = None

    async def refresh_ml_patterns(self):
        """Refresh ML patterns from pattern manager."""
        if not self.pattern_manager:
            return

        try:
            self._ml_patterns = self.pattern_manager.get_active_patterns()
            logger.info("ML patterns refreshed", count=len(self._ml_patterns))
        except Exception as e:
            logger.error("Failed to refresh ML patterns", error=str(e))

    def detect(self, messages: list[Message]) -> tuple[Verdict, list[DetectionReason], float]:
        """Enhanced detection with ML patterns.

        Performs standard heuristic detection plus ML-discovered patterns.

        Args:
            messages: List of messages to analyze

        Returns:
            Detection verdict, reasons, and confidence
        """
        # Get base heuristic detection
        verdict, reasons, confidence = super().detect(messages)

        # Add ML pattern detection
        if self._ml_patterns:
            ml_reasons, ml_confidence = self._detect_ml_patterns(messages)

            # Combine results
            reasons.extend(ml_reasons)

            # Update verdict if ML detection is more severe
            if ml_confidence > confidence:
                confidence = ml_confidence

                # Determine verdict based on ML confidence
                if ml_confidence > 0.9:
                    verdict = Verdict.BLOCK
                elif ml_confidence > 0.7:
                    verdict = Verdict.FLAG if verdict == Verdict.ALLOW else verdict
                elif ml_confidence > 0.5:
                    verdict = Verdict.FLAG if verdict == Verdict.ALLOW else verdict

        return verdict, reasons, confidence

    def _detect_ml_patterns(self, messages: list[Message]) -> tuple[list[DetectionReason], float]:
        """Detect using ML-discovered patterns.

        Args:
            messages: Messages to analyze

        Returns:
            Detection reasons and confidence
        """
        reasons = []
        max_confidence = 0.0

        for message in messages:
            text = message.content

            for pattern in self._ml_patterns:
                try:
                    if pattern.test(text):
                        # Pattern matched
                        reason = DetectionReason(
                            category=self._map_pattern_category(pattern.category),
                            description=f"ML Pattern: {pattern.description}",
                            confidence=pattern.confidence,
                            source="heuristic",  # ML patterns are considered heuristic
                            patterns_matched=[pattern.pattern_id[:8]],
                        )
                        reasons.append(reason)
                        max_confidence = max(max_confidence, pattern.confidence)

                        logger.debug(
                            "ML pattern matched",
                            pattern_id=pattern.pattern_id,
                            category=pattern.category,
                            confidence=pattern.confidence,
                        )

                except Exception as e:
                    logger.warning(
                        "Error testing ML pattern", pattern_id=pattern.pattern_id, error=str(e)
                    )

        return reasons, max_confidence

    def _map_pattern_category(self, ml_category: str) -> DetectionCategory:
        """Map ML pattern category to detection category.

        Args:
            ml_category: ML pattern category

        Returns:
            Mapped detection category
        """
        category_mapping = {
            "instruction_override": DetectionCategory.DIRECT_INJECTION,
            "injection": DetectionCategory.DIRECT_INJECTION,
            "role_manipulation": DetectionCategory.ROLE_MANIPULATION,
            "role": DetectionCategory.ROLE_MANIPULATION,
            "jailbreak": DetectionCategory.JAILBREAK,
            "extraction": DetectionCategory.PROMPT_LEAK,
            "data_extraction": DetectionCategory.PROMPT_LEAK,
            "prompt_leak": DetectionCategory.PROMPT_LEAK,
            "encoding": DetectionCategory.ENCODING_ATTACK,
            "context_switching": DetectionCategory.CONTEXT_SWITCHING,
            "context": DetectionCategory.CONTEXT_SWITCHING,
            "common_substring": DetectionCategory.DIRECT_INJECTION,
            "ngram": DetectionCategory.DIRECT_INJECTION,
            "differential": DetectionCategory.DIRECT_INJECTION,
            "template": DetectionCategory.DIRECT_INJECTION,
            "pii": DetectionCategory.PII_DETECTED,
            "evasion": DetectionCategory.CONTEXT_SWITCHING,
            "manipulation": DetectionCategory.CONTEXT_SWITCHING,
            "code": DetectionCategory.ENCODING_ATTACK,
        }

        return category_mapping.get(ml_category, DetectionCategory.DIRECT_INJECTION)

    def add_custom_pattern(
        self,
        pattern_id: str,
        regex: str,
        category: str,
        confidence: float = 0.8,
        description: str = "",
    ):
        """Add a custom pattern manually.

        Args:
            pattern_id: Unique pattern identifier
            regex: Regular expression pattern
            category: Detection category
            confidence: Pattern confidence
            description: Pattern description
        """
        from datetime import datetime

        from prompt_sentinel.ml.patterns import ExtractedPattern

        pattern = ExtractedPattern(
            pattern_id=pattern_id,
            regex=regex,
            confidence=confidence,
            support=1,
            cluster_id=-1,  # Manual pattern
            category=category,
            description=description or f"Custom pattern: {pattern_id}",
            examples=[],
            created_at=datetime.utcnow(),
            metadata={"custom": True},
        )

        self._ml_patterns.append(pattern)
        logger.info("Custom pattern added", pattern_id=pattern_id)

    def get_pattern_statistics(self) -> dict[str, any]:
        """Get statistics about loaded patterns.

        Returns:
            Pattern statistics
        """
        if not self._ml_patterns:
            return {"ml_patterns_loaded": 0, "status": "no_patterns"}

        categories = {}
        for pattern in self._ml_patterns:
            categories[pattern.category] = categories.get(pattern.category, 0) + 1

        return {
            "ml_patterns_loaded": len(self._ml_patterns),
            "categories": categories,
            "avg_confidence": sum(p.confidence for p in self._ml_patterns) / len(self._ml_patterns),
            "last_refresh": (
                self._last_pattern_refresh.isoformat() if self._last_pattern_refresh else None
            ),
        }
