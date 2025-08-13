# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Threat indicator validation."""

import re
from typing import Any

import structlog

from prompt_sentinel.detection.heuristics import HeuristicDetector

from .models import ThreatIndicator, ThreatSeverity

logger = structlog.get_logger()


class ThreatValidator:
    """Validates threat indicators and patterns."""

    def __init__(self) -> None:
        """Initialize validator."""
        self.heuristic_detector = HeuristicDetector()
        self.safe_test_phrases = [
            "Hello, how are you?",
            "What's the weather today?",
            "Can you help me with Python?",
            "Tell me a joke",
            "What is the capital of France?",
        ]

    async def validate(self, indicator: ThreatIndicator) -> bool:
        """Validate a threat indicator.

        Args:
            indicator: Threat indicator to validate

        Returns:
            True if valid
        """
        # Validate pattern syntax
        if not self._validate_pattern_syntax(indicator.pattern):
            logger.warning(
                "Invalid pattern syntax", indicator_id=indicator.id, pattern=indicator.pattern
            )
            return False

        # Test for false positives
        false_positive_rate = await self._test_false_positives(indicator)
        if false_positive_rate > 0.2:  # 20% threshold
            logger.warning(
                "High false positive rate", indicator_id=indicator.id, rate=false_positive_rate
            )
            indicator.false_positive_rate = false_positive_rate
            # Don't reject, but reduce confidence
            indicator.confidence *= 1 - false_positive_rate

        # Test detection effectiveness
        if indicator.test_cases:
            detection_rate = await self._test_detection_rate(indicator)
            if detection_rate < 0.5:  # 50% threshold
                logger.warning("Low detection rate", indicator_id=indicator.id, rate=detection_rate)
                return False

        # Validate severity consistency
        if not self._validate_severity(indicator):
            logger.warning(
                "Inconsistent severity", indicator_id=indicator.id, severity=indicator.severity
            )

        return True

    async def test_pattern(self, pattern: str, test_cases: list[str] | None = None) -> dict:
        """Test a pattern against known samples.

        Args:
            pattern: Regex pattern
            test_cases: Optional test cases

        Returns:
            Test results
        """
        results: dict[str, Any] = {
            "valid": False,
            "false_positive_rate": 0.0,
            "detection_rate": 0.0,
            "matches": [],
            "errors": [],
        }

        # Validate syntax
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            results["valid"] = True
        except re.error as e:
            results["errors"].append(f"Invalid regex: {e}")
            return results

        # Test against safe phrases
        false_positives = 0
        for phrase in self.safe_test_phrases:
            if compiled.search(phrase):
                false_positives += 1
                results["matches"].append({"text": phrase, "type": "false_positive"})

        results["false_positive_rate"] = false_positives / len(self.safe_test_phrases)

        # Test against provided test cases
        if test_cases:
            detections = 0
            for test_case in test_cases:
                if compiled.search(test_case):
                    detections += 1
                    results["matches"].append({"text": test_case, "type": "true_positive"})

            results["detection_rate"] = detections / len(test_cases) if test_cases else 0

        return results

    def calculate_confidence(self, indicator: ThreatIndicator, test_results: dict) -> float:
        """Calculate confidence score based on test results.

        Args:
            indicator: Threat indicator
            test_results: Pattern test results

        Returns:
            Confidence score (0-1)
        """
        base_confidence = indicator.confidence

        # Adjust based on false positive rate
        if "false_positive_rate" in test_results:
            fpr = test_results["false_positive_rate"]
            base_confidence *= 1 - fpr * 0.5  # Reduce by up to 50%

        # Adjust based on detection rate
        if "detection_rate" in test_results:
            dr = test_results["detection_rate"]
            base_confidence *= 0.5 + dr * 0.5  # Scale between 50-100%

        # Adjust based on severity
        severity_multipliers = {
            ThreatSeverity.CRITICAL: 1.0,
            ThreatSeverity.HIGH: 0.95,
            ThreatSeverity.MEDIUM: 0.85,
            ThreatSeverity.LOW: 0.7,
            ThreatSeverity.INFO: 0.5,
        }
        base_confidence *= severity_multipliers.get(indicator.severity, 0.8)

        return min(1.0, max(0.0, base_confidence))

    # Private methods

    def _validate_pattern_syntax(self, pattern: str) -> bool:
        """Validate regex pattern syntax."""
        if not pattern:
            return False

        try:
            re.compile(pattern, re.IGNORECASE)
            return True
        except re.error:
            return False

    async def _test_false_positives(self, indicator: ThreatIndicator) -> float:
        """Test pattern for false positives."""
        try:
            compiled = re.compile(indicator.pattern, re.IGNORECASE)
            false_positives = sum(1 for phrase in self.safe_test_phrases if compiled.search(phrase))
            return false_positives / len(self.safe_test_phrases)
        except Exception:
            return 1.0  # Assume worst case

    async def _test_detection_rate(self, indicator: ThreatIndicator) -> float:
        """Test pattern detection rate."""
        if not indicator.test_cases:
            return 1.0  # Assume it works if no test cases

        try:
            compiled = re.compile(indicator.pattern, re.IGNORECASE)
            detections = sum(1 for test_case in indicator.test_cases if compiled.search(test_case))
            return detections / len(indicator.test_cases)
        except Exception:
            return 0.0

    def _validate_severity(self, indicator: ThreatIndicator) -> bool:
        """Validate severity is appropriate."""
        # Critical severity should have high confidence
        if indicator.severity == ThreatSeverity.CRITICAL:
            return indicator.confidence >= 0.8

        # Info severity should have lower confidence
        if indicator.severity == ThreatSeverity.INFO:
            return indicator.confidence <= 0.7

        return True
