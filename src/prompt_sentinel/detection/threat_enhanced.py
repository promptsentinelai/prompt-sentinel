# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Threat intelligence enhanced detection."""

import re
from typing import Any

import structlog

from prompt_sentinel.models.schemas import (
    DetectionCategory,
    DetectionReason,
    Message,
    Verdict,
)
from prompt_sentinel.threat_intelligence import ThreatFeedManager

logger = structlog.get_logger()


class ThreatEnhancedDetector:
    """Detector enhanced with threat intelligence feeds."""

    def __init__(self, feed_manager: ThreatFeedManager | None = None):
        """Initialize threat-enhanced detector.

        Args:
            feed_manager: Threat feed manager instance
        """
        self.feed_manager = feed_manager or ThreatFeedManager()
        self._pattern_cache: dict[str, Any] = {}
        self._cache_ttl = 300  # 5 minutes
        self._last_cache_update = None

    async def detect(self, messages: list[Message]) -> tuple[Verdict, list[DetectionReason], float]:
        """Detect threats using intelligence feeds.

        Args:
            messages: Messages to analyze

        Returns:
            Tuple of (verdict, reasons, confidence)
        """
        # Update pattern cache if needed
        await self._update_pattern_cache()

        reasons = []
        max_confidence = 0.0

        for message in messages:
            content = message.content.lower()

            # Check against threat indicators
            for indicator in self._pattern_cache.values():
                try:
                    pattern = re.compile(indicator.pattern, re.IGNORECASE)
                    if pattern.search(content):
                        # Match found
                        confidence = indicator.confidence

                        # Adjust confidence based on false positive rate
                        if indicator.false_positive_rate:
                            confidence *= 1 - indicator.false_positive_rate * 0.5

                        reasons.append(
                            DetectionReason(
                                category=self._map_technique_to_category(indicator.technique.value),
                                description=f"Threat Intelligence: {indicator.description} (ID: {indicator.id}, Feed: {indicator.feed_id}, Severity: {indicator.severity.value})",
                                confidence=confidence,
                                source="heuristic",
                                patterns_matched=[indicator.pattern],
                            )
                        )

                        max_confidence = max(max_confidence, confidence)

                        # Report detection
                        await self.feed_manager.confirm_true_positive(
                            indicator.id, f"Detected in message: {message.role.value}"
                        )

                except re.error as e:
                    logger.warning(
                        "Invalid pattern in threat indicator",
                        indicator_id=indicator.id,
                        error=str(e),
                    )
                    continue

        # Determine verdict
        verdict = self._determine_verdict(max_confidence)

        return verdict, reasons, max_confidence

    async def get_threat_context(self, text: str) -> dict:
        """Get threat context for a text.

        Args:
            text: Text to analyze

        Returns:
            Threat context information
        """
        techniques_set: set[str] = set()
        context = {
            "threats_detected": [],
            "techniques": [],
            "severity": "low",
            "recommendations": [],
        }

        # Update cache
        await self._update_pattern_cache()

        # Check against indicators
        for indicator in self._pattern_cache.values():
            try:
                pattern = re.compile(indicator.pattern, re.IGNORECASE)
                if pattern.search(text.lower()):
                    threat_info = {
                        "indicator_id": indicator.id,
                        "description": indicator.description,
                        "technique": indicator.technique.value,
                        "severity": indicator.severity.value,
                        "confidence": indicator.confidence,
                        "tags": indicator.tags,
                    }
                    context["threats_detected"].append(threat_info)
                    techniques_set.add(indicator.technique.value)

                    # Update severity
                    if self._compare_severity(indicator.severity.value, context["severity"]) > 0:
                        context["severity"] = indicator.severity.value

            except Exception:
                continue

        # Convert techniques set to list
        context["techniques"] = list(techniques_set)

        # Add recommendations
        if context["threats_detected"]:
            context["recommendations"] = self._generate_recommendations(context)

        return context

    async def update_patterns(self):
        """Force update of threat patterns."""
        await self._update_pattern_cache(force=True)

    # Private methods

    async def _update_pattern_cache(self, force: bool = False):
        """Update cached threat patterns."""
        import time

        now = time.time()

        # Check if update needed
        if not force and self._last_cache_update:
            if now - self._last_cache_update < self._cache_ttl:
                return

        # Get active indicators
        indicators = await self.feed_manager.get_active_indicators(min_confidence=0.5)

        # Update cache
        self._pattern_cache = {ind.id: ind for ind in indicators}
        self._last_cache_update = now  # type: ignore[assignment]

        logger.info("Updated threat pattern cache", indicator_count=len(self._pattern_cache))

    def _map_technique_to_category(self, technique: str) -> DetectionCategory:
        """Map attack technique to detection category."""
        mapping = {
            "jailbreak": DetectionCategory.JAILBREAK,
            "role_play": DetectionCategory.ROLE_MANIPULATION,
            "instruction_override": DetectionCategory.DIRECT_INJECTION,
            "context_manipulation": DetectionCategory.CONTEXT_SWITCHING,
            "encoding_obfuscation": DetectionCategory.ENCODING_ATTACK,
            "prompt_leaking": DetectionCategory.PROMPT_LEAK,
            "indirect_injection": DetectionCategory.INDIRECT_INJECTION,
            "multi_step": DetectionCategory.DIRECT_INJECTION,  # Map to direct injection
            "adversarial": DetectionCategory.JAILBREAK,  # Map to jailbreak
            "unknown": DetectionCategory.DIRECT_INJECTION,
        }
        return mapping.get(technique, DetectionCategory.DIRECT_INJECTION)

    def _determine_verdict(self, confidence: float) -> Verdict:
        """Determine verdict based on confidence."""
        if confidence >= 0.9:
            return Verdict.BLOCK
        elif confidence >= 0.7:
            return Verdict.FLAG
        elif confidence >= 0.5:
            return Verdict.FLAG
        else:
            return Verdict.ALLOW

    def _compare_severity(self, sev1: str, sev2: str) -> int:
        """Compare severity levels."""
        levels = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        return levels.get(sev1, 0) - levels.get(sev2, 0)

    def _generate_recommendations(self, context: dict) -> list[str]:
        """Generate security recommendations."""
        recommendations = []

        # Based on severity
        if context["severity"] in ["critical", "high"]:
            recommendations.append("Block this request immediately")
            recommendations.append("Review system prompts for vulnerabilities")
            recommendations.append("Enable strict detection mode")

        # Based on techniques
        techniques = context["techniques"]
        if "jailbreak" in techniques:
            recommendations.append("Implement role-based access controls")
            recommendations.append("Use instruction hierarchies")

        if "encoding_obfuscation" in techniques:
            recommendations.append("Decode and validate all input")
            recommendations.append("Implement character filtering")

        if "prompt_leaking" in techniques:
            recommendations.append("Sanitize system prompts")
            recommendations.append("Implement output filtering")

        return recommendations
