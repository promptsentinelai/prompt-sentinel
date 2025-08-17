"""Analysis service for building WebSocket-friendly analysis payloads.

Decouples analysis result construction from WebSocket connection handling
to improve separation of concerns and reduce complexity in the ws module.
"""

from __future__ import annotations

from typing import Any

from prompt_sentinel.models.schemas import DetectionCategory, DetectionResponse


class AnalysisService:
    """Builds analysis summaries from detection responses."""

    def build_analysis_response(self, response: DetectionResponse) -> dict[str, Any]:
        """Return an analysis dict suitable for WebSocket responses."""
        return {
            "verdict": response.verdict,
            "confidence": response.confidence,
            "reasons": [reason.model_dump() for reason in (response.reasons or [])],
            "processing_time_ms": response.processing_time_ms,
            "metadata": response.metadata or {},
            "overall_risk_assessment": {
                "threat_level": self._calculate_threat_level(response),
                "confidence_breakdown": self._get_confidence_breakdown(response),
                "mitigation_suggestions": self._get_mitigation_suggestions(response),
            },
            "overall_risk_score": response.confidence,
            "recommendations": self._get_mitigation_suggestions(response),
        }

    def _calculate_threat_level(self, response: DetectionResponse) -> str:
        if response.verdict.name == "BLOCK":
            return "high"
        if response.verdict.name == "STRIP":
            return "medium"
        if response.verdict.name == "FLAG":
            return "low"
        return "none"

    def _get_confidence_breakdown(self, response: DetectionResponse) -> dict[str, float]:
        breakdown: dict[str, float] = {"overall": float(response.confidence or 0.0)}

        source_to_confidences: dict[str, list[float]] = {}
        for reason in response.reasons or []:
            source = str(reason.source)
            source_to_confidences.setdefault(source, []).append(float(reason.confidence or 0.0))

        for source, vals in source_to_confidences.items():
            breakdown[source] = sum(vals) / len(vals) if vals else 0.0

        return breakdown

    def _get_mitigation_suggestions(self, response: DetectionResponse) -> list[str]:
        suggestions: list[str] = []
        reason_categories = [r.category for r in (response.reasons or [])]

        if DetectionCategory.DIRECT_INJECTION in reason_categories:
            suggestions.append("Use strict role separation between system and user messages")
        if DetectionCategory.JAILBREAK in reason_categories:
            suggestions.append("Implement additional context validation")
        if DetectionCategory.PII_DETECTED in reason_categories:
            suggestions.append("Enable automatic PII redaction before processing")

        if not suggestions:
            suggestions.append("Consider reviewing prompt content for security best practices")

        return suggestions
