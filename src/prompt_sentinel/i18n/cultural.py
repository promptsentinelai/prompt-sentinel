# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Cultural context handling for internationalization."""

from typing import Any


class CulturalAdapter:
    """Adapt detection for cultural contexts."""

    def __init__(self):
        """Initialize cultural adapter."""
        self.cultural_contexts = {
            "formal": ["please", "kindly", "would you", "could you"],
            "informal": ["hey", "wanna", "gonna", "yeah"],
            "polite": ["sir", "madam", "excuse me", "pardon"],
            "direct": ["do this", "must", "now", "immediately"],
        }

        self.idiomatic_expressions = {
            "en": ["break a leg", "piece of cake", "hit the nail on the head"],
            "es": ["estar en las nubes", "costar un ojo de la cara"],
            "fr": ["avoir le cafard", "tomber dans les pommes"],
            "de": ["die Daumen drücken", "ins Fettnäpfchen treten"],
        }

    def detect_context(self, text: str) -> dict[str, Any]:
        """Detect cultural context from text."""
        text_lower = text.lower()

        detected_contexts = []
        for context, keywords in self.cultural_contexts.items():
            if any(keyword in text_lower for keyword in keywords):
                detected_contexts.append(context)

        # Determine primary context
        primary_context = "neutral"
        if detected_contexts:
            if "formal" in detected_contexts:
                primary_context = "formal"
            elif "informal" in detected_contexts:
                primary_context = "informal"
            elif "polite" in detected_contexts:
                primary_context = "polite"
            else:
                primary_context = detected_contexts[0]

        return {
            "primary_context": primary_context,
            "detected_contexts": detected_contexts,
            "confidence": 0.8 if detected_contexts else 0.5,
        }

    def detect_idioms(self, text: str, language: str = "en") -> list[str]:
        """Detect idiomatic expressions."""
        detected_idioms = []

        if language in self.idiomatic_expressions:
            text_lower = text.lower()
            for idiom in self.idiomatic_expressions[language]:
                if idiom.lower() in text_lower:
                    detected_idioms.append(idiom)

        return detected_idioms

    def adapt_for_culture(self, detection_result: dict[str, Any], culture: str) -> dict[str, Any]:
        """Adapt detection results for cultural context."""
        # Different cultures may have different thresholds
        cultural_adjustments = {
            "formal": {"threshold_adjustment": 0.1},  # More lenient
            "informal": {"threshold_adjustment": -0.1},  # Stricter
            "polite": {"threshold_adjustment": 0.05},
            "direct": {"threshold_adjustment": -0.05},
        }

        adjustment = cultural_adjustments.get(culture, {"threshold_adjustment": 0})

        # Apply adjustment to confidence
        if "confidence" in detection_result:
            detection_result["confidence"] = max(
                0, min(1, detection_result["confidence"] + adjustment["threshold_adjustment"])
            )

        detection_result["cultural_context"] = culture
        return detection_result
