# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Language-specific patterns for injection detection."""

from typing import Any


class LanguagePatterns:
    """Language-specific pattern detection."""

    def __init__(self):
        """Initialize language patterns."""
        self.patterns = {
            "en": ["ignore", "disregard", "forget"],
            "es": ["ignorar", "descartar", "olvidar"],
            "fr": ["ignorer", "négliger", "oublier"],
            "de": ["ignorieren", "missachten", "vergessen"],
            "ja": ["無視", "無効", "忘れる"],
            "zh": ["忽略", "忽视", "遗忘"],
            "ru": ["игнорировать", "пренебрегать", "забыть"],
            "ar": ["تجاهل", "أهمل", "انسى"],
        }

    async def detect(self, text: str, language: str | None = None) -> dict[str, Any]:
        """Detect patterns in text for specific language."""
        result: dict[str, Any] = {"detected": False, "confidence": 0.0, "patterns": []}

        # Check for patterns in text
        if language and language in self.patterns:
            for pattern in self.patterns[language]:
                if pattern.lower() in text.lower():
                    result["detected"] = True
                    result["confidence"] = 0.8
                    result["patterns"].append(pattern)

        return result

    def get_patterns(self, language: str) -> list[str]:
        """Get patterns for a specific language."""
        return self.patterns.get(language, [])
