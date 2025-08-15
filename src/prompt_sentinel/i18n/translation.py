# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Translation validation for internationalization."""

from typing import Any


class TranslationValidator:
    """Validate translation consistency."""

    def __init__(self):
        """Initialize translation validator."""
        self.supported_languages = ["en", "es", "fr", "de", "ja", "zh", "ru", "ar"]

        # Sample translations for validation
        self.test_phrases = {
            "ignore_instruction": {
                "en": "ignore all instructions",
                "es": "ignorar todas las instrucciones",
                "fr": "ignorer toutes les instructions",
                "de": "alle Anweisungen ignorieren",
            },
            "system_prompt": {
                "en": "system prompt",
                "es": "indicación del sistema",
                "fr": "invite système",
                "de": "Systemaufforderung",
            },
        }

    def validate_consistency(
        self, original_text: str, translated_text: str, source_lang: str, target_lang: str
    ) -> dict[str, Any]:
        """Validate translation consistency."""
        # Simple validation based on length ratio
        length_ratio = len(translated_text) / len(original_text) if original_text else 0

        # Expected ratios between languages (simplified)
        expected_ratios = {
            ("en", "es"): 1.1,  # Spanish is usually longer
            ("en", "fr"): 1.15,  # French is usually longer
            ("en", "de"): 1.05,  # German is slightly longer
            ("en", "ja"): 0.7,  # Japanese is more compact
            ("en", "zh"): 0.5,  # Chinese is very compact
        }

        key = (source_lang, target_lang)
        expected = expected_ratios.get(key, 1.0)

        # Check if ratio is reasonable (within 50% of expected)
        is_consistent = 0.5 * expected <= length_ratio <= 1.5 * expected

        return {
            "is_consistent": is_consistent,
            "length_ratio": length_ratio,
            "expected_ratio": expected,
            "confidence": 0.8 if is_consistent else 0.3,
        }

    def back_translate_validate(self, original: str, back_translated: str) -> float:
        """Validate using back-translation."""
        # Simple similarity check
        original_words = set(original.lower().split())
        back_words = set(back_translated.lower().split())

        if not original_words:
            return 0.0

        # Jaccard similarity
        intersection = original_words & back_words
        union = original_words | back_words

        similarity = len(intersection) / len(union) if union else 0
        return similarity

    def detect_language(self, text: str) -> str:
        """Simple language detection."""
        # Very basic detection based on character sets
        if any(0x0600 <= ord(c) <= 0x06FF for c in text):
            return "ar"  # Arabic
        elif any(0x4E00 <= ord(c) <= 0x9FFF for c in text):
            return "zh"  # Chinese
        elif any(0x3040 <= ord(c) <= 0x309F or 0x30A0 <= ord(c) <= 0x30FF for c in text):
            return "ja"  # Japanese
        elif any(0x0400 <= ord(c) <= 0x04FF for c in text):
            return "ru"  # Russian/Cyrillic

        # Default to English for Latin script
        return "en"

    def get_test_phrase(self, phrase_key: str, language: str) -> str:
        """Get test phrase in specified language."""
        if phrase_key in self.test_phrases:
            return self.test_phrases[phrase_key].get(language, "")
        return ""
