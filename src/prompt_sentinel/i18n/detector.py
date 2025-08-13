# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Multilingual detection capabilities."""

from typing import Any

from prompt_sentinel.models.schemas import Verdict


class MultilingualDetector:
    """Detector with multilingual support."""

    def __init__(self, supported_languages: list[str] | None = None):
        """Initialize multilingual detector."""
        self.supported_languages = supported_languages or [
            "en",
            "es",
            "fr",
            "de",
            "it",
            "pt",
            "zh",
            "ja",
            "ko",
            "ar",
            "hi",
            "ru",
        ]
        self.current_language = "en"

    async def detect_language(self, text: str) -> str:
        """Detect language of text."""
        # Stub implementation - returns English for now
        if "bonjour" in text.lower() or "comment" in text.lower():
            return "fr"
        elif "hola" in text.lower() or "cómo" in text.lower():
            return "es"
        elif "guten" in text.lower() or "wie" in text.lower():
            return "de"
        elif "ciao" in text.lower() or "come" in text.lower():
            return "it"
        elif "olá" in text.lower() or "como" in text.lower():
            return "pt"
        elif "你好" in text or "怎么" in text:
            return "zh"
        elif "こんにちは" in text or "どう" in text:
            return "ja"
        elif "안녕" in text or "어떻게" in text:
            return "ko"
        elif "مرحبا" in text or "كيف" in text:
            return "ar"
        elif "नमस्ते" in text or "कैसे" in text:
            return "hi"
        elif "привет" in text.lower() or "как" in text.lower():
            return "ru"
        return "en"

    async def detect(
        self, text: str, language: str | None = None
    ) -> tuple[Verdict, list[Any], float]:
        """Detect prompt injection in text."""
        # Auto-detect language if not provided
        if language is None:
            language = await self.detect_language(text)

        # Stub implementation - basic detection
        confidence = 0.0
        reasons = []

        # Check for common injection patterns in any language
        injection_keywords = {
            "en": ["ignore", "disregard", "forget", "override"],
            "es": ["ignorar", "descartar", "olvidar", "anular"],
            "fr": ["ignorer", "négliger", "oublier", "remplacer"],
            "de": ["ignorieren", "verwerfen", "vergessen", "überschreiben"],
        }

        keywords = injection_keywords.get(language, injection_keywords["en"])
        text_lower = text.lower()

        for keyword in keywords:
            if keyword in text_lower:
                confidence = 0.8
                reasons.append(f"Detected keyword: {keyword}")
                break

        if confidence > 0.7:
            return Verdict.BLOCK, reasons, confidence
        elif confidence > 0.4:
            return Verdict.FLAG, reasons, confidence
        else:
            return Verdict.ALLOW, reasons, confidence

    def normalize_unicode(self, text: str) -> str:
        """Normalize Unicode text."""
        import unicodedata

        return unicodedata.normalize("NFKC", text)

    def handle_mixed_script(self, text: str) -> str:
        """Handle mixed script text."""
        # Stub implementation
        return text

    def detect_script_mixing(self, text: str) -> bool:
        """Detect if text contains mixed scripts."""
        # Stub implementation
        import unicodedata

        scripts = set()
        for char in text:
            if char.isalpha():
                # Get the script of the character
                try:
                    name = unicodedata.name(char)
                    if "LATIN" in name:
                        scripts.add("latin")
                    elif "CYRILLIC" in name:
                        scripts.add("cyrillic")
                    elif "ARABIC" in name:
                        scripts.add("arabic")
                    elif "CJK" in name or "HIRAGANA" in name or "KATAKANA" in name:
                        scripts.add("cjk")
                except ValueError:
                    pass
        return len(scripts) > 1
