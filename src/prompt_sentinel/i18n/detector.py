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

    async def detect_language(self, text: str) -> dict[str, Any]:
        """Detect language of text."""
        # Stub implementation - returns English for now
        language = "en"
        confidence = 0.95

        if "bonjour" in text.lower() or "comment" in text.lower() or "allez" in text.lower():
            language = "fr"
        elif "hola" in text.lower() or "cómo" in text.lower() or "estás" in text.lower():
            language = "es"
        elif "guten" in text.lower() or "wie" in text.lower() or "ihnen" in text.lower():
            language = "de"
        elif "ciao" in text.lower() or "come" in text.lower():
            language = "it"
        elif "olá" in text.lower() or "como" in text.lower():
            language = "pt"
        elif "你好" in text or "怎么" in text or "好吗" in text:
            language = "zh"
        elif "こんにちは" in text or "どう" in text or "元気" in text or "お元気ですか" in text:
            language = "ja"
        elif "안녕" in text or "어떻게" in text:
            language = "ko"
        elif "مرحبا" in text or "كيف" in text or "حالك" in text:
            language = "ar"
        elif "नमस्ते" in text or "कैसे" in text:
            language = "hi"
        elif (
            "привет" in text.lower()
            or "как" in text.lower()
            or "здравствуйте" in text.lower()
            or "дела" in text.lower()
        ):
            language = "ru"

        return {"language": language, "confidence": confidence}

    async def detect(self, text: str, language: str | None = None) -> dict[str, Any]:
        """Detect prompt injection in text."""
        # Normalize text to detect transliteration attacks
        normalized_text = await self.normalize(text)

        # Auto-detect language if not provided
        detected_languages = []
        if language is None:
            lang_result = await self.detect_language(text)
            language = lang_result["language"]
            detected_languages.append(language)
        else:
            detected_languages.append(language)

        # Stub implementation - basic detection
        confidence = 0.0
        reasons = []
        flags = []

        # Expanded injection keywords for all supported languages
        injection_keywords = {
            "en": [
                "ignore",
                "disregard",
                "forget",
                "override",
                "previous instructions",
                "ignore all",
            ],
            "es": [
                "ignorar",
                "descartar",
                "olvidar",
                "anular",
                "ignora todas",
                "instrucciones anteriores",
            ],
            "fr": [
                "ignorer",
                "négliger",
                "oublier",
                "remplacer",
                "ignorez toutes",
                "instructions précédentes",
            ],
            "de": [
                "ignorieren",
                "verwerfen",
                "vergessen",
                "überschreiben",
                "ignoriere alle",
                "vorherigen anweisungen",
            ],
            "it": [
                "ignora",
                "scarta",
                "dimentica",
                "annulla",
                "ignora tutte",
                "istruzioni precedenti",
            ],
            "pt": [
                "ignore",
                "descarte",
                "esqueça",
                "anule",
                "ignore todas",
                "instruções anteriores",
            ],
            "ru": [
                "игнорируй",
                "отбрось",
                "забудь",
                "отмени",
                "игнорируй все",
                "предыдущие инструкции",
            ],
            "zh": ["忽略", "丢弃", "忘记", "覆盖", "忽略所有", "先前的指令"],
            "ja": ["無視", "破棄", "忘れる", "上書き", "以前のすべて", "指示を無視"],
            "ar": ["تجاهل", "ارفض", "انسى", "الغاء", "تجاهل جميع", "التعليمات السابقة"],
            "ko": ["무시", "버리다", "잊다", "덮어쓰기", "이전의 모든", "지시를 무시"],
            "hi": ["अनदेखा", "त्याग", "भूल", "रद्द", "सभी पिछले", "निर्देशों को अनदेखा"],
        }

        keywords = injection_keywords.get(language, injection_keywords["en"])
        text_lower = text.lower()
        normalized_lower = normalized_text.lower()

        # Check for keyword matches in both original and normalized text
        for keyword in keywords:
            if keyword in text_lower or keyword in normalized_lower:
                confidence = 0.85
                reasons.append(f"Detected injection keyword: {keyword}")
                break

        # Check for transliteration attacks (homograph attacks)
        detection_methods = []
        if self._has_homograph_chars(text):
            confidence = max(confidence, 0.8)
            reasons.append("Detected homograph/transliteration attack")
            flags.append("homograph")
            detection_methods.append("transliteration")

        # Check for mixed languages (code-switching attack)
        mixed_langs = self._detect_mixed_languages(text)
        if len(mixed_langs) > 1:
            flags.append("multilingual")
            detected_languages = mixed_langs
            confidence = max(confidence, 0.75)
            reasons.append("Mixed language content detected")

        # Determine verdict
        if confidence > 0.7:
            verdict = Verdict.BLOCK
        elif confidence > 0.4:
            verdict = Verdict.STRIP
        else:
            verdict = Verdict.ALLOW

        return {
            "verdict": verdict,
            "confidence": confidence,
            "reasons": reasons,
            "detected_language": language,
            "languages_detected": detected_languages,
            "flags": flags,
            "detection_methods": detection_methods,
        }

    def _has_homograph_chars(self, text: str) -> bool:
        """Check if text contains homograph characters (e.g., Cyrillic that looks like Latin)."""
        # Common homograph characters
        homographs = [
            "і",  # Cyrillic small i (U+0456)
            "о",  # Cyrillic small o (U+043E)
            "а",  # Cyrillic small a (U+0430)
            "е",  # Cyrillic small e (U+0435)
            "р",  # Cyrillic small r (U+0440)
            "с",  # Cyrillic small s (U+0441)
            "х",  # Cyrillic small h (U+0445)
            "у",  # Cyrillic small u (U+0443)
            "ı",  # Turkish dotless i (U+0131)
        ]

        return any(char in text for char in homographs)

    def _detect_mixed_languages(self, text: str) -> list[str]:
        """Detect if text contains multiple languages."""
        detected = []

        # Simple heuristic checks for language markers
        if any(word in text.lower() for word in ["the", "and", "or", "please", "help"]):
            detected.append("en")
        if any(word in text.lower() for word in ["ignoriere", "alle", "anweisungen"]):
            detected.append("de")
        if any(word in text.lower() for word in ["merci", "bonjour", "s'il"]):
            detected.append("fr")

        return detected if detected else ["en"]

    async def normalize(self, text: str) -> str:
        """Normalize Unicode text for consistent detection."""
        import unicodedata

        # First normalize to NFD to decompose characters
        nfd = unicodedata.normalize("NFD", text)

        # Remove diacritical marks (combining characters)
        result = ""
        for char in nfd:
            if unicodedata.category(char) != "Mn":  # Mn = Mark, Nonspacing
                result += char

        # Then normalize to NFKC for compatibility
        normalized = unicodedata.normalize("NFKC", result)

        # Additional normalization for specific characters
        # Full-width to ASCII
        final_result = ""
        for char in normalized:
            # Convert full-width Latin to ASCII
            if ord(char) >= 0xFF01 and ord(char) <= 0xFF5E:
                final_result += chr(ord(char) - 0xFEE0)
            else:
                final_result += char

        return final_result

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
