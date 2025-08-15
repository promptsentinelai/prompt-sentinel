# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Multilingual detection capabilities."""

import re
from typing import Any

from langdetect import LangDetectException, detect_langs

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
            "zh-cn",
            "zh-tw",
            "ja",
            "ko",
            "ar",
            "hi",
            "ru",
            "nl",
            "pl",
            "tr",
            "vi",
            "th",
        ]
        self.current_language = "en"

        # Injection patterns for each language
        self.injection_patterns = {
            "en": {
                "keywords": [
                    "ignore",
                    "disregard",
                    "forget",
                    "override",
                    "bypass",
                    "skip",
                    "omit",
                    "neglect",
                    "cancel",
                    "void",
                ],
                "phrases": [
                    "ignore all previous",
                    "disregard above",
                    "forget everything",
                    "new instructions",
                    "system prompt",
                    "ignore the above",
                    "ignore previous instructions",
                    "override all",
                    "bypass security",
                ],
                "patterns": [
                    r"ignore\s+(all\s+)?previous",
                    r"disregard\s+(everything|all)",
                    r"forget\s+(what|everything)",
                    r"(new|updated?)\s+instructions?",
                    r"system\s+(prompt|message)",
                ],
            },
            "es": {
                "keywords": [
                    "ignorar",
                    "descartar",
                    "olvidar",
                    "anular",
                    "omitir",
                    "saltar",
                    "cancelar",
                    "evitar",
                ],
                "phrases": [
                    "ignora todas las",
                    "olvida todo",
                    "nuevas instrucciones",
                    "ignora lo anterior",
                    "anula todo",
                    "omite las reglas",
                ],
                "patterns": [
                    r"ignora(r)?\s+(todas?\s+)?las?\s+anteriores?",
                    r"olvida(r)?\s+todo",
                    r"nuevas?\s+instrucc?iones?",
                ],
            },
            "fr": {
                "keywords": [
                    "ignorer",
                    "négliger",
                    "oublier",
                    "remplacer",
                    "annuler",
                    "omettre",
                    "éviter",
                    "contourner",
                ],
                "phrases": [
                    "ignorez toutes les",
                    "oubliez tout",
                    "nouvelles instructions",
                    "ignorez ce qui précède",
                    "annulez tout",
                ],
                "patterns": [
                    r"ignore(r|z)\s+(toutes?\s+)?les?\s+précédentes?",
                    r"oublie(r|z)\s+tout",
                    r"nouvelles?\s+instructions?",
                ],
            },
            "de": {
                "keywords": [
                    "ignoriere",
                    "ignorieren",
                    "verwerfen",
                    "vergessen",
                    "überschreiben",
                    "umgehen",
                    "auslassen",
                    "überspringen",
                ],
                "phrases": [
                    "ignoriere alle vorherigen",
                    "ignoriere alle anweisungen",
                    "vergiss alles",
                    "neue anweisungen",
                    "ignoriere das obige",
                    "überschreibe alles",
                ],
                "patterns": [
                    r"ignoriere?\s+(alle\s+)?vorherigen?",
                    r"ignoriere?\s+(alle\s+)?anweisungen?",
                    r"vergiss\s+alles",
                    r"neue\s+anweisungen?",
                ],
            },
            "zh": {
                "keywords": ["忽略", "丢弃", "忘记", "覆盖", "跳过", "取消", "绕过"],
                "phrases": ["忽略所有先前的", "忘记一切", "新指令", "忽略上述", "覆盖所有"],
                "patterns": [
                    r"忽略.*先前",
                    r"忘记.*一切",
                    r"新.*指令",
                ],
            },
            "ja": {
                "keywords": ["無視", "破棄", "忘れる", "上書き", "スキップ", "キャンセル"],
                "phrases": [
                    "以前のすべてを無視",
                    "すべて忘れて",
                    "新しい指示",
                    "上記を無視",
                    "すべて上書き",
                ],
                "patterns": [
                    r"以前.*無視",
                    r"すべて.*忘れ",
                    r"新しい.*指示",
                ],
            },
            "ru": {
                "keywords": [
                    "игнорируй",
                    "отбрось",
                    "забудь",
                    "отмени",
                    "пропусти",
                    "обойди",
                    "отключи",
                ],
                "phrases": [
                    "игнорируй все предыдущие",
                    "забудь все",
                    "новые инструкции",
                    "игнорируй выше",
                    "отмени все",
                ],
                "patterns": [
                    r"игнориру.*предыдущ",
                    r"забуд.*все",
                    r"нов.*инструкц",
                ],
            },
            "ar": {
                "keywords": ["تجاهل", "ارفض", "انسى", "الغاء", "تخطي", "الغي"],
                "phrases": [
                    "تجاهل جميع السابقة",
                    "انسى كل شيء",
                    "تعليمات جديدة",
                    "تجاهل ما سبق",
                    "الغي الكل",
                    "تجاهل جميع التعليمات السابقة",
                ],
                "patterns": [
                    r"تجاهل.*السابق",
                    r"انسى.*كل",
                    r"تعليمات.*جديدة",
                    r"تجاهل.*جميع.*التعليمات",
                ],
            },
            "it": {
                "keywords": ["ignora", "scarta", "dimentica", "annulla", "salta", "ometti"],
                "phrases": [
                    "ignora tutte le istruzioni precedenti",
                    "dimentica tutto",
                    "nuove istruzioni",
                    "ignora quanto sopra",
                ],
                "patterns": [
                    r"ignora.*tutte.*istruzioni",
                    r"dimentica.*tutto",
                    r"nuove.*istruzioni",
                ],
            },
            "pt": {
                "keywords": ["ignore", "descarte", "esqueça", "anule", "pule", "omita"],
                "phrases": [
                    "ignore todas as instruções anteriores",
                    "esqueça tudo",
                    "novas instruções",
                    "ignore o acima",
                ],
                "patterns": [
                    r"ignore.*todas.*instruções",
                    r"esqueça.*tudo",
                    r"novas.*instruções",
                ],
            },
            "ko": {
                "keywords": ["무시", "버리다", "잊다", "취소", "건너뛰기"],
                "phrases": [
                    "이전의 모든 지시를 무시하세요",
                    "모든 것을 잊어버리세요",
                    "새로운 지시",
                    "위를 무시하세요",
                ],
                "patterns": [
                    r"이전.*모든.*지시.*무시",
                    r"모든.*잊",
                    r"새로운.*지시",
                ],
            },
            "hi": {
                "keywords": ["अनदेखा", "छोड़", "भूल", "रद्द", "छोड़ें"],
                "phrases": [
                    "सभी पिछले निर्देशों को अनदेखा करें",
                    "सब कुछ भूल जाएं",
                    "नए निर्देश",
                    "ऊपर को अनदेखा करें",
                ],
                "patterns": [
                    r"सभी.*पिछले.*निर्देशों.*अनदेखा",
                    r"सब.*भूल",
                    r"नए.*निर्देश",
                ],
            },
        }

        # Add patterns for other supported languages with basic coverage
        for lang in self.supported_languages:
            if lang not in self.injection_patterns:
                self.injection_patterns[lang] = self.injection_patterns["en"]  # Fallback to English

    async def detect_language(self, text: str) -> dict[str, Any]:
        """
        Detect language of text using langdetect library.

        Args:
            text: Text to analyze

        Returns:
            Dictionary with language code and confidence
        """
        # First check with our fallback for non-Latin scripts (more reliable)
        # Check Japanese first (more specific than Chinese)
        if re.search(r"[\u3040-\u309f\u30a0-\u30ff]", text):  # Japanese (Hiragana or Katakana)
            return await self._fallback_detection(text)
        elif re.search(r"[\u0400-\u04ff]", text):  # Cyrillic
            return await self._fallback_detection(text)
        elif re.search(r"[\u4e00-\u9fff]", text):  # Chinese (Kanji also used in Japanese)
            return await self._fallback_detection(text)
        elif re.search(r"[\uac00-\ud7af]", text):  # Korean
            return await self._fallback_detection(text)
        elif re.search(r"[\u0600-\u06ff]", text):  # Arabic
            return await self._fallback_detection(text)
        elif re.search(r"[\u0900-\u097f]", text):  # Hindi
            return await self._fallback_detection(text)

        try:
            # For Latin-based scripts, use langdetect
            detected = detect_langs(text)

            if detected:
                # Get the most likely language
                best_match = detected[0]

                # Map language codes to our supported set
                lang_code = best_match.lang
                if lang_code == "zh-cn" or lang_code == "zh-tw":
                    lang_code = "zh"

                # Check if it's supported
                if lang_code not in [lang.split("-")[0] for lang in self.supported_languages]:
                    # Fallback to English if unsupported
                    return {
                        "language": "en",
                        "confidence": 0.5,
                        "detected": lang_code,
                        "supported": False,
                    }

                return {
                    "language": lang_code,
                    "confidence": best_match.prob,
                    "all_detected": [{"lang": d.lang, "prob": d.prob} for d in detected[:3]],
                }

        except LangDetectException:
            # If detection fails, try simple heuristics
            return await self._fallback_detection(text)

        # Default to English if all else fails
        return {"language": "en", "confidence": 0.3}

    async def _fallback_detection(self, text: str) -> dict[str, Any]:
        """Fallback language detection using simple heuristics."""
        # Check for specific character sets - order matters!
        # Check Japanese first (more specific)
        if re.search(r"[\u3040-\u309f]", text):  # Hiragana (Japanese)
            return {"language": "ja", "confidence": 0.9}
        elif re.search(r"[\u30a0-\u30ff]", text):  # Katakana (Japanese)
            return {"language": "ja", "confidence": 0.9}
        elif re.search(r"[\u0400-\u04ff]", text):  # Cyrillic (Russian, Ukrainian, etc.)
            # More specific check for Russian vs other Cyrillic languages
            if "ы" in text or "ъ" in text or "э" in text:
                return {"language": "ru", "confidence": 0.9}
            return {"language": "ru", "confidence": 0.8}
        elif re.search(r"[\u4e00-\u9fff]", text):  # Chinese characters (also used in Japanese)
            # If no Japanese kana found, it's likely Chinese
            return {"language": "zh", "confidence": 0.8}
        elif re.search(r"[\uac00-\ud7af]", text):  # Korean
            return {"language": "ko", "confidence": 0.8}
        elif re.search(r"[\u0600-\u06ff]", text):  # Arabic
            return {"language": "ar", "confidence": 0.8}
        elif re.search(r"[\u0900-\u097f]", text):  # Devanagari (Hindi)
            return {"language": "hi", "confidence": 0.8}

        # Default to English
        return {"language": "en", "confidence": 0.4}

    async def detect(self, text: str, language: str | None = None) -> dict[str, Any]:
        """
        Detect prompt injection in text.

        Args:
            text: Text to analyze
            language: Language code (auto-detected if not provided)

        Returns:
            Detection result with verdict, confidence, and reasons
        """
        # Only check for mixed languages if no specific language was provided
        if language is None:
            # Check for mixed languages (potential code-switching attack)
            mixed_lang_result = await self.detect_mixed_languages(text)

            # If mixed languages detected, check each language for injections
            if mixed_lang_result["mixed"]:
                # Check all detected languages for injection patterns
                max_confidence = 0.0
                all_flags = ["multilingual"]  # Add the expected flag
                all_reasons = []

                for lang in mixed_lang_result["languages"]:
                    # Check patterns for each detected language
                    patterns = self.injection_patterns.get(lang, self.injection_patterns["en"])
                    text_lower = text.lower()

                    for keyword in patterns["keywords"]:
                        if keyword.lower() in text_lower:
                            max_confidence = max(max_confidence, 0.7)
                            all_flags.append(f"mixed_lang:{lang}:{keyword}")
                            all_reasons.append(f"Mixed language attack: {lang} keyword '{keyword}'")

                    for phrase in patterns["phrases"]:
                        if phrase.lower() in text_lower:
                            max_confidence = max(max_confidence, 0.8)
                            all_flags.append(f"mixed_lang:{lang}:{phrase}")
                            all_reasons.append(f"Mixed language attack: {lang} phrase '{phrase}'")

                if max_confidence > 0.6:
                    return {
                        "verdict": Verdict.BLOCK if max_confidence >= 0.7 else Verdict.FLAG,
                        "confidence": max_confidence,
                        "language": "mixed",
                        "detected_language": "mixed",
                        "language_confidence": 1.0,
                        "reasons": all_reasons
                        or ["Mixed language content detected - potential code-switching attack"],
                        "flags": all_flags,
                        "detection_methods": ["mixed_language"],
                        "languages_detected": mixed_lang_result["languages"],
                    }

        # Auto-detect language if not provided
        if language is None:
            lang_result = await self.detect_language(text)
            language = lang_result["language"]
            lang_confidence = lang_result["confidence"]
        else:
            lang_confidence = 1.0

        # Normalize text based on language
        # For non-Latin scripts, skip homoglyph conversion
        if language in ["ru", "ar", "zh", "ja", "ko", "hi"]:
            # For these languages, only do basic normalization
            normalized_text = await self.normalize(text, convert_homoglyphs=False)
        else:
            # For Latin-based languages, do full normalization
            normalized_text = await self.normalize(text, convert_homoglyphs=True)

        # Also check with full homoglyph conversion for transliteration attacks
        fully_normalized = await self.normalize(text, convert_homoglyphs=True)

        # Get patterns for the detected language
        patterns = self.injection_patterns.get(
            language,
            self.injection_patterns["en"],  # Fallback to English
        )

        confidence = 0.0
        reasons = []
        flags = []

        # Check keywords in both normalized versions
        text_lower = normalized_text.lower()
        fully_normalized_lower = fully_normalized.lower()

        for keyword in patterns["keywords"]:
            if keyword.lower() in text_lower or keyword.lower() in fully_normalized_lower:
                confidence = max(confidence, 0.6)
                flags.append(f"keyword:{keyword}")

        # Also check English patterns on fully normalized text (for transliteration attacks)
        en_patterns = self.injection_patterns["en"]
        for keyword in en_patterns["keywords"]:
            if keyword.lower() in fully_normalized_lower:
                confidence = max(confidence, 0.7)
                flags.append(f"transliteration:{keyword}")
                reasons.append("Possible transliteration attack detected")

        # Check phrases
        for phrase in patterns["phrases"]:
            if phrase.lower() in text_lower or phrase.lower() in fully_normalized_lower:
                confidence = max(confidence, 0.8)
                reasons.append(f"Detected injection phrase: '{phrase}'")
                flags.append(f"phrase:{phrase}")

        # Check regex patterns
        for pattern in patterns.get("patterns", []):
            if re.search(pattern, text_lower, re.IGNORECASE) or re.search(
                pattern, fully_normalized_lower, re.IGNORECASE
            ):
                confidence = max(confidence, 0.9)
                reasons.append("Matched injection pattern")
                flags.append(f"pattern:{pattern}")

        # Adjust confidence based on language detection confidence
        confidence = confidence * (0.7 + 0.3 * lang_confidence)

        # Determine verdict
        if confidence >= 0.7:
            verdict = Verdict.BLOCK
        elif confidence >= 0.4:
            verdict = Verdict.FLAG
        else:
            verdict = Verdict.ALLOW

        # Build detection methods list
        detection_methods = []
        if any("keyword:" in f for f in flags):
            detection_methods.append("keyword")
        if any("phrase:" in f for f in flags):
            detection_methods.append("phrase")
        if any("pattern:" in f for f in flags):
            detection_methods.append("pattern")
        if any("transliteration:" in f for f in flags):
            detection_methods.append("transliteration")

        return {
            "verdict": verdict,
            "confidence": confidence,
            "language": language,
            "detected_language": language,  # For compatibility
            "language_confidence": lang_confidence,
            "reasons": reasons,
            "flags": flags,
            "detection_methods": detection_methods,
        }

    async def normalize(self, text: str, convert_homoglyphs: bool = True) -> str:
        """
        Normalize text for better detection.

        Handles:
        - Unicode normalization
        - Homoglyph attacks (optional)
        - Mixed scripts
        - Zero-width characters

        Args:
            text: Text to normalize
            convert_homoglyphs: Whether to convert homoglyphs to Latin equivalents
        """
        import unicodedata

        # Remove zero-width characters
        text = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", text)

        # Normalize Unicode (NFKC normalizes compatibility characters)
        text = unicodedata.normalize("NFKC", text)

        # Convert common homoglyphs only if requested
        # This should be skipped for non-Latin scripts to preserve native characters
        if convert_homoglyphs:
            # Extended homoglyph mapping
            homoglyphs = {
                # Cyrillic lookalikes
                "а": "a",
                "е": "e",
                "о": "o",
                "р": "p",
                "с": "c",
                "у": "y",
                "х": "x",
                "А": "A",
                "В": "B",
                "Е": "E",
                "К": "K",
                "М": "M",
                "Н": "H",
                "О": "O",
                "Р": "P",
                "С": "C",
                "Т": "T",
                "У": "Y",
                "Х": "X",
                # Full-width characters (already handled by NFKC but kept for safety)
                "０": "0",
                "１": "1",
                "２": "2",
                "３": "3",
                "４": "4",
                "５": "5",
                "６": "6",
                "７": "7",
                "８": "8",
                "９": "9",
                # Greek lookalikes
                "α": "a",
                "ο": "o",
                "ρ": "p",
                "χ": "x",
                "γ": "y",
                "Α": "A",
                "Β": "B",
                "Ε": "E",
                "Η": "H",
                "Ι": "I",
                "Κ": "K",
                "Μ": "M",
                "Ν": "N",
                "Ο": "O",
                "Ρ": "P",
                "Τ": "T",
                "Χ": "X",
                "Υ": "Y",
                # Special i variants
                "ı": "i",  # Turkish dotless i
                "і": "i",  # Ukrainian i
                "í": "i",
                "ì": "i",
                "î": "i",
                "ï": "i",
                "ĩ": "i",
                "į": "i",
                # Special o variants
                "ó": "o",
                "ò": "o",
                "ô": "o",
                "ö": "o",
                "õ": "o",
                "ø": "o",
                # Other accented characters
                "á": "a",
                "à": "a",
                "â": "a",
                "ä": "a",
                "ã": "a",
                "å": "a",
                "é": "e",
                "è": "e",
                "ê": "e",
                "ë": "e",
                "ẽ": "e",
                "ú": "u",
                "ù": "u",
                "û": "u",
                "ü": "u",
                "ũ": "u",
                "ñ": "n",
                "ń": "n",
                "ň": "n",
                "ć": "c",
                "č": "c",
                "ç": "c",
                "ğ": "g",
                "ǧ": "g",
                "ř": "r",
                "ŕ": "r",
                "š": "s",
                "ś": "s",
                "ş": "s",
                "ž": "z",
                "ź": "z",
                "ż": "z",
            }

            for original, replacement in homoglyphs.items():
                text = text.replace(original, replacement)

        return text

    async def detect_mixed_languages(self, text: str) -> dict[str, Any]:
        """
        Detect if text contains multiple languages (potential attack vector).

        Args:
            text: Text to analyze

        Returns:
            Detection result with mixed language analysis
        """
        # Split text into segments
        segments = text.split()

        if len(segments) < 3:
            return {"mixed": False, "languages": []}

        # Detect language for each segment
        languages_found = set()
        segment_languages = []

        for segment in segments:
            if len(segment) > 3:  # Skip very short segments
                lang_result = await self.detect_language(segment)
                lang = lang_result["language"]
                languages_found.add(lang)
                segment_languages.append(lang)

        # Check if multiple languages detected
        mixed = len(languages_found) > 1

        # Calculate entropy (how mixed the languages are)
        entropy = 0.0
        if mixed and segment_languages:
            from collections import Counter

            counts = Counter(segment_languages)
            total = len(segment_languages)
            for count in counts.values():
                if count > 0:
                    prob = count / total
                    entropy -= prob * (prob if prob > 0 else 0)

        return {
            "mixed": mixed,
            "languages": list(languages_found),
            "entropy": entropy,
            "suspicious": mixed and entropy > 0.5,
        }

    async def translate_for_detection(self, text: str, target_lang: str = "en") -> str:
        """
        Translate text to target language for better detection.
        This is a stub - would need actual translation API.

        Args:
            text: Text to translate
            target_lang: Target language code

        Returns:
            Translated text (or original if translation fails)
        """
        # Stub implementation - would integrate with translation service
        # For now, just return original text
        return text

    def get_supported_languages(self) -> list[str]:
        """Get list of supported languages."""
        return self.supported_languages

    def get_injection_patterns(self, language: str) -> dict[str, Any]:
        """Get injection patterns for a specific language."""
        return self.injection_patterns.get(language, self.injection_patterns["en"])
