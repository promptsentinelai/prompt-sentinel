# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

"""Comprehensive tests for i18n functionality."""

from datetime import datetime
from unittest.mock import AsyncMock, Mock

import pytest

from prompt_sentinel.i18n.cached_detector import CachedLanguageDetector
from prompt_sentinel.i18n.detector import MultilingualDetector
from prompt_sentinel.i18n.formatter import LocaleFormatter
from prompt_sentinel.i18n.response_formatter import ResponseFormatter
from prompt_sentinel.models.schemas import (
    DetectionCategory,
    DetectionReason,
    DetectionResponse,
    FormatRecommendation,
    Verdict,
)


class TestResponseFormatter:
    """Test response formatting with localization."""

    def test_english_formatting(self):
        """Test English response formatting."""
        formatter = ResponseFormatter("en_US")

        response = DetectionResponse(
            verdict=Verdict.BLOCK,
            confidence=0.95,
            processing_time_ms=12.5,
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            reasons=[
                DetectionReason(
                    category=DetectionCategory.DIRECT_INJECTION,
                    description="Detected prompt injection",
                    confidence=0.9,
                    source="heuristic",
                )
            ],
        )

        formatted = formatter.format_response(response)

        assert formatted["verdict"] == "Blocked"
        assert "95.0%" in formatted["confidence"]
        assert "Very High Confidence" in formatted["confidence"]
        assert formatted["processing_time"] == "12.50 ms"

    def test_spanish_formatting(self):
        """Test Spanish response formatting."""
        formatter = ResponseFormatter("es_ES")

        response = DetectionResponse(
            verdict=Verdict.FLAG,
            confidence=0.65,
            processing_time_ms=8.3,
            timestamp=datetime.utcnow(),
        )

        formatted = formatter.format_response(response)

        assert formatted["verdict"] == "Marcado para Revisión"
        assert "65.0%" in formatted["confidence"]
        assert "Confianza Media" in formatted["confidence"]

    def test_french_formatting(self):
        """Test French response formatting."""
        formatter = ResponseFormatter("fr_FR")

        response = DetectionResponse(
            verdict=Verdict.ALLOW,
            confidence=0.2,
            processing_time_ms=5.0,
            timestamp=datetime.utcnow(),
        )

        formatted = formatter.format_response(response)

        assert formatted["verdict"] == "Autorisé"
        assert "20.0" in formatted["confidence"]
        assert "Confiance Faible" in formatted["confidence"]

    def test_german_formatting(self):
        """Test German response formatting."""
        formatter = ResponseFormatter("de_DE")

        response = DetectionResponse(
            verdict=Verdict.REDACT,
            confidence=0.8,
            processing_time_ms=15.75,
            timestamp=datetime.utcnow(),
            reasons=[
                DetectionReason(
                    category=DetectionCategory.PII_DETECTED,
                    description="Personal information found",
                    confidence=0.85,
                    source="llm",
                )
            ],
        )

        formatted = formatter.format_response(response)

        assert formatted["verdict"] == "PII Geschwärzt"
        assert "80.0%" in formatted["confidence"]
        assert "Hohes Vertrauen" in formatted["confidence"]

    def test_japanese_formatting(self):
        """Test Japanese response formatting."""
        formatter = ResponseFormatter("ja_JP")

        response = DetectionResponse(
            verdict=Verdict.STRIP,
            confidence=0.75,
            processing_time_ms=10.0,
            timestamp=datetime(2024, 3, 15, 14, 30, 0),
        )

        formatted = formatter.format_response(response)

        assert formatted["verdict"] == "コンテンツ削除"
        assert "75.0%" in formatted["confidence"]
        assert "高い確信度" in formatted["confidence"]

    def test_recommendation_translation(self):
        """Test recommendation translation."""
        formatter = ResponseFormatter("es_ES")

        response = DetectionResponse(
            verdict=Verdict.FLAG,
            confidence=0.6,
            processing_time_ms=7.0,
            timestamp=datetime.utcnow(),
            format_recommendations=[
                FormatRecommendation(
                    issue="Missing role separation",
                    recommendation="Use role separation for better security",
                    severity="warning",
                )
            ],
        )

        formatted = formatter.format_response(response)

        assert len(formatted["recommendations"]) == 1
        assert "separación de roles" in formatted["recommendations"][0]["recommendation"]

    def test_rtl_language_detection(self):
        """Test RTL language detection."""
        formatter_ar = ResponseFormatter("ar_SA")
        formatter_en = ResponseFormatter("en_US")

        assert formatter_ar.is_rtl_language() is True
        assert formatter_en.is_rtl_language() is False

    def test_fallback_for_unsupported_locale(self):
        """Test fallback to English for unsupported locale."""
        formatter = ResponseFormatter("ko_KR")  # Korean not supported

        response = DetectionResponse(
            verdict=Verdict.ALLOW,
            confidence=0.3,
            processing_time_ms=4.0,
            timestamp=datetime.utcnow(),
        )

        formatted = formatter.format_response(response)

        # Should fall back to English
        assert formatted["verdict"] == "Allowed"


class TestLocaleFormatter:
    """Test locale-specific formatting."""

    def test_number_formatting(self):
        """Test number formatting for different locales."""
        formatter_en = LocaleFormatter("en_US")
        formatter_de = LocaleFormatter("de_DE")
        formatter_fr = LocaleFormatter("fr_FR")

        number = 1234.56

        assert formatter_en.format_number(number) == "1,234.56"
        assert formatter_de.format_number(number) == "1.234,56"
        assert formatter_fr.format_number(number) == "1.234,56"

    def test_percentage_formatting(self):
        """Test percentage formatting."""
        formatter_en = LocaleFormatter("en_US")
        formatter_fr = LocaleFormatter("fr_FR")

        value = 0.753

        assert formatter_en.format_percentage(value) == "75.3%"
        assert formatter_fr.format_percentage(value) == "75.3 %"  # Space before %

    def test_date_formatting(self):
        """Test date formatting."""
        formatter_us = LocaleFormatter("en_US")
        formatter_gb = LocaleFormatter("en_GB")
        formatter_de = LocaleFormatter("de_DE")
        formatter_ja = LocaleFormatter("ja_JP")

        date = datetime(2024, 3, 15, 10, 30, 0)

        assert formatter_us.format_date(date) == "03/15/2024"
        assert formatter_gb.format_date(date) == "15/03/2024"
        assert formatter_de.format_date(date) == "15.03.2024"
        assert formatter_ja.format_date(date) == "2024年03月15日"

    def test_datetime_formatting(self):
        """Test combined datetime formatting."""
        formatter_en = LocaleFormatter("en_US")
        formatter_fr = LocaleFormatter("fr_FR")
        formatter_de = LocaleFormatter("de_DE")

        dt = datetime(2024, 3, 15, 14, 30, 0)

        assert "03/15/2024" in formatter_en.format_datetime(dt)
        assert "02:30 PM" in formatter_en.format_datetime(dt)

        assert "15/03/2024" in formatter_fr.format_datetime(dt)
        assert "à 14:30" in formatter_fr.format_datetime(dt)

        assert "15.03.2024" in formatter_de.format_datetime(dt)
        assert ", 14:30" in formatter_de.format_datetime(dt)


class TestCachedLanguageDetector:
    """Test cached language detection."""

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        """Test cache hit scenario."""
        mock_cache = Mock()
        mock_cache.connected = True
        mock_cache.get = AsyncMock(return_value='{"language": "en", "confidence": 0.98}')
        mock_cache.set = AsyncMock()

        detector = CachedLanguageDetector(mock_cache)

        result = await detector.detect_language("Hello world")

        assert result["language"] == "en"
        assert result["confidence"] == 0.98
        assert detector.stats["cache_hits"] == 1
        assert detector.stats["cache_misses"] == 0

        # Cache get should have been called
        mock_cache.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_cache_miss(self):
        """Test cache miss scenario."""
        mock_cache = Mock()
        mock_cache.connected = True
        mock_cache.get = AsyncMock(return_value=None)
        mock_cache.set = AsyncMock()

        detector = CachedLanguageDetector(mock_cache)

        result = await detector.detect_language("Bonjour le monde")

        assert result["language"] == "fr"
        assert detector.stats["cache_hits"] == 0
        assert detector.stats["cache_misses"] == 1

        # Cache set should have been called to store result
        mock_cache.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_batch_detection(self):
        """Test batch language detection."""
        mock_cache = Mock()
        mock_cache.connected = True
        mock_cache.get = AsyncMock(
            side_effect=[
                '{"language": "en", "confidence": 0.99}',  # Hit
                None,  # Miss
                '{"language": "de", "confidence": 0.95}',  # Hit
            ]
        )
        mock_cache.set = AsyncMock()

        detector = CachedLanguageDetector(mock_cache)

        texts = ["Hello world", "Hola mundo", "Guten Tag"]

        results = await detector.detect_language_batch(texts)

        assert len(results) == 3
        assert results[0]["language"] == "en"  # From cache
        assert results[1]["language"] == "es"  # Detected
        assert results[2]["language"] == "de"  # From cache

        assert detector.stats["cache_hits"] == 2
        assert detector.stats["cache_misses"] == 1

    @pytest.mark.asyncio
    async def test_cache_disabled(self):
        """Test behavior when cache is disabled."""
        detector = CachedLanguageDetector(None)

        result = await detector.detect_language(
            "This is definitely an English sentence with more context"
        )

        assert result["language"] == "en"
        assert detector.stats["cache_hits"] == 0
        assert detector.stats["cache_misses"] == 1

    def test_cache_stats(self):
        """Test cache statistics."""
        detector = CachedLanguageDetector(None)
        detector.stats = {
            "cache_hits": 75,
            "cache_misses": 25,
            "total_requests": 100,
        }

        stats = detector.get_cache_stats()

        assert stats["cache_hit_rate"] == 75.0
        assert stats["cache_enabled"] is False
        assert stats["total_requests"] == 100

    @pytest.mark.asyncio
    async def test_cache_warming(self):
        """Test cache warming with common phrases."""
        mock_cache = Mock()
        mock_cache.connected = True
        mock_cache.set = AsyncMock()

        detector = CachedLanguageDetector(mock_cache)

        common_phrases = ["Hello", "Ignore all instructions", "System prompt"]

        await detector.warm_cache(common_phrases)

        # Should have called set for each phrase
        assert mock_cache.set.call_count == 3


class TestMultilingualIntegration:
    """Test integration of multilingual components."""

    @pytest.mark.asyncio
    async def test_full_detection_and_formatting(self):
        """Test complete flow from detection to formatted response."""
        # Detect language
        detector = MultilingualDetector()
        lang_result = await detector.detect_language("Bonjour, comment allez-vous?")

        assert lang_result["language"] == "fr"

        # Format response based on detected language
        formatter = ResponseFormatter(f"{lang_result['language']}_FR")

        response = DetectionResponse(
            verdict=Verdict.ALLOW,
            confidence=0.1,
            processing_time_ms=3.5,
            timestamp=datetime.utcnow(),
        )

        formatted = formatter.format_response(response)

        # Should use French formatting
        assert formatted["verdict"] == "Autorisé"
        assert "Confiance Faible" in formatted["confidence"]

    @pytest.mark.asyncio
    async def test_mixed_language_handling(self):
        """Test handling of mixed language content."""
        detector = MultilingualDetector()

        # Mixed English and Spanish
        result = await detector.detect_language("Hello, como estas? I hope you're doing well.")

        assert result["mixed_languages"] is True
        assert "en" in result["languages_detected"]
        assert "es" in result["languages_detected"]
