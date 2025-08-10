"""Negative test cases for error conditions and edge cases."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prompt_sentinel.detection.detector import PromptDetector
from prompt_sentinel.detection.heuristics import HeuristicDetector
from prompt_sentinel.detection.llm_classifier import LLMClassifierManager
from prompt_sentinel.detection.pii_detector import PIIDetector
from prompt_sentinel.models.schemas import (
    DetectionCategory,
    DetectionReason,
    DetectionResponse,
    Message,
    Role,
    Verdict,
)


class TestInvalidInputs:
    """Test cases for invalid inputs and malformed data."""

    def test_empty_string_detection(self):
        """Test detection with empty string."""
        from pydantic import ValidationError
        detector = HeuristicDetector("strict")
        
        # Message model doesn't allow empty content - test validation
        with pytest.raises(ValidationError) as exc_info:
            Message(role=Role.USER, content="")
        assert "cannot be empty" in str(exc_info.value)
        
        # Test with whitespace-only content (also not allowed)
        with pytest.raises(ValidationError) as exc_info:
            Message(role=Role.USER, content=" ")
        assert "cannot be empty" in str(exc_info.value)
        
        # Test with minimal valid content
        messages = [Message(role=Role.USER, content="a")]
        verdict, reasons, confidence = detector.detect(messages)
        assert verdict == Verdict.ALLOW
        assert len(reasons) == 0

    def test_none_input_handling(self):
        """Test handling of None inputs."""
        detector = HeuristicDetector("moderate")
        
        # Should handle None gracefully
        with pytest.raises((TypeError, AttributeError)):
            detector.detect(None)

    def test_extremely_long_input(self):
        """Test with extremely long input strings."""
        detector = HeuristicDetector("permissive")
        
        # 1MB of text
        huge_text = "a" * (1024 * 1024)
        messages = [Message(role=Role.USER, content=huge_text)]
        verdict, reasons, confidence = detector.detect(messages)
        
        # Should handle without crashing
        assert verdict is not None
        assert isinstance(verdict, Verdict)

    def test_invalid_unicode_characters(self):
        """Test with invalid/malformed unicode."""
        detector = HeuristicDetector("strict")
        
        # Various problematic unicode
        texts = [
            "\ud800",  # Unpaired high surrogate
            "\udfff",  # Unpaired low surrogate
            "\x00\x01\x02",  # Control characters
            "test\uffff",  # Non-character
            "test\ufffe",  # Byte order mark
        ]
        
        for text in texts:
            # Should not crash
            messages = [Message(role=Role.USER, content=text)]
            verdict, reasons, confidence = detector.detect(messages)
            assert verdict is not None

    def test_circular_reference_in_messages(self):
        """Test handling of circular references in message objects."""
        # Create messages that reference each other
        msg1 = Message(role=Role.USER, content="test")
        msg2 = Message(role=Role.ASSISTANT, content="response")
        
        # This should work fine - Pydantic models handle this
        messages = [msg1, msg2, msg1, msg2]  # Repeated references
        
        detector = HeuristicDetector("moderate")
        # Process all messages
        verdict, reasons, confidence = detector.detect(messages)
        assert verdict is not None

    @pytest.mark.asyncio
    async def test_null_api_keys(self):
        """Test provider initialization with null/empty API keys."""
        from prompt_sentinel.providers.anthropic_provider import AnthropicProvider
        
        configs = [
            {"api_key": None},
            {"api_key": ""},
            {"api_key": " "},
            {},  # Missing api_key
        ]
        
        for config in configs:
            # Provider accepts empty/null keys but won't work when calling classify
            provider = AnthropicProvider(config)
            # The provider should fail when trying to classify
            messages = [Message(role=Role.USER, content="test")]
            category, confidence, reasoning = await provider.classify(messages)
            # Should return BENIGN with 0 confidence on error
            assert category == DetectionCategory.BENIGN
            assert confidence == 0.0

    def test_malformed_detection_mode(self):
        """Test with invalid detection modes."""
        # Invalid mode defaults to 'moderate' instead of raising error
        detector = HeuristicDetector("INVALID_MODE")
        assert detector.mode == "moderate"  # Falls back to default
        
        # None also defaults to moderate
        detector = HeuristicDetector(None)
        assert detector.mode == "moderate"
        
        # Numeric mode gets converted to string
        detector = HeuristicDetector(123)
        assert detector.mode == "moderate"  # Falls back to default

    def test_negative_confidence_scores(self):
        """Test handling of negative confidence scores."""
        from prompt_sentinel.models.schemas import DetectionReason
        
        # Try to create reason with negative confidence
        with pytest.raises(ValueError):
            reason = DetectionReason(
                category=DetectionCategory.JAILBREAK,
                confidence=-0.5,  # Invalid negative
                explanation="test"
            )

    def test_confidence_score_above_one(self):
        """Test handling of confidence scores > 1.0."""
        from prompt_sentinel.models.schemas import DetectionReason
        
        # Try to create reason with confidence > 1
        with pytest.raises(ValueError):
            reason = DetectionReason(
                category=DetectionCategory.JAILBREAK,
                confidence=1.5,  # Invalid > 1.0
                explanation="test"
            )


class TestResourceExhaustion:
    """Test cases for resource exhaustion and limits."""

    def test_regex_catastrophic_backtracking(self):
        """Test protection against regex catastrophic backtracking."""
        detector = HeuristicDetector("strict")
        
        # Pattern that could cause exponential backtracking
        evil_input = "a" * 100 + "X"
        messages = [Message(role=Role.USER, content=evil_input)]
        
        # Should complete in reasonable time
        import time
        start = time.time()
        verdict, reasons, confidence = detector.detect(messages)
        elapsed = time.time() - start
        
        assert elapsed < 1.0  # Should be fast
        assert verdict is not None

    def test_memory_exhaustion_protection(self):
        """Test protection against memory exhaustion attacks."""
        detector = PIIDetector()
        
        # Try to exhaust memory with many matches
        # Create text with thousands of email-like patterns
        text = " test@example.com " * 10000
        
        # Should handle gracefully
        matches = detector.detect(text)
        
        # Should deduplicate and not exhaust memory
        assert len(matches) <= 10000

    @pytest.mark.asyncio
    async def test_concurrent_request_limits(self):
        """Test handling of too many concurrent requests."""
        from prompt_sentinel.providers.anthropic_provider import AnthropicProvider
        
        config = {"api_key": "test-key", "model": "claude-3"}
        with patch("prompt_sentinel.providers.anthropic_provider.Anthropic"):
            provider = AnthropicProvider(config)
            
            # Mock to simulate rate limiting
            provider.client.messages.create = AsyncMock(
                side_effect=Exception("Rate limit exceeded")
            )
            
            # Create many concurrent requests
            messages = [Message(role=Role.USER, content=f"test{i}") for i in range(100)]
            
            tasks = [provider.classify([msg]) for msg in messages]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # All should return benign on error
            for result in results:
                if not isinstance(result, Exception):
                    category, confidence, _ = result
                    assert category == DetectionCategory.BENIGN
                    assert confidence == 0.0

    def test_stack_overflow_protection(self):
        """Test protection against stack overflow from deep recursion."""
        detector = HeuristicDetector("strict")
        
        # Create deeply nested structure that might cause recursion
        nested_text = "(" * 1000 + "test" + ")" * 1000
        messages = [Message(role=Role.USER, content=nested_text)]
        
        # Should handle without stack overflow
        verdict, reasons, confidence = detector.detect(messages)
        assert verdict is not None

    def test_infinite_loop_protection(self):
        """Test protection against potential infinite loops."""
        detector = PIIDetector()
        
        # Create pattern that might cause infinite loop in bad regex
        tricky_text = "****" * 1000
        
        # Should complete without hanging
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError("Detection took too long")
        
        # Set 5 second timeout
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(5)
        
        try:
            matches = detector.detect(tricky_text)
            signal.alarm(0)  # Cancel alarm
            assert matches is not None
        except TimeoutError:
            pytest.fail("Detection caused timeout - possible infinite loop")


class TestAPIErrorHandling:
    """Test cases for API error conditions."""

    @pytest.mark.asyncio
    async def test_network_timeout_handling(self):
        """Test handling of network timeouts."""
        from prompt_sentinel.providers.openai_provider import OpenAIProvider
        
        config = {"api_key": "test-key", "model": "gpt-3.5", "timeout": 0.001}
        
        with patch("prompt_sentinel.providers.openai_provider.AsyncOpenAI"):
            provider = OpenAIProvider(config)
            
            # Mock to simulate timeout
            provider.client.chat.completions.create = AsyncMock(
                side_effect=asyncio.TimeoutError()
            )
            
            messages = [Message(role=Role.USER, content="test")]
            category, confidence, explanation = await provider.classify(messages)
            
            assert category == DetectionCategory.BENIGN
            assert confidence == 0.0
            assert "timeout" in explanation.lower()

    @pytest.mark.asyncio
    async def test_malformed_api_response(self):
        """Test handling of malformed API responses."""
        from prompt_sentinel.providers.gemini_provider import GeminiProvider
        
        config = {"api_key": "test-key", "model": "gemini-pro"}
        
        with patch("prompt_sentinel.providers.gemini_provider.genai"):
            provider = GeminiProvider(config)
            
            # Mock various malformed responses
            malformed_responses = [
                None,  # Null response
                MagicMock(text="not json at all"),  # Invalid JSON
                MagicMock(text='{"wrong": "format"}'),  # Missing required fields
                MagicMock(text='{"category": 123}'),  # Wrong type
                MagicMock(text=""),  # Empty response
            ]
            
            for mock_response in malformed_responses:
                provider.model_instance.generate_content = MagicMock(
                    return_value=mock_response
                )
                
                messages = [Message(role=Role.USER, content="test")]
                category, confidence, explanation = await provider.classify(messages)
                
                # Should gracefully default to benign
                assert category == DetectionCategory.BENIGN
                assert confidence == 0.0

    @pytest.mark.asyncio
    async def test_api_key_revoked(self):
        """Test handling of revoked API keys."""
        from prompt_sentinel.providers.anthropic_provider import AnthropicProvider
        
        config = {"api_key": "revoked-key", "model": "claude-3"}
        
        with patch("prompt_sentinel.providers.anthropic_provider.Anthropic"):
            provider = AnthropicProvider(config)
            
            # Mock authentication error
            provider.client.messages.create = AsyncMock(
                side_effect=Exception("Invalid API key")
            )
            
            messages = [Message(role=Role.USER, content="test")]
            category, confidence, explanation = await provider.classify(messages)
            
            assert category == DetectionCategory.BENIGN
            assert confidence == 0.0
            assert "Invalid API key" in explanation

    @pytest.mark.asyncio
    async def test_service_unavailable(self):
        """Test handling of service unavailable errors."""
        from prompt_sentinel.providers.openai_provider import OpenAIProvider
        
        config = {"api_key": "test-key", "model": "gpt-4"}
        
        with patch("prompt_sentinel.providers.openai_provider.AsyncOpenAI"):
            provider = OpenAIProvider(config)
            
            # Mock 503 Service Unavailable
            provider.client.chat.completions.create = AsyncMock(
                side_effect=Exception("Service temporarily unavailable")
            )
            
            messages = [Message(role=Role.USER, content="test")]
            category, confidence, explanation = await provider.classify(messages)
            
            assert category == DetectionCategory.BENIGN
            assert confidence == 0.0
            assert "Service" in explanation

    @pytest.mark.asyncio
    async def test_quota_exceeded(self):
        """Test handling of quota exceeded errors."""
        from prompt_sentinel.providers.gemini_provider import GeminiProvider
        
        config = {"api_key": "test-key", "model": "gemini-pro"}
        
        with patch("prompt_sentinel.providers.gemini_provider.genai"):
            provider = GeminiProvider(config)
            
            # Mock quota exceeded error
            provider.model_instance.generate_content = MagicMock(
                side_effect=Exception("Quota exceeded")
            )
            
            messages = [Message(role=Role.USER, content="test")]
            category, confidence, explanation = await provider.classify(messages)
            
            assert category == DetectionCategory.BENIGN
            assert confidence == 0.0
            assert "Quota exceeded" in explanation


class TestDataCorruption:
    """Test cases for data corruption and integrity issues."""

    def test_corrupted_pattern_data(self):
        """Test handling of corrupted pattern data."""
        detector = HeuristicDetector("strict")
        
        # Temporarily corrupt patterns
        original_patterns = detector.injection_patterns.copy()
        detector.injection_patterns = [
            (None, 0.9, "test"),  # None pattern
            ("", 0.8, "empty"),  # Empty pattern
            (r"[", 0.7, "invalid"),  # Invalid regex
        ]
        
        # Should handle gracefully
        try:
            messages = [Message(role=Role.USER, content="test input")]
            verdict, reasons, confidence = detector.detect(messages)
            assert verdict is not None
        finally:
            detector.injection_patterns = original_patterns

    def test_nan_confidence_values(self):
        """Test handling of NaN confidence values."""
        detector = HeuristicDetector("moderate")
        
        # Mock a pattern match with NaN confidence
        original_patterns = detector.injection_patterns.copy()
        detector.injection_patterns = [
            (r"test", float('nan'), "NaN confidence"),
        ]
        
        try:
            messages = [Message(role=Role.USER, content="test input")]
            verdict, reasons, confidence = detector.detect(messages)
            # Should handle NaN gracefully
            assert verdict is not None
            # NaN should be treated as 0 or filtered out
            for reason in reasons:
                assert reason.confidence >= 0.0
                assert reason.confidence <= 1.0
        finally:
            detector.injection_patterns = original_patterns

    def test_infinity_confidence_values(self):
        """Test handling of infinity confidence values."""
        detector = HeuristicDetector("permissive")
        
        # Mock patterns with infinity confidence
        original_patterns = detector.injection_patterns.copy()
        detector.injection_patterns = [
            (r"test", float('inf'), "Infinite confidence"),
            (r"demo", float('-inf'), "Negative infinite"),
        ]
        
        try:
            messages = [Message(role=Role.USER, content="test demo input")]
            verdict, reasons, confidence = detector.detect(messages)
            # Should handle infinity gracefully
            assert verdict is not None
            # Infinity should be clamped to valid range
            for reason in reasons:
                assert reason.confidence >= 0.0
                assert reason.confidence <= 1.0
        finally:
            detector.injection_patterns = original_patterns

    def test_circular_json_serialization(self):
        """Test handling of circular references in JSON serialization."""
        from prompt_sentinel.models.schemas import DetectionReason
        
        reason = DetectionReason(
            category=DetectionCategory.JAILBREAK,
            confidence=0.9,
            explanation="test"
        )
        
        # Create a detection result
        result = DetectionResponse(
            verdict=Verdict.BLOCK,
            confidence=0.9,
            reasons=[reason],
            processing_time_ms=10.5
        )
        
        # Should serialize without circular reference issues
        try:
            json_str = result.model_dump_json()
            assert json_str is not None
            
            # Should be valid JSON
            parsed = json.loads(json_str)
            assert parsed["verdict"] == "BLOCK"
        except Exception as e:
            pytest.fail(f"JSON serialization failed: {e}")


class TestConcurrencyIssues:
    """Test cases for concurrency and race conditions."""

    @pytest.mark.asyncio
    async def test_concurrent_detector_access(self):
        """Test thread safety of detector with concurrent access."""
        detector = HeuristicDetector("strict")
        
        async def detect_task(text):
            # Simulate some async work
            await asyncio.sleep(0.001)
            messages = [Message(role=Role.USER, content=text)]
            return detector.detect(messages)
        
        # Create many concurrent tasks
        tasks = [detect_task(f"test input {i}") for i in range(100)]
        results = await asyncio.gather(*tasks)
        
        # All should complete successfully
        assert len(results) == 100
        for verdict, reasons, confidence in results:
            assert verdict is not None
            assert isinstance(verdict, Verdict)

    @pytest.mark.asyncio
    async def test_provider_state_corruption(self):
        """Test that provider state isn't corrupted by concurrent calls."""
        from prompt_sentinel.providers.anthropic_provider import AnthropicProvider
        
        config = {"api_key": "test-key", "model": "claude-3"}
        
        with patch("prompt_sentinel.providers.anthropic_provider.Anthropic"):
            provider = AnthropicProvider(config)
            
            call_count = 0
            
            async def mock_create(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                await asyncio.sleep(0.01)  # Simulate API delay
                
                mock_response = MagicMock()
                mock_response.content = [
                    MagicMock(text=json.dumps({
                        "category": "benign",
                        "confidence": 0.1,
                        "explanation": f"Call {call_count}"
                    }))
                ]
                return mock_response
            
            provider.client.messages.create = mock_create
            
            # Make concurrent calls
            messages = [Message(role=Role.USER, content="test")]
            tasks = [provider.classify(messages) for _ in range(20)]
            results = await asyncio.gather(*tasks)
            
            # All should complete
            assert len(results) == 20
            assert call_count == 20

    @pytest.mark.asyncio
    async def test_cache_race_conditions(self):
        """Test cache behavior under concurrent access."""
        from prompt_sentinel.detection.llm_classifier import LLMClassifierManager
        
        config = {
            "provider_order": ["anthropic"],
            "providers": {
                "anthropic": {
                    "api_key": "test-key",
                    "model": "claude-3"
                }
            },
            "cache_ttl": 60
        }
        
        with patch("prompt_sentinel.detection.llm_classifier.AnthropicProvider"):
            manager = LLMClassifierManager(config)
            
            # Mock the provider
            mock_provider = MagicMock()
            mock_provider.classify = AsyncMock(
                return_value=(DetectionCategory.BENIGN, 0.1, "Cached")
            )
            mock_provider.health_check = AsyncMock(return_value=True)
            manager.providers = {"anthropic": mock_provider}
            
            messages = [Message(role=Role.USER, content="cache test")]
            
            # Make many concurrent calls with same input
            tasks = [manager.classify(messages) for _ in range(50)]
            results = await asyncio.gather(*tasks)
            
            # All should get same result
            for category, confidence, explanation in results:
                assert category == DetectionCategory.BENIGN
                assert confidence == 0.1
            
            # Provider should only be called once due to caching
            assert mock_provider.classify.call_count == 1


class TestBoundaryConditions:
    """Test cases for boundary conditions and edge cases."""

    def test_zero_length_arrays(self):
        """Test handling of zero-length arrays."""
        detector = HeuristicDetector("moderate")
        
        # Empty messages list
        messages = []
        
        # Should handle empty list
        verdict, reasons, confidence = detector.detect(messages)
        assert verdict is not None

    def test_single_character_inputs(self):
        """Test with single character inputs."""
        detector = HeuristicDetector("strict")
        
        # Test all single ASCII characters
        for i in range(32, 127):
            char = chr(i)
            messages = [Message(role=Role.USER, content=char)]
            verdict, reasons, confidence = detector.detect(messages)
            assert verdict is not None
            assert isinstance(verdict, Verdict)

    def test_maximum_message_length(self):
        """Test with maximum allowed message length."""
        detector = HeuristicDetector("permissive")
        
        # Create max length message (e.g., 100KB)
        max_text = "a" * (100 * 1024)
        messages = [Message(role=Role.USER, content=max_text)]
        verdict, reasons, confidence = detector.detect(messages)
        
        assert verdict is not None
        assert isinstance(verdict, Verdict)

    def test_boundary_confidence_values(self):
        """Test exact boundary confidence values."""
        from prompt_sentinel.models.schemas import DetectionReason
        
        # Test exact boundaries
        boundaries = [0.0, 0.5, 1.0]
        
        for conf in boundaries:
            reason = DetectionReason(
                category=DetectionCategory.BENIGN,
                confidence=conf,
                explanation="boundary test"
            )
            assert reason.confidence == conf

    def test_mixed_line_endings(self):
        """Test handling of mixed line endings."""
        detector = HeuristicDetector("moderate")
        
        # Mix of Windows, Unix, and Mac line endings
        text = "line1\r\nline2\nline3\rline4"
        messages = [Message(role=Role.USER, content=text)]
        verdict, reasons, confidence = detector.detect(messages)
        
        assert verdict is not None

    def test_bom_handling(self):
        """Test handling of Byte Order Mark."""
        detector = HeuristicDetector("strict")
        
        # UTF-8 BOM
        text_with_bom = "\ufeff" + "test content"
        messages = [Message(role=Role.USER, content=text_with_bom)]
        verdict, reasons, confidence = detector.detect(messages)
        
        assert verdict is not None

    def test_null_bytes_in_string(self):
        """Test handling of null bytes in strings."""
        detector = HeuristicDetector("permissive")
        
        # String with null bytes
        text = "test\x00content\x00here"
        messages = [Message(role=Role.USER, content=text)]
        verdict, reasons, confidence = detector.detect(messages)
        
        assert verdict is not None


class TestSystemIntegration:
    """Test cases for system integration issues."""

    @pytest.mark.asyncio
    async def test_provider_failover_exhaustion(self):
        """Test when all providers fail."""
        from prompt_sentinel.detection.llm_classifier import LLMClassifierManager
        
        config = {
            "provider_order": ["anthropic", "openai", "gemini"],
            "providers": {
                "anthropic": {"api_key": "key1", "model": "claude-3"},
                "openai": {"api_key": "key2", "model": "gpt-4"},
                "gemini": {"api_key": "key3", "model": "gemini-pro"},
            }
        }
        
        with patch("prompt_sentinel.detection.llm_classifier.AnthropicProvider"), \
             patch("prompt_sentinel.detection.llm_classifier.OpenAIProvider"), \
             patch("prompt_sentinel.detection.llm_classifier.GeminiProvider"):
            
            manager = LLMClassifierManager(config)
            
            # Make all providers fail
            for provider_name in manager.providers:
                provider = manager.providers[provider_name]
                provider.classify = AsyncMock(
                    side_effect=Exception(f"{provider_name} failed")
                )
                provider.health_check = AsyncMock(return_value=False)
            
            messages = [Message(role=Role.USER, content="test")]
            category, confidence, explanation = await manager.classify(messages)
            
            # Should return benign when all fail
            assert category == DetectionCategory.BENIGN
            assert confidence == 0.0
            assert "failed" in explanation.lower()

    def test_missing_dependencies(self):
        """Test handling of missing dependencies."""
        # Try importing with mocked missing dependency
        import sys
        
        # Temporarily remove a dependency
        original_modules = sys.modules.copy()
        
        try:
            # Simulate missing anthropic module
            if 'anthropic' in sys.modules:
                del sys.modules['anthropic']
            
            with pytest.raises(ImportError):
                from prompt_sentinel.providers.anthropic_provider import AnthropicProvider
        finally:
            # Restore modules
            sys.modules.update(original_modules)

    def test_file_system_errors(self):
        """Test handling of file system errors."""
        # This would test file-based operations if any exist
        # Currently, the system doesn't seem to have file I/O
        # but this is a placeholder for future file operations
        pass

    def test_memory_pressure_conditions(self):
        """Test behavior under memory pressure."""
        detector = PIIDetector()
        
        # Create large dataset that might cause memory pressure
        large_texts = []
        for i in range(1000):
            text = f"email{i}@example.com phone: 555-{i:04d}"
            large_texts.append(text)
        
        # Process all texts
        all_matches = []
        for text in large_texts:
            matches = detector.detect(text)
            all_matches.extend(matches)
        
        # Should complete without memory errors
        assert len(all_matches) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])