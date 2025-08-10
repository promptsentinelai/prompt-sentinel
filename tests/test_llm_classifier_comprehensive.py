"""Comprehensive tests for the LLMClassifierManager module."""

import asyncio
import hashlib
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from prompt_sentinel.detection.llm_classifier import LLMClassifierManager
from prompt_sentinel.models.schemas import (
    DetectionCategory,
    DetectionReason,
    Message,
    Role,
    Verdict,
)


class TestLLMClassifierManager:
    """Test suite for LLMClassifierManager."""

    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing."""
        settings = MagicMock()
        settings.llm_providers = ["anthropic", "openai", "gemini"]
        settings.detection_mode = "moderate"
        settings.cache_ttl_llm = 3600
        settings.get_provider_config = MagicMock(
            side_effect=lambda provider: {
                "api_key": f"test_key_{provider}",
                "model": "test-model",
                "temperature": 0.7,
            }
        )
        return settings

    @pytest.fixture
    def mock_cache_manager(self):
        """Mock cache manager."""
        cache = MagicMock()
        cache.enabled = True
        cache.get_or_compute = AsyncMock()
        return cache

    @pytest.fixture
    def mock_providers(self):
        """Create mock provider instances."""
        providers = {}
        for name in ["anthropic", "openai", "gemini"]:
            provider = MagicMock()
            provider.classify = AsyncMock(
                return_value=(DetectionCategory.BENIGN, 0.95, f"Analysis from {name}")
            )
            provider.health_check = AsyncMock(return_value=True)
            providers[name] = provider
        return providers

    @pytest.fixture
    def manager(self, mock_settings):
        """Create LLMClassifierManager instance."""
        with patch("prompt_sentinel.detection.llm_classifier.settings", mock_settings):
            manager = LLMClassifierManager()
            return manager

    @pytest.fixture
    def sample_messages(self):
        """Create sample messages for testing."""
        return [
            Message(role=Role.USER, content="Hello, how can I help you?"),
            Message(role=Role.ASSISTANT, content="I'm here to assist you."),
        ]

    def test_initialization_with_defaults(self, mock_settings):
        """Test initialization with default settings."""
        with patch("prompt_sentinel.detection.llm_classifier.settings", mock_settings):
            with patch.object(LLMClassifierManager, "_initialize_providers") as mock_init:
                manager = LLMClassifierManager()

                assert manager.provider_order == ["anthropic", "openai", "gemini"]
                assert manager.providers == {}
                mock_init.assert_called_once()

    def test_initialization_with_custom_order(self, mock_settings):
        """Test initialization with custom provider order."""
        with patch("prompt_sentinel.detection.llm_classifier.settings", mock_settings):
            with patch.object(LLMClassifierManager, "_initialize_providers"):
                manager = LLMClassifierManager(provider_order=["openai", "anthropic"])

                assert manager.provider_order == ["openai", "anthropic"]

    @patch("prompt_sentinel.detection.llm_classifier.AnthropicProvider")
    @patch("prompt_sentinel.detection.llm_classifier.OpenAIProvider")
    @patch("prompt_sentinel.detection.llm_classifier.GeminiProvider")
    def test_initialize_providers_success(
        self, mock_gemini_class, mock_openai_class, mock_anthropic_class, mock_settings
    ):
        """Test successful provider initialization."""
        # Create mock provider instances
        mock_anthropic = MagicMock()
        mock_openai = MagicMock()
        mock_gemini = MagicMock()

        mock_anthropic_class.return_value = mock_anthropic
        mock_openai_class.return_value = mock_openai
        mock_gemini_class.return_value = mock_gemini

        with patch("prompt_sentinel.detection.llm_classifier.settings", mock_settings):
            manager = LLMClassifierManager()

            assert "anthropic" in manager.providers
            assert "openai" in manager.providers
            assert "gemini" in manager.providers
            assert manager.providers["anthropic"] == mock_anthropic
            assert manager.providers["openai"] == mock_openai
            assert manager.providers["gemini"] == mock_gemini

    @patch("prompt_sentinel.detection.llm_classifier.AnthropicProvider")
    def test_initialize_providers_partial_failure(self, mock_anthropic_class, mock_settings):
        """Test provider initialization with some failures."""
        mock_anthropic_class.side_effect = Exception("Initialization failed")

        mock_settings.llm_providers = ["anthropic"]

        with patch("prompt_sentinel.detection.llm_classifier.settings", mock_settings):
            with patch("builtins.print") as mock_print:
                manager = LLMClassifierManager()

                assert "anthropic" not in manager.providers
                mock_print.assert_called_with(
                    "Failed to initialize anthropic: Initialization failed"
                )

    @patch("prompt_sentinel.detection.llm_classifier.AnthropicProvider")
    @patch("prompt_sentinel.detection.llm_classifier.OpenAIProvider")
    @patch("prompt_sentinel.detection.llm_classifier.GeminiProvider")
    def test_initialize_providers_no_api_key(
        self, mock_gemini_class, mock_openai_class, mock_anthropic_class, mock_settings
    ):
        """Test provider initialization when API key is missing."""

        # Return config with None api_key - providers shouldn't be instantiated
        def get_config_side_effect(provider_name):
            return {"api_key": None}  # Always return None api_key

        mock_settings.get_provider_config.side_effect = get_config_side_effect
        mock_settings.llm_providers = ["anthropic", "openai", "gemini"]  # Set provider order

        with patch("prompt_sentinel.detection.llm_classifier.settings", mock_settings):
            with patch("builtins.print"):  # Suppress print statements
                manager = LLMClassifierManager()

        # When api_key is None, providers shouldn't be added to the dict
        assert len(manager.providers) == 0
        # Provider classes should not have been instantiated
        mock_anthropic_class.assert_not_called()
        mock_openai_class.assert_not_called()
        mock_gemini_class.assert_not_called()

    @pytest.mark.asyncio
    async def test_classify_no_providers(self, manager, sample_messages):
        """Test classification when no providers are available."""
        manager.providers = {}

        with patch("prompt_sentinel.detection.llm_classifier.logger") as mock_logger:
            verdict, reasons, confidence = await manager.classify(sample_messages)

            assert verdict == Verdict.ALLOW
            assert reasons == []
            assert confidence == 0.0
            mock_logger.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_classify_with_cache_hit(self, manager, sample_messages, mock_cache_manager):
        """Test classification with cache hit."""
        manager.providers = {"anthropic": MagicMock()}

        # Mock cache hit
        cached_result = (
            Verdict.ALLOW,
            [
                DetectionReason(
                    category=DetectionCategory.BENIGN,
                    description="Cached result",
                    confidence=0.95,
                    source="llm",  # Must be one of: 'heuristic', 'llm', 'combined'
                    patterns_matched=[],
                )
            ],
            0.95,
        )

        mock_cache_manager.get_or_compute.return_value = cached_result

        with patch("prompt_sentinel.detection.llm_classifier.cache_manager", mock_cache_manager):
            with patch("prompt_sentinel.detection.llm_classifier.logger") as mock_logger:
                result = await manager.classify(sample_messages, use_cache=True)

                assert result == cached_result
                mock_cache_manager.get_or_compute.assert_called_once()

    @pytest.mark.asyncio
    async def test_classify_without_cache(self, manager, sample_messages, mock_providers):
        """Test classification without using cache."""
        manager.providers = {"anthropic": mock_providers["anthropic"]}

        result = await manager.classify(sample_messages, use_cache=False)

        assert result[0] == Verdict.ALLOW  # BENIGN -> ALLOW
        assert len(result[1]) == 1
        assert result[2] == 0.95

    @pytest.mark.asyncio
    async def test_classify_with_all_providers(self, manager, sample_messages, mock_providers):
        """Test classification using all providers."""
        manager.providers = mock_providers

        result = await manager.classify(sample_messages, use_all_providers=True, use_cache=False)

        # Should have results from all 3 providers
        assert len(result[1]) == 3
        assert result[2] == pytest.approx(0.95, rel=0.01)  # Average confidence
        assert all(
            "[" in reason.description for reason in result[1]
        )  # Provider names in descriptions

    @pytest.mark.asyncio
    async def test_classify_with_failover(self, manager, sample_messages):
        """Test classification with provider failover."""
        # First provider fails, second succeeds
        provider1 = MagicMock()
        provider1.classify = AsyncMock(side_effect=Exception("Provider 1 failed"))

        provider2 = MagicMock()
        provider2.classify = AsyncMock(
            return_value=(DetectionCategory.DIRECT_INJECTION, 0.85, "Injection detected")
        )

        manager.providers = {"anthropic": provider1, "openai": provider2}
        manager.provider_order = ["anthropic", "openai"]

        with patch("builtins.print") as mock_print:
            result = await manager.classify(sample_messages, use_cache=False)

            assert result[0] == Verdict.BLOCK  # High severity + high confidence
            assert result[2] == 0.85
            mock_print.assert_called_with("Provider anthropic failed: Provider 1 failed")

    @pytest.mark.asyncio
    async def test_classify_all_providers_fail(self, manager, sample_messages):
        """Test classification when all providers fail."""
        provider1 = MagicMock()
        provider1.classify = AsyncMock(side_effect=Exception("Failed"))

        manager.providers = {"anthropic": provider1}

        result = await manager.classify(sample_messages, use_cache=False)

        assert result == (Verdict.ALLOW, [], 0.0)

    @pytest.mark.asyncio
    async def test_classify_with_all_providers_mixed_results(self, manager, sample_messages):
        """Test classification with all providers returning different results."""
        provider1 = MagicMock()
        provider1.classify = AsyncMock(
            return_value=(DetectionCategory.DIRECT_INJECTION, 0.9, "Direct injection")
        )

        provider2 = MagicMock()
        provider2.classify = AsyncMock(return_value=(DetectionCategory.BENIGN, 0.8, "Looks safe"))

        provider3 = MagicMock()
        provider3.classify = AsyncMock(
            return_value=(DetectionCategory.JAILBREAK, 0.85, "Jailbreak attempt")
        )

        manager.providers = {"anthropic": provider1, "openai": provider2, "gemini": provider3}

        result = await manager.classify(sample_messages, use_all_providers=True)

        # Should pick most severe category (DIRECT_INJECTION)
        assert len(result[1]) == 3
        # Average confidence: (0.9 + 0.8 + 0.85) / 3 = 0.85
        assert result[2] == pytest.approx(0.85, rel=0.01)

    @pytest.mark.asyncio
    async def test_classify_with_all_providers_consensus_boost(self, manager, sample_messages):
        """Test confidence boost when all providers agree."""
        # All providers agree on DIRECT_INJECTION
        for provider in manager.providers.values():
            provider = MagicMock()
            provider.classify = AsyncMock(
                return_value=(DetectionCategory.DIRECT_INJECTION, 0.8, "Injection detected")
            )

        manager.providers = {
            "anthropic": MagicMock(
                classify=AsyncMock(
                    return_value=(DetectionCategory.DIRECT_INJECTION, 0.8, "Injection")
                )
            ),
            "openai": MagicMock(
                classify=AsyncMock(
                    return_value=(DetectionCategory.DIRECT_INJECTION, 0.8, "Injection")
                )
            ),
        }

        result = await manager.classify(sample_messages, use_all_providers=True)

        # Confidence should be boosted: 0.8 * 1.2 = 0.96
        assert result[2] == pytest.approx(0.96, rel=0.01)

    @pytest.mark.asyncio
    async def test_classify_with_all_providers_partial_failure(self, manager, sample_messages):
        """Test classification when some providers fail in all-provider mode."""
        provider1 = MagicMock()
        provider1.classify = AsyncMock(return_value=(DetectionCategory.BENIGN, 0.9, "Safe"))

        provider2 = MagicMock()
        provider2.classify = AsyncMock(side_effect=Exception("Provider failed"))

        manager.providers = {"anthropic": provider1, "openai": provider2}

        with patch("builtins.print"):
            result = await manager.classify(sample_messages, use_all_providers=True)

            # Should still get result from working provider
            assert len(result[1]) == 1
            assert result[2] == 0.9

    def test_determine_verdict_benign(self, manager):
        """Test verdict determination for benign category."""
        verdict = manager._determine_verdict(DetectionCategory.BENIGN, 0.95)
        assert verdict == Verdict.ALLOW

    def test_determine_verdict_high_severity_high_confidence(self, manager):
        """Test verdict for high severity with high confidence."""
        # DIRECT_INJECTION with confidence >= 0.7 -> BLOCK
        verdict = manager._determine_verdict(DetectionCategory.DIRECT_INJECTION, 0.8)
        assert verdict == Verdict.BLOCK

        # JAILBREAK with confidence >= 0.7 -> BLOCK
        verdict = manager._determine_verdict(DetectionCategory.JAILBREAK, 0.75)
        assert verdict == Verdict.BLOCK

        # PROMPT_LEAK with confidence >= 0.7 -> BLOCK
        verdict = manager._determine_verdict(DetectionCategory.PROMPT_LEAK, 0.9)
        assert verdict == Verdict.BLOCK

    def test_determine_verdict_high_severity_medium_confidence(self, manager):
        """Test verdict for high severity with medium confidence."""
        # DIRECT_INJECTION with 0.5 <= confidence < 0.7 -> STRIP
        verdict = manager._determine_verdict(DetectionCategory.DIRECT_INJECTION, 0.6)
        assert verdict == Verdict.STRIP

    def test_determine_verdict_high_severity_low_confidence(self, manager):
        """Test verdict for high severity with low confidence."""
        # DIRECT_INJECTION with confidence < 0.5 -> FLAG
        verdict = manager._determine_verdict(DetectionCategory.DIRECT_INJECTION, 0.4)
        assert verdict == Verdict.FLAG

    def test_determine_verdict_medium_severity_high_confidence(self, manager):
        """Test verdict for medium severity with high confidence."""
        # INDIRECT_INJECTION with confidence >= 0.8 -> BLOCK
        verdict = manager._determine_verdict(DetectionCategory.INDIRECT_INJECTION, 0.85)
        assert verdict == Verdict.BLOCK

        # ROLE_MANIPULATION with confidence >= 0.8 -> BLOCK
        verdict = manager._determine_verdict(DetectionCategory.ROLE_MANIPULATION, 0.9)
        assert verdict == Verdict.BLOCK

    def test_determine_verdict_medium_severity_medium_confidence(self, manager):
        """Test verdict for medium severity with medium confidence."""
        # CONTEXT_SWITCHING with 0.6 <= confidence < 0.8 -> STRIP
        verdict = manager._determine_verdict(DetectionCategory.CONTEXT_SWITCHING, 0.7)
        assert verdict == Verdict.STRIP

    def test_determine_verdict_medium_severity_low_confidence(self, manager):
        """Test verdict for medium severity with low confidence."""
        # INDIRECT_INJECTION with confidence < 0.6 -> FLAG
        verdict = manager._determine_verdict(DetectionCategory.INDIRECT_INJECTION, 0.5)
        assert verdict == Verdict.FLAG

    def test_determine_verdict_low_severity_high_confidence(self, manager):
        """Test verdict for low severity with high confidence."""
        # ENCODING_ATTACK with confidence >= 0.9 -> STRIP
        verdict = manager._determine_verdict(DetectionCategory.ENCODING_ATTACK, 0.95)
        assert verdict == Verdict.STRIP

    def test_determine_verdict_low_severity_medium_confidence(self, manager):
        """Test verdict for low severity with medium confidence."""
        # ENCODING_ATTACK with 0.7 <= confidence < 0.9 -> FLAG
        verdict = manager._determine_verdict(DetectionCategory.ENCODING_ATTACK, 0.8)
        assert verdict == Verdict.FLAG

    def test_determine_verdict_low_severity_low_confidence(self, manager):
        """Test verdict for low severity with low confidence."""
        # ENCODING_ATTACK with confidence < 0.7 -> ALLOW
        verdict = manager._determine_verdict(DetectionCategory.ENCODING_ATTACK, 0.6)
        assert verdict == Verdict.ALLOW

    def test_get_most_severe_category_single(self, manager):
        """Test getting most severe category with single category."""
        categories = [DetectionCategory.BENIGN]
        assert manager._get_most_severe_category(categories) == DetectionCategory.BENIGN

    def test_get_most_severe_category_multiple(self, manager):
        """Test getting most severe category with multiple categories."""
        categories = [
            DetectionCategory.BENIGN,
            DetectionCategory.ENCODING_ATTACK,
            DetectionCategory.DIRECT_INJECTION,
            DetectionCategory.ROLE_MANIPULATION,
        ]
        # DIRECT_INJECTION is most severe
        assert manager._get_most_severe_category(categories) == DetectionCategory.DIRECT_INJECTION

    def test_get_most_severe_category_all_same(self, manager):
        """Test getting most severe category when all are the same."""
        categories = [
            DetectionCategory.JAILBREAK,
            DetectionCategory.JAILBREAK,
            DetectionCategory.JAILBREAK,
        ]
        assert manager._get_most_severe_category(categories) == DetectionCategory.JAILBREAK

    def test_get_most_severe_category_empty(self, manager):
        """Test getting most severe category with empty list."""
        categories = []
        assert manager._get_most_severe_category(categories) == DetectionCategory.BENIGN

    @pytest.mark.asyncio
    async def test_health_check_all_healthy(self, manager, mock_providers):
        """Test health check when all providers are healthy."""
        manager.providers = mock_providers

        health_status = await manager.health_check()

        assert health_status == {
            "anthropic": True,
            "openai": True,
            "gemini": True,
        }

    @pytest.mark.asyncio
    async def test_health_check_partial_failure(self, manager):
        """Test health check with some providers unhealthy."""
        provider1 = MagicMock()
        provider1.health_check = AsyncMock(return_value=True)

        provider2 = MagicMock()
        provider2.health_check = AsyncMock(side_effect=Exception("Health check failed"))

        manager.providers = {
            "anthropic": provider1,
            "openai": provider2,
        }

        health_status = await manager.health_check()

        assert health_status == {
            "anthropic": True,
            "openai": False,
        }

    @pytest.mark.asyncio
    async def test_health_check_empty_providers(self, manager):
        """Test health check with no providers."""
        manager.providers = {}

        health_status = await manager.health_check()

        assert health_status == {}

    def test_generate_cache_key_basic(self, manager, sample_messages, mock_settings):
        """Test basic cache key generation."""
        with patch("prompt_sentinel.detection.llm_classifier.settings", mock_settings):
            key = manager._generate_cache_key(sample_messages)

            assert key.startswith("llm_classify:")
            assert len(key) > len("llm_classify:")

    def test_generate_cache_key_deterministic(self, manager, sample_messages, mock_settings):
        """Test that cache key generation is deterministic."""
        with patch("prompt_sentinel.detection.llm_classifier.settings", mock_settings):
            key1 = manager._generate_cache_key(sample_messages)
            key2 = manager._generate_cache_key(sample_messages)

            assert key1 == key2

    def test_generate_cache_key_different_messages(self, manager, mock_settings):
        """Test cache key differs for different messages."""
        messages1 = [Message(role=Role.USER, content="Hello")]
        messages2 = [Message(role=Role.USER, content="Goodbye")]

        with patch("prompt_sentinel.detection.llm_classifier.settings", mock_settings):
            key1 = manager._generate_cache_key(messages1)
            key2 = manager._generate_cache_key(messages2)

            assert key1 != key2

    def test_generate_cache_key_truncation(self, manager, mock_settings):
        """Test cache key generation with content truncation."""
        long_content = "x" * 500  # Content longer than 200 chars
        messages = [Message(role=Role.USER, content=long_content)]

        with patch("prompt_sentinel.detection.llm_classifier.settings", mock_settings):
            key = manager._generate_cache_key(messages)

            # Should generate valid key despite long content
            assert key.startswith("llm_classify:")

            # Key should be same for identical long content
            key2 = manager._generate_cache_key(messages)
            assert key == key2

    def test_generate_cache_key_includes_mode(self, manager, sample_messages, mock_settings):
        """Test that cache key includes detection mode."""
        with patch("prompt_sentinel.detection.llm_classifier.settings", mock_settings):
            mock_settings.detection_mode = "strict"
            key1 = manager._generate_cache_key(sample_messages)

            mock_settings.detection_mode = "permissive"
            key2 = manager._generate_cache_key(sample_messages)

            # Keys should differ when mode changes
            assert key1 != key2

    def test_generate_cache_key_role_order_matters(self, manager, mock_settings):
        """Test that message role order affects cache key."""
        messages1 = [
            Message(role=Role.USER, content="Hello"),
            Message(role=Role.ASSISTANT, content="Hi"),
        ]

        messages2 = [
            Message(role=Role.ASSISTANT, content="Hello"),
            Message(role=Role.USER, content="Hi"),
        ]

        with patch("prompt_sentinel.detection.llm_classifier.settings", mock_settings):
            key1 = manager._generate_cache_key(messages1)
            key2 = manager._generate_cache_key(messages2)

            assert key1 != key2

    @pytest.mark.asyncio
    async def test_classify_cache_integration(
        self, manager, sample_messages, mock_cache_manager, mock_settings
    ):
        """Test full integration with cache manager."""
        manager.providers = {"anthropic": MagicMock()}

        # Set up cache to call the compute function
        async def cache_side_effect(key, compute_func, **kwargs):
            # Simulate cache miss, call compute function
            return await compute_func()

        mock_cache_manager.get_or_compute.side_effect = cache_side_effect

        # Mock the actual classification
        with patch.object(
            manager, "_classify_with_failover", return_value=(Verdict.ALLOW, [], 0.95)
        ):
            with patch(
                "prompt_sentinel.detection.llm_classifier.cache_manager", mock_cache_manager
            ):
                with patch("prompt_sentinel.detection.llm_classifier.settings", mock_settings):
                    result = await manager.classify(sample_messages, use_cache=True)

                    assert result == (Verdict.ALLOW, [], 0.95)
                    mock_cache_manager.get_or_compute.assert_called_once()

                    # Check cache key was generated correctly
                    call_args = mock_cache_manager.get_or_compute.call_args
                    assert call_args[1]["key"].startswith("llm_classify:")
                    assert call_args[1]["ttl"] == 3600
                    assert call_args[1]["cache_on_error"] is True

    @pytest.mark.asyncio
    async def test_classify_detection_reason_creation(self, manager, sample_messages):
        """Test that detection reasons are created correctly."""
        provider = MagicMock()
        provider.classify = AsyncMock(
            return_value=(DetectionCategory.JAILBREAK, 0.85, "Detected jailbreak attempt")
        )

        manager.providers = {"test_provider": provider}
        manager.provider_order = ["test_provider"]

        verdict, reasons, confidence = await manager.classify(sample_messages, use_cache=False)

        assert len(reasons) == 1
        reason = reasons[0]
        assert reason.category == DetectionCategory.JAILBREAK
        assert reason.description == "Detected jailbreak attempt"
        assert reason.confidence == 0.85
        assert reason.source == "llm"
        assert reason.patterns_matched == ["test_provider_classification"]

    @pytest.mark.asyncio
    async def test_classify_all_providers_async_execution(self, manager, sample_messages):
        """Test that all providers are called asynchronously."""
        call_order = []

        async def mock_classify(messages):
            call_order.append("start")
            await asyncio.sleep(0.01)  # Simulate async work
            call_order.append("end")
            return (DetectionCategory.BENIGN, 0.9, "Safe")

        provider1 = MagicMock()
        provider1.classify = mock_classify

        provider2 = MagicMock()
        provider2.classify = mock_classify

        manager.providers = {
            "provider1": provider1,
            "provider2": provider2,
        }

        await manager.classify(sample_messages, use_all_providers=True)

        # If running async, should see starts before ends
        assert call_order == ["start", "start", "end", "end"]
