"""Comprehensive tests for LLM provider modules."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prompt_sentinel.models.schemas import DetectionCategory, Message, Role
from prompt_sentinel.providers.anthropic_provider import AnthropicProvider
from prompt_sentinel.providers.base import LLMProvider
from prompt_sentinel.providers.gemini_provider import GeminiProvider
from prompt_sentinel.providers.openai_provider import OpenAIProvider


class TestLLMProviderBase:
    """Test suite for the base LLMProvider class."""

    class ConcreteProvider(LLMProvider):
        """Concrete implementation for testing base class."""

        async def classify(self, messages, system_prompt=None):
            return (DetectionCategory.BENIGN, 0.95, "Test")

        async def health_check(self):
            return True

    def test_initialization_with_api_key(self):
        """Test provider initialization with API key."""
        config = {
            "api_key": "test_key_123",
            "model": "test-model",
            "max_tokens": 500,
            "temperature": 0.5,
            "timeout": 15.0,
        }
        provider = self.ConcreteProvider(config)

        assert provider.api_key == "test_key_123"
        assert provider.model == "test-model"
        assert provider.max_tokens == 500
        assert provider.temperature == 0.5
        assert provider.timeout == 15.0

    def test_initialization_without_api_key(self):
        """Test provider initialization fails without API key."""
        config = {"model": "test-model"}

        with pytest.raises(ValueError, match="API key required"):
            self.ConcreteProvider(config)

    def test_initialization_with_defaults(self):
        """Test provider initialization with default values."""
        config = {"api_key": "test_key"}
        provider = self.ConcreteProvider(config)

        assert provider.api_key == "test_key"
        assert provider.model is None
        assert provider.max_tokens == 1000
        assert provider.temperature == 0.3
        assert provider.timeout == 10.0

    def test_get_classification_prompt(self):
        """Test classification prompt generation."""
        provider = self.ConcreteProvider({"api_key": "test"})
        messages = [
            Message(role=Role.USER, content="Hello"),
            Message(role=Role.ASSISTANT, content="Hi there"),
        ]

        prompt = provider.get_classification_prompt(messages)

        assert "[USER]: Hello" in prompt
        assert "[ASSISTANT]: Hi there" in prompt
        assert "direct_injection" in prompt
        assert "JSON format" in prompt

    def test_get_system_prompt(self):
        """Test system prompt generation."""
        provider = self.ConcreteProvider({"api_key": "test"})
        prompt = provider.get_system_prompt()

        assert "security expert" in prompt
        assert "prompt injection detection" in prompt
        assert "JSON format" in prompt


class TestAnthropicProvider:
    """Test suite for AnthropicProvider."""

    @pytest.fixture
    def mock_config(self):
        """Create mock configuration."""
        return {
            "api_key": "test_anthropic_key",
            "model": "claude-3-sonnet",
            "max_tokens": 1000,
            "temperature": 0.3,
            "timeout": 10.0,
        }

    @pytest.fixture
    def provider(self, mock_config):
        """Create AnthropicProvider instance."""
        with patch("prompt_sentinel.providers.anthropic_provider.AsyncAnthropic"):
            return AnthropicProvider(mock_config)

    @pytest.fixture
    def sample_messages(self):
        """Create sample messages for testing."""
        return [
            Message(role=Role.USER, content="Test message"),
            Message(role=Role.ASSISTANT, content="Response"),
        ]

    def test_initialization(self, mock_config):
        """Test AnthropicProvider initialization."""
        with patch("prompt_sentinel.providers.anthropic_provider.AsyncAnthropic") as mock_client:
            provider = AnthropicProvider(mock_config)

            assert provider.api_key == "test_anthropic_key"
            assert provider.model == "claude-3-sonnet-20240229"  # Mapped model name
            mock_client.assert_called_once_with(api_key="test_anthropic_key")

    def test_model_mapping(self):
        """Test model name mapping."""
        config = {"api_key": "test"}

        # Test short names
        with patch("prompt_sentinel.providers.anthropic_provider.AsyncAnthropic"):
            provider = AnthropicProvider({**config, "model": "claude-3-opus"})
            assert provider.model == "claude-3-opus-20240229"

            provider = AnthropicProvider({**config, "model": "claude-3-haiku"})
            assert provider.model == "claude-3-haiku-20240307"

            # Test full names pass through
            provider = AnthropicProvider({**config, "model": "claude-3-opus-20240229"})
            assert provider.model == "claude-3-opus-20240229"

            # Test unknown model stays as-is
            provider = AnthropicProvider({**config, "model": "unknown-model"})
            assert provider.model == "unknown-model"

    @pytest.mark.asyncio
    async def test_classify_success(self, provider, sample_messages):
        """Test successful classification."""
        # Mock API response
        mock_response = MagicMock()
        mock_response.content = [
            MagicMock(
                text=json.dumps(
                    {
                        "category": "direct_injection",
                        "confidence": 0.85,
                        "explanation": "Detected injection attempt",
                    }
                )
            )
        ]

        provider.client.messages.create = AsyncMock(return_value=mock_response)

        category, confidence, explanation = await provider.classify(sample_messages)

        assert category == DetectionCategory.DIRECT_INJECTION
        assert confidence == 0.85
        assert explanation == "Detected injection attempt"

        # Verify API call
        provider.client.messages.create.assert_called_once()
        call_args = provider.client.messages.create.call_args
        assert call_args[1]["model"] == "claude-3-sonnet-20240229"
        assert call_args[1]["max_tokens"] == 1000
        assert call_args[1]["temperature"] == 0.3

    @pytest.mark.asyncio
    async def test_classify_with_custom_system_prompt(self, provider, sample_messages):
        """Test classification with custom system prompt."""
        mock_response = MagicMock()
        mock_response.content = [
            MagicMock(text='{"category": "benign", "confidence": 0.9, "explanation": "Safe"}')
        ]

        provider.client.messages.create = AsyncMock(return_value=mock_response)

        custom_prompt = "Custom security analysis prompt"
        await provider.classify(sample_messages, system_prompt=custom_prompt)

        # Verify custom prompt was used
        call_args = provider.client.messages.create.call_args
        assert call_args[1]["system"] == custom_prompt

    @pytest.mark.asyncio
    async def test_classify_timeout(self, provider, sample_messages):
        """Test classification timeout handling."""
        provider.client.messages.create = AsyncMock(side_effect=TimeoutError())

        category, confidence, explanation = await provider.classify(sample_messages)

        assert category == DetectionCategory.BENIGN
        assert confidence == 0.0
        assert explanation == "Classification timeout"

    @pytest.mark.asyncio
    async def test_classify_api_error(self, provider, sample_messages):
        """Test classification API error handling."""
        provider.client.messages.create = AsyncMock(side_effect=Exception("API Error"))

        category, confidence, explanation = await provider.classify(sample_messages)

        assert category == DetectionCategory.BENIGN
        assert confidence == 0.0
        assert "Classification error" in explanation

    @pytest.mark.asyncio
    async def test_health_check_success(self, provider):
        """Test successful health check."""
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="test")]

        provider.client.messages.create = AsyncMock(return_value=mock_response)

        result = await provider.health_check()

        assert result is True
        provider.client.messages.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_failure(self, provider):
        """Test health check failure."""
        provider.client.messages.create = AsyncMock(side_effect=Exception("Connection failed"))

        result = await provider.health_check()

        assert result is False

    def test_parse_response_valid_json(self, provider):
        """Test parsing valid JSON response."""
        content = (
            '{"category": "jailbreak", "confidence": 0.75, "explanation": "Jailbreak detected"}'
        )

        category, confidence, explanation = provider._parse_response(content)

        assert category == DetectionCategory.JAILBREAK
        assert confidence == 0.75
        assert explanation == "Jailbreak detected"

    def test_parse_response_json_with_text(self, provider):
        """Test parsing JSON embedded in text."""
        content = 'Here is my analysis: {"category": "encoding_attack", "confidence": 0.6, "explanation": "Base64 encoding detected"} That was my response.'

        category, confidence, explanation = provider._parse_response(content)

        assert category == DetectionCategory.ENCODING_ATTACK
        assert confidence == 0.6
        assert explanation == "Base64 encoding detected"

    def test_parse_response_invalid_json(self, provider):
        """Test parsing invalid JSON response."""
        content = "This is not JSON"

        category, confidence, explanation = provider._parse_response(content)

        assert category == DetectionCategory.BENIGN
        assert confidence == 0.0
        assert "Could not parse response" in explanation

    def test_parse_response_missing_fields(self, provider):
        """Test parsing JSON with missing fields."""
        content = '{"category": "prompt_leak"}'  # Missing confidence and explanation

        category, confidence, explanation = provider._parse_response(content)

        assert category == DetectionCategory.PROMPT_LEAK
        assert confidence == 0.0  # Default value
        assert explanation == ""  # Default value

    def test_parse_response_unknown_category(self, provider):
        """Test parsing response with unknown category."""
        content = '{"category": "unknown_attack", "confidence": 0.8, "explanation": "Unknown"}'

        category, confidence, explanation = provider._parse_response(content)

        assert category == DetectionCategory.BENIGN  # Default for unknown
        assert confidence == 0.8
        assert explanation == "Unknown"

    def test_get_system_prompt(self, provider):
        """Test Anthropic-specific system prompt."""
        prompt = provider.get_system_prompt()

        assert "Claude" in prompt
        assert "security expert" in prompt
        assert "JSON" in prompt
        assert "direct_injection" in prompt


class TestOpenAIProvider:
    """Test suite for OpenAIProvider."""

    @pytest.fixture
    def mock_config(self):
        """Create mock configuration."""
        return {
            "api_key": "test_openai_key",
            "model": "gpt-4",
            "max_tokens": 800,
            "temperature": 0.2,
        }

    @pytest.fixture
    def provider(self, mock_config):
        """Create OpenAIProvider instance."""
        with patch("prompt_sentinel.providers.openai_provider.AsyncOpenAI"):
            return OpenAIProvider(mock_config)

    @pytest.fixture
    def sample_messages(self):
        """Create sample messages."""
        return [
            Message(role=Role.SYSTEM, content="You are helpful"),
            Message(role=Role.USER, content="Hello"),
        ]

    def test_initialization(self, mock_config):
        """Test OpenAIProvider initialization."""
        with patch("prompt_sentinel.providers.openai_provider.AsyncOpenAI") as mock_client:
            provider = OpenAIProvider(mock_config)

            assert provider.api_key == "test_openai_key"
            assert provider.model == "gpt-4-turbo-preview"  # Mapped from gpt-4
            mock_client.assert_called_once_with(api_key="test_openai_key")

    @pytest.mark.asyncio
    async def test_classify_success(self, provider, sample_messages):
        """Test successful classification with OpenAI."""
        # Mock chat completion response
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps(
            {
                "category": "role_manipulation",
                "confidence": 0.7,
                "explanation": "Role confusion detected",
            }
        )

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        provider.client.chat.completions.create = AsyncMock(return_value=mock_response)

        category, confidence, explanation = await provider.classify(sample_messages)

        assert category == DetectionCategory.ROLE_MANIPULATION
        assert confidence == 0.7
        assert explanation == "Role confusion detected"

    @pytest.mark.asyncio
    async def test_classify_with_json_response(self, provider, sample_messages):
        """Test classification using OpenAI JSON mode response."""
        # Mock JSON response (not function calling since provider uses JSON mode)
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps(
            {
                "category": "context_switching",
                "confidence": 0.65,
                "explanation": "Context switch attempt",
            }
        )

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        provider.client.chat.completions.create = AsyncMock(return_value=mock_response)

        category, confidence, explanation = await provider.classify(sample_messages)

        assert category == DetectionCategory.CONTEXT_SWITCHING
        assert confidence == 0.65

    @pytest.mark.asyncio
    async def test_classify_api_error(self, provider, sample_messages):
        """Test OpenAI API error handling."""
        provider.client.chat.completions.create = AsyncMock(
            side_effect=Exception("OpenAI API Error")
        )

        category, confidence, explanation = await provider.classify(sample_messages)

        assert category == DetectionCategory.BENIGN
        assert confidence == 0.0
        assert "Classification error" in explanation

    @pytest.mark.asyncio
    async def test_health_check(self, provider):
        """Test OpenAI health check."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]

        provider.client.chat.completions.create = AsyncMock(return_value=mock_response)

        result = await provider.health_check()

        assert result is True


class TestGeminiProvider:
    """Test suite for GeminiProvider."""

    @pytest.fixture
    def mock_config(self):
        """Create mock configuration."""
        return {
            "api_key": "test_gemini_key",
            "model": "gemini-pro",
            "max_tokens": 1000,
        }

    @pytest.fixture
    def provider(self, mock_config):
        """Create GeminiProvider instance."""
        with patch("prompt_sentinel.providers.gemini_provider.genai"):
            return GeminiProvider(mock_config)

    @pytest.fixture
    def sample_messages(self):
        """Create sample messages."""
        return [
            Message(role=Role.USER, content="Test prompt"),
        ]

    def test_initialization(self, mock_config):
        """Test GeminiProvider initialization."""
        with patch("prompt_sentinel.providers.gemini_provider.genai") as mock_genai:
            provider = GeminiProvider(mock_config)

            assert provider.api_key == "test_gemini_key"
            assert provider.model == "gemini-pro"
            mock_genai.configure.assert_called_once_with(api_key="test_gemini_key")

    @pytest.mark.asyncio
    async def test_classify_success(self, provider, sample_messages):
        """Test successful classification with Gemini."""
        # Mock model response
        mock_response = MagicMock()
        mock_response.text = json.dumps(
            {
                "category": "indirect_injection",
                "confidence": 0.55,
                "explanation": "Subtle manipulation detected",
            }
        )

        mock_model = MagicMock()
        mock_model.generate_content = MagicMock(return_value=mock_response)
        provider.model_instance = mock_model

        category, confidence, explanation = await provider.classify(sample_messages)

        assert category == DetectionCategory.INDIRECT_INJECTION
        assert confidence == 0.55
        assert explanation == "Subtle manipulation detected"

    @pytest.mark.asyncio
    async def test_classify_safety_block(self, provider, sample_messages):
        """Test handling of Gemini safety blocks."""
        # Mock blocked response
        mock_response = MagicMock()
        mock_response.text = None  # Blocked content has no text

        mock_model = MagicMock()
        mock_model.generate_content = MagicMock(return_value=mock_response)
        provider.model_instance = mock_model

        category, confidence, explanation = await provider.classify(sample_messages)

        # When response.text is None, it should return BENIGN with classification error
        assert category == DetectionCategory.BENIGN
        assert confidence == 0.0
        assert "error" in explanation.lower()

    @pytest.mark.asyncio
    async def test_classify_api_error(self, provider, sample_messages):
        """Test Gemini API error handling."""
        mock_model = MagicMock()
        mock_model.generate_content_async = AsyncMock(side_effect=Exception("Gemini API Error"))
        provider.model = mock_model

        category, confidence, explanation = await provider.classify(sample_messages)

        assert category == DetectionCategory.BENIGN
        assert confidence == 0.0
        assert "error" in explanation.lower()

    @pytest.mark.asyncio
    async def test_health_check_success(self, provider):
        """Test Gemini health check success."""
        mock_response = MagicMock()
        mock_response.text = "test"

        mock_model = MagicMock()
        mock_model.generate_content_async = AsyncMock(return_value=mock_response)
        provider.model = mock_model

        result = await provider.health_check()

        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self, provider):
        """Test Gemini health check failure."""
        mock_model = MagicMock()
        mock_model.generate_content = MagicMock(side_effect=Exception("Connection failed"))
        provider.model_instance = mock_model

        result = await provider.health_check()

        assert result is False

    def test_format_messages_for_gemini(self, provider):
        """Test message formatting for Gemini API."""
        messages = [
            Message(role=Role.SYSTEM, content="System prompt"),
            Message(role=Role.USER, content="User message"),
            Message(role=Role.ASSISTANT, content="Assistant response"),
        ]

        formatted = provider.get_classification_prompt(messages)

        # Should contain the message content in some form
        assert "System prompt" in formatted
        assert "User message" in formatted
        assert "Assistant response" in formatted


class TestProviderIntegration:
    """Integration tests for provider interactions."""

    @pytest.mark.asyncio
    async def test_provider_failover_simulation(self):
        """Test failover between providers."""
        # Create mock providers
        anthropic_config = {"api_key": "test1", "model": "claude-3-sonnet"}
        openai_config = {"api_key": "test2", "model": "gpt-4"}
        gemini_config = {"api_key": "test3", "model": "gemini-pro"}

        with patch("prompt_sentinel.providers.anthropic_provider.AsyncAnthropic"):
            with patch("prompt_sentinel.providers.openai_provider.AsyncOpenAI"):
                with patch("prompt_sentinel.providers.gemini_provider.genai"):
                    providers = [
                        AnthropicProvider(anthropic_config),
                        OpenAIProvider(openai_config),
                        GeminiProvider(gemini_config),
                    ]

                    # Simulate first provider failing
                    providers[0].classify = AsyncMock(side_effect=Exception("Provider 1 failed"))

                    # Second provider succeeds
                    providers[1].classify = AsyncMock(
                        return_value=(DetectionCategory.JAILBREAK, 0.8, "Detected by backup")
                    )

                    # Test failover logic
                    messages = [Message(role=Role.USER, content="Test")]

                    for provider in providers:
                        try:
                            result = await provider.classify(messages)
                            if result[0] != DetectionCategory.BENIGN or result[1] > 0:
                                break
                        except Exception:
                            continue

                    assert result[0] == DetectionCategory.JAILBREAK
                    assert result[1] == 0.8

    @pytest.mark.asyncio
    async def test_all_providers_timeout_handling(self):
        """Test timeout handling across all providers."""
        configs = [
            {"api_key": "test1", "timeout": 0.001},  # Very short timeout
            {"api_key": "test2", "timeout": 0.001},
            {"api_key": "test3", "timeout": 0.001},
        ]

        messages = [Message(role=Role.USER, content="Test")]

        # Test each provider type with timeout
        with patch("prompt_sentinel.providers.anthropic_provider.AsyncAnthropic"):
            provider = AnthropicProvider(configs[0])
            provider.client.messages.create = AsyncMock(side_effect=TimeoutError())
            result = await provider.classify(messages)
            assert result[0] == DetectionCategory.BENIGN
            assert result[1] == 0.0

    def test_provider_configuration_validation(self):
        """Test configuration validation for all providers."""
        # Test missing API key
        for provider_class in [AnthropicProvider, OpenAIProvider, GeminiProvider]:
            with pytest.raises(ValueError, match="API key required"):
                with patch("prompt_sentinel.providers.anthropic_provider.AsyncAnthropic"):
                    with patch("prompt_sentinel.providers.openai_provider.AsyncOpenAI"):
                        with patch("prompt_sentinel.providers.gemini_provider.genai"):
                            provider_class({"model": "test"})

    @pytest.mark.asyncio
    async def test_concurrent_provider_calls(self):
        """Test concurrent calls to multiple providers."""
        messages = [Message(role=Role.USER, content="Test")]

        with patch("prompt_sentinel.providers.anthropic_provider.AsyncAnthropic"):
            with patch("prompt_sentinel.providers.openai_provider.AsyncOpenAI"):
                with patch("prompt_sentinel.providers.gemini_provider.genai"):
                    providers = [
                        AnthropicProvider({"api_key": "test1"}),
                        OpenAIProvider({"api_key": "test2"}),
                        GeminiProvider({"api_key": "test3"}),
                    ]

                    # Mock successful responses
                    for i, provider in enumerate(providers):
                        provider.classify = AsyncMock(
                            return_value=(DetectionCategory.BENIGN, 0.9 + i * 0.01, f"Provider {i}")
                        )

                    # Run concurrent classifications
                    tasks = [provider.classify(messages) for provider in providers]
                    results = await asyncio.gather(*tasks)

                    assert len(results) == 3
                    assert all(r[0] == DetectionCategory.BENIGN for r in results)
                    assert results[0][1] == 0.9
                    assert results[1][1] == 0.91
                    assert results[2][1] == 0.92
