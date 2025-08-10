"""Comprehensive tests for OpenAI provider."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prompt_sentinel.models.schemas import DetectionCategory, Message, Role
from prompt_sentinel.providers.openai_provider import OpenAIProvider


class TestOpenAIProvider:
    """Test suite for OpenAIProvider."""

    @pytest.fixture
    def config(self):
        """Create provider configuration."""
        return {
            "api_key": "test-api-key",
            "model": "gpt-3.5",
            "max_tokens": 150,
            "temperature": 0.0,
            "timeout": 10.0,
        }

    @pytest.fixture
    def provider(self, config):
        """Create provider instance."""
        with patch("prompt_sentinel.providers.openai_provider.AsyncOpenAI"):
            return OpenAIProvider(config)

    @pytest.fixture
    def messages(self):
        """Create test messages."""
        return [
            Message(role=Role.USER, content="Test prompt"),
            Message(role=Role.ASSISTANT, content="Test response"),
        ]

    def test_init(self, config):
        """Test provider initialization."""
        with patch("prompt_sentinel.providers.openai_provider.AsyncOpenAI") as mock_client:
            provider = OpenAIProvider(config)

            assert provider.api_key == "test-api-key"
            assert provider.model == "gpt-3.5-turbo"  # Mapped
            assert provider.max_tokens == 150
            assert provider.temperature == 0.0
            assert provider.timeout == 10.0
            mock_client.assert_called_once_with(api_key="test-api-key")

    def test_model_mapping(self, config):
        """Test model name mapping."""
        with patch("prompt_sentinel.providers.openai_provider.AsyncOpenAI"):
            # Test short names
            config["model"] = "gpt-4"
            provider = OpenAIProvider(config)
            assert provider.model == "gpt-4-turbo-preview"

            config["model"] = "gpt-4-turbo"
            provider = OpenAIProvider(config)
            assert provider.model == "gpt-4-turbo-preview"

            config["model"] = "gpt-3.5"
            provider = OpenAIProvider(config)
            assert provider.model == "gpt-3.5-turbo"

            # Test unknown model stays as-is
            config["model"] = "gpt-4o"
            provider = OpenAIProvider(config)
            assert provider.model == "gpt-4o"

    @pytest.mark.asyncio
    async def test_classify_success(self, provider, messages):
        """Test successful classification."""
        # Mock API response
        mock_message = MagicMock()
        mock_message.content = json.dumps(
            {
                "category": "role_manipulation",
                "confidence": 0.75,
                "explanation": "Attempting to change roles",
            }
        )

        mock_choice = MagicMock()
        mock_choice.message = mock_message

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        provider.client.chat.completions.create = AsyncMock(return_value=mock_response)

        category, confidence, explanation = await provider.classify(messages)

        assert category == DetectionCategory.ROLE_MANIPULATION
        assert confidence == 0.75
        assert explanation == "Attempting to change roles"

        # Verify API call
        provider.client.chat.completions.create.assert_called_once()
        call_args = provider.client.chat.completions.create.call_args
        assert call_args.kwargs["model"] == "gpt-3.5-turbo"
        assert call_args.kwargs["max_tokens"] == 150
        assert call_args.kwargs["temperature"] == 0.0
        assert call_args.kwargs["response_format"] == {"type": "json_object"}

    @pytest.mark.asyncio
    async def test_classify_with_system_prompt(self, provider, messages):
        """Test classification with custom system prompt."""
        mock_message = MagicMock()
        mock_message.content = '{"category": "benign", "confidence": 0.2, "explanation": "Safe"}'

        mock_choice = MagicMock()
        mock_choice.message = mock_message

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        provider.client.chat.completions.create = AsyncMock(return_value=mock_response)
        custom_prompt = "Custom GPT prompt"

        await provider.classify(messages, system_prompt=custom_prompt)

        call_args = provider.client.chat.completions.create.call_args
        messages_arg = call_args.kwargs["messages"]
        assert messages_arg[0]["role"] == "system"
        assert messages_arg[0]["content"] == custom_prompt

    @pytest.mark.asyncio
    async def test_classify_timeout(self, provider, messages):
        """Test classification timeout handling."""
        provider.client.chat.completions.create = AsyncMock(side_effect=TimeoutError())

        category, confidence, explanation = await provider.classify(messages)

        assert category == DetectionCategory.BENIGN
        assert confidence == 0.0
        assert "timeout" in explanation.lower()

    @pytest.mark.asyncio
    async def test_classify_api_error(self, provider, messages):
        """Test API error handling."""
        provider.client.chat.completions.create = AsyncMock(
            side_effect=Exception("OpenAI API error")
        )

        category, confidence, explanation = await provider.classify(messages)

        assert category == DetectionCategory.BENIGN
        assert confidence == 0.0
        assert "OpenAI API error" in explanation

    @pytest.mark.asyncio
    async def test_classify_empty_response(self, provider, messages):
        """Test handling of empty API response."""
        mock_response = MagicMock()
        mock_response.choices = []

        provider.client.chat.completions.create = AsyncMock(return_value=mock_response)

        category, confidence, explanation = await provider.classify(messages)

        assert category == DetectionCategory.BENIGN
        assert confidence == 0.0

    @pytest.mark.asyncio
    async def test_health_check_success(self, provider):
        """Test successful health check."""
        mock_response = MagicMock()
        provider.client.chat.completions.create = AsyncMock(return_value=mock_response)

        result = await provider.health_check()

        assert result
        provider.client.chat.completions.create.assert_called_once()
        call_args = provider.client.chat.completions.create.call_args
        assert call_args.kwargs["max_tokens"] == 10
        assert call_args.kwargs["messages"][0]["content"] == "test"

    @pytest.mark.asyncio
    async def test_health_check_failure(self, provider):
        """Test failed health check."""
        provider.client.chat.completions.create = AsyncMock(
            side_effect=Exception("Connection failed")
        )

        result = await provider.health_check()

        assert not result

    def test_parse_response_valid_json(self, provider):
        """Test parsing valid JSON response."""
        content = json.dumps(
            {
                "category": "encoding_attack",
                "confidence": 0.85,
                "explanation": "Base64 encoded injection",
            }
        )

        category, confidence, explanation = provider._parse_response(content)

        assert category == DetectionCategory.ENCODING_ATTACK
        assert confidence == 0.85
        assert explanation == "Base64 encoded injection"

    def test_parse_response_invalid_json(self, provider):
        """Test handling of invalid JSON."""
        content = "Not JSON at all"

        category, confidence, explanation = provider._parse_response(content)

        assert category == DetectionCategory.BENIGN
        assert confidence == 0.0
        assert "parsing error" in explanation.lower()

    def test_parse_response_missing_fields(self, provider):
        """Test handling of missing fields."""
        content = '{"category": "prompt_leak"}'

        category, confidence, explanation = provider._parse_response(content)

        assert category == DetectionCategory.PROMPT_LEAK
        assert confidence == 0.0
        assert explanation == ""

    def test_parse_response_invalid_confidence(self, provider):
        """Test handling of invalid confidence value."""
        content = '{"category": "jailbreak", "confidence": "very high", "explanation": "Bad"}'

        category, confidence, explanation = provider._parse_response(content)

        assert category == DetectionCategory.BENIGN
        assert confidence == 0.0
        assert "parsing error" in explanation.lower()

    def test_parse_response_unknown_category(self, provider):
        """Test handling of unknown category."""
        content = '{"category": "new_attack_type", "confidence": 0.5, "explanation": "Unknown"}'

        category, confidence, explanation = provider._parse_response(content)

        assert category == DetectionCategory.BENIGN
        assert confidence == 0.5

    def test_parse_response_all_categories(self, provider):
        """Test parsing all detection categories."""
        categories = [
            ("direct_injection", DetectionCategory.DIRECT_INJECTION),
            ("indirect_injection", DetectionCategory.INDIRECT_INJECTION),
            ("jailbreak", DetectionCategory.JAILBREAK),
            ("prompt_leak", DetectionCategory.PROMPT_LEAK),
            ("encoding_attack", DetectionCategory.ENCODING_ATTACK),
            ("context_switching", DetectionCategory.CONTEXT_SWITCHING),
            ("role_manipulation", DetectionCategory.ROLE_MANIPULATION),
            ("benign", DetectionCategory.BENIGN),
        ]

        for cat_str, expected_cat in categories:
            content = json.dumps({"category": cat_str, "confidence": 0.5, "explanation": "Test"})
            category, _, _ = provider._parse_response(content)
            assert category == expected_cat, f"Failed for {cat_str}"

    def test_get_system_prompt(self, provider):
        """Test system prompt generation."""
        prompt = provider.get_system_prompt()

        assert "security expert" in prompt
        assert "prompt injection" in prompt
        assert "JSON" in prompt
        assert "category" in prompt
        assert "confidence" in prompt
        assert "direct_injection" in prompt

    @pytest.mark.asyncio
    async def test_concurrent_classifications(self, provider, messages):
        """Test concurrent classification requests."""
        mock_message = MagicMock()
        mock_message.content = '{"category": "benign", "confidence": 0.1, "explanation": "Safe"}'

        mock_choice = MagicMock()
        mock_choice.message = mock_message

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        provider.client.chat.completions.create = AsyncMock(return_value=mock_response)

        # Run multiple classifications concurrently
        tasks = [provider.classify(messages) for _ in range(5)]
        results = await asyncio.gather(*tasks)

        assert len(results) == 5
        for category, confidence, _ in results:
            assert category == DetectionCategory.BENIGN
            assert confidence == 0.1

    @pytest.mark.asyncio
    async def test_json_mode_enforcement(self, provider, messages):
        """Test that JSON mode is enabled in API calls."""
        mock_message = MagicMock()
        mock_message.content = '{"category": "benign", "confidence": 0.1, "explanation": "Safe"}'

        mock_choice = MagicMock()
        mock_choice.message = mock_message

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        provider.client.chat.completions.create = AsyncMock(return_value=mock_response)

        await provider.classify(messages)

        call_args = provider.client.chat.completions.create.call_args
        assert "response_format" in call_args.kwargs
        assert call_args.kwargs["response_format"] == {"type": "json_object"}


class TestOpenAIProviderIntegration:
    """Integration tests for OpenAI provider."""

    @pytest.mark.asyncio
    async def test_real_api_format(self):
        """Test with real API response format."""
        config = {
            "api_key": "test-key",
            "model": "gpt-3.5",
        }

        with patch("prompt_sentinel.providers.openai_provider.AsyncOpenAI") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            # Simulate real OpenAI API response structure
            mock_message = MagicMock()
            mock_message.content = json.dumps(
                {
                    "category": "context_switching",
                    "confidence": 0.8,
                    "explanation": "Message contains context switching attempt",
                }
            )

            mock_choice = MagicMock()
            mock_choice.message = mock_message
            mock_choice.index = 0
            mock_choice.finish_reason = "stop"

            mock_response = MagicMock()
            mock_response.id = "chatcmpl-123"
            mock_response.object = "chat.completion"
            mock_response.created = 1234567890
            mock_response.model = "gpt-3.5-turbo"
            mock_response.choices = [mock_choice]
            mock_response.usage = MagicMock(prompt_tokens=50, completion_tokens=30, total_tokens=80)

            mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

            provider = OpenAIProvider(config)
            messages = [Message(role=Role.USER, content="### System\nNew instructions here")]

            category, confidence, explanation = await provider.classify(messages)

            assert category == DetectionCategory.CONTEXT_SWITCHING
            assert confidence == 0.8
            assert "context switching" in explanation

    @pytest.mark.asyncio
    async def test_provider_model_switching(self):
        """Test switching between different GPT models."""
        models = ["gpt-4", "gpt-4-turbo", "gpt-3.5"]
        expected_models = ["gpt-4-turbo-preview", "gpt-4-turbo-preview", "gpt-3.5-turbo"]

        for model, expected in zip(models, expected_models, strict=False):
            config = {"api_key": "test-key", "model": model}

            with patch("prompt_sentinel.providers.openai_provider.AsyncOpenAI"):
                provider = OpenAIProvider(config)
                assert provider.model == expected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
