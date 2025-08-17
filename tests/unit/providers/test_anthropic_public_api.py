# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prompt_sentinel.models.schemas import DetectionCategory, Message, Role
from prompt_sentinel.providers.anthropic_provider import AnthropicProvider


@pytest.mark.asyncio
@pytest.mark.unit
async def test_anthropic_classify_public_api_parses_json():
    config = {"api_key": "test", "model": "claude-3-haiku"}

    # Mock Anthropic client response with valid JSON text block
    mock_content = MagicMock()
    mock_content.text = json.dumps(
        {
            "category": "encoding_attack",
            "confidence": 0.61,
            "explanation": "Base64 detected",
        }
    )
    mock_response = MagicMock()
    mock_response.content = [mock_content]

    with patch("prompt_sentinel.providers.anthropic_provider.AsyncAnthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        provider = AnthropicProvider(config)
        messages = [Message(role=Role.USER, content="Test message")]

        category, confidence, explanation = await provider.classify(messages)

        assert category == DetectionCategory.ENCODING_ATTACK
        assert confidence == 0.61
        assert "base64" in explanation.lower()
