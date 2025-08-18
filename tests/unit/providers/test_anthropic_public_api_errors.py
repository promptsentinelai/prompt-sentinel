# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prompt_sentinel.models.schemas import DetectionCategory, Message, Role
from prompt_sentinel.providers.anthropic_provider import AnthropicProvider


@pytest.mark.asyncio
async def test_anthropic_classify_malformed_embedded_json_benign():
    config = {"api_key": "test", "model": "claude-3-haiku"}

    # Response content contains embedded JSON with invalid confidence
    mock_content = MagicMock()
    mock_content.text = 'prefix {"category": "prompt_leak", "confidence": "NaN"} suffix'
    mock_response = MagicMock()
    mock_response.content = [mock_content]

    with patch("prompt_sentinel.providers.anthropic_provider.AsyncAnthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        provider = AnthropicProvider(config)
        messages = [Message(role=Role.USER, content="Hi")]

        category, confidence, explanation = await provider.classify(messages)

        assert category == DetectionCategory.BENIGN
        assert confidence == 0.0
        assert "invalid confidence" in explanation.lower() or "parse" in explanation.lower()
