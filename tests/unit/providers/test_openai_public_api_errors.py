# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prompt_sentinel.models.schemas import DetectionCategory, Message, Role
from prompt_sentinel.providers.openai_provider import OpenAIProvider


@pytest.mark.asyncio
async def test_openai_classify_malformed_json_benign_fallback():
    config = {"api_key": "test", "model": "gpt-3.5"}

    # Mock OpenAI response with malformed JSON content
    mock_message = MagicMock()
    mock_message.content = "nonsense not json"
    mock_choice = MagicMock()
    mock_choice.message = mock_message
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]

    with patch("prompt_sentinel.providers.openai_provider.AsyncOpenAI") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        provider = OpenAIProvider(config)
        messages = [Message(role=Role.USER, content="Hi")]

        category, confidence, explanation = await provider.classify(messages)

        assert category == DetectionCategory.BENIGN
        assert confidence == 0.0
        assert "parse" in explanation.lower()
