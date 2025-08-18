# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

import pytest

from prompt_sentinel.providers.anthropic_provider import AnthropicProvider
from prompt_sentinel.providers.openai_provider import OpenAIProvider


@pytest.mark.asyncio
async def test_openai_classify_bad_json_returns_benign():
    provider = OpenAIProvider({"api_key": "k", "model": "gpt-3.5"})
    # Monkeypatch internal parsing path via compatibility method
    payload = "garbage not json"
    cat, conf, expl = provider._parse_response(payload)  # type: ignore[attr-defined]
    assert conf == 0.0
    assert "could not parse response" in expl.lower()


@pytest.mark.asyncio
async def test_anthropic_classify_embedded_bad_json_returns_benign():
    provider = AnthropicProvider({"api_key": "k", "model": "claude-3"})
    payload = 'leading text {"category": 123, "confidence": "NaN"} trailing'
    cat, conf, expl = provider._parse_response(payload)  # type: ignore[attr-defined]
    assert conf == 0.0
    assert "invalid confidence" in expl.lower() or "could not parse response" in expl.lower()
