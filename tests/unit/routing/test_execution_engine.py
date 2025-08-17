# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

from unittest.mock import AsyncMock, MagicMock

import pytest

from prompt_sentinel.models.schemas import DetectionResponse, Message, Role, Verdict
from prompt_sentinel.routing.execution import ExecutionEngine
from prompt_sentinel.routing.types import DetectionStrategy


@pytest.mark.asyncio
async def test_execute_strategy_cache_hit():
    detector = MagicMock()
    engine = ExecutionEngine(detector)

    cached = {
        "verdict": "allow",
        "confidence": 0.8,
        "reasons": [],
        "processing_time_ms": 10.0,
    }
    cache_get = AsyncMock(return_value=cached)
    cache_set = AsyncMock()

    res = await engine.execute_strategy(
        [Message(role=Role.USER, content="hi")],
        DetectionStrategy.HEURISTIC_CACHED,
        use_cache=True,
        cache_key="k",
        cache_get=cache_get,
        cache_set=cache_set,
    )

    assert isinstance(res, DetectionResponse)
    detector.detect.assert_not_called()
    cache_set.assert_not_called()


@pytest.mark.asyncio
async def test_execute_strategy_cache_miss_executes():
    detector = MagicMock()
    detector.detect = AsyncMock(
        return_value=DetectionResponse(
            verdict=Verdict.ALLOW, confidence=0.9, reasons=[], processing_time_ms=5.0
        )
    )
    engine = ExecutionEngine(detector)

    cache_get = AsyncMock(return_value=None)
    cache_set = AsyncMock()

    res = await engine.execute_strategy(
        [Message(role=Role.USER, content="hi")],
        DetectionStrategy.HEURISTIC_ONLY,
        use_cache=True,
        cache_key="k",
        cache_get=cache_get,
        cache_set=cache_set,
    )

    assert res.verdict == Verdict.ALLOW
    detector.detect.assert_awaited()
    cache_set.assert_awaited()
