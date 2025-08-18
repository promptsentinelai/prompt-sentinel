# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

import re

from prompt_sentinel.monitoring.metrics import (
    ACTIVE_REQUESTS,
    get_metrics,
    initialize_metrics,
    track_cache_metrics,
    track_detection_metrics,
    track_llm_metrics,
)


def test_initialize_and_export_metrics():
    initialize_metrics("1.2.3")
    output = get_metrics().decode("utf-8")
    assert "prompt_sentinel_service_info" in output or 'version="1.2.3"' in output


def test_track_detection_metrics_increments():
    # Record baseline
    before = ACTIVE_REQUESTS._value.get()

    track_detection_metrics("injection", "high", "heuristic", 0.92)
    data = get_metrics().decode("utf-8")
    assert "prompt_sentinel_detections_total" in data
    # Histogram exports bucket lines with suffix _bucket
    assert re.search(
        r"prompt_sentinel_detection_confidence_bucket\{[^}]*attack_type=\"injection\"[^}]*\}",
        data,
    )

    # ACTIVE_REQUESTS is a gauge; ensure it is present
    assert ACTIVE_REQUESTS._value.get() == before


def test_track_llm_and_cache_metrics():
    track_llm_metrics("openai", "gpt-4", 0.12, 10, 5, 0.01, True)
    track_cache_metrics("detection", hit=True, size_bytes=1024)
    text = get_metrics().decode("utf-8")
    assert "prompt_sentinel_llm_requests_total" in text
    assert "prompt_sentinel_cache_hits_total" in text
    assert "prompt_sentinel_cache_size_bytes" in text
