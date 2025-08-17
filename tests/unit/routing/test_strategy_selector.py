# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0


from prompt_sentinel.routing.complexity_analyzer import (
    ComplexityLevel,
    ComplexityScore,
    RiskIndicator,
)
from prompt_sentinel.routing.strategy import StrategySelector
from prompt_sentinel.routing.types import DetectionStrategy


def make_score(level: ComplexityLevel, risks: list[RiskIndicator] | None = None) -> ComplexityScore:
    return ComplexityScore(
        level=level,
        score=0.5,
        risk_indicators=risks or [],
        metrics={},
        reasoning="",
        recommended_strategy="",
    )


def test_determine_strategy_standard_mapping():
    s = StrategySelector()
    cases = [
        (ComplexityLevel.TRIVIAL, DetectionStrategy.HEURISTIC_CACHED),
        (ComplexityLevel.SIMPLE, DetectionStrategy.HEURISTIC_CACHED),
        (ComplexityLevel.MODERATE, DetectionStrategy.HEURISTIC_LLM_CACHED),
        (ComplexityLevel.COMPLEX, DetectionStrategy.HEURISTIC_LLM_PII),
        (ComplexityLevel.CRITICAL, DetectionStrategy.FULL_ANALYSIS),
    ]
    for level, expected in cases:
        strategy, _ = s.determine_strategy(
            make_score(level), performance_mode=False, llm_enabled=True, pii_enabled=True
        )
        assert strategy == expected


def test_determine_strategy_performance_mode():
    s = StrategySelector()
    cases = [
        (ComplexityLevel.TRIVIAL, DetectionStrategy.HEURISTIC_ONLY),
        (ComplexityLevel.SIMPLE, DetectionStrategy.HEURISTIC_CACHED),
        (ComplexityLevel.MODERATE, DetectionStrategy.HEURISTIC_LLM_CACHED),
        (ComplexityLevel.COMPLEX, DetectionStrategy.HEURISTIC_LLM_PII),
        (ComplexityLevel.CRITICAL, DetectionStrategy.HEURISTIC_LLM_PII),
    ]
    for level, expected in cases:
        strategy, _ = s.determine_strategy(
            make_score(level), performance_mode=True, llm_enabled=True, pii_enabled=True
        )
        assert strategy == expected


def test_determine_strategy_critical_risks_elevates():
    s = StrategySelector()
    for risk in [
        RiskIndicator.INSTRUCTION_OVERRIDE,
        RiskIndicator.CODE_INJECTION,
        RiskIndicator.ROLE_MANIPULATION,
    ]:
        strategy, reason = s.determine_strategy(
            make_score(ComplexityLevel.SIMPLE, [risk]),
            performance_mode=False,
            llm_enabled=True,
            pii_enabled=True,
        )
        assert strategy == DetectionStrategy.HEURISTIC_LLM_PII
        assert "critical" in reason.lower()


def test_determine_strategy_feature_flags():
    s = StrategySelector()
    # LLM disabled should force heuristic only when LLM strategies selected
    strategy, _ = s.determine_strategy(
        make_score(ComplexityLevel.MODERATE),
        performance_mode=False,
        llm_enabled=False,
        pii_enabled=True,
    )
    assert strategy == DetectionStrategy.HEURISTIC_ONLY

    # PII disabled should downgrade from LLM+PII to cached
    strategy, _ = s.determine_strategy(
        make_score(ComplexityLevel.COMPLEX),
        performance_mode=False,
        llm_enabled=True,
        pii_enabled=False,
    )
    assert strategy == DetectionStrategy.HEURISTIC_LLM_CACHED


def test_is_cache_eligible_rules():
    s = StrategySelector()
    score = make_score(ComplexityLevel.MODERATE)
    assert s.is_cache_eligible(DetectionStrategy.HEURISTIC_CACHED, score, True, True) is True
    assert s.is_cache_eligible(DetectionStrategy.HEURISTIC_ONLY, score, True, True) is False
    assert s.is_cache_eligible(DetectionStrategy.HEURISTIC_LLM_PII, score, False, True) is False
    assert s.is_cache_eligible(DetectionStrategy.HEURISTIC_LLM_PII, score, True, False) is False

    # Encoding risk disables cache
    score.risk_indicators = [RiskIndicator.ENCODING]
    assert s.is_cache_eligible(DetectionStrategy.HEURISTIC_CACHED, score, True, True) is False
