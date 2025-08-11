# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Tests for intelligent routing system."""

from prompt_sentinel.models.schemas import Message, Role
from prompt_sentinel.routing.complexity_analyzer import (
    ComplexityAnalyzer,
    ComplexityLevel,
)


class TestComplexityAnalyzer:
    """Test complexity analysis functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = ComplexityAnalyzer()

    def test_trivial_complexity(self):
        """Test detection of trivial complexity prompts."""
        messages = [Message(role=Role.USER, content="Hello, how are you?")]

        score = self.analyzer.analyze(messages)

        assert score.level == ComplexityLevel.TRIVIAL
        assert score.score < 0.2
        assert len(score.risk_indicators) == 0
        assert score.recommended_strategy in ["heuristic_only", "heuristic_cached"]

    def test_simple_complexity(self):
        """Test detection of simple complexity prompts."""
        messages = [
            Message(role=Role.SYSTEM, content="You are a helpful assistant."),
            Message(role=Role.USER, content="What is the weather like today in New York?"),
        ]

        score = self.analyzer.analyze(messages)

        assert score.level in [ComplexityLevel.TRIVIAL, ComplexityLevel.SIMPLE]
        assert score.score < 0.4

    def test_moderate_complexity(self):
        """Test detection of moderate complexity prompts."""
        messages = [
            Message(
                role=Role.USER,
                content="""
                Please analyze this data and provide insights:
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
                Calculate the mean, median, and standard deviation.
                Also provide a brief interpretation of the results.
            """,
            )
        ]

        score = self.analyzer.analyze(messages)

        assert score.level in [ComplexityLevel.SIMPLE, ComplexityLevel.MODERATE]
        assert 0.2 < score.score < 0.6
