# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Intelligent routing for prompt detection based on complexity analysis."""

from .complexity_analyzer import ComplexityAnalyzer
from .router import IntelligentRouter

__all__ = ["IntelligentRouter", "ComplexityAnalyzer"]
