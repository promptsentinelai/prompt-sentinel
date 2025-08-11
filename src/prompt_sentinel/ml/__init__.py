# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Machine Learning module for automated pattern discovery."""

from .clustering import ClusteringEngine
from .collector import DetectionEvent, PatternCollector
from .features import FeatureExtractor
from .manager import PatternManager
from .patterns import PatternExtractor

__all__ = [
    "PatternCollector",
    "DetectionEvent",
    "FeatureExtractor",
    "ClusteringEngine",
    "PatternExtractor",
    "PatternManager",
]
