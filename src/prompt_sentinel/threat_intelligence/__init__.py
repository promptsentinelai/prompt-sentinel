# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Threat Intelligence Feed System for PromptSentinel.

This module provides real-time threat intelligence ingestion and pattern
extraction to keep detection capabilities current with evolving attack techniques.
"""

from .extractors import PatternExtractor
from .feed_manager import ThreatFeedManager
from .models import FeedStatistics, FeedType, ThreatFeed, ThreatIndicator
from .validators import ThreatValidator

__all__ = [
    "ThreatFeedManager",
    "ThreatIndicator",
    "ThreatFeed",
    "FeedType",
    "FeedStatistics",
    "PatternExtractor",
    "ThreatValidator",
]
