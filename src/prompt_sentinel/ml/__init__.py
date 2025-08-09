"""Machine Learning module for automated pattern discovery."""

from .collector import PatternCollector, DetectionEvent
from .features import FeatureExtractor
from .clustering import ClusteringEngine
from .patterns import PatternExtractor
from .manager import PatternManager

__all__ = [
    "PatternCollector",
    "DetectionEvent",
    "FeatureExtractor",
    "ClusteringEngine",
    "PatternExtractor",
    "PatternManager",
]
