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
