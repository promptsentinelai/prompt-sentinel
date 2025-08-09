"""Tests for ML clustering module."""

from datetime import datetime
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from prompt_sentinel.ml.clustering import Cluster, ClusteringEngine


class TestCluster:
    """Test suite for Cluster dataclass."""

    @pytest.fixture
    def sample_cluster(self):
        """Create a sample cluster for testing."""
        return Cluster(
            cluster_id=1,
            centroid=np.array([0.5, 0.5, 0.5]),
            members=[0, 1, 2, 3, 4],
            density=0.85,
            avg_confidence=0.75,
            dominant_category="injection",
            patterns=["pattern1", "pattern2", "pattern3"],
            created_at=datetime.utcnow(),
            metadata={"algorithm": "dbscan", "iteration": 1}
        )

    def test_cluster_initialization(self, sample_cluster):
        """Test cluster initialization."""
        assert sample_cluster.cluster_id == 1
        assert sample_cluster.centroid is not None
        assert len(sample_cluster.members) == 5
        assert sample_cluster.density == 0.85
        assert sample_cluster.avg_confidence == 0.75
        assert sample_cluster.dominant_category == "injection"
        assert len(sample_cluster.patterns) == 3
        assert sample_cluster.metadata["algorithm"] == "dbscan"

    def test_cluster_size_property(self, sample_cluster):
        """Test cluster size property."""
        assert sample_cluster.size == 5
        
        # Test with different member counts
        sample_cluster.members = [1, 2, 3]
        assert sample_cluster.size == 3
        
        sample_cluster.members = []
        assert sample_cluster.size == 0

    def test_get_summary(self, sample_cluster):
        """Test get_summary method."""
        summary = sample_cluster.get_summary()
        
        assert summary["cluster_id"] == 1
        assert summary["size"] == 5
        assert summary["density"] == 0.85
        assert summary["avg_confidence"] == 0.75
        assert summary["dominant_category"] == "injection"
        assert "top_patterns" in summary
        assert len(summary["top_patterns"]) == 3
        assert "created_at" in summary

    def test_get_summary_with_many_patterns(self):
        """Test that get_summary limits patterns to 5."""
        cluster = Cluster(
            cluster_id=2,
            centroid=None,
            members=[0, 1, 2],
            density=0.7,
            avg_confidence=0.6,
            dominant_category="test",
            patterns=[f"pattern_{i}" for i in range(10)],
            created_at=datetime.utcnow(),
            metadata={}
        )
        
        summary = cluster.get_summary()
        assert len(summary["top_patterns"]) == 5
        assert summary["top_patterns"] == ["pattern_0", "pattern_1", "pattern_2", "pattern_3", "pattern_4"]

    def test_cluster_without_centroid(self):
        """Test cluster without centroid."""
        cluster = Cluster(
            cluster_id=3,
            centroid=None,
            members=[1, 2],
            density=0.5,
            avg_confidence=0.5,
            dominant_category="test",
            patterns=[],
            created_at=datetime.utcnow(),
            metadata={}
        )
        
        assert cluster.centroid is None
        assert cluster.size == 2

    def test_cluster_with_empty_metadata(self):
        """Test cluster with empty metadata."""
        cluster = Cluster(
            cluster_id=4,
            centroid=np.array([1.0, 2.0]),
            members=[0],
            density=1.0,
            avg_confidence=1.0,
            dominant_category="test",
            patterns=["test"],
            created_at=datetime.utcnow(),
            metadata={}
        )
        
        assert cluster.metadata == {}
        summary = cluster.get_summary()
        assert "metadata" not in summary  # metadata not included in summary


class TestClusteringEngine:
    """Test suite for ClusteringEngine."""

    @pytest.fixture
    def engine(self):
        """Create a clustering engine for testing."""
        return ClusteringEngine(
            min_cluster_size=5,
            min_samples=3,
            eps=0.3,
            algorithm="dbscan"
        )

    @pytest.fixture
    def engine_with_hdbscan(self):
        """Create a clustering engine with HDBSCAN algorithm."""
        return ClusteringEngine(
            min_cluster_size=3,
            min_samples=2,
            eps=0.5,
            algorithm="hdbscan"
        )

    @pytest.fixture
    def engine_with_kmeans(self):
        """Create a clustering engine with K-means algorithm."""
        return ClusteringEngine(
            min_cluster_size=2,
            min_samples=1,
            eps=0.2,
            algorithm="kmeans"
        )

    def test_initialization(self, engine):
        """Test engine initialization."""
        assert engine.min_cluster_size == 5
        assert engine.min_samples == 3
        assert engine.eps == 0.3
        assert engine.algorithm == "dbscan"
        # Models are initialized in __init__
        assert engine.dbscan is not None
        assert engine.kmeans is not None
        # HDBSCAN might not be installed
        # assert engine.hdbscan is None or engine.hdbscan is not None
        assert engine.clusters == []
        assert engine.noise_points == []
        assert engine.cluster_labels is None

    def test_initialization_with_different_algorithm(self, engine_with_hdbscan):
        """Test initialization with HDBSCAN algorithm."""
        assert engine_with_hdbscan.algorithm == "hdbscan"
        assert engine_with_hdbscan.min_cluster_size == 3
        assert engine_with_hdbscan.min_samples == 2

    def test_initialization_with_kmeans(self, engine_with_kmeans):
        """Test initialization with K-means algorithm."""
        assert engine_with_kmeans.algorithm == "kmeans"
        assert engine_with_kmeans.min_cluster_size == 2

    def test_min_cluster_size_edge_cases(self):
        """Test min_cluster_size edge cases."""
        # Zero size
        engine = ClusteringEngine(min_cluster_size=0)
        assert engine.min_cluster_size == 0
        
        # Negative size (allowed but might not make sense)
        engine = ClusteringEngine(min_cluster_size=-1)
        assert engine.min_cluster_size == -1
        
        # Large size
        engine = ClusteringEngine(min_cluster_size=1000)
        assert engine.min_cluster_size == 1000

    def test_eps_parameter(self):
        """Test eps parameter values."""
        # Zero eps
        engine = ClusteringEngine(eps=0.0)
        assert engine.eps == 0.0
        
        # Very small eps
        engine = ClusteringEngine(eps=0.001)
        assert engine.eps == 0.001
        
        # Large eps
        engine = ClusteringEngine(eps=10.0)
        assert engine.eps == 10.0
        
        # Negative eps (allowed but might not make sense)
        engine = ClusteringEngine(eps=-0.5)
        assert engine.eps == -0.5

    def test_algorithm_selection(self):
        """Test different algorithm selections."""
        algorithms = ["dbscan", "hdbscan", "kmeans", "optics", "custom"]
        
        for algo in algorithms:
            engine = ClusteringEngine(algorithm=algo)
            assert engine.algorithm == algo

    def test_initial_state(self, engine):
        """Test initial state of the engine."""
        assert len(engine.clusters) == 0
        assert len(engine.noise_points) == 0
        assert engine.cluster_labels is None
        
        # Models are initialized in __init__
        assert engine.dbscan is not None
        assert engine.kmeans is not None
        # HDBSCAN might or might not be installed

    def test_cluster_storage(self, engine):
        """Test cluster storage."""
        # Create sample clusters
        cluster1 = Cluster(
            cluster_id=0,
            centroid=np.array([0.1, 0.2]),
            members=[0, 1, 2],
            density=0.8,
            avg_confidence=0.7,
            dominant_category="test",
            patterns=["p1"],
            created_at=datetime.utcnow(),
            metadata={}
        )
        
        cluster2 = Cluster(
            cluster_id=1,
            centroid=np.array([0.5, 0.6]),
            members=[3, 4, 5],
            density=0.9,
            avg_confidence=0.8,
            dominant_category="test2",
            patterns=["p2"],
            created_at=datetime.utcnow(),
            metadata={}
        )
        
        # Add clusters to engine
        engine.clusters.append(cluster1)
        engine.clusters.append(cluster2)
        
        assert len(engine.clusters) == 2
        assert engine.clusters[0].cluster_id == 0
        assert engine.clusters[1].cluster_id == 1

    def test_noise_points_storage(self, engine):
        """Test noise points storage."""
        engine.noise_points = [10, 11, 12, 15, 20]
        
        assert len(engine.noise_points) == 5
        assert 10 in engine.noise_points
        assert 20 in engine.noise_points

    def test_cluster_labels_storage(self, engine):
        """Test cluster labels storage."""
        # Set cluster labels
        labels = np.array([0, 0, 0, 1, 1, 1, -1, -1])
        engine.cluster_labels = labels
        
        assert engine.cluster_labels is not None
        assert len(engine.cluster_labels) == 8
        assert engine.cluster_labels[0] == 0
        assert engine.cluster_labels[6] == -1  # Noise point

    def test_default_parameters(self):
        """Test default parameters when not specified."""
        engine = ClusteringEngine()
        
        assert engine.min_cluster_size == 5
        assert engine.min_samples == 3
        assert engine.eps == 0.3
        assert engine.algorithm == "dbscan"


class TestClusteringIntegration:
    """Integration tests for clustering functionality."""

    def test_clustering_workflow(self):
        """Test a complete clustering workflow."""
        # Create engine
        engine = ClusteringEngine(
            min_cluster_size=2,
            min_samples=2,
            eps=0.5,
            algorithm="dbscan"
        )
        
        # Simulate clustering results
        engine.cluster_labels = np.array([0, 0, 0, 1, 1, -1])
        engine.noise_points = [5]
        
        # Create clusters based on labels
        cluster_0 = Cluster(
            cluster_id=0,
            centroid=np.array([0.5, 0.5]),
            members=[0, 1, 2],
            density=0.9,
            avg_confidence=0.8,
            dominant_category="injection",
            patterns=["pattern1"],
            created_at=datetime.utcnow(),
            metadata={"algorithm": "dbscan"}
        )
        
        cluster_1 = Cluster(
            cluster_id=1,
            centroid=np.array([0.7, 0.3]),
            members=[3, 4],
            density=0.85,
            avg_confidence=0.7,
            dominant_category="extraction",
            patterns=["pattern2"],
            created_at=datetime.utcnow(),
            metadata={"algorithm": "dbscan"}
        )
        
        engine.clusters = [cluster_0, cluster_1]
        
        # Verify results
        assert len(engine.clusters) == 2
        assert engine.clusters[0].size == 3
        assert engine.clusters[1].size == 2
        assert len(engine.noise_points) == 1
        assert engine.noise_points[0] == 5

    def test_multiple_clustering_algorithms(self):
        """Test using different clustering algorithms."""
        algorithms = ["dbscan", "hdbscan", "kmeans"]
        engines = []
        
        for algo in algorithms:
            engine = ClusteringEngine(algorithm=algo)
            engines.append(engine)
            assert engine.algorithm == algo
        
        # Each engine should be independent
        assert len(engines) == 3
        for i, engine in enumerate(engines):
            assert engine.algorithm == algorithms[i]

    def test_cluster_summary_generation(self):
        """Test generating summaries for multiple clusters."""
        engine = ClusteringEngine()
        
        # Create multiple clusters
        for i in range(3):
            cluster = Cluster(
                cluster_id=i,
                centroid=np.array([i * 0.1, i * 0.2]),
                members=list(range(i * 3, (i + 1) * 3)),
                density=0.7 + i * 0.05,
                avg_confidence=0.6 + i * 0.1,
                dominant_category=f"category_{i}",
                patterns=[f"pattern_{i}_{j}" for j in range(3)],
                created_at=datetime.utcnow(),
                metadata={"iteration": i}
            )
            engine.clusters.append(cluster)
        
        # Generate summaries
        summaries = [c.get_summary() for c in engine.clusters]
        
        assert len(summaries) == 3
        for i, summary in enumerate(summaries):
            assert summary["cluster_id"] == i
            assert summary["size"] == 3
            assert summary["dominant_category"] == f"category_{i}"

    def test_empty_clustering_results(self):
        """Test handling empty clustering results."""
        engine = ClusteringEngine()
        
        # No clusters formed
        engine.cluster_labels = np.array([-1, -1, -1, -1])
        engine.noise_points = [0, 1, 2, 3]
        engine.clusters = []
        
        assert len(engine.clusters) == 0
        assert len(engine.noise_points) == 4
        assert all(label == -1 for label in engine.cluster_labels)