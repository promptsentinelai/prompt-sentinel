"""Comprehensive tests for ML clustering module."""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import numpy as np
import pytest

from prompt_sentinel.ml.clustering import Cluster, ClusteringEngine


class TestCluster:
    """Test suite for Cluster dataclass."""

    @pytest.fixture
    def sample_cluster(self):
        """Create a sample cluster."""
        return Cluster(
            cluster_id=1,
            centroid=np.array([0.5, 0.5, 0.5]),
            members=[0, 1, 2, 3, 4],
            density=0.85,
            avg_confidence=0.75,
            dominant_category="injection",
            patterns=["pattern1", "pattern2", "pattern3"],
            created_at=datetime.utcnow(),
            metadata={"algorithm": "dbscan"}
        )

    def test_initialization(self):
        """Test Cluster initialization."""
        cluster = Cluster(
            cluster_id=0,
            centroid=None,
            members=[1, 2],
            density=0.5,
            avg_confidence=0.6,
            dominant_category="test",
            patterns=[],
            created_at=datetime.utcnow()
        )
        
        assert cluster.cluster_id == 0
        assert cluster.centroid is None
        assert cluster.members == [1, 2]
        assert cluster.density == 0.5
        assert cluster.metadata == {}

    def test_size_property(self, sample_cluster):
        """Test cluster size property."""
        assert sample_cluster.size == 5
        
        # Test empty cluster
        empty_cluster = Cluster(
            cluster_id=2,
            centroid=None,
            members=[],
            density=0,
            avg_confidence=0,
            dominant_category="none",
            patterns=[],
            created_at=datetime.utcnow()
        )
        assert empty_cluster.size == 0

    def test_get_summary(self, sample_cluster):
        """Test cluster summary generation."""
        summary = sample_cluster.get_summary()
        
        assert summary["cluster_id"] == 1
        assert summary["size"] == 5
        assert summary["density"] == 0.85
        assert summary["avg_confidence"] == 0.75
        assert summary["dominant_category"] == "injection"
        assert len(summary["top_patterns"]) == 3
        assert "created_at" in summary

    def test_get_summary_limits_patterns(self):
        """Test that summary limits patterns to 5."""
        cluster = Cluster(
            cluster_id=1,
            centroid=None,
            members=[0],
            density=0.5,
            avg_confidence=0.5,
            dominant_category="test",
            patterns=[f"pattern_{i}" for i in range(10)],
            created_at=datetime.utcnow()
        )
        
        summary = cluster.get_summary()
        assert len(summary["top_patterns"]) == 5


class TestClusteringEngine:
    """Test suite for ClusteringEngine class."""

    @pytest.fixture
    def engine(self):
        """Create a ClusteringEngine instance."""
        with patch("prompt_sentinel.ml.clustering.ClusteringEngine._init_models"):
            engine = ClusteringEngine(
                min_cluster_size=3,
                min_samples=2,
                eps=0.5,
                algorithm="dbscan"
            )
            # Manually set up mock models
            engine.dbscan = MagicMock()
            engine.kmeans = MagicMock()
            engine.hdbscan = None
            return engine

    @pytest.fixture
    def sample_features(self):
        """Create sample feature vectors."""
        np.random.seed(42)
        return np.random.rand(20, 10)  # 20 samples, 10 features

    @pytest.fixture
    def sample_events(self):
        """Create sample events."""
        events = []
        for i in range(20):
            event = MagicMock()
            event.categories = ["injection", "jailbreak"] if i % 2 == 0 else ["benign"]
            event.patterns_matched = [f"pattern_{i % 3}"]
            event.confidence = 0.5 + (i % 5) * 0.1
            events.append(event)
        return events

    def test_initialization(self):
        """Test ClusteringEngine initialization."""
        with patch("prompt_sentinel.ml.clustering.ClusteringEngine._init_models"):
            engine = ClusteringEngine(
                min_cluster_size=10,
                min_samples=5,
                eps=0.2,
                algorithm="hdbscan"
            )
            
            assert engine.min_cluster_size == 10
            assert engine.min_samples == 5
            assert engine.eps == 0.2
            assert engine.algorithm == "hdbscan"
            assert engine.clusters == []
            assert engine.noise_points == []

    def test_initialization_defaults(self):
        """Test ClusteringEngine with default values."""
        with patch("prompt_sentinel.ml.clustering.ClusteringEngine._init_models"):
            engine = ClusteringEngine()
            
            assert engine.min_cluster_size == 5
            assert engine.min_samples == 3
            assert engine.eps == 0.3
            assert engine.algorithm == "dbscan"

    @patch("prompt_sentinel.ml.clustering.logger")
    def test_init_models_success(self, mock_logger):
        """Test successful model initialization."""
        with patch("sklearn.cluster.DBSCAN") as mock_dbscan:
            with patch("sklearn.cluster.MiniBatchKMeans") as mock_kmeans:
                engine = ClusteringEngine()
                
                assert engine.dbscan is not None
                assert engine.kmeans is not None
                mock_logger.info.assert_called()

    @patch("prompt_sentinel.ml.clustering.logger")
    def test_init_models_import_error(self, mock_logger):
        """Test model initialization with import error."""
        with patch("prompt_sentinel.ml.clustering.ClusteringEngine._init_models") as mock_init:
            mock_init.side_effect = ImportError("sklearn not found")
            
            with pytest.raises(ImportError):
                ClusteringEngine()

    @patch("prompt_sentinel.ml.clustering.logger")
    def test_init_models_with_hdbscan(self, mock_logger):
        """Test model initialization with HDBSCAN available."""
        # Create a mock hdbscan module
        mock_hdbscan_module = MagicMock()
        mock_hdbscan_class = MagicMock()
        mock_hdbscan_module.HDBSCAN = mock_hdbscan_class
        
        with patch.dict("sys.modules", {"hdbscan": mock_hdbscan_module}):
            with patch("sklearn.cluster.DBSCAN"):
                with patch("sklearn.cluster.MiniBatchKMeans"):
                    engine = ClusteringEngine()
                    
                    assert engine.hdbscan is not None
                    mock_hdbscan_class.assert_called_once()

    @pytest.mark.asyncio
    async def test_cluster_events_dbscan(self, engine, sample_features, sample_events):
        """Test clustering with DBSCAN algorithm."""
        # Mock DBSCAN results
        labels = np.array([0, 0, 0, 1, 1, 1, -1] + [2] * 13)  # 3 clusters + noise
        engine.dbscan.fit_predict = MagicMock(return_value=labels)
        
        clusters = await engine.cluster_events(sample_features, sample_events, "dbscan")
        
        assert isinstance(clusters, list)
        assert len(clusters) <= 3  # Filtered by min_cluster_size
        engine.dbscan.fit_predict.assert_called_once()

    @pytest.mark.asyncio
    async def test_cluster_events_kmeans(self, engine, sample_features, sample_events):
        """Test clustering with K-means algorithm."""
        # Mock K-means results
        labels = np.array([0] * 7 + [1] * 7 + [2] * 6)
        engine.kmeans.fit_predict = MagicMock(return_value=labels)
        engine.kmeans.cluster_centers_ = np.random.rand(3, 10)
        engine.kmeans.inertia_ = 100.0
        
        clusters = await engine.cluster_events(sample_features, sample_events, "kmeans")
        
        assert isinstance(clusters, list)
        engine.kmeans.fit_predict.assert_called_once()

    @pytest.mark.asyncio
    async def test_cluster_events_hdbscan_fallback(self, engine, sample_features, sample_events):
        """Test HDBSCAN falling back to DBSCAN when not available."""
        engine.hdbscan = None
        labels = np.array([0] * 10 + [1] * 10)
        engine.dbscan.fit_predict = MagicMock(return_value=labels)
        
        # Test the _cluster_hdbscan method directly since cluster_events checks algorithm first
        clusters = await engine._cluster_hdbscan(sample_features, sample_events)
        
        # Should fall back to DBSCAN
        engine.dbscan.fit_predict.assert_called_once()

    @pytest.mark.asyncio
    async def test_cluster_events_unknown_algorithm(self, engine, sample_features, sample_events):
        """Test clustering with unknown algorithm."""
        with patch("prompt_sentinel.ml.clustering.logger") as mock_logger:
            clusters = await engine.cluster_events(sample_features, sample_events, "unknown")
            
            assert clusters == []
            mock_logger.error.assert_called_with("Unknown algorithm", algorithm="unknown")

    @pytest.mark.asyncio
    async def test_cluster_events_filters_small_clusters(self, engine, sample_features, sample_events):
        """Test that small clusters are filtered out."""
        # Create labels with one small cluster
        labels = np.array([0, 0, 1, 1, 1, 1, 1, -1] + [2] * 12)  # Cluster 0 has only 2 members
        engine.dbscan.fit_predict = MagicMock(return_value=labels)
        engine.min_cluster_size = 3
        
        clusters = await engine.cluster_events(sample_features, sample_events)
        
        # Cluster 0 should be filtered out
        cluster_ids = [c.cluster_id for c in clusters]
        assert 0 not in cluster_ids

    @pytest.mark.asyncio
    async def test_cluster_dbscan_with_noise(self, engine, sample_features, sample_events):
        """Test DBSCAN clustering with noise points."""
        labels = np.array([-1, -1, 0, 0, 0, 1, 1, 1, 1, 1] + [2] * 10)
        engine.dbscan.fit_predict = MagicMock(return_value=labels)
        
        clusters = await engine._cluster_dbscan(sample_features, sample_events)
        
        assert len(engine.noise_points) == 2
        assert 0 in engine.noise_points
        assert 1 in engine.noise_points

    @pytest.mark.asyncio
    async def test_cluster_dbscan_properties(self, engine, sample_features, sample_events):
        """Test DBSCAN cluster property calculation."""
        labels = np.array([0] * 5 + [1] * 5 + [-1] * 10)
        engine.dbscan.fit_predict = MagicMock(return_value=labels)
        
        clusters = await engine._cluster_dbscan(sample_features, sample_events)
        
        for cluster in clusters:
            assert cluster.cluster_id >= 0
            assert cluster.centroid is not None
            assert len(cluster.members) > 0
            assert cluster.density > 0
            assert 0 <= cluster.avg_confidence <= 1
            assert cluster.dominant_category in ["injection", "benign"]
            assert isinstance(cluster.patterns, list)

    @pytest.mark.asyncio
    async def test_cluster_hdbscan_with_persistence(self, engine, sample_features, sample_events):
        """Test HDBSCAN clustering with persistence scores."""
        # Mock HDBSCAN
        mock_hdbscan = MagicMock()
        labels = np.array([0] * 10 + [1] * 10)
        mock_hdbscan.fit_predict = MagicMock(return_value=labels)
        mock_hdbscan.cluster_persistence_ = {0: 0.9, 1: 0.7}
        engine.hdbscan = mock_hdbscan
        
        clusters = await engine._cluster_hdbscan(sample_features, sample_events)
        
        assert len(clusters) == 2
        # Check persistence is used as density
        assert any(c.density == 0.9 for c in clusters)
        assert any(c.density == 0.7 for c in clusters)

    @pytest.mark.asyncio
    async def test_cluster_kmeans_optimal_k(self, engine, sample_features, sample_events):
        """Test K-means with automatic K selection."""
        # Test with small dataset
        small_features = sample_features[:10]
        small_events = sample_events[:10]
        
        labels = np.array([0] * 5 + [1] * 5)
        engine.kmeans.fit_predict = MagicMock(return_value=labels)
        engine.kmeans.cluster_centers_ = np.random.rand(2, 10)
        engine.kmeans.inertia_ = 50.0
        
        clusters = await engine._cluster_kmeans(small_features, small_events)
        
        # Should use minimum K value
        assert engine.kmeans.n_clusters >= 2

    @pytest.mark.asyncio
    async def test_cluster_kmeans_empty_cluster(self, engine, sample_features, sample_events):
        """Test K-means handling empty clusters."""
        # Create labels with an empty cluster
        labels = np.array([0] * 10 + [2] * 10)  # No cluster 1
        engine.kmeans.fit_predict = MagicMock(return_value=labels)
        engine.kmeans.cluster_centers_ = np.random.rand(3, 10)
        engine.kmeans.n_clusters = 3
        engine.kmeans.inertia_ = 50.0
        
        clusters = await engine._cluster_kmeans(sample_features, sample_events)
        
        # Should skip empty cluster
        cluster_ids = [c.cluster_id for c in clusters]
        assert 1 not in cluster_ids

    def test_normalize_features(self, engine):
        """Test feature normalization."""
        features = np.array([[1, 2, 3], [4, 5, 6], [7, 8, 9]])
        
        normalized = engine._normalize_features(features)
        
        # Check that mean is approximately 0 and std is approximately 1
        assert np.allclose(np.mean(normalized, axis=0), 0, atol=1e-10)
        assert np.allclose(np.std(normalized, axis=0), 1, atol=1e-10)

    def test_normalize_features_single_sample(self, engine):
        """Test normalization with single sample."""
        features = np.array([[1, 2, 3]])
        
        normalized = engine._normalize_features(features)
        
        # Should return unchanged
        assert np.array_equal(normalized, features)

    def test_normalize_features_zero_std(self, engine):
        """Test normalization with zero standard deviation."""
        features = np.array([[1, 2, 3], [1, 2, 3], [1, 2, 3]])  # All same
        
        normalized = engine._normalize_features(features)
        
        # Should handle zero std without error
        assert normalized.shape == features.shape
        assert np.allclose(normalized, 0)

    def test_find_optimal_eps(self, engine):
        """Test finding optimal eps value."""
        features = np.random.rand(100, 10)
        
        with patch("sklearn.neighbors.NearestNeighbors") as mock_nn:
            mock_nbrs = MagicMock()
            distances = np.sort(np.random.rand(100, 4), axis=1)
            indices = np.arange(100).reshape(-1, 1).repeat(4, axis=1)
            mock_nbrs.kneighbors = MagicMock(return_value=(distances, indices))
            mock_nn.return_value.fit.return_value = mock_nbrs
            
            eps = engine.find_optimal_eps(features, k=4)
            
            assert isinstance(eps, float)
            assert eps > 0

    def test_find_optimal_eps_small_dataset(self, engine):
        """Test finding optimal eps with small dataset."""
        features = np.random.rand(2, 10)
        
        with patch("sklearn.neighbors.NearestNeighbors") as mock_nn:
            mock_nbrs = MagicMock()
            distances = np.array([[0, 0.5], [0, 0.5]])
            indices = np.array([[0, 1], [1, 0]])
            mock_nbrs.kneighbors = MagicMock(return_value=(distances, indices))
            mock_nn.return_value.fit.return_value = mock_nbrs
            
            eps = engine.find_optimal_eps(features, k=2)
            
            assert isinstance(eps, float)
            # Should use median for small dataset
            assert eps == 0.5

    def test_get_cluster_statistics_no_clusters(self, engine):
        """Test statistics with no clusters."""
        engine.clusters = []
        engine.noise_points = [0, 1, 2]
        
        stats = engine.get_cluster_statistics()
        
        assert stats["n_clusters"] == 0
        assert stats["n_noise"] == 3
        assert stats["status"] == "no_clusters"

    def test_get_cluster_statistics_with_clusters(self, engine):
        """Test statistics with clusters."""
        cluster1 = Cluster(
            cluster_id=0,
            centroid=None,
            members=[0, 1, 2],
            density=0.8,
            avg_confidence=0.7,
            dominant_category="injection",
            patterns=[],
            created_at=datetime.utcnow()
        )
        
        cluster2 = Cluster(
            cluster_id=1,
            centroid=None,
            members=[3, 4, 5, 6],
            density=0.6,
            avg_confidence=0.8,
            dominant_category="jailbreak",
            patterns=[],
            created_at=datetime.utcnow()
        )
        
        engine.clusters = [cluster1, cluster2]
        engine.noise_points = [7, 8]
        engine.algorithm = "dbscan"
        
        stats = engine.get_cluster_statistics()
        
        assert stats["n_clusters"] == 2
        assert stats["n_noise"] == 2
        assert stats["total_clustered"] == 7
        assert stats["avg_cluster_size"] == 3.5
        assert stats["min_cluster_size"] == 3
        assert stats["max_cluster_size"] == 4
        assert stats["cluster_densities"] == [0.8, 0.6]
        assert stats["dominant_categories"] == ["injection", "jailbreak"]
        assert stats["algorithm_used"] == "dbscan"

    def test_export_clusters(self, engine):
        """Test cluster export."""
        cluster1 = Cluster(
            cluster_id=0,
            centroid=np.array([1, 2, 3]),
            members=[0, 1],
            density=0.5,
            avg_confidence=0.6,
            dominant_category="test",
            patterns=["p1", "p2"],
            created_at=datetime.utcnow()
        )
        
        engine.clusters = [cluster1]
        
        exported = engine.export_clusters()
        
        assert len(exported) == 1
        assert exported[0]["cluster_id"] == 0
        assert exported[0]["size"] == 2
        assert exported[0]["density"] == 0.5

    def test_export_clusters_empty(self, engine):
        """Test export with no clusters."""
        engine.clusters = []
        
        exported = engine.export_clusters()
        
        assert exported == []


class TestClusteringIntegration:
    """Integration tests for clustering functionality."""

    @pytest.mark.asyncio
    async def test_full_clustering_pipeline(self):
        """Test complete clustering pipeline."""
        with patch("sklearn.cluster.DBSCAN") as mock_dbscan:
            with patch("sklearn.cluster.MiniBatchKMeans"):
                engine = ClusteringEngine(min_cluster_size=2)
                
                # Create test data
                features = np.random.rand(50, 10)
                events = []
                for i in range(50):
                    event = MagicMock()
                    event.categories = ["injection"] if i < 25 else ["benign"]
                    event.confidence = 0.5 + (i % 10) * 0.05
                    event.patterns_matched = [f"pattern_{i % 5}"]
                    events.append(event)
                
                # Mock clustering results
                labels = np.array([0] * 15 + [1] * 15 + [2] * 15 + [-1] * 5)
                mock_dbscan.return_value.fit_predict.return_value = labels
                
                # Run clustering
                clusters = await engine.cluster_events(features, events)
                
                # Verify results
                assert len(clusters) == 3
                assert all(c.size >= 2 for c in clusters)
                
                # Check statistics
                stats = engine.get_cluster_statistics()
                assert stats["n_clusters"] == 3
                assert stats["n_noise"] == 5
                
                # Export clusters
                exported = engine.export_clusters()
                assert len(exported) == 3

    @pytest.mark.asyncio
    async def test_clustering_with_different_algorithms(self):
        """Test clustering with different algorithms."""
        features = np.random.rand(30, 5)
        events = [MagicMock() for _ in range(30)]
        
        for algo in ["dbscan", "kmeans"]:
            with patch("sklearn.cluster.DBSCAN") as mock_dbscan:
                with patch("sklearn.cluster.MiniBatchKMeans") as mock_kmeans:
                    engine = ClusteringEngine(algorithm=algo, min_cluster_size=2)
                    
                    if algo == "dbscan":
                        labels = np.array([0] * 10 + [1] * 10 + [2] * 10)
                        mock_dbscan.return_value.fit_predict.return_value = labels
                    else:
                        labels = np.array([0] * 10 + [1] * 10 + [2] * 10)
                        mock_kmeans.return_value.fit_predict.return_value = labels
                        mock_kmeans.return_value.cluster_centers_ = np.random.rand(3, 5)
                        mock_kmeans.return_value.inertia_ = 100.0
                    
                    clusters = await engine.cluster_events(features, events, algo)
                    
                    assert len(clusters) > 0
                    assert all(c.metadata["algorithm"] == algo for c in clusters)