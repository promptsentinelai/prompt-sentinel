"""Clustering engine for pattern discovery.

Implements various clustering algorithms to discover groups of similar attacks.
"""

import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import numpy as np
from collections import defaultdict

import structlog

logger = structlog.get_logger()


@dataclass
class Cluster:
    """Represents a cluster of similar prompts."""
    cluster_id: int
    centroid: Optional[np.ndarray]
    members: List[int]  # Indices of member events
    density: float
    avg_confidence: float
    dominant_category: str
    patterns: List[str]
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def size(self) -> int:
        """Get cluster size."""
        return len(self.members)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get cluster summary."""
        return {
            "cluster_id": self.cluster_id,
            "size": self.size,
            "density": self.density,
            "avg_confidence": self.avg_confidence,
            "dominant_category": self.dominant_category,
            "top_patterns": self.patterns[:5],
            "created_at": self.created_at.isoformat()
        }


class ClusteringEngine:
    """Engine for clustering detection events."""
    
    def __init__(
        self,
        min_cluster_size: int = 5,
        min_samples: int = 3,
        eps: float = 0.3,
        algorithm: str = "dbscan"
    ):
        """Initialize the clustering engine.
        
        Args:
            min_cluster_size: Minimum size for a valid cluster
            min_samples: Minimum samples in neighborhood (DBSCAN)
            eps: Maximum distance between samples (DBSCAN)
            algorithm: Clustering algorithm to use
        """
        self.min_cluster_size = min_cluster_size
        self.min_samples = min_samples
        self.eps = eps
        self.algorithm = algorithm
        
        # Clustering models
        self.dbscan = None
        self.hdbscan = None
        self.kmeans = None
        
        # Results
        self.clusters: List[Cluster] = []
        self.noise_points: List[int] = []
        self.cluster_labels: Optional[np.ndarray] = None
        
        # Initialize models
        self._init_models()
    
    def _init_models(self):
        """Initialize clustering models."""
        try:
            from sklearn.cluster import DBSCAN, MiniBatchKMeans
            self.dbscan = DBSCAN(
                eps=self.eps,
                min_samples=self.min_samples,
                metric='cosine',
                n_jobs=-1
            )
            self.kmeans = MiniBatchKMeans(
                n_clusters=10,
                batch_size=100,
                random_state=42
            )
            logger.info("Clustering models initialized", algorithm=self.algorithm)
        except ImportError:
            logger.error("scikit-learn not installed")
            raise
        
        # Try to import HDBSCAN
        try:
            import hdbscan
            self.hdbscan = hdbscan.HDBSCAN(
                min_cluster_size=self.min_cluster_size,
                min_samples=self.min_samples,
                metric='euclidean',
                cluster_selection_method='eom'
            )
            logger.info("HDBSCAN initialized")
        except ImportError:
            logger.warning("hdbscan not installed, using DBSCAN only")
    
    async def cluster_events(
        self,
        feature_vectors: np.ndarray,
        events: List[Any],
        algorithm: Optional[str] = None
    ) -> List[Cluster]:
        """Cluster events based on feature vectors.
        
        Args:
            feature_vectors: Feature matrix (n_samples x n_features)
            events: Original events corresponding to features
            algorithm: Override default algorithm
            
        Returns:
            List of discovered clusters
        """
        algorithm = algorithm or self.algorithm
        
        logger.info("Starting clustering",
                   algorithm=algorithm,
                   n_samples=len(feature_vectors))
        
        # Normalize features
        feature_vectors = self._normalize_features(feature_vectors)
        
        # Run clustering
        if algorithm == "dbscan":
            clusters = await self._cluster_dbscan(feature_vectors, events)
        elif algorithm == "hdbscan" and self.hdbscan:
            clusters = await self._cluster_hdbscan(feature_vectors, events)
        elif algorithm == "kmeans":
            clusters = await self._cluster_kmeans(feature_vectors, events)
        else:
            logger.error("Unknown algorithm", algorithm=algorithm)
            return []
        
        # Filter small clusters
        clusters = [c for c in clusters if c.size >= self.min_cluster_size]
        
        # Sort by size
        clusters.sort(key=lambda c: c.size, reverse=True)
        
        self.clusters = clusters
        
        logger.info("Clustering complete",
                   n_clusters=len(clusters),
                   n_noise=len(self.noise_points))
        
        return clusters
    
    async def _cluster_dbscan(
        self,
        features: np.ndarray,
        events: List[Any]
    ) -> List[Cluster]:
        """Cluster using DBSCAN algorithm."""
        # Run DBSCAN
        labels = self.dbscan.fit_predict(features)
        self.cluster_labels = labels
        
        # Process results
        clusters = []
        unique_labels = set(labels)
        
        for label in unique_labels:
            if label == -1:  # Noise points
                self.noise_points = np.where(labels == -1)[0].tolist()
                continue
            
            # Get cluster members
            member_indices = np.where(labels == label)[0]
            member_events = [events[i] for i in member_indices]
            
            # Calculate cluster properties
            cluster_features = features[member_indices]
            centroid = np.mean(cluster_features, axis=0)
            
            # Calculate density (average pairwise distance)
            distances = []
            for i in range(len(cluster_features)):
                for j in range(i+1, len(cluster_features)):
                    dist = np.linalg.norm(cluster_features[i] - cluster_features[j])
                    distances.append(dist)
            
            density = 1.0 / (np.mean(distances) + 1e-8) if distances else 1.0
            
            # Extract common properties
            categories = defaultdict(int)
            patterns = defaultdict(int)
            confidences = []
            
            for event in member_events:
                if hasattr(event, 'categories'):
                    for cat in event.categories:
                        categories[cat] += 1
                if hasattr(event, 'patterns_matched'):
                    for pattern in event.patterns_matched:
                        patterns[pattern] += 1
                if hasattr(event, 'confidence'):
                    confidences.append(event.confidence)
            
            # Create cluster
            cluster = Cluster(
                cluster_id=int(label),
                centroid=centroid,
                members=member_indices.tolist(),
                density=float(density),
                avg_confidence=float(np.mean(confidences)) if confidences else 0.0,
                dominant_category=max(categories, key=categories.get) if categories else "unknown",
                patterns=sorted(patterns, key=patterns.get, reverse=True)[:10],
                created_at=datetime.utcnow(),
                metadata={
                    "algorithm": "dbscan",
                    "eps": self.eps,
                    "min_samples": self.min_samples
                }
            )
            
            clusters.append(cluster)
        
        return clusters
    
    async def _cluster_hdbscan(
        self,
        features: np.ndarray,
        events: List[Any]
    ) -> List[Cluster]:
        """Cluster using HDBSCAN algorithm."""
        if not self.hdbscan:
            return await self._cluster_dbscan(features, events)
        
        # Run HDBSCAN
        labels = self.hdbscan.fit_predict(features)
        self.cluster_labels = labels
        
        # Get cluster persistence (stability)
        cluster_persistence = {}
        if hasattr(self.hdbscan, 'cluster_persistence_'):
            cluster_persistence = self.hdbscan.cluster_persistence_
        
        # Process results similar to DBSCAN
        clusters = []
        unique_labels = set(labels)
        
        for label in unique_labels:
            if label == -1:  # Noise points
                self.noise_points = np.where(labels == -1)[0].tolist()
                continue
            
            # Get cluster members
            member_indices = np.where(labels == label)[0]
            member_events = [events[i] for i in member_indices]
            
            # Calculate cluster properties
            cluster_features = features[member_indices]
            centroid = np.mean(cluster_features, axis=0)
            
            # Use persistence as density metric
            density = cluster_persistence.get(label, 1.0)
            
            # Extract common properties
            categories = defaultdict(int)
            patterns = defaultdict(int)
            confidences = []
            
            for event in member_events:
                if hasattr(event, 'categories'):
                    for cat in event.categories:
                        categories[cat] += 1
                if hasattr(event, 'patterns_matched'):
                    for pattern in event.patterns_matched:
                        patterns[pattern] += 1
                if hasattr(event, 'confidence'):
                    confidences.append(event.confidence)
            
            # Create cluster
            cluster = Cluster(
                cluster_id=int(label),
                centroid=centroid,
                members=member_indices.tolist(),
                density=float(density),
                avg_confidence=float(np.mean(confidences)) if confidences else 0.0,
                dominant_category=max(categories, key=categories.get) if categories else "unknown",
                patterns=sorted(patterns, key=patterns.get, reverse=True)[:10],
                created_at=datetime.utcnow(),
                metadata={
                    "algorithm": "hdbscan",
                    "min_cluster_size": self.min_cluster_size,
                    "persistence": density
                }
            )
            
            clusters.append(cluster)
        
        return clusters
    
    async def _cluster_kmeans(
        self,
        features: np.ndarray,
        events: List[Any]
    ) -> List[Cluster]:
        """Cluster using Mini-batch K-means."""
        # Determine optimal K using elbow method (simplified)
        n_clusters = min(10, max(2, len(features) // 50))
        self.kmeans.n_clusters = n_clusters
        
        # Run K-means
        labels = self.kmeans.fit_predict(features)
        self.cluster_labels = labels
        
        # Get cluster centers
        centers = self.kmeans.cluster_centers_
        
        # Process results
        clusters = []
        
        for label in range(n_clusters):
            # Get cluster members
            member_indices = np.where(labels == label)[0]
            if len(member_indices) == 0:
                continue
            
            member_events = [events[i] for i in member_indices]
            
            # Calculate cluster properties
            cluster_features = features[member_indices]
            centroid = centers[label]
            
            # Calculate inertia as density metric
            distances = [np.linalg.norm(f - centroid) for f in cluster_features]
            density = 1.0 / (np.mean(distances) + 1e-8)
            
            # Extract common properties
            categories = defaultdict(int)
            patterns = defaultdict(int)
            confidences = []
            
            for event in member_events:
                if hasattr(event, 'categories'):
                    for cat in event.categories:
                        categories[cat] += 1
                if hasattr(event, 'patterns_matched'):
                    for pattern in event.patterns_matched:
                        patterns[pattern] += 1
                if hasattr(event, 'confidence'):
                    confidences.append(event.confidence)
            
            # Create cluster
            cluster = Cluster(
                cluster_id=int(label),
                centroid=centroid,
                members=member_indices.tolist(),
                density=float(density),
                avg_confidence=float(np.mean(confidences)) if confidences else 0.0,
                dominant_category=max(categories, key=categories.get) if categories else "unknown",
                patterns=sorted(patterns, key=patterns.get, reverse=True)[:10],
                created_at=datetime.utcnow(),
                metadata={
                    "algorithm": "kmeans",
                    "n_clusters": n_clusters,
                    "inertia": float(self.kmeans.inertia_)
                }
            )
            
            clusters.append(cluster)
        
        return clusters
    
    def _normalize_features(self, features: np.ndarray) -> np.ndarray:
        """Normalize feature vectors."""
        # Handle empty or single sample
        if len(features) <= 1:
            return features
        
        # Standardize features (z-score normalization)
        mean = np.mean(features, axis=0)
        std = np.std(features, axis=0)
        
        # Avoid division by zero
        std[std == 0] = 1.0
        
        normalized = (features - mean) / std
        
        return normalized
    
    def find_optimal_eps(
        self,
        features: np.ndarray,
        k: int = 4
    ) -> float:
        """Find optimal eps value for DBSCAN using k-distance graph.
        
        Args:
            features: Feature matrix
            k: Number of nearest neighbors
            
        Returns:
            Suggested eps value
        """
        from sklearn.neighbors import NearestNeighbors
        
        # Fit nearest neighbors
        nbrs = NearestNeighbors(n_neighbors=k, metric='cosine').fit(features)
        distances, indices = nbrs.kneighbors(features)
        
        # Sort k-distances
        k_distances = np.sort(distances[:, k-1])
        
        # Find elbow point (simplified - use derivative)
        if len(k_distances) > 2:
            # Calculate first derivative
            diff = np.diff(k_distances)
            # Find maximum change
            elbow_idx = np.argmax(diff)
            optimal_eps = k_distances[elbow_idx]
        else:
            optimal_eps = np.median(k_distances)
        
        logger.info("Optimal eps found", eps=optimal_eps)
        
        return float(optimal_eps)
    
    def get_cluster_statistics(self) -> Dict[str, Any]:
        """Get clustering statistics.
        
        Returns:
            Dictionary of statistics
        """
        if not self.clusters:
            return {
                "n_clusters": 0,
                "n_noise": len(self.noise_points),
                "status": "no_clusters"
            }
        
        cluster_sizes = [c.size for c in self.clusters]
        
        return {
            "n_clusters": len(self.clusters),
            "n_noise": len(self.noise_points),
            "total_clustered": sum(cluster_sizes),
            "avg_cluster_size": np.mean(cluster_sizes),
            "min_cluster_size": min(cluster_sizes),
            "max_cluster_size": max(cluster_sizes),
            "cluster_densities": [c.density for c in self.clusters],
            "dominant_categories": [c.dominant_category for c in self.clusters],
            "algorithm_used": self.algorithm
        }
    
    def export_clusters(self) -> List[Dict[str, Any]]:
        """Export clusters for persistence.
        
        Returns:
            List of cluster dictionaries
        """
        return [cluster.get_summary() for cluster in self.clusters]