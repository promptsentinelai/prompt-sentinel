"""Tests for experiment metrics collectors module."""

import json
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from collections import defaultdict

from prompt_sentinel.experiments.collectors import (
    ExperimentMetric,
    AggregatedMetrics,
    MetricsCollector,
)
from prompt_sentinel.monitoring.usage_tracker import UsageTracker


class TestExperimentMetric:
    """Test suite for ExperimentMetric dataclass."""

    def test_initialization_minimal(self):
        """Test experiment metric initialization with minimal data."""
        timestamp = datetime.utcnow()
        
        metric = ExperimentMetric(
            experiment_id="exp_001",
            variant_id="control",
            user_id="user_123",
            metric_name="response_time",
            value=150.5,
            timestamp=timestamp
        )
        
        assert metric.experiment_id == "exp_001"
        assert metric.variant_id == "control"
        assert metric.user_id == "user_123"
        assert metric.metric_name == "response_time"
        assert metric.value == 150.5
        assert metric.timestamp == timestamp
        assert metric.metadata == {}

    def test_initialization_with_metadata(self):
        """Test experiment metric initialization with metadata."""
        timestamp = datetime.utcnow()
        metadata = {"provider": "anthropic", "cache_hit": True}
        
        metric = ExperimentMetric(
            experiment_id="exp_001",
            variant_id="treatment",
            user_id="user_456",
            metric_name="confidence",
            value=0.92,
            timestamp=timestamp,
            metadata=metadata
        )
        
        assert metric.metadata == metadata


class TestAggregatedMetrics:
    """Test suite for AggregatedMetrics dataclass."""

    def test_initialization(self):
        """Test aggregated metrics initialization."""
        percentiles = {50: 100.0, 95: 200.0, 99: 300.0}
        
        aggregated = AggregatedMetrics(
            variant_id="control",
            metric_name="response_time",
            count=1000,
            sum_value=150000.0,
            mean=150.0,
            min_value=50.0,
            max_value=500.0,
            std_dev=75.5,
            percentiles=percentiles
        )
        
        assert aggregated.variant_id == "control"
        assert aggregated.metric_name == "response_time"
        assert aggregated.count == 1000
        assert aggregated.sum_value == 150000.0
        assert aggregated.mean == 150.0
        assert aggregated.min_value == 50.0
        assert aggregated.max_value == 500.0
        assert aggregated.std_dev == 75.5
        assert aggregated.percentiles == percentiles


class TestMetricsCollector:
    """Test suite for MetricsCollector."""

    @pytest.fixture
    def mock_usage_tracker(self):
        """Create mock usage tracker."""
        return MagicMock(spec=UsageTracker)

    @pytest.fixture
    def metrics_collector(self, mock_usage_tracker):
        """Create metrics collector instance."""
        return MetricsCollector(usage_tracker=mock_usage_tracker)

    @pytest.fixture
    def sample_metrics(self):
        """Create sample experiment metrics."""
        base_time = datetime.utcnow()
        return [
            ExperimentMetric("exp_001", "control", "user_1", "response_time", 100.0, base_time),
            ExperimentMetric("exp_001", "control", "user_2", "response_time", 150.0, base_time),
            ExperimentMetric("exp_001", "treatment", "user_3", "response_time", 120.0, base_time),
            ExperimentMetric("exp_001", "control", "user_1", "confidence", 0.95, base_time),
            ExperimentMetric("exp_001", "treatment", "user_3", "confidence", 0.88, base_time),
        ]

    def test_initialization_default(self):
        """Test metrics collector initialization with defaults."""
        collector = MetricsCollector()
        
        assert collector.usage_tracker is None
        assert isinstance(collector.experiment_metrics, dict)
        assert len(collector.experiment_metrics) == 0
        assert isinstance(collector.aggregation_cache, dict)
        assert len(collector.aggregation_cache) == 0
        assert collector.cache_ttl == 300

    def test_initialization_with_tracker(self, mock_usage_tracker):
        """Test metrics collector initialization with usage tracker."""
        collector = MetricsCollector(usage_tracker=mock_usage_tracker)
        
        assert collector.usage_tracker == mock_usage_tracker

    @pytest.mark.asyncio
    async def test_record_experiment_metric_basic(self, metrics_collector):
        """Test recording a basic experiment metric."""
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = True
            mock_cache.lpush = AsyncMock()
            mock_cache.ltrim = AsyncMock()
            mock_cache.expire = AsyncMock()

            await metrics_collector.record_experiment_metric(
                experiment_id="exp_001",
                variant_id="control",
                metric_name="response_time",
                value=123.45,
                user_id="user_123"
            )

            # Check metric was stored
            assert "exp_001" in metrics_collector.experiment_metrics
            assert len(metrics_collector.experiment_metrics["exp_001"]) == 1
            
            metric = metrics_collector.experiment_metrics["exp_001"][0]
            assert metric.experiment_id == "exp_001"
            assert metric.variant_id == "control"
            assert metric.metric_name == "response_time"
            assert metric.value == 123.45
            assert metric.user_id == "user_123"
            assert isinstance(metric.timestamp, datetime)
            assert metric.metadata == {}

    @pytest.mark.asyncio
    async def test_record_experiment_metric_with_metadata(self, metrics_collector):
        """Test recording experiment metric with metadata."""
        metadata = {"provider": "anthropic", "cache_hit": False}
        
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = False  # Test without cache
            
            await metrics_collector.record_experiment_metric(
                experiment_id="exp_002",
                variant_id="treatment",
                metric_name="confidence",
                value=0.87,
                user_id="user_456",
                metadata=metadata
            )

            metric = metrics_collector.experiment_metrics["exp_002"][0]
            assert metric.metadata == metadata

    @pytest.mark.asyncio
    async def test_record_experiment_metric_anonymous_user(self, metrics_collector):
        """Test recording metric with anonymous user."""
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = False
            
            await metrics_collector.record_experiment_metric(
                experiment_id="exp_001",
                variant_id="control",
                metric_name="response_time",
                value=100.0
            )

            metric = metrics_collector.experiment_metrics["exp_001"][0]
            assert metric.user_id == "anonymous"

    @pytest.mark.asyncio
    async def test_record_experiment_metric_cache_invalidation(self, metrics_collector):
        """Test cache invalidation when recording metrics."""
        # Pre-populate cache
        metrics_collector.aggregation_cache["exp_001"] = {
            "control:response_time": MagicMock()
        }
        
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = False
            
            await metrics_collector.record_experiment_metric(
                experiment_id="exp_001",
                variant_id="control",
                metric_name="response_time",
                value=100.0
            )

            # Cache should be invalidated
            assert "control:response_time" not in metrics_collector.aggregation_cache["exp_001"]

    @pytest.mark.asyncio
    async def test_get_experiment_metrics_empty(self, metrics_collector):
        """Test getting metrics for non-existent experiment."""
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = False
            
            result = await metrics_collector.get_experiment_metrics("nonexistent")
            
            assert result == {}

    @pytest.mark.asyncio
    async def test_get_experiment_metrics_basic(self, metrics_collector, sample_metrics):
        """Test getting experiment metrics without filters."""
        # Add sample metrics
        for metric in sample_metrics:
            metrics_collector.experiment_metrics["exp_001"].append(metric)
        
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = False
            
            result = await metrics_collector.get_experiment_metrics("exp_001")
            
            expected = {
                "response_time": {
                    "control": [100.0, 150.0],
                    "treatment": [120.0]
                },
                "confidence": {
                    "control": [0.95],
                    "treatment": [0.88]
                }
            }
            
            assert result == expected

    @pytest.mark.asyncio
    async def test_get_experiment_metrics_with_variant_filter(self, metrics_collector, sample_metrics):
        """Test getting metrics filtered by variant."""
        for metric in sample_metrics:
            metrics_collector.experiment_metrics["exp_001"].append(metric)
        
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = False
            
            result = await metrics_collector.get_experiment_metrics(
                "exp_001", variant_ids=["control"]
            )
            
            expected = {
                "response_time": {
                    "control": [100.0, 150.0]
                },
                "confidence": {
                    "control": [0.95]
                }
            }
            
            assert result == expected

    @pytest.mark.asyncio
    async def test_get_experiment_metrics_with_metric_filter(self, metrics_collector, sample_metrics):
        """Test getting metrics filtered by metric name."""
        for metric in sample_metrics:
            metrics_collector.experiment_metrics["exp_001"].append(metric)
        
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = False
            
            result = await metrics_collector.get_experiment_metrics(
                "exp_001", metric_names=["response_time"]
            )
            
            expected = {
                "response_time": {
                    "control": [100.0, 150.0],
                    "treatment": [120.0]
                }
            }
            
            assert result == expected

    @pytest.mark.asyncio
    async def test_get_experiment_metrics_with_time_filter(self, metrics_collector):
        """Test getting metrics with time window filter."""
        now = datetime.utcnow()
        old_metric = ExperimentMetric("exp_001", "control", "user_1", "response_time", 100.0, 
                                     now - timedelta(hours=25))
        new_metric = ExperimentMetric("exp_001", "control", "user_2", "response_time", 150.0, 
                                     now - timedelta(hours=1))
        
        metrics_collector.experiment_metrics["exp_001"].extend([old_metric, new_metric])
        
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = False
            
            result = await metrics_collector.get_experiment_metrics(
                "exp_001", time_window_hours=24
            )
            
            # Should only include new metric
            expected = {
                "response_time": {
                    "control": [150.0]
                }
            }
            
            assert result == expected

    @pytest.mark.asyncio
    async def test_get_experiment_metrics_from_cache(self, metrics_collector):
        """Test getting metrics from Redis cache."""
        cached_data = {
            "response_time": {
                "control": [100.0, 150.0]
            }
        }
        
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = True
            mock_cache.get = AsyncMock(return_value=cached_data)
            mock_cache.set = AsyncMock()
            
            result = await metrics_collector.get_experiment_metrics("exp_001")
            
            assert result == cached_data
            mock_cache.get.assert_called_once_with("experiment_metrics:exp_001")

    @pytest.mark.asyncio
    async def test_get_aggregated_metrics_empty(self, metrics_collector):
        """Test getting aggregated metrics with no data."""
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = False
            
            result = await metrics_collector.get_aggregated_metrics(
                "exp_001", "control", "response_time"
            )
            
            assert result is None

    @pytest.mark.asyncio
    async def test_get_aggregated_metrics_from_cache(self, metrics_collector):
        """Test getting aggregated metrics from internal cache."""
        cached_aggregated = AggregatedMetrics(
            variant_id="control",
            metric_name="response_time",
            count=2,
            sum_value=250.0,
            mean=125.0,
            min_value=100.0,
            max_value=150.0,
            std_dev=25.0,
            percentiles={50: 125.0}
        )
        
        metrics_collector.aggregation_cache["exp_001"] = {
            "control:response_time": cached_aggregated
        }
        
        result = await metrics_collector.get_aggregated_metrics(
            "exp_001", "control", "response_time"
        )
        
        assert result == cached_aggregated

    @pytest.mark.asyncio
    async def test_get_aggregated_metrics_calculation(self, metrics_collector):
        """Test aggregated metrics calculation."""
        # Add test metrics
        metrics_collector.experiment_metrics["exp_001"] = [
            ExperimentMetric("exp_001", "control", "user_1", "response_time", 100.0, datetime.utcnow()),
            ExperimentMetric("exp_001", "control", "user_2", "response_time", 150.0, datetime.utcnow()),
            ExperimentMetric("exp_001", "control", "user_3", "response_time", 200.0, datetime.utcnow()),
        ]
        
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = False
            
            result = await metrics_collector.get_aggregated_metrics(
                "exp_001", "control", "response_time"
            )
            
            assert result is not None
            assert result.variant_id == "control"
            assert result.metric_name == "response_time"
            assert result.count == 3
            assert result.sum_value == 450.0
            assert result.mean == 150.0
            assert result.min_value == 100.0
            assert result.max_value == 200.0
            assert result.std_dev == pytest.approx(50.0, rel=0.1)
            assert 50 in result.percentiles
            assert 95 in result.percentiles

    @pytest.mark.asyncio
    async def test_get_variant_performance(self, metrics_collector, sample_metrics):
        """Test getting variant performance metrics."""
        for metric in sample_metrics:
            metrics_collector.experiment_metrics["exp_001"].append(metric)
        
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = False
            
            result = await metrics_collector.get_variant_performance(
                "exp_001", "control", time_window_hours=24
            )
            
            assert result["variant_id"] == "control"
            assert result["time_window_hours"] == 24
            assert "metrics" in result
            assert "summary" in result
            assert result["summary"]["total_events"] == 3  # 3 control metrics
            assert result["summary"]["unique_users"] == 2  # user_1 and user_2

    @pytest.mark.asyncio
    async def test_record_detection_metrics(self, metrics_collector):
        """Test recording detection-specific metrics."""
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = False
            
            await metrics_collector.record_detection_metrics(
                experiment_id="exp_001",
                variant_id="control",
                user_id="user_123",
                response_time_ms=150.5,
                confidence=0.92,
                verdict="block",
                provider_used="anthropic",
                cache_hit=True,
                pii_detected=False
            )
            
            metrics = metrics_collector.experiment_metrics["exp_001"]
            assert len(metrics) == 6  # 6 different metrics recorded
            
            # Check individual metrics
            metric_names = [m.metric_name for m in metrics]
            assert "response_time_ms" in metric_names
            assert "confidence" in metric_names
            assert "blocked" in metric_names
            assert "cache_hit" in metric_names
            assert "pii_detected" in metric_names
            assert "provider_anthropic" in metric_names

    @pytest.mark.asyncio
    async def test_export_experiment_data_json(self, metrics_collector, sample_metrics):
        """Test exporting experiment data as JSON."""
        for metric in sample_metrics:
            metrics_collector.experiment_metrics["exp_001"].append(metric)
        
        result = await metrics_collector.export_experiment_data("exp_001", "json")
        
        # Should be valid JSON
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) == 5
        
        # Check first metric
        first_metric = data[0]
        assert first_metric["experiment_id"] == "exp_001"
        assert first_metric["variant_id"] == "control"
        assert first_metric["user_id"] == "user_1"
        assert first_metric["metric_name"] == "response_time"
        assert first_metric["value"] == 100.0

    @pytest.mark.asyncio
    async def test_export_experiment_data_csv(self, metrics_collector, sample_metrics):
        """Test exporting experiment data as CSV."""
        for metric in sample_metrics:
            metrics_collector.experiment_metrics["exp_001"].append(metric)
        
        result = await metrics_collector.export_experiment_data("exp_001", "csv")
        
        lines = result.split('\n')
        assert len(lines) == 6  # Header + 5 data rows
        assert lines[0] == "experiment_id,variant_id,user_id,metric_name,value,timestamp"
        assert "exp_001,control,user_1,response_time,100.0" in lines[1]

    @pytest.mark.asyncio
    async def test_export_experiment_data_unsupported_format(self, metrics_collector):
        """Test exporting with unsupported format raises error."""
        with pytest.raises(ValueError, match="Unsupported format: xml"):
            await metrics_collector.export_experiment_data("exp_001", "xml")

    @pytest.mark.asyncio
    async def test_clear_experiment_data(self, metrics_collector, sample_metrics):
        """Test clearing experiment data."""
        # Add sample data
        for metric in sample_metrics:
            metrics_collector.experiment_metrics["exp_001"].append(metric)
        
        metrics_collector.aggregation_cache["exp_001"] = {"key": "value"}
        
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = True
            mock_cache.delete_pattern = AsyncMock()
            mock_cache.delete = AsyncMock()
            
            await metrics_collector.clear_experiment_data("exp_001")
            
            # Check memory cleared
            assert "exp_001" not in metrics_collector.experiment_metrics
            assert "exp_001" not in metrics_collector.aggregation_cache
            
            # Check Redis calls
            mock_cache.delete_pattern.assert_called_once_with("experiment_metric:exp_001:*")
            mock_cache.delete.assert_called_once_with("experiment_metrics:exp_001")

    def test_calculate_aggregations_empty_values(self, metrics_collector):
        """Test calculating aggregations with empty values."""
        result = metrics_collector._calculate_aggregations("control", "response_time", [])
        
        assert result.variant_id == "control"
        assert result.metric_name == "response_time"
        assert result.count == 0
        assert result.sum_value == 0.0
        assert result.mean == 0.0
        assert result.min_value == 0.0
        assert result.max_value == 0.0
        assert result.std_dev == 0.0
        assert result.percentiles == {}

    def test_calculate_aggregations_single_value(self, metrics_collector):
        """Test calculating aggregations with single value."""
        result = metrics_collector._calculate_aggregations("control", "response_time", [150.0])
        
        assert result.count == 1
        assert result.sum_value == 150.0
        assert result.mean == 150.0
        assert result.min_value == 150.0
        assert result.max_value == 150.0
        assert result.std_dev == 0.0  # Single value has no deviation

    def test_calculate_aggregations_multiple_values(self, metrics_collector):
        """Test calculating aggregations with multiple values."""
        values = [100.0, 150.0, 200.0, 250.0, 300.0]
        result = metrics_collector._calculate_aggregations("control", "response_time", values)
        
        assert result.count == 5
        assert result.sum_value == 1000.0
        assert result.mean == 200.0
        assert result.min_value == 100.0
        assert result.max_value == 300.0
        assert result.std_dev == pytest.approx(79.06, rel=0.01)
        assert result.percentiles[50] == 200.0  # Median
        assert result.percentiles[25] == 150.0  # 25th percentile

    def test_percentile_calculation_empty(self, metrics_collector):
        """Test percentile calculation with empty list."""
        result = metrics_collector._percentile([], 50)
        assert result == 0.0

    def test_percentile_calculation_single_value(self, metrics_collector):
        """Test percentile calculation with single value."""
        result = metrics_collector._percentile([100.0], 50)
        assert result == 100.0

    def test_percentile_calculation_multiple_values(self, metrics_collector):
        """Test percentile calculation with multiple values."""
        values = [10.0, 20.0, 30.0, 40.0, 50.0]
        
        # Test various percentiles
        assert metrics_collector._percentile(values, 0) == 10.0
        assert metrics_collector._percentile(values, 50) == 30.0  # Median
        assert metrics_collector._percentile(values, 100) == 50.0

    def test_filter_metrics_data_no_filters(self, metrics_collector):
        """Test filtering metrics data with no filters."""
        data = {
            "response_time": {
                "control": [100.0, 150.0],
                "treatment": [120.0]
            },
            "confidence": {
                "control": [0.95],
                "treatment": [0.88]
            }
        }
        
        result = metrics_collector._filter_metrics_data(data, None, None, None)
        assert result == data

    def test_filter_metrics_data_variant_filter(self, metrics_collector):
        """Test filtering metrics data by variant IDs."""
        data = {
            "response_time": {
                "control": [100.0, 150.0],
                "treatment": [120.0]
            }
        }
        
        result = metrics_collector._filter_metrics_data(data, ["control"], None, None)
        expected = {
            "response_time": {
                "control": [100.0, 150.0]
            }
        }
        
        assert result == expected

    def test_filter_metrics_data_metric_filter(self, metrics_collector):
        """Test filtering metrics data by metric names."""
        data = {
            "response_time": {
                "control": [100.0, 150.0]
            },
            "confidence": {
                "control": [0.95]
            }
        }
        
        result = metrics_collector._filter_metrics_data(data, None, ["response_time"], None)
        expected = {
            "response_time": {
                "control": [100.0, 150.0]
            }
        }
        
        assert result == expected

    @pytest.mark.asyncio
    async def test_cache_metric_without_cache_manager(self, metrics_collector):
        """Test caching metric when cache manager is not available."""
        metric = ExperimentMetric(
            "exp_001", "control", "user_1", "response_time", 100.0, datetime.utcnow()
        )
        
        with patch('prompt_sentinel.experiments.collectors.cache_manager', None):
            # Should not raise exception
            await metrics_collector._cache_metric(metric)

    @pytest.mark.asyncio
    async def test_cache_metric_with_cache_manager(self, metrics_collector):
        """Test caching metric with Redis cache manager."""
        metric = ExperimentMetric(
            "exp_001", "control", "user_1", "response_time", 100.0, datetime.utcnow()
        )
        
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = True
            mock_cache.lpush = AsyncMock()
            mock_cache.ltrim = AsyncMock()
            mock_cache.expire = AsyncMock()
            
            await metrics_collector._cache_metric(metric)
            
            expected_key = "experiment_metric:exp_001:control:response_time"
            mock_cache.lpush.assert_called_once()
            mock_cache.ltrim.assert_called_once_with(expected_key, 0, 999)
            mock_cache.expire.assert_called_once_with(expected_key, 86400)

    @pytest.mark.asyncio
    async def test_cache_metric_redis_error(self, metrics_collector):
        """Test handling Redis errors when caching metrics."""
        metric = ExperimentMetric(
            "exp_001", "control", "user_1", "response_time", 100.0, datetime.utcnow()
        )
        
        with patch('prompt_sentinel.experiments.collectors.cache_manager') as mock_cache:
            mock_cache.connected = True
            mock_cache.lpush = AsyncMock(side_effect=Exception("Redis error"))
            
            # Should not raise exception, just log warning
            await metrics_collector._cache_metric(metric)