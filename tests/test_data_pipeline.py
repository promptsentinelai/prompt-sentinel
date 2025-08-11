# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Data pipeline tests for PromptSentinel."""

import pytest
import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Iterator, AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch
import uuid
from collections import defaultdict
import pandas as pd
import numpy as np

from prompt_sentinel.models.schemas import Message, Role, Verdict

# Skip all tests in this file - feature not implemented
pytestmark = pytest.mark.skip(reason="Feature not yet implemented")



class TestDataIngestion:
    """Test data ingestion pipelines."""

    @pytest.fixture
    def ingestion_pipeline(self):
        """Create data ingestion pipeline."""
        from prompt_sentinel.pipeline.ingestion import IngestionPipeline
        return IngestionPipeline()

    @pytest.mark.asyncio
    async def test_streaming_ingestion(self, ingestion_pipeline):
        """Test real-time streaming data ingestion."""
        # Configure streaming sources
        stream_config = {
            "sources": [
                {
                    "name": "kafka_detections",
                    "type": "kafka",
                    "config": {
                        "bootstrap_servers": ["localhost:9092"],
                        "topics": ["detection_events"],
                        "group_id": "ingestion_consumer"
                    }
                },
                {
                    "name": "api_stream",
                    "type": "webhook",
                    "config": {
                        "endpoint": "/webhook/detections",
                        "authentication": "api_key"
                    }
                }
            ],
            "processors": [
                {
                    "name": "validator",
                    "type": "validation",
                    "config": {"schema": "detection_schema"}
                },
                {
                    "name": "enricher",
                    "type": "enrichment",
                    "config": {"lookup_tables": ["users", "threats"]}
                }
            ]
        }
        
        await ingestion_pipeline.configure_streams(stream_config)
        
        # Start streaming ingestion
        ingestion_task = asyncio.create_task(
            ingestion_pipeline.start_streaming()
        )
        
        # Simulate incoming data
        test_events = [
            {
                "detection_id": f"det_{i}",
                "timestamp": datetime.utcnow().isoformat(),
                "prompt": f"Test prompt {i}",
                "verdict": "BLOCK" if i % 2 == 0 else "ALLOW"
            }
            for i in range(100)
        ]
        
        # Feed test data
        for event in test_events:
            await ingestion_pipeline.process_event(event)
        
        await asyncio.sleep(2)
        
        # Check ingestion metrics
        metrics = await ingestion_pipeline.get_ingestion_metrics()
        
        assert metrics["events_processed"] >= 100
        assert metrics["processing_rate"] > 0
        assert metrics["error_rate"] < 0.1
        
        # Stop streaming
        ingestion_task.cancel()

    @pytest.mark.asyncio
    async def test_batch_ingestion(self, ingestion_pipeline):
        """Test batch data ingestion."""
        # Configure batch sources
        batch_config = {
            "sources": [
                {
                    "name": "csv_logs",
                    "type": "csv",
                    "config": {
                        "file_path": "/data/detection_logs.csv",
                        "delimiter": ",",
                        "header": True
                    }
                },
                {
                    "name": "json_exports",
                    "type": "json_lines",
                    "config": {
                        "file_path": "/data/detections.jsonl",
                        "batch_size": 1000
                    }
                }
            ],
            "schedule": {
                "type": "cron",
                "expression": "0 */6 * * *"  # Every 6 hours
            }
        }
        
        await ingestion_pipeline.configure_batch_jobs(batch_config)
        
        # Create mock data files
        mock_csv_data = pd.DataFrame({
            "detection_id": [f"det_{i}" for i in range(1000)],
            "timestamp": [datetime.utcnow() for _ in range(1000)],
            "prompt": [f"Prompt {i}" for i in range(1000)],
            "verdict": ["ALLOW", "BLOCK"] * 500
        })
        
        # Execute batch ingestion
        with patch('pandas.read_csv', return_value=mock_csv_data):
            result = await ingestion_pipeline.execute_batch_ingestion("csv_logs")
            
            assert result["status"] == "completed"
            assert result["records_processed"] == 1000
            assert result["errors"] == 0

    @pytest.mark.asyncio
    async def test_data_validation(self, ingestion_pipeline):
        """Test data validation during ingestion."""
        # Define validation schema
        validation_schema = {
            "detection_id": {"type": "string", "required": True, "pattern": r"^det_\d+$"},
            "timestamp": {"type": "datetime", "required": True},
            "prompt": {"type": "string", "required": True, "max_length": 10000},
            "verdict": {"type": "enum", "values": ["ALLOW", "BLOCK", "FLAG", "STRIP"]},
            "confidence": {"type": "float", "min": 0.0, "max": 1.0}
        }
        
        await ingestion_pipeline.set_validation_schema(validation_schema)
        
        # Test valid records
        valid_records = [
            {
                "detection_id": "det_1",
                "timestamp": "2024-01-15T10:30:00Z",
                "prompt": "Valid prompt",
                "verdict": "ALLOW",
                "confidence": 0.85
            }
        ]
        
        validation_result = await ingestion_pipeline.validate_records(valid_records)
        
        assert validation_result["valid_count"] == 1
        assert validation_result["invalid_count"] == 0
        
        # Test invalid records
        invalid_records = [
            {
                "detection_id": "invalid_id",  # Wrong format
                "timestamp": "not-a-date",
                "prompt": "x" * 20000,  # Too long
                "verdict": "INVALID",  # Not in enum
                "confidence": 1.5  # Out of range
            }
        ]
        
        validation_result = await ingestion_pipeline.validate_records(invalid_records)
        
        assert validation_result["valid_count"] == 0
        assert validation_result["invalid_count"] == 1
        assert len(validation_result["errors"]) == 5  # 5 validation failures

    @pytest.mark.asyncio
    async def test_data_deduplication(self, ingestion_pipeline):
        """Test duplicate record handling."""
        # Configure deduplication
        dedup_config = {
            "key_fields": ["detection_id"],
            "time_window": "1h",
            "strategy": "keep_latest"
        }
        
        await ingestion_pipeline.configure_deduplication(dedup_config)
        
        # Test data with duplicates
        records_with_dupes = [
            {"detection_id": "det_1", "timestamp": "2024-01-15T10:00:00Z", "version": 1},
            {"detection_id": "det_2", "timestamp": "2024-01-15T10:01:00Z", "version": 1},
            {"detection_id": "det_1", "timestamp": "2024-01-15T10:30:00Z", "version": 2},  # Duplicate
            {"detection_id": "det_3", "timestamp": "2024-01-15T10:02:00Z", "version": 1}
        ]
        
        dedup_result = await ingestion_pipeline.deduplicate_records(records_with_dupes)
        
        assert dedup_result["original_count"] == 4
        assert dedup_result["deduplicated_count"] == 3
        assert dedup_result["duplicates_removed"] == 1
        
        # Check that latest version was kept
        remaining_det_1 = next(
            r for r in dedup_result["records"] 
            if r["detection_id"] == "det_1"
        )
        assert remaining_det_1["version"] == 2

    @pytest.mark.asyncio
    async def test_data_partitioning(self, ingestion_pipeline):
        """Test data partitioning strategies."""
        # Configure partitioning
        partition_config = {
            "strategy": "time_based",
            "partition_field": "timestamp",
            "partition_format": "YYYY/MM/DD/HH",
            "partition_size": "1GB"
        }
        
        await ingestion_pipeline.configure_partitioning(partition_config)
        
        # Generate time-distributed data
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        time_distributed_data = []
        
        for hour in range(24):
            for minute in range(0, 60, 10):  # Every 10 minutes
                timestamp = base_time + timedelta(hours=hour, minutes=minute)
                time_distributed_data.append({
                    "detection_id": f"det_{hour}_{minute}",
                    "timestamp": timestamp.isoformat(),
                    "data": "sample_data"
                })
        
        # Partition data
        partition_result = await ingestion_pipeline.partition_data(time_distributed_data)
        
        assert partition_result["partitions_created"] == 24  # 24 hours
        assert all("2024/01/15" in path for path in partition_result["partition_paths"])
        
        # Verify partition distribution
        for partition_info in partition_result["partition_details"]:
            assert partition_info["record_count"] == 6  # 6 records per hour


class TestDataTransformation:
    """Test data transformation pipelines."""

    @pytest.fixture
    def transform_pipeline(self):
        """Create transformation pipeline."""
        from prompt_sentinel.pipeline.transform import TransformationPipeline
        return TransformationPipeline()

    @pytest.mark.asyncio
    async def test_schema_transformation(self, transform_pipeline):
        """Test schema transformation and mapping."""
        # Define transformation mapping
        schema_mapping = {
            "source_schema": {
                "det_id": "detection_id",
                "ts": "timestamp",
                "msg": "prompt", 
                "result": "verdict",
                "score": "confidence"
            },
            "transformations": [
                {
                    "field": "timestamp",
                    "operation": "parse_datetime",
                    "format": "unix_timestamp"
                },
                {
                    "field": "verdict",
                    "operation": "map_values",
                    "mapping": {"0": "ALLOW", "1": "BLOCK", "2": "FLAG"}
                },
                {
                    "field": "confidence",
                    "operation": "normalize",
                    "range": [0, 1]
                }
            ]
        }
        
        await transform_pipeline.configure_schema_mapping(schema_mapping)
        
        # Source data in old format
        source_data = [
            {
                "det_id": "det_001",
                "ts": 1643723400,  # Unix timestamp
                "msg": "Test prompt",
                "result": "1",  # String representation
                "score": 85  # 0-100 scale
            }
        ]
        
        # Transform data
        transformed = await transform_pipeline.apply_schema_transformation(source_data)
        
        assert len(transformed) == 1
        record = transformed[0]
        
        assert record["detection_id"] == "det_001"
        assert "T" in record["timestamp"]  # ISO format
        assert record["verdict"] == "BLOCK"
        assert 0 <= record["confidence"] <= 1

    @pytest.mark.asyncio
    async def test_data_enrichment(self, transform_pipeline):
        """Test data enrichment from external sources."""
        # Configure enrichment sources
        enrichment_config = {
            "sources": [
                {
                    "name": "user_lookup",
                    "type": "database",
                    "config": {
                        "table": "users",
                        "key_field": "user_id",
                        "fields": ["account_type", "risk_level", "country"]
                    }
                },
                {
                    "name": "ip_geolocation",
                    "type": "api",
                    "config": {
                        "endpoint": "https://ip-api.com/json/{ip}",
                        "cache_ttl": 3600
                    }
                }
            ]
        }
        
        await transform_pipeline.configure_enrichment(enrichment_config)
        
        # Mock enrichment data
        mock_user_data = {
            "user_123": {"account_type": "premium", "risk_level": "low", "country": "US"}
        }
        
        mock_ip_data = {
            "192.168.1.1": {"country": "US", "city": "New York", "isp": "Example ISP"}
        }
        
        with patch('prompt_sentinel.pipeline.transform.database_lookup', 
                  return_value=mock_user_data), \
             patch('prompt_sentinel.pipeline.transform.api_call', 
                  return_value=mock_ip_data):
            
            # Data to enrich
            base_data = [
                {
                    "detection_id": "det_1",
                    "user_id": "user_123",
                    "source_ip": "192.168.1.1",
                    "prompt": "Test prompt"
                }
            ]
            
            enriched = await transform_pipeline.enrich_data(base_data)
            
            assert len(enriched) == 1
            record = enriched[0]
            
            # Should contain original and enriched data
            assert record["detection_id"] == "det_1"
            assert record["account_type"] == "premium"
            assert record["city"] == "New York"

    @pytest.mark.asyncio
    async def test_data_aggregation(self, transform_pipeline):
        """Test data aggregation operations."""
        # Configure aggregation rules
        aggregation_config = {
            "time_window": "5m",
            "group_by": ["user_id", "verdict"],
            "aggregations": [
                {"field": "confidence", "operation": "avg", "alias": "avg_confidence"},
                {"field": "detection_id", "operation": "count", "alias": "detection_count"},
                {"field": "confidence", "operation": "max", "alias": "max_confidence"},
                {"field": "timestamp", "operation": "min", "alias": "first_seen"},
                {"field": "timestamp", "operation": "max", "alias": "last_seen"}
            ]
        }
        
        await transform_pipeline.configure_aggregation(aggregation_config)
        
        # Generate sample data
        base_time = datetime.utcnow()
        raw_detections = []
        
        for i in range(100):
            raw_detections.append({
                "detection_id": f"det_{i}",
                "user_id": f"user_{i % 10}",  # 10 different users
                "verdict": "BLOCK" if i % 3 == 0 else "ALLOW",
                "confidence": 0.5 + (i % 50) / 100,  # 0.5 to 0.99
                "timestamp": (base_time + timedelta(seconds=i * 3)).isoformat()
            })
        
        # Perform aggregation
        aggregated = await transform_pipeline.aggregate_data(raw_detections)
        
        # Should have groups for each user_id + verdict combination
        assert len(aggregated) > 10  # At least one group per user
        
        # Verify aggregation structure
        for group in aggregated:
            assert "user_id" in group
            assert "verdict" in group
            assert "avg_confidence" in group
            assert "detection_count" in group
            assert group["detection_count"] > 0

    @pytest.mark.asyncio
    async def test_data_filtering(self, transform_pipeline):
        """Test data filtering operations."""
        # Configure filters
        filter_config = {
            "filters": [
                {
                    "name": "confidence_filter",
                    "condition": "confidence >= 0.7"
                },
                {
                    "name": "verdict_filter", 
                    "condition": "verdict in ['BLOCK', 'FLAG']"
                },
                {
                    "name": "time_filter",
                    "condition": "timestamp >= now() - interval '24 hours'"
                },
                {
                    "name": "user_whitelist",
                    "condition": "user_id not in ['test_user', 'admin']"
                }
            ],
            "combination": "AND"  # All filters must pass
        }
        
        await transform_pipeline.configure_filters(filter_config)
        
        # Test data with mixed characteristics
        test_data = [
            {
                "detection_id": "det_1",
                "user_id": "user_1",
                "verdict": "BLOCK",
                "confidence": 0.8,
                "timestamp": datetime.utcnow().isoformat()
            },  # Should pass all filters
            {
                "detection_id": "det_2", 
                "user_id": "user_2",
                "verdict": "ALLOW",
                "confidence": 0.9,
                "timestamp": datetime.utcnow().isoformat()
            },  # Fails verdict filter
            {
                "detection_id": "det_3",
                "user_id": "test_user",
                "verdict": "BLOCK", 
                "confidence": 0.8,
                "timestamp": datetime.utcnow().isoformat()
            },  # Fails user whitelist
            {
                "detection_id": "det_4",
                "user_id": "user_3",
                "verdict": "BLOCK",
                "confidence": 0.5,
                "timestamp": datetime.utcnow().isoformat()
            }   # Fails confidence filter
        ]
        
        filtered = await transform_pipeline.apply_filters(test_data)
        
        # Only det_1 should pass all filters
        assert len(filtered) == 1
        assert filtered[0]["detection_id"] == "det_1"

    @pytest.mark.asyncio
    async def test_data_normalization(self, transform_pipeline):
        """Test data normalization and standardization."""
        # Configure normalization
        normalization_config = {
            "numeric_fields": [
                {
                    "field": "confidence",
                    "method": "min_max",
                    "range": [0, 1]
                },
                {
                    "field": "response_time",
                    "method": "z_score"
                }
            ],
            "text_fields": [
                {
                    "field": "prompt",
                    "operations": ["lowercase", "strip", "normalize_whitespace"]
                },
                {
                    "field": "user_agent",
                    "operations": ["extract_browser", "extract_os"]
                }
            ],
            "categorical_fields": [
                {
                    "field": "verdict",
                    "method": "one_hot_encoding"
                }
            ]
        }
        
        await transform_pipeline.configure_normalization(normalization_config)
        
        # Test data with various formats
        raw_data = [
            {
                "detection_id": "det_1",
                "confidence": 75,  # 0-100 scale
                "response_time": 150,  # milliseconds
                "prompt": "  Test PROMPT with   Extra Spaces  ",
                "verdict": "BLOCK",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        ]
        
        normalized = await transform_pipeline.normalize_data(raw_data)
        
        assert len(normalized) == 1
        record = normalized[0]
        
        # Check normalization results
        assert 0 <= record["confidence"] <= 1  # Min-max normalized
        assert record["prompt"] == "test prompt with extra spaces"  # Text normalized
        assert "browser" in record  # User agent extracted
        assert "os" in record


class TestDataProcessing:
    """Test data processing and analytics pipelines."""

    @pytest.fixture
    def processing_pipeline(self):
        """Create data processing pipeline."""
        from prompt_sentinel.pipeline.processing import ProcessingPipeline
        return ProcessingPipeline()

    @pytest.mark.asyncio
    async def test_stream_processing(self, processing_pipeline):
        """Test real-time stream processing."""
        # Configure stream processing
        stream_config = {
            "input_streams": ["detection_events"],
            "processing_windows": [
                {
                    "name": "sliding_5min",
                    "type": "sliding",
                    "size": "5m",
                    "slide": "1m"
                },
                {
                    "name": "tumbling_1hour",
                    "type": "tumbling", 
                    "size": "1h"
                }
            ],
            "operations": [
                {
                    "name": "threat_aggregation",
                    "window": "sliding_5min",
                    "operation": "count",
                    "group_by": ["verdict", "user_id"],
                    "filter": "verdict = 'BLOCK'"
                },
                {
                    "name": "confidence_stats",
                    "window": "tumbling_1hour",
                    "operation": "statistics",
                    "field": "confidence",
                    "stats": ["mean", "std", "min", "max", "percentiles"]
                }
            ]
        }
        
        await processing_pipeline.configure_stream_processing(stream_config)
        
        # Start stream processing
        processing_task = asyncio.create_task(
            processing_pipeline.start_stream_processing()
        )
        
        # Generate streaming data
        for i in range(1000):
            event = {
                "detection_id": f"det_{i}",
                "user_id": f"user_{i % 20}",
                "verdict": "BLOCK" if i % 4 == 0 else "ALLOW",
                "confidence": 0.5 + (i % 50) / 100,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await processing_pipeline.process_stream_event(event)
            
            if i % 100 == 0:
                await asyncio.sleep(0.1)  # Brief pause
        
        await asyncio.sleep(2)
        
        # Get processing results
        results = await processing_pipeline.get_processing_results()
        
        assert "threat_aggregation" in results
        assert "confidence_stats" in results
        
        # Check threat aggregation
        threat_counts = results["threat_aggregation"]
        assert any(count["count"] > 0 for count in threat_counts)
        
        # Check confidence statistics
        conf_stats = results["confidence_stats"]
        assert "mean" in conf_stats
        assert "std" in conf_stats
        assert 0 <= conf_stats["mean"] <= 1
        
        processing_task.cancel()

    @pytest.mark.asyncio
    async def test_batch_processing(self, processing_pipeline):
        """Test large-scale batch processing."""
        # Configure batch processing
        batch_config = {
            "chunk_size": 1000,
            "parallelism": 4,
            "operations": [
                {
                    "name": "feature_extraction",
                    "type": "ml_feature",
                    "config": {"features": ["text_length", "special_chars", "entropy"]}
                },
                {
                    "name": "anomaly_detection",
                    "type": "ml_model",
                    "config": {"model": "isolation_forest", "threshold": 0.1}
                },
                {
                    "name": "risk_scoring",
                    "type": "composite_score",
                    "config": {"weights": {"confidence": 0.4, "anomaly": 0.6}}
                }
            ]
        }
        
        await processing_pipeline.configure_batch_processing(batch_config)
        
        # Generate large dataset
        large_dataset = []
        for i in range(10000):
            large_dataset.append({
                "detection_id": f"det_{i}",
                "prompt": f"Test prompt number {i} with varying content and length patterns",
                "confidence": 0.3 + (i % 70) / 100,
                "verdict": "BLOCK" if i % 5 == 0 else "ALLOW"
            })
        
        # Process in batches
        processing_results = await processing_pipeline.process_batch(large_dataset)
        
        assert processing_results["total_processed"] == 10000
        assert processing_results["chunks_processed"] == 10  # 10000 / 1000
        assert processing_results["processing_time"] > 0
        
        # Verify processing output
        processed_data = processing_results["data"]
        sample_record = processed_data[0]
        
        assert "text_length" in sample_record  # Feature extraction
        assert "anomaly_score" in sample_record  # Anomaly detection
        assert "risk_score" in sample_record  # Risk scoring

    @pytest.mark.asyncio
    async def test_machine_learning_pipeline(self, processing_pipeline):
        """Test ML model training and inference pipeline."""
        # Configure ML pipeline
        ml_config = {
            "training": {
                "model_type": "random_forest",
                "features": ["confidence", "text_length", "special_char_ratio"],
                "target": "verdict",
                "validation_split": 0.2,
                "hyperparameters": {
                    "n_estimators": 100,
                    "max_depth": 10
                }
            },
            "inference": {
                "batch_size": 100,
                "confidence_threshold": 0.7
            }
        }
        
        await processing_pipeline.configure_ml_pipeline(ml_config)
        
        # Generate training data
        training_data = []
        for i in range(5000):
            prompt = f"Test prompt {i}"
            special_chars = sum(1 for c in prompt if not c.isalnum() and not c.isspace())
            
            training_data.append({
                "detection_id": f"train_{i}",
                "confidence": 0.3 + (i % 70) / 100,
                "text_length": len(prompt),
                "special_char_ratio": special_chars / len(prompt),
                "verdict": "BLOCK" if i % 4 == 0 else "ALLOW"
            })
        
        # Train model
        training_result = await processing_pipeline.train_ml_model(training_data)
        
        assert training_result["model_trained"] is True
        assert training_result["accuracy"] > 0.5  # Reasonable accuracy
        assert training_result["model_id"] is not None
        
        # Test inference
        inference_data = []
        for i in range(1000):
            prompt = f"Inference prompt {i}"
            special_chars = sum(1 for c in prompt if not c.isalnum() and not c.isspace())
            
            inference_data.append({
                "detection_id": f"inf_{i}",
                "confidence": 0.4 + (i % 60) / 100,
                "text_length": len(prompt),
                "special_char_ratio": special_chars / len(prompt)
            })
        
        inference_result = await processing_pipeline.run_ml_inference(
            inference_data,
            model_id=training_result["model_id"]
        )
        
        assert inference_result["predictions_made"] == 1000
        assert len(inference_result["predictions"]) == 1000
        
        # Check prediction format
        sample_prediction = inference_result["predictions"][0]
        assert "predicted_verdict" in sample_prediction
        assert "prediction_confidence" in sample_prediction

    @pytest.mark.asyncio
    async def test_data_quality_monitoring(self, processing_pipeline):
        """Test data quality monitoring and validation."""
        # Configure quality monitoring
        quality_config = {
            "checks": [
                {
                    "name": "completeness",
                    "type": "null_check",
                    "fields": ["detection_id", "timestamp", "verdict"],
                    "threshold": 0.95  # 95% completeness required
                },
                {
                    "name": "validity",
                    "type": "format_check", 
                    "rules": [
                        {"field": "confidence", "range": [0, 1]},
                        {"field": "verdict", "values": ["ALLOW", "BLOCK", "FLAG", "STRIP"]}
                    ]
                },
                {
                    "name": "consistency",
                    "type": "logic_check",
                    "rules": [
                        "if verdict == 'BLOCK' then confidence >= 0.5"
                    ]
                },
                {
                    "name": "freshness",
                    "type": "time_check",
                    "field": "timestamp",
                    "max_age": "2h"
                }
            ]
        }
        
        await processing_pipeline.configure_quality_monitoring(quality_config)
        
        # Generate data with quality issues
        test_data = []
        
        # Good data (80%)
        for i in range(800):
            test_data.append({
                "detection_id": f"det_{i}",
                "timestamp": datetime.utcnow().isoformat(),
                "prompt": f"Prompt {i}",
                "verdict": "ALLOW",
                "confidence": 0.3 + (i % 60) / 100
            })
        
        # Data with issues (20%)
        for i in range(200):
            bad_data = {
                "detection_id": f"bad_{i}",
                "timestamp": (datetime.utcnow() - timedelta(hours=5)).isoformat(),  # Too old
                "prompt": f"Bad prompt {i}",
                "verdict": "INVALID_VERDICT",  # Invalid value
                "confidence": 1.5 if i % 2 == 0 else None  # Out of range or null
            }
            
            # Some missing required fields
            if i % 3 == 0:
                bad_data.pop("detection_id")
            
            test_data.append(bad_data)
        
        # Run quality checks
        quality_result = await processing_pipeline.run_quality_checks(test_data)
        
        assert quality_result["total_records"] == 1000
        assert quality_result["overall_quality_score"] < 1.0  # Should detect issues
        
        # Check individual quality metrics
        checks = quality_result["check_results"]
        
        # Completeness check should fail (missing detection_ids)
        completeness = next(c for c in checks if c["name"] == "completeness")
        assert completeness["passed"] is False
        
        # Validity check should fail (invalid verdicts and confidence values)  
        validity = next(c for c in checks if c["name"] == "validity")
        assert validity["passed"] is False
        
        # Freshness check should fail (old timestamps)
        freshness = next(c for c in checks if c["name"] == "freshness")
        assert freshness["passed"] is False

    @pytest.mark.asyncio
    async def test_pipeline_orchestration(self, processing_pipeline):
        """Test orchestrating complex multi-stage pipelines."""
        # Define complex pipeline
        pipeline_definition = {
            "name": "comprehensive_detection_pipeline",
            "stages": [
                {
                    "name": "ingestion",
                    "type": "data_ingestion",
                    "config": {"source": "api_stream"},
                    "outputs": ["raw_detections"]
                },
                {
                    "name": "validation",
                    "type": "data_validation",
                    "inputs": ["raw_detections"],
                    "outputs": ["valid_detections", "invalid_detections"],
                    "config": {"schema": "detection_schema"}
                },
                {
                    "name": "enrichment",
                    "type": "data_enrichment", 
                    "inputs": ["valid_detections"],
                    "outputs": ["enriched_detections"],
                    "config": {"sources": ["user_lookup", "threat_intel"]}
                },
                {
                    "name": "feature_extraction",
                    "type": "feature_engineering",
                    "inputs": ["enriched_detections"],
                    "outputs": ["feature_vectors"],
                    "config": {"feature_set": "detection_features_v2"}
                },
                {
                    "name": "ml_inference",
                    "type": "ml_prediction",
                    "inputs": ["feature_vectors"],
                    "outputs": ["ml_predictions"],
                    "config": {"model": "detection_classifier_v3"}
                },
                {
                    "name": "post_processing",
                    "type": "result_aggregation",
                    "inputs": ["ml_predictions"],
                    "outputs": ["final_results"],
                    "config": {"combine_strategy": "ensemble"}
                }
            ],
            "error_handling": {
                "retry_policy": {"max_attempts": 3},
                "dead_letter_queue": True
            }
        }
        
        pipeline_id = await processing_pipeline.create_pipeline(pipeline_definition)
        
        # Execute pipeline
        execution = await processing_pipeline.execute_pipeline(
            pipeline_id=pipeline_id,
            input_data=[
                {
                    "detection_id": "orchestration_test",
                    "prompt": "Test orchestration prompt",
                    "timestamp": datetime.utcnow().isoformat()
                }
            ]
        )
        
        # Monitor pipeline execution
        await asyncio.sleep(3)
        
        status = await processing_pipeline.get_pipeline_status(execution["execution_id"])
        
        assert status["status"] in ["completed", "running"]
        assert len(status["stage_statuses"]) == 6  # All stages tracked
        
        # Verify stage progression
        completed_stages = [
            stage for stage in status["stage_statuses"]
            if stage["status"] == "completed"
        ]
        
        assert len(completed_stages) >= 1  # At least some stages completed
        
        # Check final outputs if pipeline completed
        if status["status"] == "completed":
            outputs = await processing_pipeline.get_pipeline_outputs(execution["execution_id"])
            assert "final_results" in outputs


if __name__ == "__main__":
    pytest.main([__file__, "-v"])