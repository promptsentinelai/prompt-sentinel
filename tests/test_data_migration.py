"""Data migration and schema evolution tests for PromptSentinel."""

import pytest
import asyncio
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any
from unittest.mock import AsyncMock, MagicMock, patch
import tempfile
import shutil
from pathlib import Path

from prompt_sentinel.models.schemas import Message, Role, Verdict

# Skip all tests in this file - feature not implemented
pytestmark = pytest.mark.skip(reason="Feature not yet implemented")



class TestSchemaMigration:
    """Test database schema migrations."""

    @pytest.fixture
    def migration_manager(self):
        """Create migration manager."""
        from prompt_sentinel.migration.manager import MigrationManager
        return MigrationManager(
            database_url="sqlite:///test.db",
            migrations_dir="migrations"
        )

    @pytest.mark.asyncio
    async def test_migration_execution(self, migration_manager):
        """Test executing migrations."""
        # Create test migrations
        migrations = [
            {
                "version": "001",
                "name": "initial_schema",
                "up": """
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY,
                        email TEXT NOT NULL,
                        created_at TIMESTAMP
                    );
                """,
                "down": "DROP TABLE users;"
            },
            {
                "version": "002",
                "name": "add_detections_table",
                "up": """
                    CREATE TABLE detections (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER,
                        verdict TEXT,
                        confidence REAL,
                        created_at TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    );
                """,
                "down": "DROP TABLE detections;"
            }
        ]
        
        # Execute migrations
        for migration in migrations:
            result = await migration_manager.apply_migration(migration)
            assert result["status"] == "success"
            assert result["version"] == migration["version"]
        
        # Verify schema
        schema = await migration_manager.get_current_schema()
        assert "users" in schema["tables"]
        assert "detections" in schema["tables"]

    @pytest.mark.asyncio
    async def test_migration_rollback(self, migration_manager):
        """Test rolling back migrations."""
        # Apply migration
        migration = {
            "version": "003",
            "name": "add_column",
            "up": "ALTER TABLE users ADD COLUMN status TEXT;",
            "down": "ALTER TABLE users DROP COLUMN status;"
        }
        
        await migration_manager.apply_migration(migration)
        
        # Verify column exists
        schema = await migration_manager.get_table_schema("users")
        assert "status" in [col["name"] for col in schema["columns"]]
        
        # Rollback
        result = await migration_manager.rollback_migration("003")
        assert result["status"] == "success"
        
        # Verify column removed
        schema = await migration_manager.get_table_schema("users")
        assert "status" not in [col["name"] for col in schema["columns"]]

    @pytest.mark.asyncio
    async def test_migration_versioning(self, migration_manager):
        """Test migration version tracking."""
        # Get current version
        current = await migration_manager.get_current_version()
        
        # Apply new migration
        await migration_manager.apply_migration({
            "version": "004",
            "name": "test_migration",
            "up": "SELECT 1;",
            "down": "SELECT 1;"
        })
        
        # Check version updated
        new_version = await migration_manager.get_current_version()
        assert new_version > current
        assert new_version == "004"
        
        # Get migration history
        history = await migration_manager.get_migration_history()
        assert len(history) > 0
        assert history[-1]["version"] == "004"

    @pytest.mark.asyncio
    async def test_migration_validation(self, migration_manager):
        """Test migration validation before execution."""
        # Invalid migration (syntax error)
        invalid_migration = {
            "version": "005",
            "name": "invalid",
            "up": "CREATE TABLE INVALID SYNTAX;",
            "down": "DROP TABLE test;"
        }
        
        # Should fail validation
        validation = await migration_manager.validate_migration(invalid_migration)
        assert validation["valid"] is False
        assert "error" in validation
        
        # Valid migration
        valid_migration = {
            "version": "005",
            "name": "valid",
            "up": "CREATE TABLE test (id INTEGER);",
            "down": "DROP TABLE test;"
        }
        
        validation = await migration_manager.validate_migration(valid_migration)
        assert validation["valid"] is True

    @pytest.mark.asyncio
    async def test_migration_dependencies(self, migration_manager):
        """Test migration dependencies."""
        # Define migrations with dependencies
        migrations = [
            {
                "version": "010",
                "name": "base_table",
                "depends_on": [],
                "up": "CREATE TABLE base (id INTEGER);"
            },
            {
                "version": "011",
                "name": "dependent_table",
                "depends_on": ["010"],
                "up": "CREATE TABLE dependent (base_id INTEGER, FOREIGN KEY (base_id) REFERENCES base(id));"
            }
        ]
        
        # Try to apply dependent first (should fail)
        with pytest.raises(Exception) as exc:
            await migration_manager.apply_migration(migrations[1])
        assert "dependency" in str(exc.value).lower()
        
        # Apply in correct order
        await migration_manager.apply_migration(migrations[0])
        await migration_manager.apply_migration(migrations[1])
        
        # Both should be applied
        history = await migration_manager.get_migration_history()
        versions = [m["version"] for m in history]
        assert "010" in versions
        assert "011" in versions


class TestDataTransformation:
    """Test data transformation during migration."""

    @pytest.fixture
    def data_transformer(self):
        """Create data transformer."""
        from prompt_sentinel.migration.transformer import DataTransformer
        return DataTransformer()

    @pytest.mark.asyncio
    async def test_field_mapping(self, data_transformer):
        """Test field mapping transformation."""
        # Old format
        old_data = [
            {"user_name": "john", "detection_result": "malicious"},
            {"user_name": "jane", "detection_result": "safe"}
        ]
        
        # Define mapping
        mapping = {
            "user_name": "user_id",
            "detection_result": lambda x: "BLOCK" if x == "malicious" else "ALLOW"
        }
        
        # Transform data
        new_data = await data_transformer.transform(old_data, mapping)
        
        assert new_data[0]["user_id"] == "john"
        assert new_data[0]["detection_result"] == "BLOCK"
        assert new_data[1]["detection_result"] == "ALLOW"

    @pytest.mark.asyncio
    async def test_data_type_conversion(self, data_transformer):
        """Test data type conversion."""
        # String timestamps to datetime
        old_data = [
            {"timestamp": "2024-01-01 12:00:00", "score": "0.95"},
            {"timestamp": "2024-01-02 13:00:00", "score": "0.75"}
        ]
        
        # Define conversions
        conversions = {
            "timestamp": lambda x: datetime.strptime(x, "%Y-%m-%d %H:%M:%S"),
            "score": float
        }
        
        # Convert types
        converted = await data_transformer.convert_types(old_data, conversions)
        
        assert isinstance(converted[0]["timestamp"], datetime)
        assert isinstance(converted[0]["score"], float)
        assert converted[0]["score"] == 0.95

    @pytest.mark.asyncio
    async def test_data_validation_during_migration(self, data_transformer):
        """Test data validation during migration."""
        # Data with invalid entries
        data = [
            {"email": "valid@example.com", "age": 25},
            {"email": "invalid-email", "age": -5},
            {"email": "another@valid.com", "age": 30}
        ]
        
        # Define validation rules
        validators = {
            "email": lambda x: "@" in x and "." in x,
            "age": lambda x: 0 <= x <= 150
        }
        
        # Validate and filter
        valid_data = await data_transformer.validate_and_filter(data, validators)
        
        assert len(valid_data) == 2
        assert all(v["email"] != "invalid-email" for v in valid_data)
        assert all(v["age"] >= 0 for v in valid_data)

    @pytest.mark.asyncio
    async def test_data_aggregation_migration(self, data_transformer):
        """Test data aggregation during migration."""
        # Detailed records to aggregate
        detailed_data = [
            {"user": "john", "date": "2024-01-01", "count": 5},
            {"user": "john", "date": "2024-01-01", "count": 3},
            {"user": "john", "date": "2024-01-02", "count": 7},
            {"user": "jane", "date": "2024-01-01", "count": 10}
        ]
        
        # Aggregate by user and date
        aggregated = await data_transformer.aggregate(
            data=detailed_data,
            group_by=["user", "date"],
            aggregations={"count": "sum"}
        )
        
        assert len(aggregated) == 3
        john_jan1 = next(a for a in aggregated 
                         if a["user"] == "john" and a["date"] == "2024-01-01")
        assert john_jan1["count"] == 8


class TestBulkDataMigration:
    """Test bulk data migration operations."""

    @pytest.fixture
    def bulk_migrator(self):
        """Create bulk migrator."""
        from prompt_sentinel.migration.bulk import BulkMigrator
        return BulkMigrator(
            batch_size=1000,
            parallel_workers=4
        )

    @pytest.mark.asyncio
    async def test_batch_processing(self, bulk_migrator):
        """Test batch processing of large datasets."""
        # Generate large dataset
        total_records = 10000
        data = [{"id": i, "value": f"value_{i}"} for i in range(total_records)]
        
        processed_count = 0
        
        async def process_batch(batch):
            nonlocal processed_count
            processed_count += len(batch)
            # Simulate processing
            await asyncio.sleep(0.01)
            return [{"id": r["id"], "processed": True} for r in batch]
        
        # Process in batches
        results = await bulk_migrator.process_in_batches(data, process_batch)
        
        assert processed_count == total_records
        assert len(results) == total_records
        assert all(r["processed"] for r in results)

    @pytest.mark.asyncio
    async def test_parallel_migration(self, bulk_migrator):
        """Test parallel data migration."""
        # Multiple data sources
        sources = {
            "users": [{"id": i} for i in range(1000)],
            "detections": [{"id": i} for i in range(2000)],
            "configs": [{"id": i} for i in range(500)]
        }
        
        migrated = {}
        
        async def migrate_source(name, data):
            # Simulate migration work
            await asyncio.sleep(0.1)
            migrated[name] = len(data)
            return data
        
        # Migrate in parallel
        results = await bulk_migrator.migrate_parallel(sources, migrate_source)
        
        assert len(migrated) == 3
        assert migrated["users"] == 1000
        assert migrated["detections"] == 2000
        assert migrated["configs"] == 500

    @pytest.mark.asyncio
    async def test_resume_interrupted_migration(self, bulk_migrator):
        """Test resuming interrupted migration."""
        # Simulate interrupted migration
        total_records = 1000
        checkpoint_at = 600
        
        processed_ids = set()
        
        async def process_with_interruption(record):
            if record["id"] == checkpoint_at:
                raise Exception("Simulated interruption")
            processed_ids.add(record["id"])
            return record
        
        # First attempt (will be interrupted)
        data = [{"id": i} for i in range(total_records)]
        
        try:
            await bulk_migrator.migrate_with_checkpoint(
                data=data,
                processor=process_with_interruption,
                checkpoint_interval=100
            )
        except Exception:
            pass
        
        # Get checkpoint
        checkpoint = await bulk_migrator.get_last_checkpoint()
        assert checkpoint["last_processed_id"] < checkpoint_at
        
        # Resume from checkpoint
        async def process_resumed(record):
            processed_ids.add(record["id"])
            return record
        
        remaining_data = [{"id": i} for i in range(checkpoint["last_processed_id"], total_records)]
        await bulk_migrator.migrate_with_checkpoint(
            data=remaining_data,
            processor=process_resumed,
            resume_from=checkpoint
        )
        
        # All records should be processed
        assert len(processed_ids) == total_records - 1  # Minus the one that caused interruption


class TestBackwardCompatibility:
    """Test backward compatibility during migration."""

    @pytest.fixture
    def compatibility_manager(self):
        """Create compatibility manager."""
        from prompt_sentinel.migration.compatibility import CompatibilityManager
        return CompatibilityManager()

    @pytest.mark.asyncio
    async def test_dual_write_migration(self, compatibility_manager):
        """Test dual-write migration strategy."""
        # Configure dual write
        await compatibility_manager.enable_dual_write(
            old_table="detections_v1",
            new_table="detections_v2"
        )
        
        # Write data
        data = {"id": 1, "verdict": "BLOCK", "confidence": 0.95}
        
        result = await compatibility_manager.write(data)
        
        # Should write to both tables
        assert result["written_to"] == ["detections_v1", "detections_v2"]
        
        # Read should prefer new table
        read_result = await compatibility_manager.read(id=1)
        assert read_result["source"] == "detections_v2"

    @pytest.mark.asyncio
    async def test_feature_flag_migration(self, compatibility_manager):
        """Test feature flag controlled migration."""
        # Set feature flags
        await compatibility_manager.set_feature_flag("use_new_schema", False)
        
        # Operation uses old schema
        result = await compatibility_manager.execute_with_flag(
            flag="use_new_schema",
            old_operation=lambda: {"schema": "v1"},
            new_operation=lambda: {"schema": "v2"}
        )
        assert result["schema"] == "v1"
        
        # Enable new schema
        await compatibility_manager.set_feature_flag("use_new_schema", True)
        
        result = await compatibility_manager.execute_with_flag(
            flag="use_new_schema",
            old_operation=lambda: {"schema": "v1"},
            new_operation=lambda: {"schema": "v2"}
        )
        assert result["schema"] == "v2"

    @pytest.mark.asyncio
    async def test_gradual_rollout(self, compatibility_manager):
        """Test gradual rollout of migrations."""
        # Configure gradual rollout
        await compatibility_manager.configure_rollout(
            feature="new_detection_logic",
            percentage=20  # 20% of traffic
        )
        
        # Test traffic routing
        v1_count = 0
        v2_count = 0
        
        for i in range(1000):
            user_id = f"user_{i}"
            version = await compatibility_manager.get_version_for_user(
                user_id,
                feature="new_detection_logic"
            )
            
            if version == "v1":
                v1_count += 1
            else:
                v2_count += 1
        
        # Should be approximately 80/20 split
        assert 750 < v1_count < 850
        assert 150 < v2_count < 250


class TestDataIntegrityValidation:
    """Test data integrity during migration."""

    @pytest.fixture
    def integrity_validator(self):
        """Create integrity validator."""
        from prompt_sentinel.migration.integrity import IntegrityValidator
        return IntegrityValidator()

    @pytest.mark.asyncio
    async def test_checksum_validation(self, integrity_validator):
        """Test checksum validation of migrated data."""
        # Original data
        original_data = [
            {"id": 1, "value": "test1"},
            {"id": 2, "value": "test2"},
            {"id": 3, "value": "test3"}
        ]
        
        # Calculate checksums
        checksums = await integrity_validator.calculate_checksums(original_data)
        
        # Migrate data (simulated)
        migrated_data = original_data.copy()
        
        # Validate checksums
        validation = await integrity_validator.validate_checksums(
            migrated_data,
            checksums
        )
        assert validation["valid"] is True
        assert validation["mismatch_count"] == 0
        
        # Corrupt data
        migrated_data[1]["value"] = "corrupted"
        
        validation = await integrity_validator.validate_checksums(
            migrated_data,
            checksums
        )
        assert validation["valid"] is False
        assert validation["mismatch_count"] == 1

    @pytest.mark.asyncio
    async def test_referential_integrity(self, integrity_validator):
        """Test referential integrity validation."""
        # Tables with foreign keys
        users = [
            {"id": 1, "name": "john"},
            {"id": 2, "name": "jane"}
        ]
        
        detections = [
            {"id": 1, "user_id": 1, "verdict": "ALLOW"},
            {"id": 2, "user_id": 2, "verdict": "BLOCK"},
            {"id": 3, "user_id": 3, "verdict": "ALLOW"}  # Invalid reference
        ]
        
        # Check referential integrity
        issues = await integrity_validator.check_referential_integrity(
            parent_table=users,
            child_table=detections,
            parent_key="id",
            child_key="user_id"
        )
        
        assert len(issues) == 1
        assert issues[0]["child_id"] == 3
        assert issues[0]["missing_parent_id"] == 3

    @pytest.mark.asyncio
    async def test_constraint_validation(self, integrity_validator):
        """Test constraint validation after migration."""
        # Data with constraints
        data = [
            {"email": "valid@example.com", "age": 25, "score": 0.8},
            {"email": "invalid", "age": 200, "score": 1.5},
            {"email": "another@test.com", "age": 30, "score": 0.9}
        ]
        
        # Define constraints
        constraints = {
            "email": lambda x: "@" in x and "." in x,
            "age": lambda x: 0 <= x <= 150,
            "score": lambda x: 0 <= x <= 1
        }
        
        # Validate constraints
        violations = await integrity_validator.validate_constraints(
            data,
            constraints
        )
        
        assert len(violations) == 1
        assert violations[0]["record_index"] == 1
        assert set(violations[0]["failed_constraints"]) == {"email", "age", "score"}


class TestMigrationRollback:
    """Test migration rollback scenarios."""

    @pytest.fixture
    def rollback_manager(self):
        """Create rollback manager."""
        from prompt_sentinel.migration.rollback import RollbackManager
        return RollbackManager()

    @pytest.mark.asyncio
    async def test_snapshot_before_migration(self, rollback_manager):
        """Test creating snapshots before migration."""
        # Create snapshot
        snapshot_id = await rollback_manager.create_snapshot(
            tables=["users", "detections"],
            description="Before v2 migration"
        )
        
        assert snapshot_id is not None
        
        # Verify snapshot
        snapshot = await rollback_manager.get_snapshot(snapshot_id)
        assert snapshot["tables"] == ["users", "detections"]
        assert snapshot["status"] == "completed"
        assert snapshot["size"] > 0

    @pytest.mark.asyncio
    async def test_rollback_to_snapshot(self, rollback_manager):
        """Test rolling back to a snapshot."""
        # Create initial data
        initial_data = {"users": [{"id": 1, "name": "john"}]}
        
        # Create snapshot
        snapshot_id = await rollback_manager.create_snapshot_from_data(
            initial_data
        )
        
        # Modify data (simulated migration)
        current_data = {"users": [{"id": 1, "name": "modified"}]}
        
        # Rollback
        result = await rollback_manager.rollback_to_snapshot(snapshot_id)
        
        assert result["status"] == "success"
        assert result["restored_tables"] == ["users"]
        
        # Verify data restored
        restored_data = await rollback_manager.get_current_data()
        assert restored_data["users"][0]["name"] == "john"

    @pytest.mark.asyncio
    async def test_incremental_rollback(self, rollback_manager):
        """Test incremental rollback of migrations."""
        # Apply multiple migrations
        migrations = ["v1", "v2", "v3", "v4"]
        
        for version in migrations:
            await rollback_manager.record_migration(version)
        
        # Rollback last two migrations
        result = await rollback_manager.rollback_migrations(count=2)
        
        assert result["rolled_back"] == ["v4", "v3"]
        assert result["current_version"] == "v2"

    @pytest.mark.asyncio
    async def test_rollback_validation(self, rollback_manager):
        """Test validating rollback safety."""
        # Check if rollback is safe
        safety_check = await rollback_manager.is_rollback_safe(
            from_version="v3",
            to_version="v1"
        )
        
        if not safety_check["safe"]:
            assert "reasons" in safety_check
            # Might include: data loss, incompatible schemas, etc.


class TestCrossVersionTesting:
    """Test cross-version compatibility."""

    @pytest.mark.asyncio
    async def test_api_compatibility_across_versions(self):
        """Test API compatibility across schema versions."""
        from prompt_sentinel.migration.testing import CompatibilityTester
        
        tester = CompatibilityTester()
        
        # Define API versions
        v1_api = {
            "endpoint": "/detect",
            "request": {"text": "test"},
            "response": {"is_malicious": False}
        }
        
        v2_api = {
            "endpoint": "/v2/detect",
            "request": {"input": {"messages": [{"role": "user", "content": "test"}]}},
            "response": {"verdict": "ALLOW"}
        }
        
        # Test compatibility
        result = await tester.test_compatibility(
            old_version=v1_api,
            new_version=v2_api,
            adapter=lambda old: {
                "input": {"messages": [{"role": "user", "content": old["text"]}]}
            }
        )
        
        assert result["compatible"] is True
        assert result["adapter_works"] is True

    @pytest.mark.asyncio
    async def test_data_format_evolution(self):
        """Test data format evolution across versions."""
        from prompt_sentinel.migration.evolution import FormatEvolution
        
        evolution = FormatEvolution()
        
        # Version history
        formats = {
            "v1": {"fields": ["id", "text", "result"]},
            "v2": {"fields": ["id", "prompt", "verdict", "confidence"]},
            "v3": {"fields": ["id", "messages", "verdict", "confidence", "metadata"]}
        }
        
        # Test forward compatibility
        v1_data = {"id": 1, "text": "test", "result": "safe"}
        
        v2_data = await evolution.migrate_forward(v1_data, "v1", "v2")
        assert "prompt" in v2_data
        assert v2_data["prompt"] == "test"
        
        v3_data = await evolution.migrate_forward(v2_data, "v2", "v3")
        assert "messages" in v3_data
        assert "metadata" in v3_data


class TestMigrationMonitoring:
    """Test migration monitoring and alerting."""

    @pytest.fixture
    def migration_monitor(self):
        """Create migration monitor."""
        from prompt_sentinel.migration.monitor import MigrationMonitor
        return MigrationMonitor()

    @pytest.mark.asyncio
    async def test_migration_progress_tracking(self, migration_monitor):
        """Test tracking migration progress."""
        # Start migration
        migration_id = await migration_monitor.start_migration(
            name="v2_migration",
            total_records=10000
        )
        
        # Update progress
        for i in range(0, 10000, 1000):
            await migration_monitor.update_progress(
                migration_id,
                processed=i,
                errors=i // 100
            )
            
            # Get status
            status = await migration_monitor.get_status(migration_id)
            assert status["processed"] == i
            assert status["percentage"] == (i / 10000) * 100
        
        # Complete migration
        await migration_monitor.complete_migration(migration_id)
        
        final_status = await migration_monitor.get_status(migration_id)
        assert final_status["status"] == "completed"

    @pytest.mark.asyncio
    async def test_migration_health_metrics(self, migration_monitor):
        """Test migration health metrics."""
        # Record metrics during migration
        await migration_monitor.record_metric("throughput", 1000, unit="records/sec")
        await migration_monitor.record_metric("error_rate", 0.01, unit="percentage")
        await migration_monitor.record_metric("memory_usage", 512, unit="MB")
        
        # Check health
        health = await migration_monitor.check_health()
        
        assert health["status"] in ["healthy", "degraded", "unhealthy"]
        assert "metrics" in health
        assert health["metrics"]["throughput"] == 1000

    @pytest.mark.asyncio
    async def test_migration_alerting(self, migration_monitor):
        """Test migration alerting."""
        # Configure alert thresholds
        await migration_monitor.set_alert_thresholds({
            "error_rate": 0.05,
            "duration_minutes": 60,
            "memory_usage_mb": 1024
        })
        
        # Trigger conditions
        await migration_monitor.record_metric("error_rate", 0.1)
        
        # Check alerts
        alerts = await migration_monitor.get_active_alerts()
        
        assert len(alerts) > 0
        assert any(a["type"] == "error_rate_exceeded" for a in alerts)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])