"""Tests for database operations and persistence."""

import pytest
import asyncio
import tempfile
import sqlite3
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import json

from prompt_sentinel.experiments.database import (
    ExperimentDatabase, Experiment, ExperimentResult
)
from prompt_sentinel.models.schemas import Message, Role, Verdict


class TestExperimentDatabase:
    """Test experiment database operations."""

    @pytest.fixture
    async def db(self):
        """Create test database instance."""
        with tempfile.NamedTemporaryFile(suffix='.db') as f:
            database = ExperimentDatabase(db_path=f.name)
            await database.initialize()
            yield database
            await database.close()

    @pytest.mark.asyncio
    async def test_database_initialization(self, db):
        """Test database initialization and schema creation."""
        # Check tables exist
        tables = await db.get_tables()
        assert "experiments" in tables
        assert "experiment_results" in tables
        assert "experiment_metrics" in tables

    @pytest.mark.asyncio
    async def test_create_experiment(self, db):
        """Test creating an experiment."""
        experiment = await db.create_experiment(
            name="test_experiment",
            description="Test experiment for unit tests",
            config={
                "variant_a": {"threshold": 0.3},
                "variant_b": {"threshold": 0.5}
            }
        )
        
        assert experiment.id is not None
        assert experiment.name == "test_experiment"
        assert experiment.status == "active"
        assert len(experiment.variants) == 2

    @pytest.mark.asyncio
    async def test_record_experiment_result(self, db):
        """Test recording experiment results."""
        # Create experiment
        experiment = await db.create_experiment(
            name="result_test",
            config={"control": {}, "treatment": {}}
        )
        
        # Record result
        result = await db.record_result(
            experiment_id=experiment.id,
            variant="treatment",
            user_id="user123",
            outcome="detected",
            metrics={
                "confidence": 0.85,
                "latency_ms": 45
            }
        )
        
        assert result.id is not None
        assert result.variant == "treatment"
        assert result.outcome == "detected"
        assert result.metrics["confidence"] == 0.85

    @pytest.mark.asyncio
    async def test_get_experiment_results(self, db):
        """Test retrieving experiment results."""
        # Create and populate experiment
        experiment = await db.create_experiment(
            name="results_test",
            config={"A": {}, "B": {}}
        )
        
        # Record multiple results
        for i in range(10):
            await db.record_result(
                experiment_id=experiment.id,
                variant="A" if i % 2 == 0 else "B",
                user_id=f"user{i}",
                outcome="success" if i < 7 else "failure"
            )
        
        # Get results
        results = await db.get_experiment_results(experiment.id)
        
        assert len(results) == 10
        assert sum(1 for r in results if r.variant == "A") == 5
        assert sum(1 for r in results if r.outcome == "success") == 7

    @pytest.mark.asyncio
    async def test_update_experiment_status(self, db):
        """Test updating experiment status."""
        experiment = await db.create_experiment(
            name="status_test",
            config={"default": {}}
        )
        
        # Update status
        await db.update_experiment_status(experiment.id, "completed")
        
        # Verify update
        updated = await db.get_experiment(experiment.id)
        assert updated.status == "completed"

    @pytest.mark.asyncio
    async def test_database_transactions(self, db):
        """Test database transaction handling."""
        async with db.transaction() as tx:
            # Create experiment in transaction
            experiment = await tx.create_experiment(
                name="transaction_test",
                config={"variant": {}}
            )
            
            # Record results in same transaction
            for i in range(5):
                await tx.record_result(
                    experiment_id=experiment.id,
                    variant="variant",
                    user_id=f"user{i}",
                    outcome="success"
                )
            
            # Commit transaction
            await tx.commit()
        
        # Verify data persisted
        results = await db.get_experiment_results(experiment.id)
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_database_rollback(self, db):
        """Test transaction rollback."""
        try:
            async with db.transaction() as tx:
                # Create experiment
                experiment = await tx.create_experiment(
                    name="rollback_test",
                    config={"variant": {}}
                )
                
                # Simulate error
                raise Exception("Test error")
                
        except Exception:
            pass
        
        # Experiment should not exist due to rollback
        experiments = await db.get_all_experiments()
        assert not any(e.name == "rollback_test" for e in experiments)


class TestDetectionHistoryDatabase:
    """Test detection history storage."""

    @pytest.fixture
    async def history_db(self):
        """Create detection history database."""
        with tempfile.NamedTemporaryFile(suffix='.db') as f:
            from prompt_sentinel.storage.history import DetectionHistoryDB
            db = DetectionHistoryDB(db_path=f.name)
            await db.initialize()
            yield db
            await db.close()

    @pytest.mark.asyncio
    async def test_save_detection_history(self, history_db):
        """Test saving detection history."""
        detection = {
            "timestamp": datetime.utcnow().isoformat(),
            "messages": [{"role": "user", "content": "test"}],
            "verdict": "ALLOW",
            "confidence": 0.95,
            "reasons": [],
            "metadata": {"source": "api", "version": "1.0"}
        }
        
        record_id = await history_db.save_detection(detection)
        assert record_id is not None

    @pytest.mark.asyncio
    async def test_query_detection_history(self, history_db):
        """Test querying detection history."""
        # Save multiple detections
        for i in range(20):
            await history_db.save_detection({
                "timestamp": datetime.utcnow().isoformat(),
                "verdict": "ALLOW" if i % 2 == 0 else "BLOCK",
                "confidence": 0.5 + (i * 0.02),
                "messages": [{"role": "user", "content": f"test {i}"}]
            })
        
        # Query with filters
        blocked = await history_db.query(
            verdict="BLOCK",
            limit=10
        )
        assert len(blocked) == 10
        assert all(d["verdict"] == "BLOCK" for d in blocked)
        
        # Query by confidence
        high_confidence = await history_db.query(
            min_confidence=0.8
        )
        assert all(d["confidence"] >= 0.8 for d in high_confidence)

    @pytest.mark.asyncio
    async def test_detection_statistics(self, history_db):
        """Test computing detection statistics."""
        # Populate with test data
        for i in range(100):
            await history_db.save_detection({
                "timestamp": (datetime.utcnow() - timedelta(hours=i)).isoformat(),
                "verdict": ["ALLOW", "FLAG", "STRIP", "BLOCK"][i % 4],
                "confidence": 0.5 + (i % 50) * 0.01
            })
        
        # Get statistics
        stats = await history_db.get_statistics(
            start_time=datetime.utcnow() - timedelta(days=7),
            end_time=datetime.utcnow()
        )
        
        assert stats["total_detections"] > 0
        assert "verdict_distribution" in stats
        assert "average_confidence" in stats
        assert 0.5 <= stats["average_confidence"] <= 1.0


class TestAPIKeyDatabase:
    """Test API key database operations."""

    @pytest.fixture
    async def api_db(self):
        """Create API key database."""
        from prompt_sentinel.auth.storage import APIKeyDatabase
        db = APIKeyDatabase(":memory:")
        await db.initialize()
        yield db
        await db.close()

    @pytest.mark.asyncio
    async def test_store_api_key(self, api_db):
        """Test storing API keys."""
        key_data = {
            "key_hash": "hashed_key_123",
            "name": "test_key",
            "tier": "PRO",
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(days=30),
            "metadata": {"user_id": "user123"}
        }
        
        key_id = await api_db.store_key(key_data)
        assert key_id is not None

    @pytest.mark.asyncio
    async def test_retrieve_api_key(self, api_db):
        """Test retrieving API keys."""
        # Store key
        key_data = {
            "key_hash": "hashed_key_456",
            "name": "retrieve_test",
            "tier": "FREE"
        }
        key_id = await api_db.store_key(key_data)
        
        # Retrieve
        retrieved = await api_db.get_key(key_hash="hashed_key_456")
        assert retrieved is not None
        assert retrieved["name"] == "retrieve_test"
        assert retrieved["tier"] == "FREE"

    @pytest.mark.asyncio
    async def test_update_api_key_usage(self, api_db):
        """Test updating API key usage statistics."""
        # Store key
        key_id = await api_db.store_key({
            "key_hash": "usage_test",
            "name": "usage_key",
            "tier": "PRO"
        })
        
        # Update usage
        for i in range(10):
            await api_db.increment_usage(
                key_hash="usage_test",
                endpoint="/v1/detect"
            )
        
        # Get usage stats
        stats = await api_db.get_usage_stats("usage_test")
        assert stats["total_requests"] == 10
        assert stats["endpoints"]["/v1/detect"] == 10


class TestCacheDatabase:
    """Test cache persistence database."""

    @pytest.fixture
    async def cache_db(self):
        """Create cache database."""
        from prompt_sentinel.cache.persistent import PersistentCache
        cache = PersistentCache(":memory:")
        await cache.initialize()
        yield cache
        await cache.close()

    @pytest.mark.asyncio
    async def test_persistent_cache_set_get(self, cache_db):
        """Test persistent cache operations."""
        key = "test_key"
        value = {"data": "test_value", "timestamp": datetime.utcnow().isoformat()}
        
        # Set value
        await cache_db.set(key, value, ttl=3600)
        
        # Get value
        retrieved = await cache_db.get(key)
        assert retrieved == value

    @pytest.mark.asyncio
    async def test_cache_expiration_cleanup(self, cache_db):
        """Test cleaning up expired cache entries."""
        # Add entries with different TTLs
        await cache_db.set("expire_soon", "value1", ttl=1)
        await cache_db.set("expire_later", "value2", ttl=3600)
        
        # Wait for first to expire
        await asyncio.sleep(1.5)
        
        # Run cleanup
        await cache_db.cleanup_expired()
        
        # Check results
        assert await cache_db.get("expire_soon") is None
        assert await cache_db.get("expire_later") == "value2"


class TestDatabaseMigrations:
    """Test database migration system."""

    @pytest.fixture
    def migration_manager(self):
        """Create migration manager."""
        from prompt_sentinel.storage.migrations import MigrationManager
        return MigrationManager(":memory:")

    @pytest.mark.asyncio
    async def test_apply_migrations(self, migration_manager):
        """Test applying database migrations."""
        # Define test migrations
        migrations = [
            {
                "version": 1,
                "sql": "CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT);"
            },
            {
                "version": 2,
                "sql": "ALTER TABLE test_table ADD COLUMN created_at TIMESTAMP;"
            }
        ]
        
        # Apply migrations
        for migration in migrations:
            await migration_manager.apply_migration(migration)
        
        # Check current version
        current_version = await migration_manager.get_current_version()
        assert current_version == 2

    @pytest.mark.asyncio
    async def test_migration_rollback(self, migration_manager):
        """Test rolling back migrations."""
        # Apply migration with rollback
        migration = {
            "version": 1,
            "up": "CREATE TABLE test (id INTEGER);",
            "down": "DROP TABLE test;"
        }
        
        await migration_manager.apply_migration(migration)
        assert await migration_manager.table_exists("test")
        
        await migration_manager.rollback_migration(migration)
        assert not await migration_manager.table_exists("test")


class TestDatabaseConnectionPool:
    """Test database connection pooling."""

    @pytest.mark.asyncio
    async def test_connection_pool_creation(self):
        """Test creating connection pool."""
        from prompt_sentinel.storage.pool import DatabasePool
        
        pool = DatabasePool(
            dsn="sqlite:///:memory:",
            min_size=2,
            max_size=10
        )
        
        await pool.initialize()
        
        assert pool.size >= 2
        assert pool.size <= 10
        
        await pool.close()

    @pytest.mark.asyncio
    async def test_connection_pool_concurrency(self):
        """Test concurrent database access through pool."""
        from prompt_sentinel.storage.pool import DatabasePool
        
        pool = DatabasePool(
            dsn="sqlite:///:memory:",
            max_size=5
        )
        await pool.initialize()
        
        async def db_operation(i):
            async with pool.acquire() as conn:
                # Simulate database operation
                await asyncio.sleep(0.1)
                return i
        
        # Run concurrent operations
        tasks = [db_operation(i) for i in range(20)]
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 20
        assert sorted(results) == list(range(20))
        
        await pool.close()

    @pytest.mark.asyncio
    async def test_connection_pool_health_check(self):
        """Test connection pool health checking."""
        from prompt_sentinel.storage.pool import DatabasePool
        
        pool = DatabasePool(
            dsn="sqlite:///:memory:",
            health_check_interval=1
        )
        await pool.initialize()
        
        # Check health
        is_healthy = await pool.health_check()
        assert is_healthy is True
        
        # Simulate unhealthy connection
        pool._connections[0].close()
        
        # Health check should detect and recover
        await asyncio.sleep(1.5)
        is_healthy = await pool.health_check()
        assert is_healthy is True
        
        await pool.close()


class TestDatabaseBackup:
    """Test database backup and restore."""

    @pytest.mark.asyncio
    async def test_database_backup(self):
        """Test creating database backup."""
        from prompt_sentinel.storage.backup import DatabaseBackup
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create database with data
            db_path = f"{tmpdir}/test.db"
            backup_path = f"{tmpdir}/backup.db"
            
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE test (id INTEGER, data TEXT)")
            conn.execute("INSERT INTO test VALUES (1, 'test_data')")
            conn.commit()
            conn.close()
            
            # Create backup
            backup = DatabaseBackup(db_path)
            await backup.create_backup(backup_path)
            
            # Verify backup
            assert os.path.exists(backup_path)
            
            # Check backup contains data
            conn = sqlite3.connect(backup_path)
            cursor = conn.execute("SELECT * FROM test")
            rows = cursor.fetchall()
            assert len(rows) == 1
            assert rows[0][1] == "test_data"
            conn.close()

    @pytest.mark.asyncio
    async def test_database_restore(self):
        """Test restoring from backup."""
        from prompt_sentinel.storage.backup import DatabaseBackup
        
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = f"{tmpdir}/test.db"
            backup_path = f"{tmpdir}/backup.db"
            
            # Create backup with data
            conn = sqlite3.connect(backup_path)
            conn.execute("CREATE TABLE test (id INTEGER, data TEXT)")
            conn.execute("INSERT INTO test VALUES (1, 'backup_data')")
            conn.commit()
            conn.close()
            
            # Restore from backup
            backup = DatabaseBackup(db_path)
            await backup.restore_from_backup(backup_path)
            
            # Verify restore
            conn = sqlite3.connect(db_path)
            cursor = conn.execute("SELECT * FROM test")
            rows = cursor.fetchall()
            assert len(rows) == 1
            assert rows[0][1] == "backup_data"
            conn.close()


class TestDatabasePerformance:
    """Test database performance optimizations."""

    @pytest.mark.asyncio
    async def test_batch_insert_performance(self):
        """Test batch insert performance."""
        from prompt_sentinel.storage.batch import BatchInserter
        
        with tempfile.NamedTemporaryFile(suffix='.db') as f:
            inserter = BatchInserter(
                db_path=f.name,
                batch_size=1000
            )
            await inserter.initialize()
            
            # Prepare data
            records = [
                {"id": i, "data": f"record_{i}"}
                for i in range(10000)
            ]
            
            # Batch insert
            import time
            start = time.time()
            await inserter.insert_batch("test_table", records)
            elapsed = time.time() - start
            
            # Should be fast (< 1 second for 10k records)
            assert elapsed < 1.0
            
            # Verify all records inserted
            count = await inserter.count("test_table")
            assert count == 10000

    @pytest.mark.asyncio
    async def test_database_indexing(self):
        """Test database index creation and usage."""
        from prompt_sentinel.storage.optimizer import DatabaseOptimizer
        
        with tempfile.NamedTemporaryFile(suffix='.db') as f:
            optimizer = DatabaseOptimizer(f.name)
            await optimizer.initialize()
            
            # Create table
            await optimizer.execute(
                "CREATE TABLE test (id INTEGER, user_id TEXT, created_at TIMESTAMP)"
            )
            
            # Add data
            for i in range(1000):
                await optimizer.execute(
                    "INSERT INTO test VALUES (?, ?, ?)",
                    (i, f"user_{i % 100}", datetime.utcnow())
                )
            
            # Create index
            await optimizer.create_index("test", ["user_id"])
            
            # Query should be fast with index
            import time
            start = time.time()
            results = await optimizer.query(
                "SELECT * FROM test WHERE user_id = ?",
                ("user_50",)
            )
            elapsed = time.time() - start
            
            assert elapsed < 0.01  # Should be very fast with index
            assert len(results) == 10  # 1000 / 100 users


if __name__ == "__main__":
    pytest.main([__file__, "-v"])