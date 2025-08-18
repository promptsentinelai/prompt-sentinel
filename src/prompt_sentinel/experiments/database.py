# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Database interface for experiment management.

This module provides the database layer for storing and retrieving
experiment configurations, metrics, and analysis results.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite
import structlog

from .analyzer import ExperimentResult
from .config import ExperimentConfig, ExperimentStatus, ExperimentType
from .safety import GuardrailViolation

logger = structlog.get_logger()


class DatabaseError(Exception):
    """Exception raised for database operations."""

    pass


class ExperimentDatabase:
    """Database interface for experiment management.

    Provides persistent storage for experiments, metrics, and analysis results.
    Uses SQLite for simplicity, but can be extended for other databases.
    """

    def __init__(self, db_path: str = "experiments.db"):
        """Initialize database.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.initialized = False

    async def initialize(self):
        """Initialize database schema."""
        if self.initialized:
            return

        # Ensure database directory exists
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        async with aiosqlite.connect(self.db_path) as db:
            # Create experiments table
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS experiments (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    config JSON NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP
                )
            """
            )

            # Create experiment_metrics table
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS experiment_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    experiment_id TEXT NOT NULL,
                    variant_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    value REAL NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    metadata JSON,
                    FOREIGN KEY (experiment_id) REFERENCES experiments (id)
                )
            """
            )

            # Create experiment_assignments table
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS experiment_assignments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    experiment_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    variant_id TEXT NOT NULL,
                    assigned_at TIMESTAMP NOT NULL,
                    context JSON,
                    FOREIGN KEY (experiment_id) REFERENCES experiments (id),
                    UNIQUE(experiment_id, user_id)
                )
            """
            )

            # Create experiment_results table
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS experiment_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    experiment_id TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    control_variant_id TEXT NOT NULL,
                    treatment_variant_id TEXT NOT NULL,
                    results JSON NOT NULL,
                    analyzed_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (experiment_id) REFERENCES experiments (id)
                )
            """
            )

            # Create safety_violations table
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS safety_violations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    experiment_id TEXT NOT NULL,
                    guardrail_name TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    threshold_value REAL NOT NULL,
                    actual_value REAL NOT NULL,
                    severity TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    message TEXT,
                    metadata JSON,
                    FOREIGN KEY (experiment_id) REFERENCES experiments (id)
                )
            """
            )

            # Create assignment_events table
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS assignment_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    experiment_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    variant_id TEXT,
                    timestamp TIMESTAMP NOT NULL,
                    context JSON,
                    FOREIGN KEY (experiment_id) REFERENCES experiments (id)
                )
            """
            )

            # Create indexes for performance
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_experiments_status ON experiments(status)"
            )
            await db.execute("CREATE INDEX IF NOT EXISTS idx_experiments_type ON experiments(type)")
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_metrics_experiment ON experiment_metrics(experiment_id)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_metrics_variant ON experiment_metrics(variant_id)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON experiment_metrics(timestamp)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_assignments_experiment ON experiment_assignments(experiment_id)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_assignments_user ON experiment_assignments(user_id)"
            )

            await db.commit()

        self.initialized = True
        logger.info("Experiment database initialized", db_path=self.db_path)

    async def close(self):
        """Close database connections."""
        # SQLite connections are automatically closed
        logger.info("Experiment database closed")

    async def save_experiment(self, config: ExperimentConfig) -> bool:
        """Save experiment configuration to database.

        Args:
            config: Experiment configuration

        Returns:
            True if saved successfully
        """
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    """
                    INSERT OR REPLACE INTO experiments
                    (id, name, description, type, status, config, created_at, updated_at, start_time, end_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        config.id,
                        config.name,
                        config.description,
                        config.type.value,
                        config.status.value,
                        json.dumps(config.model_dump()),
                        config.created_at,
                        config.updated_at,
                        config.start_time,
                        config.end_time,
                    ),
                )
                await db.commit()

            logger.debug("Experiment saved", experiment_id=config.id)
            return True

        except Exception as e:
            logger.error("Failed to save experiment", experiment_id=config.id, error=str(e))
            return False

    async def get_experiment(self, experiment_id: str) -> ExperimentConfig | None:
        """Get experiment configuration by ID.

        Args:
            experiment_id: Experiment identifier

        Returns:
            Experiment configuration or None if not found
        """
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(
                    "SELECT config FROM experiments WHERE id = ?", (experiment_id,)
                ) as cursor:
                    row = await cursor.fetchone()  # type: ignore[assignment]

                if row:
                    config_data = json.loads(row[0])
                    return ExperimentConfig(**config_data)

        except Exception as e:
            logger.error("Failed to get experiment", experiment_id=experiment_id, error=str(e))

        return None

    async def update_experiment(self, config: ExperimentConfig) -> bool:
        """Update existing experiment configuration.

        Args:
            config: Updated experiment configuration

        Returns:
            True if updated successfully
        """
        config.updated_at = datetime.utcnow()
        return await self.save_experiment(config)

    async def list_experiments(
        self,
        status_filter: ExperimentStatus | None = None,
        type_filter: ExperimentType | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ExperimentConfig]:
        """List experiments with optional filtering.

        Args:
            status_filter: Filter by experiment status
            type_filter: Filter by experiment type
            limit: Maximum number of experiments to return
            offset: Number of experiments to skip

        Returns:
            List of experiment configurations
        """
        try:
            query = "SELECT config FROM experiments WHERE 1=1"
            params = []

            if status_filter:
                query += " AND status = ?"
                params.append(status_filter.value)

            if type_filter:
                query += " AND type = ?"
                params.append(type_filter.value)

            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([str(limit), str(offset)])

            experiments = []
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(query, params) as cursor:
                    async for row in cursor:
                        config_data = json.loads(row[0])
                        experiments.append(ExperimentConfig(**config_data))

            return experiments

        except Exception as e:
            logger.error("Failed to list experiments", error=str(e))
            return []

    async def delete_experiment(self, experiment_id: str) -> bool:
        """Delete experiment and all related data.

        Args:
            experiment_id: Experiment identifier

        Returns:
            True if deleted successfully
        """
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Delete in order due to foreign key constraints
                await db.execute(
                    "DELETE FROM experiment_metrics WHERE experiment_id = ?", (experiment_id,)
                )
                await db.execute(
                    "DELETE FROM experiment_assignments WHERE experiment_id = ?", (experiment_id,)
                )
                await db.execute(
                    "DELETE FROM experiment_results WHERE experiment_id = ?", (experiment_id,)
                )
                await db.execute(
                    "DELETE FROM safety_violations WHERE experiment_id = ?", (experiment_id,)
                )
                await db.execute(
                    "DELETE FROM assignment_events WHERE experiment_id = ?", (experiment_id,)
                )
                await db.execute("DELETE FROM experiments WHERE id = ?", (experiment_id,))
                await db.commit()

            logger.info("Experiment deleted", experiment_id=experiment_id)
            return True

        except Exception as e:
            logger.error("Failed to delete experiment", experiment_id=experiment_id, error=str(e))
            return False

    async def save_metrics_batch(self, metrics: list[dict[str, Any]]) -> bool:
        """Save batch of metrics to database.

        Args:
            metrics: List of metric dictionaries

        Returns:
            True if saved successfully
        """
        if not metrics:
            return True

        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.executemany(
                    """
                    INSERT INTO experiment_metrics
                    (experiment_id, variant_id, user_id, metric_name, value, timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    [
                        (
                            metric["experiment_id"],
                            metric["variant_id"],
                            metric["user_id"],
                            metric["metric_name"],
                            metric["value"],
                            metric["timestamp"],
                            json.dumps(metric.get("metadata", {})),
                        )
                        for metric in metrics
                    ],
                )
                await db.commit()

            logger.debug("Metrics batch saved", count=len(metrics))
            return True

        except Exception as e:
            logger.error("Failed to save metrics batch", error=str(e))
            return False

    async def get_experiment_metrics(
        self,
        experiment_id: str,
        variant_ids: list[str] | None = None,
        metric_names: list[str] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, dict[str, list[float]]]:
        """Get metrics for experiment analysis.

        Args:
            experiment_id: Experiment identifier
            variant_ids: Filter by variant IDs
            metric_names: Filter by metric names
            start_time: Start time filter
            end_time: End time filter

        Returns:
            Nested dict {metric_name: {variant_id: [values]}}
        """
        try:
            query = """
                SELECT metric_name, variant_id, value
                FROM experiment_metrics
                WHERE experiment_id = ?
            """
            params = [experiment_id]

            if variant_ids:
                placeholders = ",".join("?" * len(variant_ids))
                query += f" AND variant_id IN ({placeholders})"
                params.extend(variant_ids)

            if metric_names:
                placeholders = ",".join("?" * len(metric_names))
                query += f" AND metric_name IN ({placeholders})"
                params.extend(metric_names)

            if start_time:
                query += " AND timestamp >= ?"
                params.append(
                    start_time.isoformat() if isinstance(start_time, datetime) else str(start_time)
                )

            if end_time:
                query += " AND timestamp <= ?"
                params.append(
                    end_time.isoformat() if isinstance(end_time, datetime) else str(end_time)
                )

            from collections import defaultdict

            data: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))

            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(query, params) as cursor:
                    async for row in cursor:
                        metric_name, variant_id, value = row
                        data[metric_name][variant_id].append(value)

            # Convert to regular dict
            return {k: dict(v) for k, v in data.items()}

        except Exception as e:
            logger.error(
                "Failed to get experiment metrics", experiment_id=experiment_id, error=str(e)
            )
            return {}

    async def save_analysis_results(
        self, experiment_id: str, results: list[ExperimentResult]
    ) -> bool:
        """Save statistical analysis results.

        Args:
            experiment_id: Experiment identifier
            results: Analysis results

        Returns:
            True if saved successfully
        """
        if not results:
            return True

        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Delete existing results for this experiment
                await db.execute(
                    "DELETE FROM experiment_results WHERE experiment_id = ?", (experiment_id,)
                )

                # Insert new results
                for result in results:
                    await db.execute(
                        """
                        INSERT INTO experiment_results
                        (experiment_id, metric_name, control_variant_id, treatment_variant_id,
                         results, analyzed_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """,
                        (
                            experiment_id,
                            result.metric_name,
                            result.control_variant_id,
                            result.treatment_variant_id,
                            json.dumps(result.get_summary()),
                            result.analysis_timestamp,
                        ),
                    )

                await db.commit()

            logger.debug(
                "Analysis results saved", experiment_id=experiment_id, results_count=len(results)
            )
            return True

        except Exception as e:
            logger.error(
                "Failed to save analysis results", experiment_id=experiment_id, error=str(e)
            )
            return False

    async def get_analysis_results(self, experiment_id: str) -> list[dict[str, Any]]:
        """Get latest analysis results for experiment.

        Args:
            experiment_id: Experiment identifier

        Returns:
            List of analysis result summaries
        """
        try:
            results = []
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(
                    """
                    SELECT metric_name, control_variant_id, treatment_variant_id,
                           results, analyzed_at
                    FROM experiment_results
                    WHERE experiment_id = ?
                    ORDER BY analyzed_at DESC
                """,
                    (experiment_id,),
                ) as cursor:
                    async for row in cursor:
                        metric_name, control_id, treatment_id, results_json, analyzed_at = row
                        result_data = json.loads(results_json)
                        result_data.update(
                            {
                                "metric_name": metric_name,
                                "control_variant_id": control_id,
                                "treatment_variant_id": treatment_id,
                                "analyzed_at": analyzed_at,
                            }
                        )
                        results.append(result_data)

            return results

        except Exception as e:
            logger.error(
                "Failed to get analysis results", experiment_id=experiment_id, error=str(e)
            )
            return []

    async def save_assignment_event(self, event: dict[str, Any]) -> bool:
        """Save assignment event for analytics.

        Args:
            event: Assignment event data

        Returns:
            True if saved successfully
        """
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    """
                    INSERT INTO assignment_events
                    (event_type, experiment_id, user_id, variant_id, timestamp, context)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        event["event_type"],
                        event["experiment_id"],
                        event["user_id"],
                        event.get("variant_id"),
                        event["timestamp"],
                        json.dumps(event.get("context", {})),
                    ),
                )
                await db.commit()

            return True

        except Exception as e:
            logger.error("Failed to save assignment event", error=str(e))
            return False

    async def save_safety_violation(self, violation: GuardrailViolation) -> bool:
        """Save safety violation record.

        Args:
            violation: Safety violation

        Returns:
            True if saved successfully
        """
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    """
                    INSERT INTO safety_violations
                    (experiment_id, guardrail_name, metric_name, threshold_value,
                     actual_value, severity, action_taken, timestamp, message, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        violation.experiment_id,
                        violation.guardrail_name,
                        violation.metric_name,
                        violation.threshold_value,
                        violation.actual_value,
                        violation.severity.value,
                        violation.action_taken.value,
                        violation.timestamp,
                        violation.message,
                        json.dumps(violation.metadata),
                    ),
                )
                await db.commit()

            logger.debug("Safety violation saved", experiment_id=violation.experiment_id)
            return True

        except Exception as e:
            logger.error(
                "Failed to save safety violation",
                experiment_id=violation.experiment_id,
                error=str(e),
            )
            return False

    async def get_experiment_stats(self) -> dict[str, Any]:
        """Get overall experiment statistics.

        Returns:
            Statistics about experiments in database
        """
        try:
            stats = {
                "total_experiments": 0,
                "experiments_by_status": {},
                "experiments_by_type": {},
                "total_metrics": 0,
                "total_assignments": 0,
                "total_violations": 0,
            }

            async with aiosqlite.connect(self.db_path) as db:
                # Count experiments by status
                async with db.execute(
                    """
                    SELECT status, COUNT(*) FROM experiments GROUP BY status
                """
                ) as cursor:
                    async for row in cursor:
                        if hasattr(stats["experiments_by_status"], "__setitem__"):
                            stats["experiments_by_status"][row[0]] = row[1]
                        stats["total_experiments"] += row[1]

                # Count experiments by type
                async with db.execute(
                    """
                    SELECT type, COUNT(*) FROM experiments GROUP BY type
                """
                ) as cursor:
                    async for row in cursor:
                        if hasattr(stats["experiments_by_type"], "__setitem__"):
                            stats["experiments_by_type"][row[0]] = row[1]

                # Count metrics
                async with db.execute(
                    """
                    SELECT COUNT(*) FROM experiment_metrics
                """
                ) as cursor:
                    row = await cursor.fetchone()  # type: ignore[assignment]
                    if row:
                        stats["total_metrics"] = row[0]

                # Count assignments
                async with db.execute(
                    """
                    SELECT COUNT(*) FROM experiment_assignments
                """
                ) as cursor:
                    row = await cursor.fetchone()  # type: ignore[assignment]
                    if row:
                        stats["total_assignments"] = row[0]

                # Count violations
                async with db.execute(
                    """
                    SELECT COUNT(*) FROM safety_violations
                """
                ) as cursor:
                    row = await cursor.fetchone()  # type: ignore[assignment]
                    if row:
                        stats["total_violations"] = row[0]

            return stats

        except Exception as e:
            logger.error("Failed to get experiment stats", error=str(e))
            return {}
