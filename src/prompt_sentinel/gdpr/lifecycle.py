# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Data lifecycle management for GDPR compliance."""

import asyncio
import json
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import structlog

from prompt_sentinel.cache.cache_manager import cache_manager

logger = structlog.get_logger()


class DataCategory(str, Enum):
    """Categories of data for retention policies."""

    DETECTION_LOGS = "detection_logs"
    AUDIT_LOGS = "audit_logs"
    PII_PROCESSING = "pii_processing"
    USER_CONSENT = "user_consent"
    API_ACCESS_LOGS = "api_access_logs"
    CACHED_PROMPTS = "cached_prompts"
    METRICS = "metrics"
    TEMP_DATA = "temp_data"


class RetentionAction(str, Enum):
    """Actions to take when retention period expires."""

    DELETE = "delete"
    ANONYMIZE = "anonymize"
    ARCHIVE = "archive"
    REVIEW = "review"


class RetentionPolicy:
    """Data retention policy configuration."""

    def __init__(
        self,
        category: DataCategory,
        retention_days: int,
        action: RetentionAction = RetentionAction.DELETE,
        anonymization_days: int | None = None,
        legal_hold: bool = False,
        description: str = "",
    ):
        """
        Initialize retention policy.

        Args:
            category: Data category
            retention_days: Days to retain data
            action: Action when retention expires
            anonymization_days: Days before anonymization (if applicable)
            legal_hold: Whether data is under legal hold
            description: Policy description
        """
        self.category = category
        self.retention_days = retention_days
        self.action = action
        self.anonymization_days = anonymization_days
        self.legal_hold = legal_hold
        self.description = description

    @property
    def retention_timedelta(self) -> timedelta:
        """Get retention period as timedelta."""
        return timedelta(days=self.retention_days)

    @property
    def anonymization_timedelta(self) -> timedelta | None:
        """Get anonymization period as timedelta."""
        return timedelta(days=self.anonymization_days) if self.anonymization_days else None

    def is_expired(self, created_at: datetime) -> bool:
        """Check if data is expired according to policy."""
        if self.legal_hold:
            return False

        age = datetime.utcnow() - created_at
        return age > self.retention_timedelta

    def should_anonymize(self, created_at: datetime) -> bool:
        """Check if data should be anonymized."""
        if not self.anonymization_days or self.legal_hold:
            return False

        age = datetime.utcnow() - created_at
        return age > self.anonymization_timedelta and not self.is_expired(created_at)


class DataLifecycleManager:
    """Manages data retention and deletion for GDPR compliance."""

    def __init__(self):
        """Initialize data lifecycle manager."""
        self.policies: dict[DataCategory, RetentionPolicy] = {}
        self.deletion_queue: list[dict[str, Any]] = []
        self._setup_default_policies()

    def _setup_default_policies(self):
        """Set up default retention policies."""
        # Detection logs: 30 days
        self.policies[DataCategory.DETECTION_LOGS] = RetentionPolicy(
            DataCategory.DETECTION_LOGS,
            retention_days=30,
            action=RetentionAction.DELETE,
            anonymization_days=7,
            description="Detection logs retained for 30 days, anonymized after 7 days",
        )

        # Audit logs: 7 years (legal requirement)
        self.policies[DataCategory.AUDIT_LOGS] = RetentionPolicy(
            DataCategory.AUDIT_LOGS,
            retention_days=2555,  # ~7 years
            action=RetentionAction.ARCHIVE,
            legal_hold=False,
            description="Audit logs retained for 7 years for compliance",
        )

        # PII processing logs: 3 years
        self.policies[DataCategory.PII_PROCESSING] = RetentionPolicy(
            DataCategory.PII_PROCESSING,
            retention_days=1095,  # 3 years
            action=RetentionAction.ANONYMIZE,
            anonymization_days=365,  # Anonymize after 1 year
            description="PII processing logs retained for 3 years, anonymized after 1 year",
        )

        # User consent: 5 years minimum
        self.policies[DataCategory.USER_CONSENT] = RetentionPolicy(
            DataCategory.USER_CONSENT,
            retention_days=1825,  # 5 years
            action=RetentionAction.REVIEW,
            legal_hold=True,  # Never auto-delete consent records
            description="User consent records retained for 5 years minimum",
        )

        # API access logs: 90 days
        self.policies[DataCategory.API_ACCESS_LOGS] = RetentionPolicy(
            DataCategory.API_ACCESS_LOGS,
            retention_days=90,
            action=RetentionAction.DELETE,
            description="API access logs retained for 90 days",
        )

        # Cached prompts: 24 hours
        self.policies[DataCategory.CACHED_PROMPTS] = RetentionPolicy(
            DataCategory.CACHED_PROMPTS,
            retention_days=1,
            action=RetentionAction.DELETE,
            description="Cached prompts retained for 24 hours",
        )

        # Metrics: 1 year
        self.policies[DataCategory.METRICS] = RetentionPolicy(
            DataCategory.METRICS,
            retention_days=365,
            action=RetentionAction.ANONYMIZE,
            anonymization_days=30,
            description="Metrics retained for 1 year, anonymized after 30 days",
        )

        # Temp data: 1 hour
        self.policies[DataCategory.TEMP_DATA] = RetentionPolicy(
            DataCategory.TEMP_DATA,
            retention_days=0,  # Less than a day
            action=RetentionAction.DELETE,
            description="Temporary data retained for 1 hour",
        )

    def set_policy(self, policy: RetentionPolicy):
        """Set or update retention policy."""
        self.policies[policy.category] = policy
        logger.info(
            "Retention policy updated",
            category=policy.category.value,
            retention_days=policy.retention_days,
            action=policy.action.value,
        )

    def get_policy(self, category: DataCategory) -> RetentionPolicy | None:
        """Get retention policy for category."""
        return self.policies.get(category)

    async def handle_deletion_request(
        self,
        data_subject_id: str,
        categories: list[DataCategory] | None = None,
        reason: str = "user_request",
    ) -> dict[str, Any]:
        """
        Handle GDPR deletion request (Right to be Forgotten).

        Args:
            data_subject_id: ID of data subject requesting deletion
            categories: Specific categories to delete (None = all allowed)
            reason: Reason for deletion

        Returns:
            Deletion summary
        """
        categories = categories or list(DataCategory)
        deletion_summary = {
            "data_subject_id": data_subject_id,
            "timestamp": datetime.utcnow().isoformat(),
            "reason": reason,
            "categories": {},
            "total_deleted": 0,
        }

        logger.info(
            "Processing deletion request",
            data_subject_id=data_subject_id,
            categories=[c.value for c in categories],
            reason=reason,
        )

        for category in categories:
            policy = self.get_policy(category)

            # Skip if under legal hold
            if policy and policy.legal_hold:
                deletion_summary["categories"][category.value] = {
                    "status": "skipped",
                    "reason": "legal_hold",
                    "count": 0,
                }
                continue

            # Process deletion
            try:
                count = await self._delete_data_by_category(data_subject_id, category)
                deletion_summary["categories"][category.value] = {
                    "status": "deleted",
                    "count": count,
                }
                deletion_summary["total_deleted"] += count

                # Log deletion for audit
                await self._log_deletion_action(data_subject_id, category, count, reason)

            except Exception as e:
                logger.error(
                    "Failed to delete data",
                    category=category.value,
                    data_subject_id=data_subject_id,
                    error=str(e),
                )
                deletion_summary["categories"][category.value] = {
                    "status": "error",
                    "error": str(e),
                    "count": 0,
                }

        return deletion_summary

    async def _delete_data_by_category(self, data_subject_id: str, category: DataCategory) -> int:
        """Delete data for specific category."""
        deleted_count = 0

        # Category-specific deletion logic
        if category == DataCategory.CACHED_PROMPTS:
            # Delete from cache
            if cache_manager.connected:
                pattern = f"detect:*:{data_subject_id}:*"
                deleted_count = await self._delete_cache_pattern(pattern)

        elif category == DataCategory.DETECTION_LOGS:
            # Delete detection logs (would be from database in production)
            deleted_count = await self._delete_detection_logs(data_subject_id)

        elif category == DataCategory.API_ACCESS_LOGS:
            # Delete API access logs
            deleted_count = await self._delete_api_logs(data_subject_id)

        # Add to deletion queue for async processing
        self.deletion_queue.append(
            {
                "data_subject_id": data_subject_id,
                "category": category.value,
                "timestamp": datetime.utcnow().isoformat(),
                "count": deleted_count,
            }
        )

        return deleted_count

    async def _delete_cache_pattern(self, pattern: str) -> int:
        """Delete cache entries matching pattern."""
        if not cache_manager.connected:
            return 0

        try:
            # Use SCAN to find matching keys
            deleted_count = 0
            cursor = 0

            while True:
                cursor, keys = await cache_manager.client.scan(cursor, match=pattern, count=100)

                if keys:
                    await cache_manager.client.delete(*keys)
                    deleted_count += len(keys)

                if cursor == 0:
                    break

            return deleted_count

        except Exception as e:
            logger.error("Cache deletion failed", pattern=pattern, error=str(e))
            return 0

    async def _delete_detection_logs(self, data_subject_id: str) -> int:
        """Delete detection logs for data subject."""
        # In production, this would delete from database
        # For now, track in memory
        return 0

    async def _delete_api_logs(self, data_subject_id: str) -> int:
        """Delete API access logs for data subject."""
        # In production, this would delete from database
        return 0

    async def _log_deletion_action(
        self, data_subject_id: str, category: DataCategory, count: int, reason: str
    ):
        """Log deletion action for audit trail."""
        audit_entry = {
            "event_type": "data_deletion",
            "data_subject_id": data_subject_id,
            "category": category.value,
            "deleted_count": count,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat(),
            "compliance": "GDPR Article 17 - Right to Erasure",
        }

        # Store audit log (never deleted)
        if cache_manager.connected:
            audit_key = f"audit:deletion:{data_subject_id}:{datetime.utcnow().timestamp()}"
            await cache_manager.set(audit_key, audit_entry, ttl=2555 * 24 * 3600)  # 7 years

        logger.info("Deletion action logged", **audit_entry)

    async def run_retention_cleanup(self) -> dict[str, Any]:
        """Run automated retention cleanup based on policies."""
        logger.info("Starting retention cleanup")

        cleanup_summary = {
            "timestamp": datetime.utcnow().isoformat(),
            "categories_processed": 0,
            "total_deleted": 0,
            "total_anonymized": 0,
            "errors": [],
        }

        for category, policy in self.policies.items():
            if policy.legal_hold:
                continue

            try:
                # Calculate cutoff date
                cutoff_date = datetime.utcnow() - policy.retention_timedelta

                if policy.action == RetentionAction.DELETE:
                    deleted = await self._cleanup_expired_data(category, cutoff_date)
                    cleanup_summary["total_deleted"] += deleted

                elif policy.action == RetentionAction.ANONYMIZE:
                    if policy.anonymization_days:
                        anon_cutoff = datetime.utcnow() - policy.anonymization_timedelta
                        anonymized = await self._anonymize_old_data(category, anon_cutoff)
                        cleanup_summary["total_anonymized"] += anonymized

                    # Still delete very old data
                    deleted = await self._cleanup_expired_data(category, cutoff_date)
                    cleanup_summary["total_deleted"] += deleted

                cleanup_summary["categories_processed"] += 1

            except Exception as e:
                error_msg = f"Cleanup failed for {category.value}: {str(e)}"
                logger.error(error_msg)
                cleanup_summary["errors"].append(error_msg)

        logger.info(
            "Retention cleanup completed",
            deleted=cleanup_summary["total_deleted"],
            anonymized=cleanup_summary["total_anonymized"],
            errors=len(cleanup_summary["errors"]),
        )

        return cleanup_summary

    async def _cleanup_expired_data(self, category: DataCategory, cutoff_date: datetime) -> int:
        """Clean up expired data for category."""
        # Implementation would vary by storage backend
        # This is a placeholder that tracks cleanup
        deleted_count = 0

        if category == DataCategory.CACHED_PROMPTS:
            # Cache has its own TTL, but we can force cleanup
            # Would check timestamps and delete old entries
            deleted_count = 0  # Placeholder

        return deleted_count

    async def _anonymize_old_data(self, category: DataCategory, cutoff_date: datetime) -> int:
        """Anonymize old data for category."""
        # Implementation would anonymize data in place
        # This is a placeholder
        return 0

    def get_retention_report(self) -> dict[str, Any]:
        """Generate retention policy report."""
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "policies": {},
            "compliance_status": "compliant",
        }

        for category, policy in self.policies.items():
            report["policies"][category.value] = {
                "retention_days": policy.retention_days,
                "action": policy.action.value,
                "anonymization_days": policy.anonymization_days,
                "legal_hold": policy.legal_hold,
                "description": policy.description,
            }

        return report

    async def handle_data_export_request(
        self, data_subject_id: str, categories: list[DataCategory] | None = None
    ) -> dict[str, Any]:
        """
        Handle GDPR data export request (Right to Data Portability).

        Args:
            data_subject_id: ID of data subject requesting export
            categories: Specific categories to export (None = all)

        Returns:
            Exported data in portable format
        """
        categories = categories or list(DataCategory)

        export_data = {
            "data_subject_id": data_subject_id,
            "export_timestamp": datetime.utcnow().isoformat(),
            "categories": {},
        }

        for category in categories:
            try:
                data = await self._export_data_by_category(data_subject_id, category)
                if data:
                    export_data["categories"][category.value] = data
            except Exception as e:
                logger.error("Export failed for category", category=category.value, error=str(e))
                export_data["categories"][category.value] = {"error": str(e)}

        return export_data

    async def _export_data_by_category(
        self, data_subject_id: str, category: DataCategory
    ) -> dict[str, Any] | None:
        """Export data for specific category."""
        # Implementation would fetch and return data
        # This is a placeholder
        return {
            "category": category.value,
            "data_subject_id": data_subject_id,
            "records": [],
            "count": 0,
        }


# Global instance
lifecycle_manager = DataLifecycleManager()


# Scheduled cleanup task
async def retention_cleanup_task():
    """Scheduled task for retention cleanup."""
    while True:
        try:
            # Run cleanup daily
            await asyncio.sleep(86400)  # 24 hours

            # Run cleanup
            summary = await lifecycle_manager.run_retention_cleanup()

            logger.info("Scheduled retention cleanup completed", **summary)

        except Exception as e:
            logger.error("Retention cleanup task failed", error=str(e))
            # Wait before retrying
            await asyncio.sleep(3600)  # 1 hour


# Example usage
if __name__ == "__main__":
    import asyncio

    async def test_lifecycle():
        # Test deletion request
        deletion_result = await lifecycle_manager.handle_deletion_request(
            data_subject_id="user123",
            categories=[DataCategory.CACHED_PROMPTS, DataCategory.DETECTION_LOGS],
            reason="user_request",
        )
        print("Deletion result:", json.dumps(deletion_result, indent=2))

        # Test export request
        export_result = await lifecycle_manager.handle_data_export_request(
            data_subject_id="user123", categories=[DataCategory.DETECTION_LOGS]
        )
        print("\nExport result:", json.dumps(export_result, indent=2))

        # Get retention report
        report = lifecycle_manager.get_retention_report()
        print("\nRetention report:", json.dumps(report, indent=2))

    asyncio.run(test_lifecycle())
