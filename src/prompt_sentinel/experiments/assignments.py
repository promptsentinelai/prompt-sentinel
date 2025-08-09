"""User assignment and bucketing service for A/B testing.

This module handles the assignment of users to experiment variants using
various bucketing strategies while ensuring consistency and statistical validity.
"""

import asyncio
import hashlib
import random
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

import structlog

from prompt_sentinel.cache.cache_manager import cache_manager

from .config import ExperimentAssignment, ExperimentConfig, ExperimentVariant

logger = structlog.get_logger()


class BucketingStrategy(Enum):
    """Strategies for assigning users to experiment variants."""

    RANDOM = "random"  # Pure random assignment
    HASH_BASED = "hash_based"  # Consistent hash-based assignment
    WEIGHTED = "weighted"  # Weighted random assignment
    STRATIFIED = "stratified"  # Stratified by user attributes


class AssignmentError(Exception):
    """Exception raised during user assignment process."""

    pass


@dataclass
class AssignmentContext:
    """Context information for user assignment."""

    user_id: str
    session_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    attributes: dict[str, Any] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.attributes is None:
            self.attributes = {}
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class AssignmentService:
    """Service for assigning users to experiment variants.

    Handles user bucketing, assignment persistence, and consistency
    guarantees for A/B testing experiments.
    """

    def __init__(self, cache_ttl_seconds: int = 86400):  # 24 hours default
        """Initialize assignment service.

        Args:
            cache_ttl_seconds: TTL for cached assignments
        """
        self.cache_ttl = cache_ttl_seconds
        self.assignments_cache = {}  # In-memory fallback

    async def assign_user(
        self,
        context: AssignmentContext,
        experiment: ExperimentConfig,
        strategy: BucketingStrategy = BucketingStrategy.HASH_BASED,
    ) -> ExperimentAssignment | None:
        """Assign user to experiment variant.

        Args:
            context: User context for assignment
            experiment: Experiment configuration
            strategy: Bucketing strategy to use

        Returns:
            Assignment if user should participate, None if excluded
        """
        # Check if experiment is active
        if not experiment.is_active():
            logger.debug(
                "Experiment not active", experiment_id=experiment.id, status=experiment.status.value
            )
            return None

        # Check for existing assignment (consistency)
        existing_assignment = await self._get_existing_assignment(context.user_id, experiment.id)
        if existing_assignment:
            logger.debug(
                "Using existing assignment",
                user_id=context.user_id,
                experiment_id=experiment.id,
                variant_id=existing_assignment.variant_id,
            )
            return existing_assignment

        # Apply targeting filters
        if not self._passes_targeting_filters(context, experiment):
            logger.debug(
                "User excluded by targeting filters",
                user_id=context.user_id,
                experiment_id=experiment.id,
            )
            return None

        # Check if user is in experiment sample
        if not self._is_in_experiment_sample(context.user_id, experiment):
            logger.debug(
                "User not in experiment sample",
                user_id=context.user_id,
                experiment_id=experiment.id,
            )
            return None

        # Assign to variant using selected strategy
        variant = await self._assign_to_variant(context, experiment, strategy)
        if not variant:
            return None

        # Create assignment record
        assignment = ExperimentAssignment(
            user_id=context.user_id,
            experiment_id=experiment.id,
            variant_id=variant.id,
            assigned_at=datetime.utcnow(),
        )

        # Cache the assignment
        await self._cache_assignment(assignment)

        logger.info(
            "User assigned to experiment variant",
            user_id=context.user_id,
            experiment_id=experiment.id,
            variant_id=variant.id,
            strategy=strategy.value,
        )

        return assignment

    async def get_assignment(self, user_id: str, experiment_id: str) -> ExperimentAssignment | None:
        """Get existing user assignment for experiment.

        Args:
            user_id: User identifier
            experiment_id: Experiment identifier

        Returns:
            Assignment if exists, None otherwise
        """
        return await self._get_existing_assignment(user_id, experiment_id)

    async def bulk_assign_users(
        self,
        contexts: list[AssignmentContext],
        experiment: ExperimentConfig,
        strategy: BucketingStrategy = BucketingStrategy.HASH_BASED,
    ) -> list[ExperimentAssignment | None]:
        """Assign multiple users to experiment variants.

        Args:
            contexts: List of user contexts
            experiment: Experiment configuration
            strategy: Bucketing strategy

        Returns:
            List of assignments (None for excluded users)
        """
        tasks = [self.assign_user(context, experiment, strategy) for context in contexts]

        assignments = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions
        results = []
        for i, assignment in enumerate(assignments):
            if isinstance(assignment, Exception):
                logger.error(
                    "Failed to assign user",
                    user_id=contexts[i].user_id,
                    experiment_id=experiment.id,
                    error=str(assignment),
                )
                results.append(None)
            else:
                results.append(assignment)

        return results

    async def _get_existing_assignment(
        self, user_id: str, experiment_id: str
    ) -> ExperimentAssignment | None:
        """Get existing assignment from cache or storage.

        Args:
            user_id: User identifier
            experiment_id: Experiment identifier

        Returns:
            Existing assignment if found
        """
        cache_key = f"assignment:{experiment_id}:{user_id}"

        # Try cache first
        if cache_manager and cache_manager.connected:
            try:
                cached_data = await cache_manager.get(cache_key)
                if cached_data:
                    return ExperimentAssignment(**cached_data)
            except Exception as e:
                logger.warning(
                    "Failed to get assignment from cache", error=str(e), cache_key=cache_key
                )

        # Try in-memory fallback
        if cache_key in self.assignments_cache:
            return self.assignments_cache[cache_key]

        return None

    async def _cache_assignment(self, assignment: ExperimentAssignment):
        """Cache user assignment for consistency.

        Args:
            assignment: Assignment to cache
        """
        cache_key = f"assignment:{assignment.experiment_id}:{assignment.user_id}"
        assignment_data = {
            "user_id": assignment.user_id,
            "experiment_id": assignment.experiment_id,
            "variant_id": assignment.variant_id,
            "assigned_at": assignment.assigned_at.isoformat(),
            "sticky": assignment.sticky,
        }

        # Cache in Redis if available
        if cache_manager and cache_manager.connected:
            try:
                await cache_manager.set(cache_key, assignment_data, ttl=self.cache_ttl)
            except Exception as e:
                logger.warning("Failed to cache assignment", error=str(e), cache_key=cache_key)

        # Always keep in-memory backup
        self.assignments_cache[cache_key] = assignment

    def _passes_targeting_filters(
        self, context: AssignmentContext, experiment: ExperimentConfig
    ) -> bool:
        """Check if user passes targeting filters.

        Args:
            context: User context
            experiment: Experiment configuration

        Returns:
            True if user passes all filters
        """
        if not experiment.target_filters:
            return True

        for filter_name, filter_value in experiment.target_filters.items():
            if filter_name == "min_requests":
                # Example filter: minimum number of API requests
                user_requests = context.attributes.get("total_requests", 0)
                if user_requests < filter_value:
                    return False

            elif filter_name == "user_type":
                # Example filter: user type
                user_type = context.attributes.get("user_type", "free")
                if user_type != filter_value:
                    return False

            elif filter_name == "region":
                # Example filter: geographic region
                user_region = context.attributes.get("region", "unknown")
                if isinstance(filter_value, list):
                    if user_region not in filter_value:
                        return False
                elif user_region != filter_value:
                    return False

            elif filter_name == "feature_flags":
                # Example filter: required feature flags
                user_flags = context.attributes.get("feature_flags", [])
                required_flags = filter_value if isinstance(filter_value, list) else [filter_value]
                if not all(flag in user_flags for flag in required_flags):
                    return False

        return True

    def _is_in_experiment_sample(self, user_id: str, experiment: ExperimentConfig) -> bool:
        """Check if user is in experiment sample.

        Uses consistent hashing to determine if user should be
        included in the experiment based on target_percentage.

        Args:
            user_id: User identifier
            experiment: Experiment configuration

        Returns:
            True if user should be included in experiment
        """
        if experiment.target_percentage >= 1.0:
            return True

        # Consistent hash-based sampling
        hash_input = f"{experiment.id}:{user_id}:sample"
        hash_value = int(hashlib.md5(hash_input.encode()).hexdigest(), 16)
        sample_bucket = (hash_value % 10000) / 10000.0  # 0.0 to 1.0

        return sample_bucket < experiment.target_percentage

    async def _assign_to_variant(
        self, context: AssignmentContext, experiment: ExperimentConfig, strategy: BucketingStrategy
    ) -> ExperimentVariant | None:
        """Assign user to specific variant using bucketing strategy.

        Args:
            context: User context
            experiment: Experiment configuration
            strategy: Bucketing strategy

        Returns:
            Assigned variant or None
        """
        if strategy == BucketingStrategy.HASH_BASED:
            return self._hash_based_assignment(context.user_id, experiment)

        elif strategy == BucketingStrategy.WEIGHTED:
            return self._weighted_assignment(context.user_id, experiment)

        elif strategy == BucketingStrategy.RANDOM:
            return self._random_assignment(experiment)

        elif strategy == BucketingStrategy.STRATIFIED:
            return self._stratified_assignment(context, experiment)

        else:
            raise AssignmentError(f"Unknown bucketing strategy: {strategy}")

    def _hash_based_assignment(
        self, user_id: str, experiment: ExperimentConfig
    ) -> ExperimentVariant:
        """Assign user using consistent hash-based bucketing.

        Args:
            user_id: User identifier
            experiment: Experiment configuration

        Returns:
            Assigned variant
        """
        # Create consistent hash
        hash_input = f"{experiment.id}:{user_id}:variant"
        hash_value = int(hashlib.md5(hash_input.encode()).hexdigest(), 16)
        bucket = hash_value % 10000  # 0 to 9999

        # Map bucket to variant based on traffic allocation
        cumulative_percentage = 0.0
        for variant in experiment.variants:
            cumulative_percentage += variant.traffic_percentage
            if bucket < cumulative_percentage * 10000:
                return variant

        # Fallback to control (should not happen with proper config)
        return experiment.get_control_variant()

    def _weighted_assignment(self, user_id: str, experiment: ExperimentConfig) -> ExperimentVariant:
        """Assign user using weighted random assignment.

        Args:
            user_id: User identifier
            experiment: Experiment configuration

        Returns:
            Assigned variant
        """
        # Use user_id as seed for consistency
        random.seed(hash(f"{experiment.id}:{user_id}"))

        # Weighted random selection
        weights = [variant.traffic_percentage for variant in experiment.variants]
        variant = random.choices(experiment.variants, weights=weights)[0]

        return variant

    def _random_assignment(self, experiment: ExperimentConfig) -> ExperimentVariant:
        """Assign user using pure random assignment.

        Args:
            experiment: Experiment configuration

        Returns:
            Assigned variant
        """
        weights = [variant.traffic_percentage for variant in experiment.variants]
        return random.choices(experiment.variants, weights=weights)[0]

    def _stratified_assignment(
        self, context: AssignmentContext, experiment: ExperimentConfig
    ) -> ExperimentVariant:
        """Assign user using stratified sampling.

        Ensures balanced representation across user segments.

        Args:
            context: User context
            experiment: Experiment configuration

        Returns:
            Assigned variant
        """
        # For now, use hash-based as fallback
        # Could be extended to consider user attributes for stratification
        user_segment = context.attributes.get("segment", "default")
        hash_input = f"{experiment.id}:{context.user_id}:{user_segment}:stratified"

        hash_value = int(hashlib.md5(hash_input.encode()).hexdigest(), 16)
        bucket = hash_value % 10000

        cumulative_percentage = 0.0
        for variant in experiment.variants:
            cumulative_percentage += variant.traffic_percentage
            if bucket < cumulative_percentage * 10000:
                return variant

        return experiment.get_control_variant()

    async def get_assignment_stats(
        self, experiment_id: str, time_window_hours: int = 24
    ) -> dict[str, Any]:
        """Get assignment statistics for experiment.

        Args:
            experiment_id: Experiment identifier
            time_window_hours: Time window for stats

        Returns:
            Assignment statistics
        """
        # This would typically query a database
        # For now, return basic stats from cache

        stats = {
            "experiment_id": experiment_id,
            "total_assignments": 0,
            "variant_counts": {},
            "time_window_hours": time_window_hours,
            "last_updated": datetime.utcnow().isoformat(),
        }

        # Count cached assignments (simplified implementation)
        for _key, assignment in self.assignments_cache.items():
            if assignment.experiment_id == experiment_id:
                stats["total_assignments"] += 1
                variant_id = assignment.variant_id
                stats["variant_counts"][variant_id] = stats["variant_counts"].get(variant_id, 0) + 1

        return stats

    async def invalidate_assignments(self, experiment_id: str):
        """Invalidate all assignments for an experiment.

        Used when experiment configuration changes.

        Args:
            experiment_id: Experiment identifier
        """
        # Clear from Redis cache
        if cache_manager and cache_manager.connected:
            try:
                pattern = f"assignment:{experiment_id}:*"
                await cache_manager.delete_pattern(pattern)
                logger.info("Invalidated Redis assignments", experiment_id=experiment_id)
            except Exception as e:
                logger.warning(
                    "Failed to invalidate Redis assignments",
                    experiment_id=experiment_id,
                    error=str(e),
                )

        # Clear from memory cache
        keys_to_remove = [
            key
            for key in self.assignments_cache.keys()
            if key.startswith(f"assignment:{experiment_id}:")
        ]
        for key in keys_to_remove:
            del self.assignments_cache[key]

        logger.info(
            "Invalidated experiment assignments",
            experiment_id=experiment_id,
            count=len(keys_to_remove),
        )
