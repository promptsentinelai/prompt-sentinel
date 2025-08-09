"""Simplified tests for experiment assignments module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from prompt_sentinel.experiments.assignments import (
    AssignmentContext,
    AssignmentError,
    AssignmentService,
    BucketingStrategy,
)


class TestBucketingStrategy:
    """Test suite for BucketingStrategy enum."""

    def test_bucketing_strategy_values(self):
        """Test bucketing strategy enum values."""
        assert BucketingStrategy.RANDOM.value == "random"
        assert BucketingStrategy.HASH_BASED.value == "hash_based"
        assert BucketingStrategy.WEIGHTED.value == "weighted"
        assert BucketingStrategy.STRATIFIED.value == "stratified"


class TestAssignmentError:
    """Test suite for AssignmentError exception."""

    def test_assignment_error_creation(self):
        """Test creating assignment error."""
        error = AssignmentError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)


class TestAssignmentContext:
    """Test suite for AssignmentContext dataclass."""

    def test_initialization_minimal(self):
        """Test assignment context initialization with minimal data."""
        context = AssignmentContext(user_id="user_001")
        
        assert context.user_id == "user_001"
        assert context.session_id is None
        assert context.ip_address is None
        assert context.user_agent is None
        assert isinstance(context.attributes, dict)
        assert len(context.attributes) == 0
        assert isinstance(context.timestamp, datetime)

    def test_initialization_full(self):
        """Test assignment context initialization with full data."""
        timestamp = datetime.utcnow()
        attributes = {"device": "mobile", "region": "us-east"}
        
        context = AssignmentContext(
            user_id="user_001",
            session_id="sess_123",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            attributes=attributes,
            timestamp=timestamp
        )
        
        assert context.user_id == "user_001"
        assert context.session_id == "sess_123"
        assert context.ip_address == "192.168.1.1"
        assert context.user_agent == "Mozilla/5.0"
        assert context.attributes == attributes
        assert context.timestamp == timestamp


class TestAssignmentService:
    """Test suite for AssignmentService."""

    @pytest.fixture
    def assignment_service(self):
        """Create assignment service instance."""
        return AssignmentService(cache_ttl_seconds=3600)

    @pytest.fixture
    def assignment_context(self):
        """Create sample assignment context."""
        return AssignmentContext(
            user_id="user_001",
            session_id="sess_123",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            attributes={"device": "mobile", "region": "us-east"}
        )

    def test_initialization(self, assignment_service):
        """Test assignment service initialization."""
        assert assignment_service.cache_ttl == 3600
        assert isinstance(assignment_service.assignments_cache, dict)
        assert len(assignment_service.assignments_cache) == 0

    def test_initialization_default_ttl(self):
        """Test assignment service initialization with default TTL."""
        service = AssignmentService()
        assert service.cache_ttl == 86400  # 24 hours

    @pytest.mark.asyncio
    async def test_assign_user_inactive_experiment(self, assignment_service, assignment_context):
        """Test assignment fails for inactive experiment."""
        # Mock experiment that returns False for is_active()
        mock_experiment = MagicMock()
        mock_experiment.is_active.return_value = False
        mock_experiment.id = "exp_001"
        mock_experiment.status.value = "draft"
        
        assignment = await assignment_service.assign_user(
            assignment_context,
            mock_experiment
        )
        
        assert assignment is None

    @pytest.mark.asyncio
    async def test_get_assignment_not_exists(self, assignment_service):
        """Test getting non-existent assignment."""
        result = await assignment_service.get_assignment("user_999", "exp_999")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_existing_assignment_memory_cache(self, assignment_service):
        """Test getting existing assignment from memory cache."""
        from prompt_sentinel.experiments.config import ExperimentAssignment
        
        # Create assignment in memory cache
        assignment = ExperimentAssignment(
            user_id="user_001",
            experiment_id="exp_001",
            variant_id="control",
            assigned_at=datetime.utcnow()
        )
        
        cache_key = "assignment:exp_001:user_001"
        assignment_service.assignments_cache[cache_key] = assignment
        
        result = await assignment_service._get_existing_assignment("user_001", "exp_001")
        
        assert result == assignment

    @pytest.mark.asyncio
    async def test_get_existing_assignment_from_redis(self, assignment_service):
        """Test getting existing assignment from Redis."""
        with patch('prompt_sentinel.experiments.assignments.cache_manager') as mock_cache:
            mock_cache.connected = True
            mock_cache.get = AsyncMock(return_value={
                "user_id": "user_001",
                "experiment_id": "exp_001",
                "variant_id": "control",
                "assigned_at": datetime.utcnow().isoformat(),
                "sticky": True
            })
            
            assignment = await assignment_service._get_existing_assignment("user_001", "exp_001")
            
            assert assignment is not None
            assert assignment.user_id == "user_001"
            assert assignment.variant_id == "control"

    @pytest.mark.asyncio
    async def test_cache_assignment_memory_only(self, assignment_service):
        """Test caching assignment in memory."""
        from prompt_sentinel.experiments.config import ExperimentAssignment
        
        assignment = ExperimentAssignment(
            user_id="user_001",
            experiment_id="exp_001",
            variant_id="control",
            assigned_at=datetime.utcnow()
        )
        
        await assignment_service._cache_assignment(assignment)
        
        cache_key = "assignment:exp_001:user_001"
        assert cache_key in assignment_service.assignments_cache
        assert assignment_service.assignments_cache[cache_key] == assignment

    def test_passes_targeting_filters_no_filters(self, assignment_service, assignment_context):
        """Test targeting filters pass when no filters configured."""
        mock_experiment = MagicMock()
        mock_experiment.target_filters = {}
        
        result = assignment_service._passes_targeting_filters(assignment_context, mock_experiment)
        
        assert result is True

    def test_passes_targeting_filters_min_requests_pass(self, assignment_service, assignment_context):
        """Test min_requests filter passes."""
        mock_experiment = MagicMock()
        mock_experiment.target_filters = {"min_requests": 10}
        assignment_context.attributes = {"total_requests": 50}
        
        result = assignment_service._passes_targeting_filters(assignment_context, mock_experiment)
        
        assert result is True

    def test_passes_targeting_filters_min_requests_fail(self, assignment_service, assignment_context):
        """Test min_requests filter fails."""
        mock_experiment = MagicMock()
        mock_experiment.target_filters = {"min_requests": 100}
        assignment_context.attributes = {"total_requests": 50}
        
        result = assignment_service._passes_targeting_filters(assignment_context, mock_experiment)
        
        assert result is False

    def test_is_in_experiment_sample_full_percentage(self, assignment_service):
        """Test sample inclusion with 100% target percentage."""
        mock_experiment = MagicMock()
        mock_experiment.target_percentage = 1.0
        
        result = assignment_service._is_in_experiment_sample("user_001", mock_experiment)
        
        assert result is True

    def test_is_in_experiment_sample_zero_percentage(self, assignment_service):
        """Test sample exclusion with 0% target percentage."""
        mock_experiment = MagicMock()
        mock_experiment.target_percentage = 0.0
        
        result = assignment_service._is_in_experiment_sample("user_001", mock_experiment)
        
        assert result is False

    def test_hash_based_assignment_consistent(self, assignment_service):
        """Test hash-based assignment is consistent."""
        # Mock experiment with variants
        mock_experiment = MagicMock()
        mock_experiment.id = "exp_001"
        
        # Mock variants
        control_variant = MagicMock()
        control_variant.id = "control"
        control_variant.traffic_percentage = 0.5
        
        treatment_variant = MagicMock()
        treatment_variant.id = "treatment"
        treatment_variant.traffic_percentage = 0.5
        
        mock_experiment.variants = [control_variant, treatment_variant]
        mock_experiment.get_control_variant.return_value = control_variant
        
        variant1 = assignment_service._hash_based_assignment("user_001", mock_experiment)
        variant2 = assignment_service._hash_based_assignment("user_001", mock_experiment)
        
        assert variant1 == variant2

    def test_weighted_assignment_consistent(self, assignment_service):
        """Test weighted assignment is consistent for same user."""
        # Mock experiment with variants
        mock_experiment = MagicMock()
        mock_experiment.id = "exp_001"
        
        control_variant = MagicMock()
        control_variant.traffic_percentage = 0.5
        
        treatment_variant = MagicMock()
        treatment_variant.traffic_percentage = 0.5
        
        mock_experiment.variants = [control_variant, treatment_variant]
        
        variant1 = assignment_service._weighted_assignment("user_001", mock_experiment)
        variant2 = assignment_service._weighted_assignment("user_001", mock_experiment)
        
        assert variant1 == variant2

    @pytest.mark.asyncio
    async def test_get_assignment_stats_empty(self, assignment_service):
        """Test getting assignment statistics when empty."""
        stats = await assignment_service.get_assignment_stats("exp_001")
        
        assert stats["experiment_id"] == "exp_001"
        assert stats["total_assignments"] == 0
        assert stats["variant_counts"] == {}

    @pytest.mark.asyncio
    async def test_invalidate_assignments_memory(self, assignment_service):
        """Test invalidating assignments from memory."""
        from prompt_sentinel.experiments.config import ExperimentAssignment
        
        # Add test assignments
        for i in range(3):
            assignment = ExperimentAssignment(
                user_id=f"user_{i}",
                experiment_id="exp_001",
                variant_id="control",
                assigned_at=datetime.utcnow()
            )
            cache_key = f"assignment:exp_001:user_{i}"
            assignment_service.assignments_cache[cache_key] = assignment
        
        # Add assignment for different experiment
        other_assignment = ExperimentAssignment(
            user_id="user_other",
            experiment_id="exp_002",
            variant_id="control",
            assigned_at=datetime.utcnow()
        )
        assignment_service.assignments_cache["assignment:exp_002:user_other"] = other_assignment
        
        await assignment_service.invalidate_assignments("exp_001")
        
        # Should remove exp_001 assignments but keep exp_002
        exp_001_keys = [k for k in assignment_service.assignments_cache.keys() if ":exp_001:" in k]
        exp_002_keys = [k for k in assignment_service.assignments_cache.keys() if ":exp_002:" in k]
        
        assert len(exp_001_keys) == 0
        assert len(exp_002_keys) == 1

    @pytest.mark.asyncio 
    async def test_assign_to_variant_unknown_strategy(self, assignment_service, assignment_context):
        """Test assign_to_variant with unknown strategy raises error."""
        mock_experiment = MagicMock()
        mock_experiment.id = "exp_001"
        
        # Create unknown strategy 
        unknown_strategy = MagicMock()
        unknown_strategy.value = "unknown"
        
        with pytest.raises(AssignmentError, match="Unknown bucketing strategy"):
            await assignment_service._assign_to_variant(
                assignment_context,
                mock_experiment,
                unknown_strategy
            )

    @pytest.mark.asyncio
    async def test_bulk_assign_with_exceptions(self, assignment_service):
        """Test bulk assignment handles exceptions gracefully."""
        contexts = [AssignmentContext(user_id="user_001")]
        mock_experiment = MagicMock()
        
        # Mock assign_user to raise exception
        with patch.object(assignment_service, 'assign_user', side_effect=Exception("Test error")):
            assignments = await assignment_service.bulk_assign_users(
                contexts,
                mock_experiment
            )
        
        assert len(assignments) == 1
        assert assignments[0] is None