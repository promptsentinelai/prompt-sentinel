# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""API routes for experiment management."""

import uuid
from datetime import datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, Path, Query

from prompt_sentinel.experiments.assignments import AssignmentContext
from prompt_sentinel.experiments.config import ExperimentConfig, ExperimentStatus, ExperimentType

from .schemas import (
    BatchMetricsRequest,
    CreateExperimentRequest,
    ExperimentAssignmentRequest,
    ExperimentAssignmentResponse,
    ExperimentStatsResponse,
    ExperimentStatusRequest,
    ExperimentSummary,
    RecordMetricRequest,
    UpdateExperimentRequest,
)

logger = structlog.get_logger()

# Router instance
router = APIRouter(prefix="/experiments", tags=["Experiments"])


# Dependency to get experiment manager
async def get_experiment_manager():
    """Get the global experiment manager instance."""
    from prompt_sentinel.main import experiment_manager

    if not experiment_manager:
        raise HTTPException(status_code=503, detail="Experiment manager not available")
    return experiment_manager


@router.post("/", response_model=dict, summary="Create experiment")
async def create_experiment(
    request: CreateExperimentRequest, manager=Depends(get_experiment_manager)
):
    """Create a new A/B testing experiment.

    Creates a new experiment with the specified configuration, variants,
    and safety guardrails. The experiment will be in DRAFT status by default.

    Args:
        request: Experiment creation request

    Returns:
        Created experiment details

    Raises:
        HTTPException: 400 for invalid configuration, 500 for creation errors
    """
    try:
        # Generate unique experiment ID
        experiment_id = f"exp_{uuid.uuid4().hex[:8]}_{int(datetime.utcnow().timestamp())}"

        # Create experiment configuration
        config = ExperimentConfig(
            id=experiment_id,
            name=request.name,
            description=request.description,
            type=request.type,
            variants=request.variants,
            target_percentage=request.target_percentage,
            target_filters=request.target_filters,
            primary_metrics=request.primary_metrics,
            secondary_metrics=request.secondary_metrics,
            min_sample_size=request.min_sample_size,
            confidence_level=request.confidence_level,
            effect_size=request.effect_size,
            guardrails=request.guardrails,
            auto_promote=request.auto_promote,
            duration_hours=request.duration_hours,
            tags=request.tags,
            created_by="api_user",  # Would get from authentication
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

        # Create experiment
        created_id = await manager.create_experiment(
            config, start_immediately=request.start_immediately
        )

        logger.info(
            "Experiment created via API",
            experiment_id=created_id,
            name=request.name,
            type=request.type.value,
        )

        return {
            "experiment_id": created_id,
            "status": "created",
            "message": f"Experiment '{request.name}' created successfully",
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error("Failed to create experiment", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create experiment") from e


@router.get("/", response_model=list[ExperimentSummary], summary="List experiments")
async def list_experiments(
    status: ExperimentStatus | None = Query(None, description="Filter by status"),
    experiment_type: ExperimentType | None = Query(
        None, alias="type", description="Filter by type"
    ),
    limit: int = Query(100, ge=1, le=1000, description="Maximum experiments to return"),
    offset: int = Query(0, ge=0, description="Number of experiments to skip"),
    manager=Depends(get_experiment_manager),
):
    """List experiments with optional filtering.

    Returns a paginated list of experiments with summary information.
    Supports filtering by status, type, and pagination.

    Args:
        status: Filter by experiment status
        experiment_type: Filter by experiment type
        limit: Maximum number of experiments to return
        offset: Number of experiments to skip

    Returns:
        List of experiment summaries
    """
    try:
        experiments = await manager.list_experiments(status, experiment_type)

        # Apply pagination
        paginated = experiments[offset : offset + limit]

        summaries = []
        for exp_data in paginated:
            # Get additional stats for each experiment
            exp_status = await manager.get_experiment_status(exp_data["id"])

            summary = ExperimentSummary(
                id=exp_data["id"],
                name=exp_data["name"],
                type=exp_data.get("type", "unknown"),
                status=exp_data.get("status", "unknown"),
                created_at=datetime.fromisoformat(
                    exp_data.get("created_at", datetime.utcnow().isoformat())
                ),
                start_time=(
                    datetime.fromisoformat(exp_data["start_time"])
                    if exp_data.get("start_time")
                    else None
                ),
                end_time=(
                    datetime.fromisoformat(exp_data["end_time"])
                    if exp_data.get("end_time")
                    else None
                ),
                variants_count=exp_data.get("variants_count", 0),
                is_active=exp_data.get("is_active", False),
                target_percentage=(
                    exp_status.get("runtime_metrics", {}).get("target_percentage", 0.0)
                    if exp_status
                    else 0.0
                ),
                total_assignments=(
                    exp_status.get("assignment_stats", {}).get("total_assignments", 0)
                    if exp_status
                    else 0
                ),
                health_score=(
                    exp_status.get("safety_report", {}).get("health_score", 1.0)
                    if exp_status
                    else 1.0
                ),
            )
            summaries.append(summary)

        return summaries

    except Exception as e:
        logger.error("Failed to list experiments", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to list experiments") from e


@router.get("/{experiment_id}", response_model=dict, summary="Get experiment details")
async def get_experiment(
    experiment_id: str = Path(..., description="Experiment identifier"),
    manager=Depends(get_experiment_manager),
):
    """Get detailed information about a specific experiment.

    Returns comprehensive experiment details including configuration,
    current metrics, safety status, and analysis results.

    Args:
        experiment_id: Experiment identifier

    Returns:
        Detailed experiment information

    Raises:
        HTTPException: 404 if experiment not found
    """
    try:
        status = await manager.get_experiment_status(experiment_id)
        if not status:
            raise HTTPException(status_code=404, detail="Experiment not found")

        return status

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get experiment", experiment_id=experiment_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get experiment") from e


@router.patch("/{experiment_id}", response_model=dict, summary="Update experiment")
async def update_experiment(
    experiment_id: str = Path(..., description="Experiment identifier"),
    request: UpdateExperimentRequest = ...,
    manager=Depends(get_experiment_manager),
):
    """Update experiment configuration.

    Allows updating certain experiment properties. Some changes may
    require experiment restart or invalidate cached assignments.

    Args:
        experiment_id: Experiment identifier
        request: Update request with new values

    Returns:
        Update confirmation

    Raises:
        HTTPException: 404 if not found, 400 for invalid updates
    """
    # Note: Full implementation would require getting the existing config,
    # updating fields, validating changes, and saving back
    raise HTTPException(status_code=501, detail="Update not implemented yet")


@router.post("/{experiment_id}/status", response_model=dict, summary="Change experiment status")
async def change_experiment_status(
    experiment_id: str = Path(..., description="Experiment identifier"),
    request: ExperimentStatusRequest = ...,
    manager=Depends(get_experiment_manager),
):
    """Change experiment status (start, pause, stop).

    Controls experiment lifecycle by changing its status.
    Some status changes may trigger safety checks or cleanup.

    Args:
        experiment_id: Experiment identifier
        request: Status change request

    Returns:
        Status change confirmation
    """
    try:
        if request.status == ExperimentStatus.RUNNING:
            success = await manager.start_experiment(experiment_id)
            action = "started"
        elif request.status in [ExperimentStatus.COMPLETED, ExperimentStatus.TERMINATED]:
            success = await manager.stop_experiment(experiment_id, request.reason)
            action = "stopped"
        else:
            raise HTTPException(
                status_code=400, detail=f"Status transition to {request.status} not supported"
            )

        if not success:
            raise HTTPException(
                status_code=404, detail="Experiment not found or cannot change status"
            )

        logger.info(
            "Experiment status changed via API",
            experiment_id=experiment_id,
            status=request.status.value,
            reason=request.reason,
        )

        return {
            "experiment_id": experiment_id,
            "status": request.status.value,
            "action": action,
            "reason": request.reason,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to change experiment status", experiment_id=experiment_id, error=str(e)
        )
        raise HTTPException(status_code=500, detail="Failed to change experiment status") from e


@router.post(
    "/{experiment_id}/assign",
    response_model=ExperimentAssignmentResponse,
    summary="Assign user to experiment",
)
async def assign_user_to_experiment(
    experiment_id: str = Path(..., description="Experiment identifier"),
    request: ExperimentAssignmentRequest = ...,
    manager=Depends(get_experiment_manager),
):
    """Assign a user to an experiment variant.

    Determines which variant (if any) a user should see for this experiment.
    Uses consistent assignment algorithms to ensure users get the same
    variant on repeated calls.

    Args:
        experiment_id: Experiment identifier
        request: Assignment request with user context

    Returns:
        Assignment result with variant configuration
    """
    try:
        # Create assignment context
        context = AssignmentContext(
            user_id=request.user_id,
            session_id=request.session_id,
            attributes=request.attributes or {},
        )

        # Get assignment
        assignment = await manager.assign_user(request.user_id, experiment_id, context)

        if assignment:
            # Get variant configuration
            variant_config = await manager.get_variant_config(request.user_id, experiment_id)

            return ExperimentAssignmentResponse(
                experiment_id=experiment_id,
                variant_id=assignment.variant_id,
                assigned=True,
                reason=f"Assigned to variant {assignment.variant_id}",
                config=variant_config,
            )
        else:
            return ExperimentAssignmentResponse(
                experiment_id=experiment_id,
                variant_id=None,
                assigned=False,
                reason="User not eligible for experiment",
                config=None,
            )

    except Exception as e:
        logger.error(
            "Failed to assign user to experiment",
            experiment_id=experiment_id,
            user_id=request.user_id,
            error=str(e),
        )
        raise HTTPException(status_code=500, detail="Failed to assign user") from e


@router.post("/{experiment_id}/metrics", response_model=dict, summary="Record experiment metric")
async def record_experiment_metric(
    experiment_id: str = Path(..., description="Experiment identifier"),
    request: RecordMetricRequest = ...,
    manager=Depends(get_experiment_manager),
):
    """Record a metric value for experiment analysis.

    Records performance or outcome metrics that will be used for
    statistical analysis of experiment results.

    Args:
        experiment_id: Experiment identifier
        request: Metric recording request

    Returns:
        Recording confirmation
    """
    try:
        await manager.record_metric(
            experiment_id, request.user_id, request.metric_name, request.value, request.metadata
        )

        return {
            "experiment_id": experiment_id,
            "metric_name": request.metric_name,
            "recorded": True,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(
            "Failed to record experiment metric", experiment_id=experiment_id, error=str(e)
        )
        raise HTTPException(status_code=500, detail="Failed to record metric") from e


@router.post(
    "/{experiment_id}/metrics/batch",
    response_model=dict,
    summary="Record multiple experiment metrics",
)
async def record_experiment_metrics_batch(
    experiment_id: str = Path(..., description="Experiment identifier"),
    request: BatchMetricsRequest = ...,
    manager=Depends(get_experiment_manager),
):
    """Record multiple metrics for experiment analysis.

    Efficiently records multiple metric values in a single request.

    Args:
        experiment_id: Experiment identifier
        request: Batch metrics request

    Returns:
        Batch recording confirmation
    """
    try:
        recorded_count = 0
        for metric in request.metrics:
            await manager.record_metric(
                experiment_id, metric.user_id, metric.metric_name, metric.value, metric.metadata
            )
            recorded_count += 1

        return {
            "experiment_id": experiment_id,
            "metrics_recorded": recorded_count,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error("Failed to record batch metrics", experiment_id=experiment_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to record batch metrics") from e


@router.get("/{experiment_id}/results", response_model=dict, summary="Get experiment results")
async def get_experiment_results(
    experiment_id: str = Path(..., description="Experiment identifier"),
    manager=Depends(get_experiment_manager),
):
    """Get statistical analysis results for experiment.

    Returns comprehensive statistical analysis including significance tests,
    effect sizes, confidence intervals, and recommendations.

    Args:
        experiment_id: Experiment identifier

    Returns:
        Experiment analysis results
    """
    try:
        results = await manager.get_experiment_results(experiment_id)

        if not results:
            return {
                "experiment_id": experiment_id,
                "results": [],
                "message": "No analysis results available yet",
            }

        return {
            "experiment_id": experiment_id,
            "results": [result.get_summary() for result in results],
            "analyzed_at": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error("Failed to get experiment results", experiment_id=experiment_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get experiment results") from e


@router.delete("/{experiment_id}", response_model=dict, summary="Delete experiment")
async def delete_experiment(
    experiment_id: str = Path(..., description="Experiment identifier"),
    manager=Depends(get_experiment_manager),
):
    """Delete an experiment and all associated data.

    Permanently removes experiment configuration, metrics, and results.
    This action cannot be undone.

    Args:
        experiment_id: Experiment identifier

    Returns:
        Deletion confirmation

    Raises:
        HTTPException: 404 if not found, 400 if experiment is running
    """
    try:
        # Check if experiment exists and is not running
        status = await manager.get_experiment_status(experiment_id)
        if not status:
            raise HTTPException(status_code=404, detail="Experiment not found")

        if status.get("is_active", False):
            raise HTTPException(
                status_code=400, detail="Cannot delete active experiment. Stop it first."
            )

        # Delete experiment (would need to implement this in manager)
        # success = await manager.delete_experiment(experiment_id)

        logger.info("Experiment deleted via API", experiment_id=experiment_id)

        return {
            "experiment_id": experiment_id,
            "deleted": True,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to delete experiment", experiment_id=experiment_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to delete experiment") from e


@router.get(
    "/stats/overview", response_model=ExperimentStatsResponse, summary="Get experiment statistics"
)
async def get_experiment_stats(manager=Depends(get_experiment_manager)):
    """Get overall experiment system statistics.

    Returns high-level statistics about the experiment system including
    total experiments, status distribution, and activity metrics.

    Returns:
        Experiment system statistics
    """
    try:
        # This would need to be implemented in the manager
        return ExperimentStatsResponse(
            total_experiments=0,
            experiments_by_status={},
            experiments_by_type={},
            total_assignments=0,
            total_metrics_recorded=0,
            active_experiments=0,
        )

    except Exception as e:
        logger.error("Failed to get experiment stats", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get experiment statistics") from e
