"""API routes for ML pattern discovery and management."""

import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Query, Path, Body
from pydantic import BaseModel, Field
import structlog

from prompt_sentinel.models.schemas import Verdict
from prompt_sentinel.ml.collector import EventType, pattern_collector
from prompt_sentinel.ml.manager import PatternStatus

logger = structlog.get_logger()

# Router instance
router = APIRouter(prefix="/ml", tags=["Machine Learning"])


# Request/Response Models
class FeedbackRequest(BaseModel):
    """Request model for submitting feedback."""
    event_id: str = Field(..., description="Event ID to provide feedback for")
    user_label: str = Field(..., description="User's label for the event")
    is_false_positive: bool = Field(False, description="Whether this was a false positive")
    is_false_negative: bool = Field(False, description="Whether this was a false negative")
    comments: Optional[str] = Field(None, description="Additional comments")


class FeedbackResponse(BaseModel):
    """Response model for feedback submission."""
    success: bool
    message: str
    event_id: str


class PatternDiscoveryRequest(BaseModel):
    """Request model for triggering pattern discovery."""
    min_events: Optional[int] = Field(100, description="Minimum events for clustering")
    algorithm: Optional[str] = Field("dbscan", description="Clustering algorithm")
    force: bool = Field(False, description="Force discovery even if not enough events")


class PatternPromotionRequest(BaseModel):
    """Request model for pattern promotion."""
    pattern_id: str = Field(..., description="Pattern ID to promote")
    reason: Optional[str] = Field(None, description="Reason for promotion")


class PatternRetirementRequest(BaseModel):
    """Request model for pattern retirement."""
    pattern_id: str = Field(..., description="Pattern ID to retire")
    reason: str = Field(..., description="Reason for retirement")


class PatternTestRequest(BaseModel):
    """Request model for testing a pattern."""
    pattern_id: str = Field(..., description="Pattern ID to test")
    text: str = Field(..., description="Text to test against pattern")


class CollectorStatsResponse(BaseModel):
    """Response model for collector statistics."""
    total_events: int
    buffer_size: int
    unique_prompts: int
    false_positives: int
    false_negatives: int
    verdict_distribution: Dict[str, int]
    category_distribution: Dict[str, int]
    ready_for_clustering: bool


class PatternResponse(BaseModel):
    """Response model for a pattern."""
    pattern_id: str
    regex: str
    confidence: float
    support: int
    cluster_id: int
    category: str
    description: str
    examples: List[str]
    created_at: str
    status: Optional[str] = None
    performance: Optional[Dict[str, Any]] = None


class ClusterResponse(BaseModel):
    """Response model for a cluster."""
    cluster_id: int
    size: int
    density: float
    avg_confidence: float
    dominant_category: str
    top_patterns: List[str]
    created_at: str


# Dependency to get pattern manager
async def get_pattern_manager():
    """Get the global pattern manager instance."""
    from prompt_sentinel.main import pattern_manager
    if not pattern_manager:
        raise HTTPException(
            status_code=503,
            detail="Pattern manager not available"
        )
    return pattern_manager


# Endpoints
@router.post("/feedback", response_model=FeedbackResponse, 
             summary="Submit feedback for detection event")
async def submit_feedback(request: FeedbackRequest):
    """Submit user feedback for a detection event.
    
    This helps improve pattern discovery by labeling false positives
    and false negatives.
    
    Args:
        request: Feedback request with event ID and labels
        
    Returns:
        Feedback submission result
    """
    try:
        success = await pattern_collector.add_feedback(
            event_id=request.event_id,
            user_label=request.user_label,
            is_false_positive=request.is_false_positive,
            is_false_negative=request.is_false_negative
        )
        
        if success:
            logger.info("Feedback submitted",
                       event_id=request.event_id,
                       label=request.user_label)
            
            return FeedbackResponse(
                success=True,
                message="Feedback recorded successfully",
                event_id=request.event_id
            )
        else:
            return FeedbackResponse(
                success=False,
                message="Event not found in buffer",
                event_id=request.event_id
            )
            
    except Exception as e:
        logger.error("Failed to submit feedback", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to submit feedback")


@router.get("/collector/stats", response_model=CollectorStatsResponse,
            summary="Get event collector statistics")
async def get_collector_stats():
    """Get statistics about the event collector.
    
    Returns information about collected events, buffer status,
    and readiness for clustering.
    
    Returns:
        Collector statistics
    """
    stats = pattern_collector.get_statistics()
    
    return CollectorStatsResponse(**stats)


@router.post("/patterns/discover", response_model=List[PatternResponse],
             summary="Trigger pattern discovery")
async def discover_patterns(
    request: PatternDiscoveryRequest,
    manager=Depends(get_pattern_manager)
):
    """Manually trigger pattern discovery.
    
    Runs clustering and pattern extraction on collected events.
    
    Args:
        request: Discovery configuration
        manager: Pattern manager instance
        
    Returns:
        List of discovered patterns
    """
    try:
        # Check if enough events
        stats = pattern_collector.get_statistics()
        
        if not request.force and stats["buffer_size"] < request.min_events:
            raise HTTPException(
                status_code=400,
                detail=f"Not enough events. Have {stats['buffer_size']}, need {request.min_events}"
            )
        
        # Run discovery
        patterns = await manager.discover_patterns()
        
        # Convert to response
        response = []
        for pattern in patterns:
            response.append(PatternResponse(
                pattern_id=pattern.pattern_id,
                regex=pattern.regex,
                confidence=pattern.confidence,
                support=pattern.support,
                cluster_id=pattern.cluster_id,
                category=pattern.category,
                description=pattern.description,
                examples=pattern.examples[:3],
                created_at=pattern.created_at.isoformat()
            ))
        
        logger.info("Pattern discovery completed", 
                   patterns_found=len(patterns))
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Pattern discovery failed", error=str(e))
        raise HTTPException(status_code=500, detail="Pattern discovery failed")


@router.get("/patterns", response_model=List[PatternResponse],
            summary="List discovered patterns")
async def list_patterns(
    status: Optional[PatternStatus] = Query(None, description="Filter by status"),
    category: Optional[str] = Query(None, description="Filter by category"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0, description="Minimum confidence"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum patterns to return"),
    manager=Depends(get_pattern_manager)
):
    """List discovered patterns with optional filtering.
    
    Args:
        status: Filter by pattern status
        category: Filter by detection category
        min_confidence: Minimum confidence threshold
        limit: Maximum number of patterns
        manager: Pattern manager instance
        
    Returns:
        List of patterns matching criteria
    """
    try:
        patterns = []
        
        # Get patterns based on status
        if status:
            pattern_ids = manager.patterns_by_status.get(status, [])
        else:
            pattern_ids = list(manager.patterns.keys())
        
        # Filter and convert
        for pattern_id in pattern_ids[:limit]:
            if pattern_id not in manager.patterns:
                continue
            
            managed = manager.patterns[pattern_id]
            pattern = managed.pattern
            
            # Apply filters
            if category and pattern.category != category:
                continue
            if pattern.confidence < min_confidence:
                continue
            
            # Create response
            patterns.append(PatternResponse(
                pattern_id=pattern.pattern_id,
                regex=pattern.regex,
                confidence=pattern.confidence,
                support=pattern.support,
                cluster_id=pattern.cluster_id,
                category=pattern.category,
                description=pattern.description,
                examples=pattern.examples[:3],
                created_at=pattern.created_at.isoformat(),
                status=managed.status.value,
                performance={
                    "precision": managed.performance.precision,
                    "recall": managed.performance.recall,
                    "f1_score": managed.performance.f1_score,
                    "total_matches": managed.performance.total_matches
                }
            ))
        
        return patterns
        
    except Exception as e:
        logger.error("Failed to list patterns", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to list patterns")


@router.get("/patterns/{pattern_id}", response_model=PatternResponse,
            summary="Get pattern details")
async def get_pattern(
    pattern_id: str = Path(..., description="Pattern identifier"),
    manager=Depends(get_pattern_manager)
):
    """Get detailed information about a specific pattern.
    
    Args:
        pattern_id: Pattern identifier
        manager: Pattern manager instance
        
    Returns:
        Pattern details including performance metrics
    """
    if pattern_id not in manager.patterns:
        raise HTTPException(status_code=404, detail="Pattern not found")
    
    managed = manager.patterns[pattern_id]
    pattern = managed.pattern
    
    return PatternResponse(
        pattern_id=pattern.pattern_id,
        regex=pattern.regex,
        confidence=pattern.confidence,
        support=pattern.support,
        cluster_id=pattern.cluster_id,
        category=pattern.category,
        description=pattern.description,
        examples=pattern.examples,
        created_at=pattern.created_at.isoformat(),
        status=managed.status.value,
        performance={
            "precision": managed.performance.precision,
            "recall": managed.performance.recall,
            "f1_score": managed.performance.f1_score,
            "accuracy": managed.performance.accuracy,
            "true_positives": managed.performance.true_positives,
            "false_positives": managed.performance.false_positives,
            "true_negatives": managed.performance.true_negatives,
            "false_negatives": managed.performance.false_negatives,
            "total_matches": managed.performance.total_matches,
            "last_match": managed.performance.last_match.isoformat() 
                if managed.performance.last_match else None
        }
    )


@router.post("/patterns/{pattern_id}/test", response_model=dict,
             summary="Test pattern against text")
async def test_pattern(
    pattern_id: str = Path(..., description="Pattern identifier"),
    request: PatternTestRequest = ...,
    manager=Depends(get_pattern_manager)
):
    """Test a pattern against provided text.
    
    Args:
        pattern_id: Pattern to test
        request: Text to test against
        manager: Pattern manager instance
        
    Returns:
        Test result
    """
    if pattern_id not in manager.patterns:
        raise HTTPException(status_code=404, detail="Pattern not found")
    
    pattern = manager.patterns[pattern_id].pattern
    
    matches = pattern.test(request.text)
    
    return {
        "pattern_id": pattern_id,
        "text": request.text,
        "matches": matches,
        "regex": pattern.regex
    }


@router.post("/patterns/{pattern_id}/promote", response_model=dict,
             summary="Promote pattern to active status")
async def promote_pattern(
    pattern_id: str = Path(..., description="Pattern identifier"),
    manager=Depends(get_pattern_manager)
):
    """Manually promote a pattern to active status.
    
    Args:
        pattern_id: Pattern to promote
        manager: Pattern manager instance
        
    Returns:
        Promotion result
    """
    success = await manager.promote_pattern(pattern_id)
    
    if success:
        return {
            "success": True,
            "pattern_id": pattern_id,
            "message": "Pattern promoted to active status"
        }
    else:
        raise HTTPException(
            status_code=400,
            detail="Pattern cannot be promoted or not found"
        )


@router.post("/patterns/{pattern_id}/retire", response_model=dict,
             summary="Retire pattern from active use")
async def retire_pattern(
    pattern_id: str = Path(..., description="Pattern identifier"),
    request: PatternRetirementRequest = ...,
    manager=Depends(get_pattern_manager)
):
    """Retire a pattern from active use.
    
    Args:
        pattern_id: Pattern to retire
        request: Retirement reason
        manager: Pattern manager instance
        
    Returns:
        Retirement result
    """
    success = await manager.retire_pattern(pattern_id, request.reason)
    
    if success:
        return {
            "success": True,
            "pattern_id": pattern_id,
            "message": f"Pattern retired: {request.reason}"
        }
    else:
        raise HTTPException(
            status_code=404,
            detail="Pattern not found"
        )


@router.get("/clusters", response_model=List[ClusterResponse],
            summary="Get current clusters")
async def get_clusters(
    manager=Depends(get_pattern_manager)
):
    """Get information about current clusters.
    
    Args:
        manager: Pattern manager instance
        
    Returns:
        List of clusters from last discovery
    """
    clusters = manager.clustering_engine.export_clusters()
    
    response = []
    for cluster_data in clusters:
        response.append(ClusterResponse(**cluster_data))
    
    return response


@router.get("/metrics", response_model=dict,
            summary="Get ML system metrics")
async def get_ml_metrics(
    manager=Depends(get_pattern_manager)
):
    """Get comprehensive ML system metrics.
    
    Returns statistics about pattern discovery, performance,
    and system health.
    
    Args:
        manager: Pattern manager instance
        
    Returns:
        ML system metrics
    """
    stats = manager.get_pattern_statistics()
    
    return {
        "pattern_stats": stats,
        "clustering_stats": manager.clustering_engine.get_cluster_statistics(),
        "collector_stats": pattern_collector.get_statistics(),
        "timestamp": datetime.utcnow().isoformat()
    }


@router.delete("/patterns/{pattern_id}", response_model=dict,
             summary="Delete a pattern")
async def delete_pattern(
    pattern_id: str = Path(..., description="Pattern identifier"),
    manager=Depends(get_pattern_manager)
):
    """Permanently delete a pattern.
    
    Args:
        pattern_id: Pattern to delete
        manager: Pattern manager instance
        
    Returns:
        Deletion result
    """
    if pattern_id not in manager.patterns:
        raise HTTPException(status_code=404, detail="Pattern not found")
    
    # Remove from all indexes
    managed = manager.patterns[pattern_id]
    status = managed.status
    
    if pattern_id in manager.patterns_by_status[status]:
        manager.patterns_by_status[status].remove(pattern_id)
    
    del manager.patterns[pattern_id]
    
    logger.info("Pattern deleted", pattern_id=pattern_id)
    
    return {
        "success": True,
        "pattern_id": pattern_id,
        "message": "Pattern deleted successfully"
    }