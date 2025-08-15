# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Threat intelligence API routes."""

from datetime import datetime

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from prompt_sentinel.threat_intelligence import (
    FeedStatistics,
    FeedType,
    ThreatFeed,
    ThreatFeedManager,
)

router = APIRouter(prefix="/api/v1/threat", tags=["Threat Intelligence"])

# Global feed manager instance
# This is initialized in the main app's lifespan context
feed_manager = ThreatFeedManager()


# Request/Response models


class AddFeedRequest(BaseModel):
    """Request to add a threat feed."""

    name: str = Field(..., description="Feed name")
    description: str = Field(..., description="Feed description")
    type: FeedType = Field(..., description="Feed type")
    url: str | None = Field(None, description="Feed URL")
    api_key: str | None = Field(None, description="API key if required")
    headers: dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    refresh_interval: int = Field(3600, description="Refresh interval in seconds")
    priority: int = Field(5, ge=1, le=10, description="Processing priority")
    auto_validate: bool = Field(True, description="Auto-validate patterns")


class FeedResponse(BaseModel):
    """Feed information response."""

    id: str
    name: str
    description: str
    type: FeedType
    enabled: bool
    priority: int
    refresh_interval: int
    last_fetch: datetime | None
    last_error: str | None
    total_indicators: int
    active_indicators: int
    statistics: FeedStatistics | None


class IndicatorResponse(BaseModel):
    """Threat indicator response."""

    id: str
    feed_id: str
    pattern: str
    technique: str
    severity: str
    confidence: float
    description: str
    tags: list[str]
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None
    false_positive_rate: float | None


class TestPatternRequest(BaseModel):
    """Request to test a pattern."""

    pattern: str = Field(..., description="Regex pattern to test")
    test_cases: list[str] = Field(
        default_factory=list, description="Test cases to validate against"
    )


# API Endpoints


@router.post("/feeds", response_model=FeedResponse, summary="Add threat feed")
async def add_threat_feed(request: AddFeedRequest):
    """Add a new threat intelligence feed.

    Configures a new feed source for automatic pattern updates.
    """
    # Create feed configuration
    from pydantic import HttpUrl

    feed = ThreatFeed(
        id=request.name.lower().replace(" ", "_"),
        name=request.name,
        description=request.description,
        type=request.type,
        url=HttpUrl(request.url) if request.url else None,
        api_key=request.api_key,
        headers=request.headers,
        refresh_interval=request.refresh_interval,
        priority=request.priority,
        auto_validate=request.auto_validate,
        last_fetch=None,
        last_error=None,
    )

    # Add feed
    success = await feed_manager.add_feed(feed)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to add feed")

    # Get statistics
    stats = feed_manager.statistics.get(feed.id)

    return FeedResponse(
        id=feed.id,
        name=feed.name,
        description=feed.description,
        type=feed.type,
        enabled=feed.enabled,
        priority=feed.priority,
        refresh_interval=feed.refresh_interval,
        last_fetch=feed.last_fetch,
        last_error=feed.last_error,
        total_indicators=feed.total_indicators,
        active_indicators=feed.active_indicators,
        statistics=stats,
    )


@router.get("/feeds", response_model=list[FeedResponse], summary="List feeds")
async def list_threat_feeds():
    """List all configured threat feeds."""
    feeds = []

    for feed in feed_manager.feeds.values():
        stats = feed_manager.statistics.get(feed.id)
        feeds.append(
            FeedResponse(
                id=feed.id,
                name=feed.name,
                description=feed.description,
                type=feed.type,
                enabled=feed.enabled,
                priority=feed.priority,
                refresh_interval=feed.refresh_interval,
                last_fetch=feed.last_fetch,
                last_error=feed.last_error,
                total_indicators=feed.total_indicators,
                active_indicators=feed.active_indicators,
                statistics=stats,
            )
        )

    return feeds


@router.get("/feeds/{feed_id}", response_model=FeedResponse, summary="Get feed")
async def get_threat_feed(feed_id: str):
    """Get details for a specific threat feed."""
    if feed_id not in feed_manager.feeds:
        raise HTTPException(status_code=404, detail="Feed not found")

    feed = feed_manager.feeds[feed_id]
    stats = feed_manager.statistics.get(feed_id)

    return FeedResponse(
        id=feed.id,
        name=feed.name,
        description=feed.description,
        type=feed.type,
        enabled=feed.enabled,
        priority=feed.priority,
        refresh_interval=feed.refresh_interval,
        last_fetch=feed.last_fetch,
        last_error=feed.last_error,
        total_indicators=feed.total_indicators,
        active_indicators=feed.active_indicators,
        statistics=stats,
    )


@router.post("/feeds/{feed_id}/update", summary="Update feed")
async def update_threat_feed(feed_id: str):
    """Manually trigger feed update."""
    if feed_id not in feed_manager.feeds:
        raise HTTPException(status_code=404, detail="Feed not found")

    success = await feed_manager.update_feed(feed_id)

    return {
        "status": "success" if success else "failed",
        "feed_id": feed_id,
        "timestamp": datetime.utcnow(),
    }


@router.delete("/feeds/{feed_id}", summary="Remove feed")
async def remove_threat_feed(feed_id: str):
    """Remove a threat feed."""
    success = await feed_manager.remove_feed(feed_id)
    if not success:
        raise HTTPException(status_code=404, detail="Feed not found")

    return {"status": "removed", "feed_id": feed_id}


@router.get("/indicators", response_model=list[IndicatorResponse], summary="List indicators")
async def list_threat_indicators(
    technique: str | None = Query(None, description="Filter by technique"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0, description="Minimum confidence"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
):
    """List active threat indicators."""
    indicators = await feed_manager.get_active_indicators(technique, min_confidence)

    # Limit results
    indicators = indicators[:limit]

    return [
        IndicatorResponse(
            id=ind.id,
            feed_id=ind.feed_id,
            pattern=ind.pattern,
            technique=ind.technique.value,
            severity=ind.severity.value,
            confidence=ind.confidence,
            description=ind.description,
            tags=ind.tags,
            first_seen=ind.first_seen,
            last_seen=ind.last_seen,
            expires_at=ind.expires_at,
            false_positive_rate=ind.false_positive_rate,
        )
        for ind in indicators
    ]


@router.get(
    "/indicators/search", response_model=list[IndicatorResponse], summary="Search indicators"
)
async def search_threat_indicators(
    q: str = Query(..., description="Search query"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
):
    """Search threat indicators."""
    indicators = await feed_manager.search_indicators(q, limit)

    return [
        IndicatorResponse(
            id=ind.id,
            feed_id=ind.feed_id,
            pattern=ind.pattern,
            technique=ind.technique.value,
            severity=ind.severity.value,
            confidence=ind.confidence,
            description=ind.description,
            tags=ind.tags,
            first_seen=ind.first_seen,
            last_seen=ind.last_seen,
            expires_at=ind.expires_at,
            false_positive_rate=ind.false_positive_rate,
        )
        for ind in indicators
    ]


@router.post("/indicators/{indicator_id}/false-positive", summary="Report false positive")
async def report_false_positive(
    indicator_id: str,
    details: str | None = None,
):
    """Report a false positive for an indicator."""
    await feed_manager.report_false_positive(indicator_id, details)

    return {
        "status": "reported",
        "indicator_id": indicator_id,
        "timestamp": datetime.utcnow(),
    }


@router.post("/indicators/{indicator_id}/true-positive", summary="Confirm true positive")
async def confirm_true_positive(
    indicator_id: str,
    details: str | None = None,
):
    """Confirm a true positive detection."""
    await feed_manager.confirm_true_positive(indicator_id, details)

    return {
        "status": "confirmed",
        "indicator_id": indicator_id,
        "timestamp": datetime.utcnow(),
    }


@router.post("/test-pattern", summary="Test pattern")
async def test_pattern(request: TestPatternRequest):
    """Test a pattern against known samples."""
    from prompt_sentinel.threat_intelligence import ThreatValidator

    validator = ThreatValidator()
    results = await validator.test_pattern(request.pattern, request.test_cases)

    return results


@router.get("/statistics", summary="Get statistics")
async def get_threat_statistics():
    """Get overall threat intelligence statistics."""
    total_feeds = len(feed_manager.feeds)
    active_feeds = sum(1 for f in feed_manager.feeds.values() if f.enabled)
    total_indicators = len(feed_manager.indicators)
    active_indicators = len(await feed_manager.get_active_indicators())

    # Calculate average confidence
    if feed_manager.indicators:
        avg_confidence = sum(i.confidence for i in feed_manager.indicators.values()) / len(
            feed_manager.indicators
        )
    else:
        avg_confidence = 0.0

    # Technique distribution
    technique_counts: dict[str, int] = {}
    for indicator in feed_manager.indicators.values():
        technique = indicator.technique.value
        technique_counts[technique] = technique_counts.get(technique, 0) + 1

    return {
        "feeds": {
            "total": total_feeds,
            "active": active_feeds,
        },
        "indicators": {
            "total": total_indicators,
            "active": active_indicators,
            "average_confidence": round(avg_confidence, 3),
        },
        "technique_distribution": technique_counts,
        "last_update": datetime.utcnow(),
    }


# Startup and shutdown are now handled by the lifespan context manager
