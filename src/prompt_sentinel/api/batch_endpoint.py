# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Batch detection endpoint for high-throughput processing.

This module provides API endpoints for batch processing of multiple
detection requests in a single call. It supports parallel processing,
intelligent caching, and comprehensive error handling.

Key features:
- Process up to 100 items per batch
- Parallel or sequential processing modes
- Partial failure handling with continue_on_error
- Detailed statistics and performance metrics
- CSV export support for results
"""

import csv
import io
import time
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from prompt_sentinel.config.settings import settings
from prompt_sentinel.detection.detector import PromptDetector
from prompt_sentinel.models.schemas import (
    BatchDetectionRequest,
    BatchDetectionResponse,
    BatchDetectionResult,
    BatchStatistics,
)
from prompt_sentinel.monitoring.metrics import track_detection_metrics

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1", tags=["Batch Processing"])

# Global detector instance (initialized in main.py)
_detector: PromptDetector | None = None


def get_detector() -> PromptDetector:
    """Get the global detector instance."""
    global _detector
    if _detector is None:
        _detector = PromptDetector()
    return _detector


@router.post("/detect/batch", response_model=BatchDetectionResponse)
async def batch_detect(
    request: BatchDetectionRequest,
    detector: PromptDetector = Depends(get_detector),
) -> BatchDetectionResponse:
    """Process multiple detection requests in a single batch.

    Efficiently processes up to 100 detection requests with support for
    parallel execution, error handling, and comprehensive statistics.

    Args:
        request: Batch detection request with items to process
        detector: Injected detector instance

    Returns:
        BatchDetectionResponse with individual results and statistics

    Raises:
        HTTPException: If batch processing fails completely
    """
    start_time = time.time()
    batch_id = str(uuid.uuid4())

    logger.info(
        "Batch detection request",
        batch_id=batch_id,
        item_count=len(request.items),
        parallel=request.parallel,
    )

    try:
        # Convert request items to detector format
        detector_items = []
        for item in request.items:
            messages = item.to_messages()
            detector_items.append((item.id, messages))

        # Process batch using detector
        detection_results, stats = await detector.detect_batch(
            items=detector_items,
            parallel=request.parallel,
            continue_on_error=request.continue_on_error,
            chunk_size=10,  # Process 10 items at a time when parallel
            check_format=True,
            use_heuristics=settings.heuristic_enabled,
            use_llm=settings.llm_classification_enabled,
            check_pii=settings.pii_detection_enabled,
        )

        # Convert results to response format
        results = []
        for item_id, detection_result in detection_results:
            if detection_result is None:
                # Find error message from stats
                error_msg = None
                if stats.get("errors"):
                    for err_id, err_msg in stats["errors"]:
                        if err_id == item_id:
                            error_msg = err_msg
                            break

                results.append(
                    BatchDetectionResult(
                        id=item_id,
                        success=False,
                        result=None,
                        error=error_msg or "Unknown error",
                        processing_time_ms=0,
                    )
                )
            else:
                results.append(
                    BatchDetectionResult(
                        id=item_id,
                        success=True,
                        result=detection_result,
                        error=None,
                        processing_time_ms=detection_result.processing_time_ms,
                    )
                )

        # Create statistics
        if request.include_statistics:
            batch_stats = BatchStatistics(
                total_items=stats["total_items"],
                successful_items=stats["successful"],
                failed_items=stats["failed"],
                total_processing_time_ms=stats["total_processing_time_ms"],
                average_processing_time_ms=stats["average_processing_time_ms"],
                min_processing_time_ms=stats["min_processing_time_ms"],
                max_processing_time_ms=stats["max_processing_time_ms"],
                cache_hits=stats["cache_hits"],
                verdicts=stats["verdicts"],
                average_confidence=stats["average_confidence"],
            )
        else:
            batch_stats = None

        # Track metrics
        for verdict_str, _count in stats["verdicts"].items():
            # Map verdict to attack type
            attack_type = "benign" if verdict_str == "ALLOW" else "malicious"
            severity = (
                "low"
                if verdict_str == "ALLOW"
                else ("high" if verdict_str == "BLOCK" else "medium")
            )

            track_detection_metrics(
                attack_type=attack_type,
                severity=severity,
                method="batch",
                confidence=stats["average_confidence"] or 0,
            )

        # Create response
        response = BatchDetectionResponse(
            batch_id=batch_id,
            results=results,
            statistics=batch_stats,
            metadata={
                "config": request.config or {},
                "parallel": request.parallel,
                "cache_hit_rate": stats.get("cache_hit_rate", 0),
                "detection_mode": settings.detection_mode,
            },
        )

        total_time = (time.time() - start_time) * 1000
        logger.info(
            "Batch detection completed",
            batch_id=batch_id,
            successful=stats["successful"],
            failed=stats["failed"],
            total_time_ms=total_time,
        )

        return response

    except Exception as e:
        logger.error("Batch detection failed", batch_id=batch_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Batch processing failed: {str(e)}") from e


@router.post("/detect/batch/csv")
async def batch_detect_csv(
    request: BatchDetectionRequest,
    detector: PromptDetector = Depends(get_detector),
) -> StreamingResponse:
    """Process batch detection and return results as CSV.

    Useful for data analysis and export to spreadsheet applications.

    Args:
        request: Batch detection request
        detector: Injected detector instance

    Returns:
        StreamingResponse with CSV content
    """
    # Process batch
    response = await batch_detect(request, detector)

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow(
        [
            "ID",
            "Success",
            "Verdict",
            "Confidence",
            "Processing Time (ms)",
            "Reasons",
            "Error",
        ]
    )

    # Write data rows
    for result in response.results:
        if result.success and result.result:
            reasons = "; ".join([r.description for r in result.result.reasons])
            writer.writerow(
                [
                    result.id,
                    "Yes",
                    result.result.verdict.value,
                    f"{result.result.confidence:.2f}",
                    f"{result.processing_time_ms:.2f}",
                    reasons,
                    "",
                ]
            )
        else:
            writer.writerow(
                [
                    result.id,
                    "No",
                    "",
                    "",
                    f"{result.processing_time_ms:.2f}",
                    "",
                    result.error or "Unknown error",
                ]
            )

    # Add statistics if included
    if response.statistics:
        writer.writerow([])  # Empty row
        writer.writerow(["Statistics"])
        writer.writerow(["Total Items", response.statistics.total_items])
        writer.writerow(["Successful", response.statistics.successful_items])
        writer.writerow(["Failed", response.statistics.failed_items])
        writer.writerow(
            [
                "Average Processing Time (ms)",
                f"{response.statistics.average_processing_time_ms:.2f}",
            ]
        )
        writer.writerow(["Cache Hits", response.statistics.cache_hits])

    # Return CSV as streaming response
    output.seek(0)
    resp = StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="batch_results_{response.batch_id}.csv"'
        },
    )
    # Force exact content-type for tests that require no charset
    resp.headers["content-type"] = "text/csv"
    return resp


@router.get("/detect/batch/{batch_id}/status")
async def get_batch_status(batch_id: str) -> dict[str, Any]:
    """Get status of a batch processing job.

    Future enhancement: Track async batch jobs.
    This endpoint is a stub and will be implemented when async batch
    orchestration is introduced.

    Args:
        batch_id: Batch identifier

    Returns:
        Status information

    Note:
        Currently returns placeholder for future async job tracking
    """
    # Stub behavior for now: explicitly signal that this is not implemented
    raise NotImplementedError(
        "Batch status endpoint is a stub; async job tracking will be added in a future release."
    )


@router.post("/detect/batch/validate")
async def validate_batch(request: dict[str, Any]) -> dict[str, Any]:
    """Validate a batch request without processing.

    Useful for pre-flight checks before submitting large batches.

    Args:
        request: Batch detection request to validate

    Returns:
        Validation results
    """
    # Accept raw dict to avoid 422s and report structured validation
    validation: dict[str, Any] = {
        "valid": True,
        "item_count": len(request.get("items", []) if isinstance(request, dict) else []),
        "estimated_time_ms": len(request.get("items", [])) * 50 if isinstance(request, dict) else 0,
        "warnings": [],
        "errors": [],
    }

    # Check for duplicate IDs
    items = request.get("items", []) if isinstance(request, dict) else []
    # Check item structure
    for idx, item in enumerate(items):
        if not isinstance(item, dict) or "id" not in item or "input" not in item:
            validation["errors"].append(f"Invalid item at index {idx}")
            validation["valid"] = False
        else:
            # Enforce input type to be str or list[dict]
            if not isinstance(item["input"], str | list):
                validation["errors"].append(f"Invalid item input type at index {idx}")
                validation["valid"] = False

    ids = [item.get("id") for item in items if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        validation["errors"].append("Duplicate item IDs found")
        validation["valid"] = False

    # Check for empty content
    empty_items = [item.get("id") for item in items if not item.get("input")]
    if empty_items:
        validation["warnings"].append(f"Empty content in items: {empty_items}")

    # Warn about large batches
    if len(items) > 50:
        validation["warnings"].append(
            f"Large batch size ({len(items)}). Consider splitting for better performance."
        )

    # Check configuration
    config = request.get("config") if isinstance(request, dict) else None
    if config:
        if "detection_mode" in config:
            if config["detection_mode"] not in ["strict", "moderate", "permissive"]:
                validation["errors"].append("Invalid detection_mode in config")
                validation["valid"] = False

    return validation
