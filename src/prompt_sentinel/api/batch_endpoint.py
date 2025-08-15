# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Batch detection endpoint for high-throughput processing."""

import asyncio
import time
from typing import Any

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field

from prompt_sentinel.cache.optimized_cache import BatchCache, OptimizedCache
from prompt_sentinel.detection.detector import PromptDetector
from prompt_sentinel.models.schemas import DetectionResponse, SimplePromptRequest, Verdict
from prompt_sentinel.monitoring.metrics import track_detection_metrics

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1", tags=["Batch Processing"])


class BatchDetectionRequest(BaseModel):
    """Request model for batch detection."""

    prompts: list[str] = Field(
        ..., description="List of prompts to analyze", min_length=1, max_length=100
    )
    detection_mode: str = Field(
        default="moderate", description="Detection sensitivity: strict, moderate, or permissive"
    )
    use_cache: bool = Field(default=True, description="Whether to use caching for results")
    parallel: bool = Field(default=True, description="Process prompts in parallel")


class BatchDetectionResponse(BaseModel):
    """Response model for batch detection."""

    results: list[DetectionResponse] = Field(..., description="Detection results for each prompt")
    batch_metadata: dict[str, Any] = Field(
        default_factory=dict, description="Batch processing metadata"
    )


class BatchProcessor:
    """Handles batch detection processing with optimizations."""

    def __init__(self, detector: PromptDetector, cache: OptimizedCache | None = None):
        """
        Initialize batch processor.

        Args:
            detector: Detection engine
            cache: Optional cache manager
        """
        self.detector = detector
        self.cache = cache
        self.batch_cache = BatchCache(cache) if cache else None
        self.semaphore = asyncio.Semaphore(10)  # Limit concurrent detections

    async def process_batch(
        self,
        prompts: list[str],
        detection_mode: str = "moderate",
        use_cache: bool = True,
        parallel: bool = True,
    ) -> BatchDetectionResponse:
        """
        Process multiple prompts efficiently.

        Args:
            prompts: List of prompts to analyze
            detection_mode: Detection sensitivity
            use_cache: Whether to use caching
            parallel: Process in parallel

        Returns:
            Batch detection response
        """
        start_time = time.perf_counter()

        if parallel and len(prompts) > 1:
            results = await self._process_parallel(prompts, detection_mode, use_cache)
        else:
            results = await self._process_sequential(prompts, detection_mode, use_cache)

        process_time = time.perf_counter() - start_time

        # Calculate batch statistics
        malicious_count = sum(1 for r in results if r.verdict == Verdict.BLOCK)
        suspicious_count = sum(1 for r in results if r.verdict == Verdict.FLAG)
        safe_count = sum(1 for r in results if r.verdict == Verdict.ALLOW)

        batch_metadata = {
            "total_prompts": len(prompts),
            "processing_time_ms": process_time * 1000,
            "avg_time_per_prompt_ms": (process_time * 1000) / len(prompts),
            "throughput_per_second": len(prompts) / process_time if process_time > 0 else 0,
            "verdict_summary": {
                "block": malicious_count,
                "flag": suspicious_count,
                "allow": safe_count,
            },
            "cache_used": use_cache,
            "parallel_processing": parallel,
        }

        logger.info(
            "Batch processing complete",
            prompts=len(prompts),
            time_ms=process_time * 1000,
            throughput=batch_metadata["throughput_per_second"],
        )

        return BatchDetectionResponse(results=results, batch_metadata=batch_metadata)

    async def _process_parallel(
        self, prompts: list[str], detection_mode: str, use_cache: bool
    ) -> list[DetectionResponse]:
        """Process prompts in parallel with concurrency control."""
        tasks = []

        for prompt in prompts:
            task = self._detect_with_semaphore(prompt, detection_mode, use_cache)
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle any exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Detection failed for prompt {i}", error=str(result))
                # Return safe verdict on error
                processed_results.append(
                    DetectionResponse(
                        verdict=Verdict.ALLOW,
                        confidence=0.0,
                        processing_time_ms=0,
                        metadata={"error": str(result)},
                    )
                )
            else:
                processed_results.append(result)

        return processed_results

    async def _process_sequential(
        self, prompts: list[str], detection_mode: str, use_cache: bool
    ) -> list[DetectionResponse]:
        """Process prompts sequentially."""
        results = []

        for prompt in prompts:
            try:
                result = await self._detect_single(prompt, detection_mode, use_cache)
                results.append(result)
            except Exception as e:
                logger.error("Detection failed", error=str(e))
                results.append(
                    DetectionResponse(
                        verdict=Verdict.ALLOW,
                        confidence=0.0,
                        processing_time_ms=0,
                        metadata={"error": str(e)},
                    )
                )

        return results

    async def _detect_with_semaphore(
        self, prompt: str, detection_mode: str, use_cache: bool
    ) -> DetectionResponse:
        """Detect with concurrency control."""
        async with self.semaphore:
            return await self._detect_single(prompt, detection_mode, use_cache)

    async def _detect_single(
        self, prompt: str, detection_mode: str, use_cache: bool
    ) -> DetectionResponse:
        """Perform detection on a single prompt."""
        # Generate cache key
        if use_cache and self.cache:
            cache_key = self.cache._generate_fast_key(f"{prompt}:{detection_mode}")

            # Try cache first
            cached = await self.cache.get_multi_tier(
                cache_key,
                lambda: self._perform_detection(prompt, detection_mode),
                ttl=300,
                memory_ttl=60,
            )

            if cached and isinstance(cached, dict):
                # Convert dict to DetectionResponse
                return DetectionResponse(**cached)

        # No cache or cache miss
        result = await self._perform_detection(prompt, detection_mode)

        # Track metrics
        track_detection_metrics(
            attack_type="batch", severity="low", method="batch", confidence=result.confidence
        )

        return result

    async def _perform_detection(self, prompt: str, detection_mode: str) -> DetectionResponse:
        """Perform actual detection."""
        # Create detection request
        request = SimplePromptRequest(prompt=prompt)

        # Use detector
        verdict, reasons, confidence = await self.detector.detect(
            request.prompt, detection_mode=detection_mode
        )

        return DetectionResponse(
            verdict=verdict,
            confidence=confidence,
            reasons=reasons,
            processing_time_ms=0,  # Will be set by caller
        )


# Global batch processor instance (initialized in main.py)
batch_processor: BatchProcessor | None = None


def get_batch_processor() -> BatchProcessor:
    """Get batch processor dependency."""
    if not batch_processor:
        raise RuntimeError("Batch processor not initialized")
    return batch_processor


@router.post(
    "/detect/batch",
    response_model=BatchDetectionResponse,
    summary="Batch prompt injection detection",
    description="Analyze multiple prompts for injection attacks in a single request",
)
async def detect_batch(
    request: BatchDetectionRequest,
    background_tasks: BackgroundTasks,
    processor: BatchProcessor = Depends(get_batch_processor),
) -> BatchDetectionResponse:
    """
    Perform batch detection on multiple prompts.

    This endpoint is optimized for high-throughput scenarios where multiple
    prompts need to be analyzed efficiently. It supports:
    - Parallel processing for better performance
    - Caching to avoid redundant computations
    - Batch statistics and metadata

    Args:
        request: Batch detection request
        background_tasks: FastAPI background tasks
        processor: Batch processor instance

    Returns:
        Batch detection response with results and metadata

    Raises:
        HTTPException: If batch processing fails
    """
    try:
        response = await processor.process_batch(
            prompts=request.prompts,
            detection_mode=request.detection_mode,
            use_cache=request.use_cache,
            parallel=request.parallel,
        )

        # Log batch summary in background
        background_tasks.add_task(log_batch_summary, request.prompts, response.batch_metadata)

        return response

    except Exception as e:
        logger.error("Batch detection failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Batch processing failed: {str(e)}") from e


async def log_batch_summary(prompts: list[str], metadata: dict[str, Any]):
    """Log batch processing summary."""
    logger.info(
        "Batch detection summary",
        total_prompts=metadata.get("total_prompts"),
        processing_time_ms=metadata.get("processing_time_ms"),
        throughput=metadata.get("throughput_per_second"),
        verdicts=metadata.get("verdict_summary"),
    )
