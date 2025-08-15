# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Main detection orchestrator combining multiple detection strategies.

This module implements the core detection logic for PromptSentinel, orchestrating
various detection methods including heuristic pattern matching, LLM-based
classification, and PII detection. It combines results from multiple strategies
to provide comprehensive threat assessment.

The detector supports configurable detection modes (strict/moderate/permissive)
and can operate with or without LLM providers based on availability.

Usage:
    detector = PromptDetector()
    result = await detector.detect(messages)
    if result.verdict == Verdict.BLOCK:
        # Handle blocked prompt

Key Features:
    - Multi-layer detection combining heuristics and AI
    - PII detection and redaction capabilities
    - Confidence-based verdict determination
    - Format validation and recommendations
    - Batch processing support
"""

import asyncio
import logging
import time
from typing import Any

from prompt_sentinel.cache.cache_manager import CacheManager
from prompt_sentinel.cache.detection_cache import DetectionCache
from prompt_sentinel.config.settings import settings
from prompt_sentinel.detection.custom_pii_loader import CustomPIIRulesLoader
from prompt_sentinel.detection.heuristics import HeuristicDetector
from prompt_sentinel.detection.llm_classifier import LLMClassifierManager
from prompt_sentinel.detection.pii_detector import PIIDetector
from prompt_sentinel.detection.prompt_processor import PromptProcessor
from prompt_sentinel.models.schemas import (
    DetectionCategory,
    DetectionReason,
    DetectionResponse,
    Message,
    PIIDetection,
    Verdict,
)


class PromptDetector:
    """Main detector orchestrating all detection methods.

    Coordinates multiple detection strategies to identify prompt injection
    attempts and other security threats in LLM inputs. Manages the lifecycle
    of detection components and combines their results.

    Attributes:
        processor: PromptProcessor for input validation and sanitization
        heuristic_detector: Pattern-based detection engine
        llm_classifier: LLM-based semantic analysis manager
        pii_detector: Optional PII detection and redaction system
    """

    def __init__(self, pattern_manager=None):
        """Initialize the detector with configured components.

        Sets up all detection subsystems based on configuration settings.
        Initializes PII detector only if enabled in settings.

        Args:
            pattern_manager: Optional ML pattern manager for discovered patterns
        """
        self.processor = PromptProcessor()
        self.pattern_manager = pattern_manager
        self.heuristic_detector = HeuristicDetector(
            settings.detection_mode, pattern_manager=pattern_manager
        )
        self.llm_classifier = LLMClassifierManager()
        self.threat_detector = None  # Will be set by main.py if threat intelligence is available

        # Initialize detection cache
        cache_manager = CacheManager() if settings.cache_enabled else None
        self.detection_cache = DetectionCache(cache_manager, ttl=settings.cache_ttl)

        # Initialize PII detector if enabled
        if settings.pii_detection_enabled:
            pii_config = {"types": settings.pii_types_list}

            # Load custom PII rules if enabled
            custom_rules_loader = None
            if settings.custom_pii_rules_enabled and settings.custom_pii_rules_path:
                try:
                    custom_rules_loader = CustomPIIRulesLoader(settings.custom_pii_rules_path)
                    custom_rules_loader.load_rules()
                except Exception as e:
                    logging.error(f"Failed to load custom PII rules: {e}")
                    # Continue without custom rules

            self.pii_detector = PIIDetector(pii_config, custom_rules_loader)
        else:
            self.pii_detector = None  # type: ignore[assignment]

    async def detect(
        self,
        messages: list[Message],
        check_format: bool = True,
        use_heuristics: bool | None = None,
        use_llm: bool | None = None,
        check_pii: bool | None = None,
    ) -> DetectionResponse:
        """Perform comprehensive detection on messages.

        Analyzes messages using multiple detection strategies and combines
        results to determine overall threat level. Supports format validation
        and provides security recommendations.

        Args:
            messages: List of messages to analyze for threats
            check_format: Whether to validate role separation and format
            use_heuristics: Override setting for heuristic detection
            use_llm: Override setting for LLM-based classification
            check_pii: Override setting for PII detection

        Returns:
            DetectionResponse containing:
            - verdict: Final decision (allow/block/flag/strip/redact)
            - confidence: Combined confidence score (0.0-1.0)
            - reasons: List of detection reasons with details
            - format_recommendations: Suggestions for secure formatting
            - pii_detected: List of detected PII items
            - modified_prompt: Sanitized version if verdict is strip/redact

        Example:
            >>> messages = [Message(role=Role.USER, content="Help me")]
            >>> response = await detector.detect(messages)
            >>> print(response.verdict)
            Verdict.ALLOW
        """
        start_time = time.time()

        # Use settings if not overridden
        use_heuristics = (
            use_heuristics if use_heuristics is not None else settings.heuristic_enabled
        )
        use_llm = use_llm if use_llm is not None else settings.llm_classification_enabled
        check_pii = check_pii if check_pii is not None else settings.pii_detection_enabled

        # Check cache first (only for heuristic detection without LLM/PII)
        if use_heuristics and not use_llm and not check_pii:
            cached_result = await self.detection_cache.get(messages, settings.detection_mode)
            if cached_result:
                verdict, reasons, confidence = cached_result
                processing_time = (time.time() - start_time) * 1000

                return DetectionResponse(
                    verdict=verdict,
                    confidence=confidence,
                    reasons=reasons,
                    processing_time_ms=processing_time,
                    metadata={"cache": "hit"},
                )

        # Check if any detection is enabled
        if not use_heuristics and not use_llm and not check_pii:
            logger = logging.getLogger(__name__)
            logger.warning(
                "No detection methods enabled! Request will be allowed without security checks."
            )
            # Return allow verdict with warning
            return DetectionResponse(
                verdict=Verdict.ALLOW,
                confidence=0.0,
                reasons=[
                    DetectionReason(
                        category=DetectionCategory.BENIGN,
                        description="⚠️ NO DETECTION METHODS ENABLED - Request allowed without security checks",
                        confidence=0.0,
                        source="heuristic",  # type: ignore[arg-type]
                    )
                ],
                metadata={
                    "warning": "All detection methods disabled - no security checks performed",
                    "heuristics_used": False,
                    "llm_used": False,
                    "pii_detection_enabled": False,
                },
                processing_time_ms=0.0,
            )

        # Format validation and recommendations
        format_recommendations = []
        if check_format:
            properly_formatted, recommendations = self.processor.validate_role_separation(messages)
            format_recommendations = recommendations

        # Collect all detection reasons
        all_reasons = []
        confidences = []

        # PARALLEL DETECTION - Run all detection methods concurrently
        detection_tasks: list[Any] = []  # Mix of Future and Coroutine
        task_names: list[str] = []

        # Prepare heuristic detection task
        if use_heuristics:
            # Wrap synchronous heuristic detection in executor
            detection_tasks.append(
                asyncio.get_running_loop().run_in_executor(
                    None, self.heuristic_detector.detect, messages
                )
            )
            task_names.append("heuristic")

        # Prepare LLM detection task
        if use_llm:
            detection_tasks.append(self.llm_classifier.classify(messages))
            task_names.append("llm")

        # Prepare threat detection task
        if self.threat_detector and settings.threat_intelligence_enabled:
            detection_tasks.append(self.threat_detector.detect(messages))
            task_names.append("threat")

        # Execute all detection tasks in parallel
        parallel_start = time.time()
        if detection_tasks:
            results = await asyncio.gather(*detection_tasks, return_exceptions=True)
            parallel_time = (time.time() - parallel_start) * 1000
            logging.debug(f"Parallel detection completed in {parallel_time:.2f}ms")
        else:
            results = []
            parallel_time = 0

        # Process results
        heuristic_verdict = Verdict.ALLOW
        llm_verdict = Verdict.ALLOW
        # threat_verdict = Verdict.ALLOW  # Reserved for future threat-specific logic

        for name, result in zip(task_names, results, strict=False):
            if isinstance(result, Exception):
                logging.error(f"{name} detection error: {result}")
                continue

            # Safely unpack result tuple
            if not isinstance(result, tuple) or len(result) != 3:
                logging.error(f"{name} detection returned invalid result: {result}")
                continue

            verdict, reasons, confidence = result

            if name == "heuristic":
                heuristic_verdict = verdict
                all_reasons.extend(reasons)
                if confidence > 0:
                    confidences.append(confidence)
            elif name == "llm":
                llm_verdict = verdict
                all_reasons.extend(reasons)
                if confidence > 0:
                    confidences.append(confidence)
            elif name == "threat":
                # threat_verdict = verdict  # Reserved for future threat-specific logic
                all_reasons.extend(reasons)
                if confidence > 0:
                    confidences.append(confidence)

        # PII detection
        pii_detections = []
        pii_verdict = Verdict.ALLOW
        if self.pii_detector and check_pii:
            combined_text = "\n".join([msg.content for msg in messages])
            pii_matches = self.pii_detector.detect(combined_text)

            if pii_matches:
                # Convert to schema format
                for match in pii_matches:
                    if match.confidence >= settings.pii_confidence_threshold:
                        pii_detections.append(
                            PIIDetection(
                                pii_type=match.pii_type.value,
                                masked_value=match.masked_value,
                                confidence=match.confidence,
                                location={"start": match.start_pos, "end": match.end_pos},
                            )
                        )

                if pii_detections:
                    # Log PII detection if enabled and in pass-alert mode
                    if settings.pii_redaction_mode == "pass-alert" and settings.pii_log_detected:
                        logger = logging.getLogger(__name__)
                        pii_types = list({p.pii_type for p in pii_detections})
                        logger.warning(
                            f"PII detected in pass-alert mode: {len(pii_detections)} item(s) of types {pii_types}"
                        )

                    # Determine PII verdict based on redaction mode
                    if settings.pii_redaction_mode == "reject":
                        pii_verdict = Verdict.BLOCK
                    elif settings.pii_redaction_mode in ["pass-silent", "pass-alert"]:
                        pii_verdict = Verdict.ALLOW  # Allow but track detection
                    else:
                        pii_verdict = Verdict.REDACT

                    # Add PII detection reason
                    all_reasons.append(
                        DetectionReason(
                            category=DetectionCategory.PII_DETECTED,
                            description=f"Detected {len(pii_detections)} PII item(s)",
                            confidence=max(p.confidence for p in pii_detections),
                            source="heuristic",
                            patterns_matched=[p.pii_type for p in pii_detections],
                        )
                    )

        # Combine all verdicts
        final_verdict, final_confidence = self._combine_verdicts_with_pii(
            heuristic_verdict, llm_verdict, pii_verdict, confidences
        )

        # Generate modified prompt if needed
        modified_prompt = None
        if final_verdict == Verdict.STRIP:
            modified_prompt = self._strip_malicious_content(messages, all_reasons)
        elif final_verdict == Verdict.REDACT and pii_matches:
            # Redact PII from the prompt
            combined_text = "\n".join([msg.content for msg in messages])
            modified_prompt = self.pii_detector.redact(
                combined_text, pii_matches, mode=settings.pii_redaction_mode
            )

        # Calculate processing time
        processing_time_ms = (time.time() - start_time) * 1000

        # Build metadata
        metadata = {
            "detection_mode": settings.detection_mode,
            "heuristics_used": use_heuristics,
            "llm_used": use_llm,
            "message_count": len(messages),
            "format_valid": check_format and len(format_recommendations) == 0,
        }

        # Collect event for ML pattern discovery (if enabled)
        if self.pattern_manager and self.pattern_manager.collector:
            try:
                if final_verdict in [Verdict.BLOCK, Verdict.FLAG]:
                    # Extract categories and patterns from reasons
                    categories = list(
                        {r.category.value for r in all_reasons if hasattr(r, "category")}
                    )
                    patterns = []
                    for r in all_reasons:
                        if hasattr(r, "patterns_matched") and r.patterns_matched:
                            patterns.extend(r.patterns_matched)

                    # Collect event asynchronously (fire and forget)
                    asyncio.create_task(
                        self.pattern_manager.collector.collect_event(
                            prompt="\n".join([msg.content for msg in messages]),
                            verdict=final_verdict,
                            confidence=final_confidence,
                            categories=categories,
                            patterns_matched=patterns,
                            provider_used=(
                                metadata.get("providers_used", ["heuristic"])[0]  # type: ignore[index]
                                if metadata.get("providers_used")
                                else "heuristic"
                            ),
                            processing_time_ms=processing_time_ms,
                            metadata=metadata,
                        )
                    )
            except Exception:
                # Don't let ML collection errors affect detection
                pass

        # Add PII pass-alert warning to metadata
        if settings.pii_redaction_mode == "pass-alert" and pii_detections:
            metadata["pii_warning"] = "PII detected but passed through (pass-alert mode)"  # type: ignore[assignment]
            # Note: pass-silent doesn't add warnings by design

        # Cache the result for future use (only for heuristic-only detection)
        if use_heuristics and not use_llm and not check_pii:
            await self.detection_cache.set(
                messages, settings.detection_mode, final_verdict, all_reasons, final_confidence
            )

        return DetectionResponse(
            verdict=final_verdict,
            confidence=final_confidence,
            modified_prompt=modified_prompt,
            reasons=all_reasons,
            format_recommendations=format_recommendations,
            pii_detected=pii_detections,
            metadata=metadata,
            processing_time_ms=processing_time_ms,
        )

    def _combine_verdicts_with_pii(
        self,
        heuristic_verdict: Verdict,
        llm_verdict: Verdict,
        pii_verdict: Verdict,
        confidences: list[float],
    ) -> tuple[Verdict, float]:
        """Combine verdicts from all detection methods including PII.

        Implements verdict priority logic where more severe verdicts take
        precedence. Adjusts confidence based on agreement between methods
        and applies confidence thresholds for verdict downgrading.

        Args:
            heuristic_verdict: Verdict from pattern-based detection
            llm_verdict: Verdict from AI-based classification
            pii_verdict: Verdict from PII detection (BLOCK or REDACT)
            confidences: List of confidence scores from all methods

        Returns:
            Tuple containing:
            - final_verdict: Most severe verdict considering all inputs
            - final_confidence: Weighted confidence score (0.0-1.0)

        Note:
            Verdict priority: BLOCK > REDACT > STRIP > FLAG > ALLOW
            Confidence boost applied when methods agree on threats
        """
        # Calculate combined confidence
        if confidences:
            avg_confidence = sum(confidences) / len(confidences)

            # Boost confidence if methods agree
            if (
                heuristic_verdict != Verdict.ALLOW
                and llm_verdict != Verdict.ALLOW
                and heuristic_verdict == llm_verdict
            ):
                avg_confidence = min(1.0, avg_confidence * 1.15)
        else:
            avg_confidence = 0.0

        # Verdict priority: BLOCK > REDACT > STRIP > FLAG > ALLOW
        verdict_priority = {
            Verdict.BLOCK: 5,
            Verdict.REDACT: 4,
            Verdict.STRIP: 3,
            Verdict.FLAG: 2,
            Verdict.ALLOW: 1,
        }

        # Take the most severe verdict
        verdicts = [heuristic_verdict, llm_verdict, pii_verdict]
        final_verdict = max(verdicts, key=lambda v: verdict_priority.get(v, 1))

        # Adjust verdict based on confidence threshold
        if avg_confidence < settings.confidence_threshold and final_verdict not in [
            Verdict.ALLOW,
            Verdict.REDACT,
        ]:
            # Downgrade verdict if confidence is too low (except for PII redaction)
            if final_verdict == Verdict.BLOCK:
                final_verdict = Verdict.STRIP
            elif final_verdict == Verdict.STRIP:
                final_verdict = Verdict.FLAG

        return final_verdict, avg_confidence

    def _combine_verdicts(
        self, heuristic_verdict: Verdict, llm_verdict: Verdict, confidences: list[float]
    ) -> tuple[Verdict, float]:
        """
        Combine verdicts from different detection methods.

        Args:
            heuristic_verdict: Verdict from heuristic detection
            llm_verdict: Verdict from LLM classification
            confidences: List of confidence scores

        Returns:
            Tuple of (final_verdict, final_confidence)
        """
        # Calculate combined confidence
        if confidences:
            # Weighted average with boost for agreement
            avg_confidence = sum(confidences) / len(confidences)

            # Boost confidence if both methods agree on a threat
            if (
                heuristic_verdict != Verdict.ALLOW
                and llm_verdict != Verdict.ALLOW
                and heuristic_verdict == llm_verdict
            ):
                avg_confidence = min(1.0, avg_confidence * 1.15)
        else:
            avg_confidence = 0.0

        # Verdict priority: BLOCK > STRIP > FLAG > ALLOW
        verdict_priority = {Verdict.BLOCK: 4, Verdict.STRIP: 3, Verdict.FLAG: 2, Verdict.ALLOW: 1}

        # Take the more severe verdict
        if verdict_priority.get(heuristic_verdict, 1) > verdict_priority.get(llm_verdict, 1):
            final_verdict = heuristic_verdict
        else:
            final_verdict = llm_verdict

        # Adjust verdict based on confidence threshold
        if avg_confidence < settings.confidence_threshold and final_verdict != Verdict.ALLOW:
            # Downgrade verdict if confidence is too low
            if final_verdict == Verdict.BLOCK:
                final_verdict = Verdict.STRIP
            elif final_verdict == Verdict.STRIP:
                final_verdict = Verdict.FLAG

        return final_verdict, avg_confidence

    def _strip_malicious_content(
        self, messages: list[Message], reasons: list[DetectionReason]
    ) -> str:
        """Strip detected malicious content from messages.

        Removes or neutralizes identified threats while preserving legitimate
        content. Applies aggressive sanitization for high-confidence threats.

        Args:
            messages: Original messages containing potential threats
            reasons: Detection reasons indicating what threats were found

        Returns:
            Sanitized prompt text with malicious content removed

        Note:
            Sanitization aggressiveness depends on threat confidence levels
        """
        # Combine all message content
        combined_content = "\n".join([msg.content for msg in messages])

        # Apply sanitization based on detection reasons
        aggressive = any(r.confidence > 0.8 for r in reasons)
        sanitized = self.processor.sanitize_prompt(combined_content, aggressive=aggressive)

        return sanitized

    async def analyze_batch(self, message_batches: list[list[Message]]) -> list[DetectionResponse]:
        """Analyze multiple message batches in sequence.

        Processes multiple independent conversations or prompt sets,
        useful for bulk validation or testing scenarios.

        Args:
            message_batches: List of message lists to analyze

        Returns:
            List of DetectionResponse objects, one per batch

        Example:
            >>> batches = [[msg1], [msg2, msg3]]
            >>> results = await detector.analyze_batch(batches)
            >>> print(len(results))  # 2
        """
        results = []
        for messages in message_batches:
            result = await self.detect(messages)
            results.append(result)
        return results

    async def detect_batch(
        self,
        items: list[tuple[str, list[Message]]],
        parallel: bool = True,
        continue_on_error: bool = True,
        chunk_size: int = 10,
        **detect_kwargs,
    ) -> tuple[list[tuple[str, DetectionResponse | None]], dict[str, Any]]:
        """Process multiple detection requests efficiently.

        Implements intelligent batch processing with parallel execution,
        error handling, and performance optimization. Supports chunking
        for large batches to prevent resource exhaustion.

        Args:
            items: List of (id, messages) tuples to process
            parallel: Whether to process items in parallel
            continue_on_error: Continue processing if individual items fail
            chunk_size: Number of items to process in parallel per chunk
            **detect_kwargs: Additional arguments passed to detect()

        Returns:
            Tuple containing:
            - List of (id, result) tuples where result is DetectionResponse or None on error
            - Statistics dictionary with processing metrics

        Example:
            >>> items = [("item1", [msg1]), ("item2", [msg2, msg3])]
            >>> results, stats = await detector.detect_batch(items)
            >>> print(f"Processed {stats['successful']} items successfully")
        """
        import time
        import uuid

        batch_id = str(uuid.uuid4())
        start_time = time.time()
        results: list[tuple[str, DetectionResponse | None]] = []
        errors: list[tuple[str, str]] = []
        processing_times: list[float] = []

        # Statistics tracking
        stats: dict[str, Any] = {
            "batch_id": batch_id,
            "total_items": len(items),
            "successful": 0,
            "failed": 0,
            "cache_hits": 0,
            "verdicts": {},
            "confidences": [],
        }

        if parallel:
            # Process in chunks to avoid overwhelming the system
            for i in range(0, len(items), chunk_size):
                chunk = items[i : i + chunk_size]

                # Create detection tasks for this chunk
                tasks = []
                for item_id, messages in chunk:
                    task = self._detect_with_error_handling(
                        item_id, messages, continue_on_error, **detect_kwargs
                    )
                    tasks.append(task)

                # Execute chunk in parallel
                chunk_start = time.time()
                chunk_results = await asyncio.gather(*tasks)
                chunk_time = (time.time() - chunk_start) * 1000

                # Process chunk results
                for (item_id, _), (result, error, item_time) in zip(
                    chunk, chunk_results, strict=False
                ):
                    processing_times.append(item_time)

                    if error:
                        results.append((item_id, None))
                        errors.append((item_id, error))
                        stats["failed"] += 1
                    else:
                        results.append((item_id, result))
                        stats["successful"] += 1

                        # Update statistics
                        if result:
                            verdict_str = result.verdict.value
                            stats["verdicts"][verdict_str] = (
                                stats["verdicts"].get(verdict_str, 0) + 1
                            )
                            stats["confidences"].append(result.confidence)

                            # Check for cache hit
                            if result.metadata.get("cache") == "hit":
                                stats["cache_hits"] += 1

                logging.debug(f"Processed chunk {i // chunk_size + 1}, time: {chunk_time:.2f}ms")

        else:
            # Sequential processing
            for item_id, messages in items:
                item_start = time.time()

                try:
                    result = await self.detect(messages, **detect_kwargs)
                    item_time = (time.time() - item_start) * 1000
                    processing_times.append(item_time)

                    results.append((item_id, result))
                    stats["successful"] += 1

                    # Update statistics
                    verdict_str = result.verdict.value
                    stats["verdicts"][verdict_str] = stats["verdicts"].get(verdict_str, 0) + 1
                    stats["confidences"].append(result.confidence)

                    if result.metadata.get("cache") == "hit":
                        stats["cache_hits"] += 1

                except Exception as e:
                    item_time = (time.time() - item_start) * 1000
                    processing_times.append(item_time)

                    if continue_on_error:
                        results.append((item_id, None))
                        errors.append((item_id, str(e)))
                        stats["failed"] += 1
                        logging.error(f"Batch item {item_id} failed: {e}")
                    else:
                        raise

        # Calculate final statistics
        total_time = (time.time() - start_time) * 1000
        stats.update(
            {
                "total_processing_time_ms": total_time,
                "average_processing_time_ms": (
                    sum(processing_times) / len(processing_times) if processing_times else 0
                ),
                "min_processing_time_ms": min(processing_times) if processing_times else 0,
                "max_processing_time_ms": max(processing_times) if processing_times else 0,
                "average_confidence": (
                    sum(stats["confidences"]) / len(stats["confidences"])
                    if stats["confidences"]
                    else None
                ),
                "errors": errors if errors else None,
                "cache_hit_rate": (
                    stats["cache_hits"] / stats["successful"] if stats["successful"] > 0 else 0
                ),
            }
        )

        logging.info(
            f"Batch {batch_id} completed: {stats['successful']}/{stats['total_items']} successful, "
            f"time: {total_time:.2f}ms, cache hits: {stats['cache_hits']}"
        )

        return results, stats

    async def _detect_with_error_handling(
        self, item_id: str, messages: list[Message], continue_on_error: bool, **detect_kwargs
    ) -> tuple[DetectionResponse | None, str | None, float]:
        """Detect with error handling for batch processing.

        Args:
            item_id: Unique identifier for this item
            messages: Messages to analyze
            continue_on_error: Whether to catch exceptions
            **detect_kwargs: Arguments for detect()

        Returns:
            Tuple of (result, error_message, processing_time_ms)
        """
        import time

        start_time = time.time()

        try:
            result = await self.detect(messages, **detect_kwargs)
            processing_time = (time.time() - start_time) * 1000
            return result, None, processing_time

        except Exception as e:
            processing_time = (time.time() - start_time) * 1000
            error_msg = f"Detection failed for item {item_id}: {str(e)}"
            logging.error(error_msg)

            if continue_on_error:
                return None, error_msg, processing_time
            else:
                raise

    def get_complexity_analysis(self, messages: list[Message]) -> dict:
        """Get complexity metrics for messages.

        Analyzes structural and content complexity to identify suspicious
        patterns that might indicate obfuscation or encoding attempts.

        Args:
            messages: Messages to analyze for complexity

        Returns:
            Dictionary containing:
            - message_{i}: Per-message complexity metrics
            - overall: Combined complexity analysis
            Including metrics like entropy, special char ratio, encoding detection

        Example:
            >>> metrics = detector.get_complexity_analysis(messages)
            >>> print(metrics["overall"]["entropy"])
            4.2
        """
        metrics = {}
        for i, msg in enumerate(messages):
            metrics[f"message_{i}"] = self.processor.calculate_complexity_metrics(msg.content)

        # Overall metrics
        total_content = " ".join([msg.content for msg in messages])
        metrics["overall"] = self.processor.calculate_complexity_metrics(total_content)

        return metrics
