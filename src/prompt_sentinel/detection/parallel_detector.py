# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

"""Parallel detection implementation for improved performance."""

import asyncio
import logging
import time

from prompt_sentinel.models.schemas import (
    DetectionReason,
    Message,
    Verdict,
)


class ParallelDetectionExecutor:
    """Execute multiple detection methods in parallel for improved latency."""

    def __init__(self, detector):
        """Initialize with reference to main detector."""
        self.detector = detector
        self.logger = logging.getLogger(__name__)

    async def run_heuristic_detection(
        self, messages: list[Message]
    ) -> tuple[Verdict, list[DetectionReason], float]:
        """Run heuristic detection asynchronously."""
        try:
            # Heuristic detection is synchronous, so run in executor
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self.detector.heuristic_detector.detect, messages
            )
        except Exception as e:
            self.logger.error(f"Heuristic detection error: {e}")
            return Verdict.ALLOW, [], 0.0

    async def run_llm_detection(
        self, messages: list[Message]
    ) -> tuple[Verdict, list[DetectionReason], float]:
        """Run LLM classification asynchronously."""
        try:
            return await self.detector.llm_classifier.classify(messages)
        except Exception as e:
            self.logger.error(f"LLM classification error: {e}")
            return Verdict.ALLOW, [], 0.0

    async def run_threat_detection(
        self, messages: list[Message]
    ) -> tuple[Verdict, list[DetectionReason], float]:
        """Run threat intelligence detection asynchronously."""
        try:
            if self.detector.threat_detector:
                return await self.detector.threat_detector.detect(messages)
            return Verdict.ALLOW, [], 0.0
        except Exception as e:
            self.logger.error(f"Threat detection error: {e}")
            return Verdict.ALLOW, [], 0.0

    async def run_pii_detection(
        self, messages: list[Message]
    ) -> tuple[Verdict, list[DetectionReason], float]:
        """Run PII detection asynchronously."""
        from prompt_sentinel.models.schemas import DetectionCategory, DetectionReason

        try:
            if not self.detector.pii_detector:
                return Verdict.ALLOW, [], 0.0

            # Run PII detection in executor since it's synchronous
            loop = asyncio.get_event_loop()
            combined_text = "\n".join([msg.content for msg in messages])

            pii_matches = await loop.run_in_executor(
                None, self.detector.pii_detector.detect, combined_text
            )

            # Convert PII matches to detection reasons
            if pii_matches:
                from prompt_sentinel.config.settings import settings

                reasons = [
                    DetectionReason(
                        category=DetectionCategory.PII_DETECTED,
                        description=(
                            f"PII detected: {match['type']} - {match['value']}"
                            if isinstance(match, dict)
                            else f"PII detected: {match}"
                        ),
                        confidence=0.9,
                        source="heuristic",  # PII detection is part of heuristic checks
                    )
                    for match in pii_matches[:3]  # Limit to first 3 matches
                ]

                if settings.pii_redaction_mode == "reject":
                    return Verdict.BLOCK, reasons, 0.9
                elif settings.pii_redaction_mode in ["pass-silent", "pass-alert"]:
                    return Verdict.ALLOW, reasons, 0.9
                else:
                    return Verdict.REDACT, reasons, 0.9

            return Verdict.ALLOW, [], 0.0

        except Exception as e:
            self.logger.error(f"PII detection error: {e}")
            return Verdict.ALLOW, [], 0.0

    async def execute_parallel_detection(
        self,
        messages: list[Message],
        use_heuristics: bool,
        use_llm: bool,
        use_threat: bool,
        check_pii: bool,
    ) -> dict:
        """
        Execute all detection methods in parallel.

        Returns dict with results from each detection method.
        """
        tasks = []
        task_names = []

        # Build list of tasks to run
        if use_heuristics:
            tasks.append(self.run_heuristic_detection(messages))
            task_names.append("heuristic")

        if use_llm:
            tasks.append(self.run_llm_detection(messages))
            task_names.append("llm")

        if use_threat:
            tasks.append(self.run_threat_detection(messages))
            task_names.append("threat")

        if check_pii:
            tasks.append(self.run_pii_detection(messages))
            task_names.append("pii")

        if not tasks:
            return {
                "heuristic": (Verdict.ALLOW, [], 0.0),
                "llm": (Verdict.ALLOW, [], 0.0),
                "threat": (Verdict.ALLOW, [], 0.0),
                "pii": ([], Verdict.ALLOW),
            }

        # Execute all tasks in parallel
        start_time = time.perf_counter()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        parallel_time = (time.perf_counter() - start_time) * 1000

        self.logger.debug(
            f"Parallel detection completed in {parallel_time:.2f}ms ({len(tasks)} detectors)"
        )

        # Map results to their names
        result_dict = {
            "heuristic": (Verdict.ALLOW, [], 0.0),
            "llm": (Verdict.ALLOW, [], 0.0),
            "threat": (Verdict.ALLOW, [], 0.0),
            "pii": ([], Verdict.ALLOW),
            "parallel_time_ms": parallel_time,
        }

        for name, result in zip(task_names, results, strict=False):
            if isinstance(result, Exception):
                self.logger.error(f"{name} detection failed: {result}")
                # Keep default values for failed detections
            else:
                result_dict[name] = result

        return result_dict


class ParallelDetectionMixin:
    """Mixin to add parallel detection capabilities to the main detector."""

    def __init__(self, *args, **kwargs):
        """Initialize with parallel executor."""
        super().__init__(*args, **kwargs)
        self.parallel_executor = ParallelDetectionExecutor(self)

    async def detect_parallel(
        self,
        messages: list[Message],
        use_heuristics: bool = True,
        use_llm: bool = True,
        check_pii: bool = True,
    ) -> dict:
        """
        Run detection methods in parallel for improved performance.

        This method runs all enabled detection methods concurrently
        and returns their results for combination.
        """
        from prompt_sentinel.config.settings import settings

        use_threat = (
            hasattr(self, "threat_detector")
            and self.threat_detector is not None
            and settings.threat_intelligence_enabled
        )

        return await self.parallel_executor.execute_parallel_detection(
            messages, use_heuristics, use_llm, use_threat, check_pii
        )
