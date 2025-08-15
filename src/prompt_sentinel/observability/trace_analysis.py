# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Trace analysis for observability."""

from typing import Any

from .tracing import Span


class TraceAnalyzer:
    """Analyze distributed traces."""

    def __init__(self):
        """Initialize trace analyzer."""
        self.traces = []

    def analyze_critical_path(self, spans: list[Span]) -> list[Span]:
        """Find the critical path in a trace."""
        if not spans:
            return []

        # Build span tree
        root_spans = [s for s in spans if s.parent_id is None]
        if not root_spans:
            # If no root, use first span
            root_spans = [spans[0]]

        # Find longest path from root
        critical_path = []
        for root in root_spans:
            path = self._find_longest_path(root, spans)
            if len(path) > len(critical_path):
                critical_path = path

        return critical_path

    def _find_longest_path(self, root: Span, all_spans: list[Span]) -> list[Span]:
        """Find longest path from a root span."""
        children = [s for s in all_spans if s.parent_id == root.span_id]

        if not children:
            return [root]

        longest_child_path = []
        for child in children:
            child_path = self._find_longest_path(child, all_spans)
            if sum(s.get_duration() for s in child_path) > sum(
                s.get_duration() for s in longest_child_path
            ):
                longest_child_path = child_path

        return [root] + longest_child_path

    def calculate_span_statistics(self, spans: list[Span]) -> dict[str, Any]:
        """Calculate statistics for spans."""
        if not spans:
            return {
                "total_spans": 0,
                "total_duration": 0,
                "average_duration": 0,
                "min_duration": 0,
                "max_duration": 0,
            }

        durations = [s.get_duration() for s in spans]

        return {
            "total_spans": len(spans),
            "total_duration": sum(durations),
            "average_duration": sum(durations) / len(durations),
            "min_duration": min(durations),
            "max_duration": max(durations),
            "span_names": list({s.name for s in spans}),
        }

    def generate_dependency_graph(self, spans: list[Span]) -> dict[str, list[str]]:
        """Generate dependency graph from spans."""
        dependencies = {}

        for span in spans:
            if span.parent_id:
                parent = next((s for s in spans if s.span_id == span.parent_id), None)
                if parent:
                    if parent.name not in dependencies:
                        dependencies[parent.name] = []
                    if span.name not in dependencies[parent.name]:
                        dependencies[parent.name].append(span.name)

        return dependencies

    def find_bottlenecks(self, spans: list[Span], threshold_percentile: float = 0.95) -> list[Span]:
        """Find bottleneck spans."""
        if not spans:
            return []

        durations = sorted([s.get_duration() for s in spans])
        threshold = durations[int(len(durations) * threshold_percentile)]

        return [s for s in spans if s.get_duration() >= threshold]

    def analyze_errors(self, spans: list[Span]) -> dict[str, Any]:
        """Analyze errors in spans."""
        error_spans = [s for s in spans if s.status == "error"]

        error_summary = {
            "total_errors": len(error_spans),
            "error_rate": len(error_spans) / len(spans) if spans else 0,
            "error_types": defaultdict(int),
        }

        for span in error_spans:
            # Categorize errors by span name
            error_summary["error_types"][span.name] += 1

        error_summary["error_types"] = dict(error_summary["error_types"])
        return error_summary


from collections import defaultdict
