# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Log aggregation and analysis for observability."""

import re
from collections import defaultdict
from typing import Any


class LogAggregator:
    """Aggregate and analyze logs."""

    def __init__(self):
        """Initialize log aggregator."""
        self.patterns = {}
        self.clusters = defaultdict(list)
        self.anomalies = []

    def detect_patterns(self, logs: list[dict[str, Any]]) -> dict[str, int]:
        """Detect patterns in logs."""
        pattern_counts: dict[str, int] = defaultdict(int)

        for log in logs:
            message = log.get("message", "")

            # Simple pattern detection based on structure
            # Remove numbers and UUIDs to find patterns
            pattern = re.sub(r"\d+", "N", message)
            pattern = re.sub(
                r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "UUID", pattern
            )
            pattern = re.sub(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "EMAIL", pattern
            )

            pattern_counts[pattern] += 1

        self.patterns = dict(pattern_counts)
        return self.patterns

    def cluster_errors(self, logs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """Cluster similar errors together."""
        error_clusters = defaultdict(list)

        for log in logs:
            if log.get("level") == "ERROR":
                message = log.get("message", "")
                # Simple clustering by error type
                if "timeout" in message.lower():
                    error_clusters["timeout_errors"].append(log)
                elif "connection" in message.lower():
                    error_clusters["connection_errors"].append(log)
                elif "permission" in message.lower() or "forbidden" in message.lower():
                    error_clusters["permission_errors"].append(log)
                elif "not found" in message.lower() or "404" in str(log.get("status_code", "")):
                    error_clusters["not_found_errors"].append(log)
                else:
                    error_clusters["other_errors"].append(log)

        self.clusters = dict(error_clusters)
        return self.clusters

    def detect_anomalies(self, logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect anomalies in logs."""
        anomalies: list[dict[str, Any]] = []

        # Calculate baseline metrics
        if not logs:
            return anomalies

        # Simple anomaly detection based on log frequency
        timestamps = [log.get("timestamp", 0) for log in logs]
        if len(timestamps) > 10:
            # Calculate average time between logs
            time_diffs = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
                if timestamps[i + 1] > timestamps[i]
            ]

            if time_diffs:
                avg_diff = sum(time_diffs) / len(time_diffs)
                std_diff = (sum((x - avg_diff) ** 2 for x in time_diffs) / len(time_diffs)) ** 0.5

                # Detect anomalies (logs that are too frequent or too sparse)
                for i, diff in enumerate(time_diffs):
                    if abs(diff - avg_diff) > 2 * std_diff:  # 2 standard deviations
                        anomalies.append(
                            {
                                "type": "frequency_anomaly",
                                "index": i,
                                "expected_interval": avg_diff,
                                "actual_interval": diff,
                                "message": "Unusual log frequency detected",
                            }
                        )

        # Detect unusual error spikes
        error_counts_by_minute: dict[int, int] = defaultdict(int)
        for log in logs:
            if log.get("level") == "ERROR":
                minute = int(log.get("timestamp", 0) // 60)
                error_counts_by_minute[minute] += 1

        if error_counts_by_minute:
            avg_errors = sum(error_counts_by_minute.values()) / len(error_counts_by_minute)
            for minute, count in error_counts_by_minute.items():
                if count > avg_errors * 3:  # 3x average is anomaly
                    anomalies.append(
                        {
                            "type": "error_spike",
                            "minute": minute,
                            "count": count,
                            "average": avg_errors,
                            "message": f"Error spike detected: {count} errors in minute {minute}",
                        }
                    )

        self.anomalies = anomalies
        return anomalies

    def get_summary(self) -> dict[str, Any]:
        """Get aggregation summary."""
        return {
            "pattern_count": len(self.patterns),
            "top_patterns": sorted(self.patterns.items(), key=lambda x: x[1], reverse=True)[:5],
            "error_clusters": {k: len(v) for k, v in self.clusters.items()},
            "anomaly_count": len(self.anomalies),
        }
