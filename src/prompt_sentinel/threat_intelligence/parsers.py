# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Feed parsers for different formats."""

import csv
from abc import ABC, abstractmethod
from datetime import datetime
from io import StringIO
from typing import Any

import structlog

from .models import FeedType

logger = structlog.get_logger()


class FeedParser(ABC):
    """Base class for feed parsers."""

    @abstractmethod
    def parse(self, data: Any, config: dict) -> list[dict]:
        """Parse feed data.

        Args:
            data: Raw feed data
            config: Parser configuration

        Returns:
            List of indicator dictionaries
        """
        pass


class JSONParser(FeedParser):
    """Parser for JSON feeds."""

    def parse(self, data: Any, config: dict) -> list[dict]:
        """Parse JSON feed data."""
        indicators = []

        # Handle different JSON structures
        if isinstance(data, list):
            # Direct list of indicators
            indicators = data
        elif isinstance(data, dict):
            # Look for indicators key
            indicators_key = config.get("indicators_key", "indicators")
            if indicators_key in data:
                indicators = data[indicators_key]
            else:
                # Single indicator
                indicators = [data]

        # Process each indicator
        processed = []
        for item in indicators:
            if isinstance(item, dict):
                processed.append(self._process_item(item, config))

        return processed

    def _process_item(self, item: dict, config: dict) -> dict:
        """Process a single JSON item."""
        # Apply transformations
        if "transformations" in config:
            for field, transform in config["transformations"].items():
                if field in item:
                    if transform == "lowercase":
                        item[field] = item[field].lower()
                    elif transform == "uppercase":
                        item[field] = item[field].upper()
                    elif transform == "timestamp":
                        # Convert to datetime
                        try:
                            item[field] = datetime.fromisoformat(item[field])
                        except Exception:
                            pass

        return item


class CSVParser(FeedParser):
    """Parser for CSV feeds."""

    def parse(self, data: Any, config: dict) -> list[dict]:
        """Parse CSV feed data."""
        indicators = []

        # Convert to string if needed
        if not isinstance(data, str):
            data = str(data)

        # Parse CSV
        reader = csv.DictReader(StringIO(data))

        for row in reader:
            # Process row
            indicator = {}

            # Map columns
            column_map = config.get("column_map", {})
            for csv_col, indicator_field in column_map.items():
                if csv_col in row:
                    indicator[indicator_field] = row[csv_col]

            # Add unmapped columns if configured
            if config.get("include_unmapped", False):
                for col, value in row.items():
                    if col not in column_map:
                        indicator[col] = value

            indicators.append(indicator)

        return indicators


class STIXParser(FeedParser):
    """Parser for STIX format feeds."""

    def parse(self, data: Any, config: dict) -> list[dict]:
        """Parse STIX feed data."""
        indicators = []

        # STIX 2.1 structure
        if isinstance(data, dict) and "objects" in data:
            for obj in data["objects"]:
                if obj.get("type") == "indicator":
                    indicator = self._parse_stix_indicator(obj)
                    indicators.append(indicator)

        return indicators

    def _parse_stix_indicator(self, stix_obj: dict) -> dict:
        """Parse STIX indicator object."""
        indicator = {
            "pattern": stix_obj.get("pattern", ""),
            "description": stix_obj.get("description", stix_obj.get("name", "")),
            "confidence": self._map_stix_confidence(stix_obj.get("confidence")),
            "first_seen": stix_obj.get("valid_from"),
            "expires_at": stix_obj.get("valid_until"),
        }

        # Extract labels as tags
        if "labels" in stix_obj:
            indicator["tags"] = stix_obj["labels"]

        # Extract kill chain phases
        if "kill_chain_phases" in stix_obj:
            indicator["mitre_tactics"] = [
                phase["phase_name"] for phase in stix_obj["kill_chain_phases"]
            ]

        return indicator

    def _map_stix_confidence(self, confidence: Any) -> float:
        """Map STIX confidence to 0-1 scale."""
        if isinstance(confidence, int | float):
            return min(1.0, max(0.0, confidence / 100))
        return 0.7  # Default


class MISPParser(FeedParser):
    """Parser for MISP format feeds."""

    def parse(self, data: Any, config: dict) -> list[dict]:
        """Parse MISP feed data."""
        indicators = []

        if isinstance(data, dict):
            # MISP event format
            if "Event" in data:
                event = data["Event"]
                if "Attribute" in event:
                    for attr in event["Attribute"]:
                        indicator = self._parse_misp_attribute(attr)
                        indicators.append(indicator)

        return indicators

    def _parse_misp_attribute(self, attr: dict) -> dict:
        """Parse MISP attribute."""
        return {
            "pattern": attr.get("value", ""),
            "description": attr.get("comment", attr.get("type", "")),
            "tags": attr.get("Tag", []),
            "first_seen": attr.get("first_seen"),
            "last_seen": attr.get("last_seen"),
            "iocs": [attr.get("value", "")],
        }


class GitHubParser(FeedParser):
    """Parser for GitHub repository feeds."""

    def parse(self, data: Any, config: dict) -> list[dict]:
        """Parse GitHub repository data."""
        indicators = []

        # Parse repository files
        if isinstance(data, list):
            for file_info in data:
                if file_info.get("type") == "file":
                    # Check if it's a pattern file
                    if self._is_pattern_file(file_info["name"], config):
                        # Would need to fetch file content
                        # For now, create indicator from filename
                        indicator = {
                            "pattern": "",  # Would be filled from file content
                            "description": f"Pattern from {file_info['name']}",
                            "source_url": file_info.get("html_url"),
                        }
                        indicators.append(indicator)

        return indicators

    def _is_pattern_file(self, filename: str, config: dict) -> bool:
        """Check if file contains patterns."""
        extensions = config.get("pattern_extensions", [".txt", ".json", ".yaml"])
        return any(filename.endswith(ext) for ext in extensions)


def get_parser(feed_type: FeedType) -> FeedParser:
    """Get parser for feed type.

    Args:
        feed_type: Type of feed

    Returns:
        Appropriate parser instance
    """
    parsers = {
        FeedType.JSON: JSONParser(),
        FeedType.CSV: CSVParser(),
        FeedType.STIX: STIXParser(),
        FeedType.MISP: MISPParser(),
        FeedType.GITHUB: GitHubParser(),
    }

    parser = parsers.get(feed_type)
    if not parser:
        # Default to JSON parser
        logger.warning(f"No parser for feed type {feed_type}, using JSON")
        return JSONParser()

    return parser
