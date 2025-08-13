# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Threat intelligence feed manager."""

import asyncio
import hashlib
from datetime import datetime
from typing import Any

import httpx
import structlog
from pydantic import ValidationError

from prompt_sentinel.cache import cache_manager

from .extractors import PatternExtractor
from .models import FeedStatistics, FeedType, ThreatFeed, ThreatIndicator
from .parsers import get_parser
from .validators import ThreatValidator

logger = structlog.get_logger()


class ThreatFeedManager:
    """Manages threat intelligence feeds and pattern extraction."""

    def __init__(self):
        """Initialize feed manager."""
        self.feeds: dict[str, ThreatFeed] = {}
        self.indicators: dict[str, ThreatIndicator] = {}
        self.statistics: dict[str, FeedStatistics] = {}
        self.pattern_extractor = PatternExtractor()
        self.validator = ThreatValidator()
        self.update_tasks: dict[str, asyncio.Task] = {}
        self._running = False

    async def initialize(self):
        """Initialize feed manager and load configured feeds."""
        logger.info("Initializing threat feed manager")

        # Load feeds from configuration
        await self._load_configured_feeds()

        # Load cached indicators
        await self._load_cached_indicators()

        # Start feed update scheduler
        self._running = True
        asyncio.create_task(self._feed_update_scheduler())

    async def shutdown(self):
        """Shutdown feed manager."""
        logger.info("Shutting down threat feed manager")
        self._running = False

        # Cancel all update tasks
        for task in self.update_tasks.values():
            task.cancel()

        # Save indicators to cache
        await self._save_indicators_to_cache()

    async def add_feed(self, feed: ThreatFeed) -> bool:
        """Add a new threat feed.

        Args:
            feed: Feed configuration

        Returns:
            Success status
        """
        try:
            # Validate feed configuration
            if not await self._validate_feed(feed):
                return False

            # Add to feeds
            self.feeds[feed.id] = feed
            self.statistics[feed.id] = FeedStatistics(feed_id=feed.id)

            # Schedule immediate update
            if feed.enabled:
                await self.update_feed(feed.id)

            logger.info("Added threat feed", feed_id=feed.id, name=feed.name)
            return True

        except Exception as e:
            logger.error("Failed to add feed", feed_id=feed.id, error=str(e))
            return False

    async def remove_feed(self, feed_id: str) -> bool:
        """Remove a threat feed.

        Args:
            feed_id: Feed identifier

        Returns:
            Success status
        """
        if feed_id not in self.feeds:
            return False

        # Cancel update task
        if feed_id in self.update_tasks:
            self.update_tasks[feed_id].cancel()
            del self.update_tasks[feed_id]

        # Remove indicators from this feed
        self.indicators = {k: v for k, v in self.indicators.items() if v.feed_id != feed_id}

        # Remove feed
        del self.feeds[feed_id]
        del self.statistics[feed_id]

        logger.info("Removed threat feed", feed_id=feed_id)
        return True

    async def update_feed(self, feed_id: str) -> bool:
        """Update indicators from a specific feed.

        Args:
            feed_id: Feed identifier

        Returns:
            Success status
        """
        if feed_id not in self.feeds:
            return False

        feed = self.feeds[feed_id]
        stats = self.statistics[feed_id]

        try:
            logger.info("Updating threat feed", feed_id=feed_id, name=feed.name)
            start_time = datetime.utcnow()

            # Fetch feed data
            data = await self._fetch_feed_data(feed)
            if not data:
                raise ValueError("No data received from feed")

            # Parse indicators
            parser = get_parser(feed.type)
            raw_indicators = parser.parse(data, feed.parser_config)

            # Process indicators
            processed = 0
            accepted = 0
            for raw in raw_indicators:
                indicator = await self._process_indicator(raw, feed)
                if indicator:
                    # Validate indicator
                    if await self.validator.validate(indicator):
                        self.indicators[indicator.id] = indicator
                        accepted += 1
                processed += 1

            # Update statistics
            duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            stats.successful_fetches += 1
            stats.indicators_received += processed
            stats.indicators_accepted += accepted
            stats.last_fetch_duration_ms = duration

            # Update feed metadata
            feed.last_fetch = datetime.utcnow()
            feed.total_indicators = len(
                [i for i in self.indicators.values() if i.feed_id == feed_id]
            )
            feed.active_indicators = len(
                [
                    i
                    for i in self.indicators.values()
                    if i.feed_id == feed_id
                    and (not i.expires_at or i.expires_at > datetime.utcnow())
                ]
            )

            logger.info(
                "Feed update completed",
                feed_id=feed_id,
                processed=processed,
                accepted=accepted,
                duration_ms=duration,
            )
            return True

        except Exception as e:
            logger.error("Feed update failed", feed_id=feed_id, error=str(e))
            stats.failed_fetches += 1
            feed.last_error = str(e)
            return False

    async def get_active_indicators(
        self, technique: str | None = None, min_confidence: float = 0.0
    ) -> list[ThreatIndicator]:
        """Get active threat indicators.

        Args:
            technique: Filter by technique
            min_confidence: Minimum confidence threshold

        Returns:
            List of active indicators
        """
        now = datetime.utcnow()
        active = []

        for indicator in self.indicators.values():
            # Check expiration
            if indicator.expires_at and indicator.expires_at < now:
                continue

            # Apply filters
            if technique and indicator.technique != technique:
                continue
            if indicator.confidence < min_confidence:
                continue

            active.append(indicator)

        return sorted(active, key=lambda x: x.confidence, reverse=True)

    async def search_indicators(self, query: str, limit: int = 100) -> list[ThreatIndicator]:
        """Search threat indicators.

        Args:
            query: Search query
            limit: Maximum results

        Returns:
            Matching indicators
        """
        query_lower = query.lower()
        matches = []

        for indicator in self.indicators.values():
            # Search in various fields
            if (
                query_lower in indicator.pattern.lower()
                or query_lower in indicator.description.lower()
                or any(query_lower in tag.lower() for tag in indicator.tags)
                or any(query_lower in ioc.lower() for ioc in indicator.iocs)
            ):
                matches.append(indicator)

            if len(matches) >= limit:
                break

        return matches

    async def report_false_positive(self, indicator_id: str, details: str | None = None):
        """Report a false positive for an indicator.

        Args:
            indicator_id: Indicator ID
            details: Additional details
        """
        if indicator_id not in self.indicators:
            return

        indicator = self.indicators[indicator_id]

        # Update false positive rate
        if indicator.false_positive_rate is None:
            indicator.false_positive_rate = 0.1
        else:
            # Exponential moving average
            indicator.false_positive_rate = min(1.0, indicator.false_positive_rate * 0.9 + 0.1)

        # Update statistics
        if indicator.feed_id in self.statistics:
            self.statistics[indicator.feed_id].false_positives_reported += 1

        # Reduce confidence
        indicator.confidence *= 0.95

        logger.warning(
            "False positive reported",
            indicator_id=indicator_id,
            pattern=indicator.pattern,
            new_confidence=indicator.confidence,
            details=details,
        )

    async def confirm_true_positive(self, indicator_id: str, details: str | None = None):
        """Confirm a true positive detection.

        Args:
            indicator_id: Indicator ID
            details: Additional details
        """
        if indicator_id not in self.indicators:
            return

        indicator = self.indicators[indicator_id]

        # Update last seen
        indicator.last_seen = datetime.utcnow()

        # Increase confidence slightly
        indicator.confidence = min(1.0, indicator.confidence * 1.02)

        # Update statistics
        if indicator.feed_id in self.statistics:
            self.statistics[indicator.feed_id].true_positives_confirmed += 1

        logger.info(
            "True positive confirmed",
            indicator_id=indicator_id,
            pattern=indicator.pattern,
            new_confidence=indicator.confidence,
            details=details,
        )

    # Private methods

    async def _feed_update_scheduler(self):
        """Background task to schedule feed updates."""
        while self._running:
            try:
                for feed_id, feed in self.feeds.items():
                    if not feed.enabled:
                        continue

                    # Check if update needed
                    if self._should_update_feed(feed):
                        # Cancel existing task if running
                        if feed_id in self.update_tasks:
                            if not self.update_tasks[feed_id].done():
                                continue

                        # Schedule update
                        task = asyncio.create_task(self.update_feed(feed_id))
                        self.update_tasks[feed_id] = task

                await asyncio.sleep(60)  # Check every minute

            except Exception as e:
                logger.error("Feed scheduler error", error=str(e))
                await asyncio.sleep(60)

    def _should_update_feed(self, feed: ThreatFeed) -> bool:
        """Check if feed should be updated."""
        if not feed.last_fetch:
            return True

        elapsed = (datetime.utcnow() - feed.last_fetch).total_seconds()
        return elapsed >= feed.refresh_interval

    async def _fetch_feed_data(self, feed: ThreatFeed) -> Any:
        """Fetch data from feed source."""
        if feed.type == FeedType.API:
            return await self._fetch_api_feed(feed)
        elif feed.type == FeedType.GITHUB:
            return await self._fetch_github_feed(feed)
        elif feed.type in [FeedType.JSON, FeedType.CSV]:
            return await self._fetch_http_feed(feed)
        else:
            raise ValueError(f"Unsupported feed type: {feed.type}")

    async def _fetch_api_feed(self, feed: ThreatFeed) -> Any:
        """Fetch data from API feed."""
        async with httpx.AsyncClient() as client:
            headers = feed.headers.copy()
            if feed.api_key:
                headers["Authorization"] = f"Bearer {feed.api_key}"

            response = await client.get(str(feed.url), headers=headers, timeout=30.0)
            response.raise_for_status()
            return response.json()

    async def _fetch_github_feed(self, feed: ThreatFeed) -> Any:
        """Fetch data from GitHub repository."""
        # Extract owner/repo from URL
        # Example: https://github.com/owner/repo
        parts = str(feed.url).split("/")
        owner = parts[-2]
        repo = parts[-1].replace(".git", "")

        # Use GitHub API to fetch repository data
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"

        async with httpx.AsyncClient() as client:
            headers = {"Accept": "application/vnd.github.v3+json"}
            if feed.api_key:
                headers["Authorization"] = f"token {feed.api_key}"

            response = await client.get(api_url, headers=headers)
            response.raise_for_status()
            return response.json()

    async def _fetch_http_feed(self, feed: ThreatFeed) -> Any:
        """Fetch data from HTTP feed."""
        async with httpx.AsyncClient() as client:
            response = await client.get(str(feed.url), headers=feed.headers, timeout=30.0)
            response.raise_for_status()

            if feed.type == FeedType.JSON:
                return response.json()
            else:
                return response.text

    async def _process_indicator(self, raw_data: dict, feed: ThreatFeed) -> ThreatIndicator | None:
        """Process raw indicator data."""
        try:
            # Apply field mappings
            if feed.field_mappings:
                mapped = {}
                for target, source in feed.field_mappings.items():
                    if source in raw_data:
                        mapped[target] = raw_data[source]
                raw_data.update(mapped)

            # Generate ID
            raw_data["id"] = self._generate_indicator_id(feed.id, raw_data.get("pattern", ""))
            raw_data["feed_id"] = feed.id

            # Create indicator
            indicator = ThreatIndicator(**raw_data)

            # Apply filters
            if feed.filters:
                if not self._apply_filters(indicator, feed.filters):
                    return None

            # Check age
            age_days = (datetime.utcnow() - indicator.first_seen).days
            if age_days > feed.max_age_days:
                return None

            # Check confidence
            if indicator.confidence < feed.min_confidence:
                return None

            return indicator

        except ValidationError as e:
            logger.warning("Invalid indicator data", error=str(e), data=raw_data)
            return None

    def _generate_indicator_id(self, feed_id: str, pattern: str) -> str:
        """Generate unique indicator ID."""
        data = f"{feed_id}:{pattern}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _apply_filters(self, indicator: ThreatIndicator, filters: dict) -> bool:
        """Apply filters to indicator."""
        for field, value in filters.items():
            if hasattr(indicator, field):
                indicator_value = getattr(indicator, field)
                if isinstance(value, list):
                    if indicator_value not in value:
                        return False
                else:
                    if indicator_value != value:
                        return False
        return True

    async def _validate_feed(self, feed: ThreatFeed) -> bool:
        """Validate feed configuration."""
        if not feed.url and feed.type != FeedType.WEBHOOK:
            logger.error("Feed missing URL", feed_id=feed.id)
            return False

        if feed.type == FeedType.API and not feed.api_key:
            logger.warning("API feed missing API key", feed_id=feed.id)

        return True

    async def _load_configured_feeds(self):
        """Load feeds from configuration."""
        # Load from settings or database
        # For now, we'll add some default feeds

        # Temporarily disable default feeds until we have valid sources
        default_feeds: list[ThreatFeed] = [
            # Will add real threat feed sources here
        ]

        for feed in default_feeds:
            await self.add_feed(feed)

    async def _load_cached_indicators(self):
        """Load indicators from cache."""
        if not cache_manager.enabled:
            return

        try:
            cached = await cache_manager.get("threat_indicators")
            if cached:
                for data in cached:
                    try:
                        indicator = ThreatIndicator(**data)
                        self.indicators[indicator.id] = indicator
                    except Exception as e:
                        logger.warning("Invalid cached indicator", error=str(e))

                logger.info("Loaded cached indicators", count=len(self.indicators))
        except Exception as e:
            logger.error("Failed to load cached indicators", error=str(e))

    async def _save_indicators_to_cache(self):
        """Save indicators to cache."""
        if not cache_manager.enabled:
            return

        try:
            data = [indicator.model_dump() for indicator in self.indicators.values()]
            await cache_manager.set("threat_indicators", data, ttl=86400)  # 24 hours
            logger.info("Saved indicators to cache", count=len(data))
        except Exception as e:
            logger.error("Failed to save indicators", error=str(e))
