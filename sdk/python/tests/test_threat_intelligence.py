"""Tests for threat intelligence SDK methods."""

from unittest.mock import Mock, patch

import httpx
import pytest
from promptsentinel import AsyncPromptSentinel, PromptSentinel


class TestSyncThreatIntelligence:
    """Tests for synchronous threat intelligence methods."""

    def setup_method(self):
        """Set up test client."""
        self.client = PromptSentinel(base_url="http://test.local")

    @patch.object(httpx.Client, "post")
    def test_add_threat_feed(self, mock_post):
        """Test adding a new threat feed."""
        feed_data = {
            "name": "Test Feed",
            "description": "Test threat feed",
            "type": "json",
            "url": "https://example.com/feed.json",
            "refresh_interval": 3600,
            "priority": 5,
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "test_feed",
            **feed_data,
            "enabled": True,
            "last_fetch": None,
            "statistics": {},
        }
        mock_post.return_value = mock_response

        result = self.client.add_threat_feed(feed_data)

        assert result["id"] == "test_feed"
        assert result["name"] == "Test Feed"
        mock_post.assert_called_once()

    @patch.object(httpx.Client, "get")
    def test_list_threat_feeds(self, mock_get):
        """Test listing all threat feeds."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"id": "feed1", "name": "Feed 1", "type": "json"},
            {"id": "feed2", "name": "Feed 2", "type": "csv"},
        ]
        mock_get.return_value = mock_response

        result = self.client.list_threat_feeds()

        assert len(result) == 2
        assert result[0]["name"] == "Feed 1"
        mock_get.assert_called_once()

    @patch.object(httpx.Client, "get")
    def test_get_threat_feed(self, mock_get):
        """Test getting a specific threat feed."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "test_feed",
            "name": "Test Feed",
            "type": "json",
            "enabled": True,
        }
        mock_get.return_value = mock_response

        result = self.client.get_threat_feed("test_feed")

        assert result["id"] == "test_feed"
        assert result["name"] == "Test Feed"
        mock_get.assert_called_once()

    @patch.object(httpx.Client, "post")
    def test_update_threat_feed(self, mock_post):
        """Test manually updating a threat feed."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "indicators_added": 10,
            "indicators_updated": 5,
        }
        mock_post.return_value = mock_response

        result = self.client.update_threat_feed("test_feed")

        assert result["success"] is True
        assert result["indicators_added"] == 10
        mock_post.assert_called_once()

    @patch.object(httpx.Client, "delete")
    def test_remove_threat_feed(self, mock_delete):
        """Test removing a threat feed."""
        mock_response = Mock()
        mock_response.status_code = 204
        mock_delete.return_value = mock_response

        result = self.client.remove_threat_feed("test_feed")

        assert result is True
        mock_delete.assert_called_once()

    @patch.object(httpx.Client, "get")
    def test_get_threat_indicators(self, mock_get):
        """Test getting active threat indicators."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "id": "ind1",
                "pattern": "ignore.*instructions",
                "confidence": 0.9,
                "technique": "jailbreak",
            },
            {
                "id": "ind2",
                "pattern": "DAN mode",
                "confidence": 0.95,
                "technique": "jailbreak",
            },
        ]
        mock_get.return_value = mock_response

        result = self.client.get_threat_indicators()

        assert len(result) == 2
        assert result[0]["pattern"] == "ignore.*instructions"
        mock_get.assert_called_once()

    @patch.object(httpx.Client, "get")
    def test_get_threat_indicators_with_filter(self, mock_get):
        """Test getting threat indicators with filters."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "id": "ind1",
                "pattern": "role play",
                "confidence": 0.85,
                "technique": "role_play",
            },
        ]
        mock_get.return_value = mock_response

        result = self.client.get_threat_indicators(technique="role_play", min_confidence=0.8)

        assert len(result) == 1
        assert result[0]["technique"] == "role_play"
        mock_get.assert_called_once()

    @patch.object(httpx.Client, "get")
    def test_search_threat_indicators(self, mock_get):
        """Test searching threat indicators."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "id": "ind1",
                "pattern": "jailbreak attempt",
                "description": "Common jailbreak pattern",
            },
        ]
        mock_get.return_value = mock_response

        result = self.client.search_threat_indicators("jailbreak")

        assert len(result) == 1
        assert "jailbreak" in result[0]["pattern"]
        mock_get.assert_called_once()

    @patch.object(httpx.Client, "post")
    def test_report_false_positive(self, mock_post):
        """Test reporting a false positive."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "indicator_id": "ind1",
            "false_positive_count": 3,
            "confidence_adjusted": 0.75,
        }
        mock_post.return_value = mock_response

        result = self.client.report_false_positive("ind1", "Not actually malicious")

        assert result["success"] is True
        assert result["confidence_adjusted"] == 0.75
        mock_post.assert_called_once()

    @patch.object(httpx.Client, "post")
    def test_confirm_true_positive(self, mock_post):
        """Test confirming a true positive."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "indicator_id": "ind1",
            "true_positive_count": 10,
            "confidence_adjusted": 0.98,
        }
        mock_post.return_value = mock_response

        result = self.client.confirm_true_positive("ind1", "Confirmed malicious")

        assert result["success"] is True
        assert result["confidence_adjusted"] == 0.98
        mock_post.assert_called_once()

    @patch.object(httpx.Client, "get")
    def test_get_threat_statistics(self, mock_get):
        """Test getting threat statistics."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "total_feeds": 5,
            "active_feeds": 4,
            "total_indicators": 1500,
            "active_indicators": 1200,
            "false_positives_last_7d": 15,
            "true_positives_last_7d": 85,
            "average_confidence": 0.87,
        }
        mock_get.return_value = mock_response

        result = self.client.get_threat_statistics()

        assert result["total_feeds"] == 5
        assert result["active_indicators"] == 1200
        assert result["average_confidence"] == 0.87
        mock_get.assert_called_once()


class TestAsyncThreatIntelligence:
    """Tests for asynchronous threat intelligence methods."""

    def setup_method(self):
        """Set up test client."""
        self.client = AsyncPromptSentinel(base_url="http://test.local")

    @pytest.mark.asyncio
    @patch.object(httpx.AsyncClient, "post")
    async def test_add_threat_feed_async(self, mock_post):
        """Test adding a new threat feed asynchronously."""
        feed_data = {
            "name": "Test Feed",
            "description": "Test threat feed",
            "type": "json",
            "url": "https://example.com/feed.json",
            "refresh_interval": 3600,
            "priority": 5,
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "test_feed",
            **feed_data,
            "enabled": True,
            "last_fetch": None,
            "statistics": {},
        }
        mock_post.return_value = mock_response

        async with self.client:
            result = await self.client.add_threat_feed(feed_data)

        assert result["id"] == "test_feed"
        assert result["name"] == "Test Feed"
        mock_post.assert_called_once()

    @pytest.mark.asyncio
    @patch.object(httpx.AsyncClient, "get")
    async def test_list_threat_feeds_async(self, mock_get):
        """Test listing all threat feeds asynchronously."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"id": "feed1", "name": "Feed 1", "type": "json"},
            {"id": "feed2", "name": "Feed 2", "type": "csv"},
        ]
        mock_get.return_value = mock_response

        async with self.client:
            result = await self.client.list_threat_feeds()

        assert len(result) == 2
        assert result[0]["name"] == "Feed 1"
        mock_get.assert_called_once()

    @pytest.mark.asyncio
    @patch.object(httpx.AsyncClient, "get")
    async def test_search_threat_indicators_async(self, mock_get):
        """Test searching threat indicators asynchronously."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "id": "ind1",
                "pattern": "jailbreak attempt",
                "description": "Common jailbreak pattern",
            },
        ]
        mock_get.return_value = mock_response

        async with self.client:
            result = await self.client.search_threat_indicators("jailbreak")

        assert len(result) == 1
        assert "jailbreak" in result[0]["pattern"]
        mock_get.assert_called_once()

    @pytest.mark.asyncio
    @patch.object(httpx.AsyncClient, "delete")
    async def test_remove_threat_feed_async(self, mock_delete):
        """Test removing a threat feed asynchronously."""
        mock_response = Mock()
        mock_response.status_code = 204
        mock_delete.return_value = mock_response

        async with self.client:
            result = await self.client.remove_threat_feed("test_feed")

        assert result is True
        mock_delete.assert_called_once()
