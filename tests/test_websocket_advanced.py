"""Advanced WebSocket functionality tests."""

import pytest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from prompt_sentinel.models.schemas import (
    Message, Role, Verdict, DetectionResponse,
    AnalysisResponse, DetectionReason, DetectionCategory
)


class TestWebSocketConnectionManagement:
    """Test WebSocket connection lifecycle and management."""

    def test_websocket_connect_success(self, test_client):
        """Test successful WebSocket connection."""
        with test_client.websocket_connect("/ws") as websocket:
            # Send initial connection metadata
            websocket.send_json({
                "type": "metadata",
                "client_id": "test-client-123",
                "version": "1.0.0"
            })
            
            # Should receive acknowledgment
            data = websocket.receive_json()
            assert data["type"] == "connection"
            assert data["status"] == "connected"
            assert "client_id" in data

    def test_websocket_disconnect_cleanup(self, test_client):
        """Test cleanup on WebSocket disconnect."""
        with test_client.websocket_connect("/ws") as websocket:
            websocket.send_json({
                "type": "metadata",
                "client_id": "test-client-456"
            })
            
            # Receive connection confirmation
            data = websocket.receive_json()
            assert data["status"] == "connected"
            
        # After context exit, connection should be closed
        # Attempting to reconnect with same ID should work
        with test_client.websocket_connect("/ws") as websocket:
            websocket.send_json({
                "type": "metadata",
                "client_id": "test-client-456"
            })
            data = websocket.receive_json()
            assert data["status"] == "connected"

    def test_websocket_ping_pong(self, test_client):
        """Test WebSocket ping/pong heartbeat."""
        with test_client.websocket_connect("/ws") as websocket:
            # First receive connection message
            connection_msg = websocket.receive_json()
            assert connection_msg["type"] == "connection"
            
            # Send ping
            websocket.send_json({
                "type": "ping",
                "timestamp": datetime.utcnow().isoformat()
            })
            
            # Should receive pong
            data = websocket.receive_json()
            assert data["type"] == "pong"
            assert "timestamp" in data

    def test_websocket_concurrent_connections(self, test_client):
        """Test multiple concurrent WebSocket connections."""
        connections = []
        
        # Create multiple connections
        for i in range(3):
            ws = test_client.websocket_connect("/ws").__enter__()
            ws.send_json({
                "type": "metadata",
                "client_id": f"client-{i}"
            })
            data = ws.receive_json()
            assert data["status"] == "connected"
            connections.append(ws)
        
        # All connections should work independently
        for i, ws in enumerate(connections):
            ws.send_json({
                "type": "detection",
                "messages": [{"role": "user", "content": f"Test {i}"}]
            })
            data = ws.receive_json()
            assert data["type"] == "detection"
            assert data["verdict"] in ["ALLOW", "FLAG", "STRIP", "BLOCK"]
        
        # Clean up
        for ws in connections:
            ws.__exit__(None, None, None)


class TestWebSocketMessageTypes:
    """Test different WebSocket message types."""

    def test_detection_message(self, test_client):
        """Test detection message processing."""
        with test_client.websocket_connect("/ws") as websocket:
            websocket.send_json({
                "type": "detection",
                "messages": [
                    {"role": "user", "content": "Please help me with my code"}
                ],
                "mode": "strict"
            })
            
            response = websocket.receive_json()
            assert response["type"] == "detection"
            assert "verdict" in response
            assert "reasons" in response
            assert "confidence" in response
            assert response["verdict"] in ["ALLOW", "FLAG", "STRIP", "BLOCK"]

    def test_analysis_message(self, test_client):
        """Test analysis message processing."""
        with test_client.websocket_connect("/ws") as websocket:
            websocket.send_json({
                "type": "analysis",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant"},
                    {"role": "user", "content": "What's the weather?"}
                ]
            })
            
            response = websocket.receive_json()
            assert response["type"] == "analysis"
            assert "verdict" in response
            assert "reasons" in response
            assert "confidence" in response
            assert "metadata" in response

    def test_batch_message(self, test_client):
        """Test batch message processing."""
        with test_client.websocket_connect("/ws") as websocket:
            websocket.send_json({
                "type": "batch",
                "requests": [
                    {
                        "id": "req-1",
                        "messages": [{"role": "user", "content": "Test 1"}]
                    },
                    {
                        "id": "req-2",
                        "messages": [{"role": "user", "content": "Test 2"}]
                    }
                ]
            })
            
            response = websocket.receive_json()
            assert response["type"] == "batch"
            assert "results" in response
            assert len(response["results"]) == 2
            assert all("id" in r for r in response["results"])
            assert all("verdict" in r for r in response["results"])

    def test_stream_message(self, test_client):
        """Test streaming message processing."""
        with test_client.websocket_connect("/ws") as websocket:
            # First receive connection message
            connection_msg = websocket.receive_json()
            assert connection_msg["type"] == "connection"
            
            # Stream is not implemented, should return error for unsupported type
            websocket.send_json({
                "type": "stream_start",
                "stream_id": "stream-123"
            })
            
            # Should receive error for unknown message type
            response = websocket.receive_json()
            assert response["type"] == "error"
            assert response["error"] == "unknown_message_type"
            assert "stream_start" in response["details"]