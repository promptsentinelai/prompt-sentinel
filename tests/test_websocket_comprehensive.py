# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Comprehensive tests for the WebSocket module."""

import asyncio
import json
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from fastapi import WebSocket
from fastapi.websockets import WebSocketState
from pydantic import ValidationError

from prompt_sentinel.api.websocket import ConnectionManager, StreamingDetector, handle_websocket_connection, broadcast_system_message
from prompt_sentinel.detection.detector import PromptDetector
from prompt_sentinel.models.schemas import (
    DetectionCategory,
    DetectionReason,
    DetectionResponse,
    Message,
    Role,
    Verdict,
)
from prompt_sentinel.routing.router import IntelligentRouter


class TestConnectionManager:
    """Test suite for ConnectionManager."""

    @pytest.fixture
    def manager(self):
        """Create a ConnectionManager instance."""
        return ConnectionManager()

    @pytest.fixture
    def mock_websocket(self):
        """Create a mock WebSocket."""
        websocket = MagicMock(spec=WebSocket)
        websocket.accept = AsyncMock()
        websocket.close = AsyncMock()
        websocket.send_json = AsyncMock()
        websocket.client_state = WebSocketState.CONNECTED
        return websocket

    def test_initialization(self):
        """Test ConnectionManager initialization."""
        manager = ConnectionManager()
        
        assert manager.active_connections == {}
        assert manager.connection_metadata == {}
        assert manager.message_queues == {}
        assert manager.usage_tracker is not None

    @pytest.mark.asyncio
    async def test_connect_success(self, manager, mock_websocket):
        """Test successful WebSocket connection."""
        client_id = "test_client_123"
        
        with patch('prompt_sentinel.api.websocket.logger') as mock_logger:
            result = await manager.connect(mock_websocket, client_id)
        
        assert result is True
        assert client_id in manager.active_connections
        assert client_id in manager.message_queues
        assert client_id in manager.connection_metadata
        
        # Check metadata
        metadata = manager.connection_metadata[client_id]
        assert metadata["messages_processed"] == 0
        assert metadata["authenticated"] is False
        assert "connected_at" in metadata
        assert "last_activity" in metadata
        
        # Check welcome message was sent
        mock_websocket.accept.assert_called_once()
        mock_websocket.send_json.assert_called_once()
        welcome_msg = mock_websocket.send_json.call_args[0][0]
        assert welcome_msg["type"] == "connection"
        assert welcome_msg["status"] == "connected"
        assert welcome_msg["client_id"] == client_id

    @pytest.mark.asyncio
    async def test_connect_failure(self, manager):
        """Test failed WebSocket connection."""
        client_id = "test_client_123"
        mock_websocket = MagicMock(spec=WebSocket)
        mock_websocket.accept = AsyncMock(side_effect=Exception("Connection failed"))
        
        with patch('prompt_sentinel.api.websocket.logger') as mock_logger:
            result = await manager.connect(mock_websocket, client_id)
        
        assert result is False
        assert client_id not in manager.active_connections
        mock_logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect(self, manager, mock_websocket):
        """Test WebSocket disconnection."""
        client_id = "test_client_123"
        
        # First connect
        await manager.connect(mock_websocket, client_id)
        assert client_id in manager.active_connections
        
        # Then disconnect
        with patch('prompt_sentinel.api.websocket.logger') as mock_logger:
            await manager.disconnect(client_id)
        
        assert client_id not in manager.active_connections
        assert client_id not in manager.message_queues
        assert client_id not in manager.connection_metadata
        mock_websocket.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect_already_disconnected(self, manager, mock_websocket):
        """Test disconnecting already disconnected client."""
        client_id = "test_client_123"
        
        # Connect and set state to disconnected
        await manager.connect(mock_websocket, client_id)
        mock_websocket.client_state = WebSocketState.DISCONNECTED
        
        await manager.disconnect(client_id)
        
        # Should not call close on already disconnected socket
        mock_websocket.close.assert_not_called()

    @pytest.mark.asyncio
    async def test_disconnect_non_existent(self, manager):
        """Test disconnecting non-existent client."""
        client_id = "non_existent"
        
        # Should not raise error
        await manager.disconnect(client_id)

    @pytest.mark.asyncio
    async def test_send_json_success(self, manager, mock_websocket):
        """Test successful JSON sending."""
        client_id = "test_client_123"
        await manager.connect(mock_websocket, client_id)
        
        data = {"message": "test", "value": 123}
        result = await manager.send_json(client_id, data)
        
        assert result is True
        mock_websocket.send_json.assert_called_with(data)
        
        # Check activity timestamp was updated
        metadata = manager.connection_metadata[client_id]
        assert "last_activity" in metadata

    @pytest.mark.asyncio
    async def test_send_json_non_existent_client(self, manager):
        """Test sending to non-existent client."""
        result = await manager.send_json("non_existent", {"test": "data"})
        assert result is False

    @pytest.mark.asyncio
    async def test_send_json_disconnected_client(self, manager, mock_websocket):
        """Test sending to disconnected client."""
        client_id = "test_client_123"
        await manager.connect(mock_websocket, client_id)
        
        # Set client state to disconnected
        mock_websocket.client_state = WebSocketState.DISCONNECTED
        
        result = await manager.send_json(client_id, {"test": "data"})
        assert result is False

    @pytest.mark.asyncio
    async def test_send_json_failure(self, manager, mock_websocket):
        """Test JSON sending failure."""
        client_id = "test_client_123"
        await manager.connect(mock_websocket, client_id)
        
        # Make send_json raise exception
        mock_websocket.send_json = AsyncMock(side_effect=Exception("Send failed"))
        
        with patch('prompt_sentinel.api.websocket.logger') as mock_logger:
            result = await manager.send_json(client_id, {"test": "data"})
        
        assert result is False
        mock_logger.error.assert_called_once()
        # Should disconnect failed client
        assert client_id not in manager.active_connections

    @pytest.mark.asyncio
    async def test_broadcast_success(self, manager):
        """Test broadcasting to multiple clients."""
        # Connect multiple clients
        clients = {}
        for i in range(3):
            client_id = f"client_{i}"
            websocket = MagicMock(spec=WebSocket)
            websocket.accept = AsyncMock()
            websocket.send_json = AsyncMock()
            websocket.client_state = WebSocketState.CONNECTED
            clients[client_id] = websocket
            await manager.connect(websocket, client_id)
        
        # Broadcast message
        data = {"broadcast": "message"}
        await manager.broadcast(data)
        
        # All clients should receive message
        for websocket in clients.values():
            websocket.send_json.assert_called_with(data)

    @pytest.mark.asyncio
    async def test_broadcast_with_exclusion(self, manager):
        """Test broadcasting with excluded clients."""
        # Connect multiple clients
        clients = {}
        for i in range(3):
            client_id = f"client_{i}"
            websocket = MagicMock(spec=WebSocket)
            websocket.accept = AsyncMock()
            websocket.send_json = AsyncMock()
            websocket.client_state = WebSocketState.CONNECTED
            clients[client_id] = websocket
            await manager.connect(websocket, client_id)
        
        # Reset mock calls after connection (connection sends status messages)
        for client in clients.values():
            client.send_json.reset_mock()
        
        # Broadcast with exclusion
        data = {"broadcast": "message"}
        exclude = {"client_1"}
        await manager.broadcast(data, exclude=exclude)
        
        # Excluded client should not receive broadcast message
        clients["client_0"].send_json.assert_called_once_with(data)
        clients["client_1"].send_json.assert_not_called()
        clients["client_2"].send_json.assert_called_once_with(data)

    @pytest.mark.asyncio
    async def test_broadcast_cleanup_failed_clients(self, manager):
        """Test that broadcast cleans up failed clients."""
        # Connect clients with one that will fail
        client1 = MagicMock(spec=WebSocket)
        client1.accept = AsyncMock()
        client1.send_json = AsyncMock()
        client1.client_state = WebSocketState.CONNECTED
        await manager.connect(client1, "client_1")
        
        client2 = MagicMock(spec=WebSocket)
        client2.accept = AsyncMock()
        client2.send_json = AsyncMock(side_effect=Exception("Send failed"))
        client2.client_state = WebSocketState.CONNECTED
        client2.close = AsyncMock()
        await manager.connect(client2, "client_2")
        
        # Broadcast
        await manager.broadcast({"test": "data"})
        
        # Failed client should be disconnected
        assert "client_1" in manager.active_connections
        assert "client_2" not in manager.active_connections

    def test_get_connection_stats(self, manager):
        """Test getting connection statistics."""
        # Add some connections with metadata
        manager.active_connections = {"client1": MagicMock(), "client2": MagicMock()}
        manager.connection_metadata = {
            "client1": {
                "connected_at": "2024-01-01T00:00:00",
                "messages_processed": 10,
                "last_activity": "2024-01-01T00:10:00"
            },
            "client2": {
                "connected_at": "2024-01-01T00:05:00",
                "messages_processed": 5,
                "last_activity": "2024-01-01T00:15:00"
            }
        }
        
        stats = manager.get_connection_stats()
        
        assert stats["active_connections"] == 2
        assert stats["total_messages_processed"] == 15
        assert len(stats["connections"]) == 2
        
        # Check connection details
        for conn in stats["connections"]:
            assert "client_id" in conn
            assert "connected_at" in conn
            assert "messages_processed" in conn
            assert "last_activity" in conn


class TestStreamingDetector:
    """Test suite for StreamingDetector."""

    @pytest.fixture
    def mock_detector(self):
        """Create a mock PromptDetector."""
        detector = MagicMock(spec=PromptDetector)
        detector.detect = AsyncMock(return_value=DetectionResponse(
            verdict=Verdict.ALLOW,
            confidence=0.95,
            reasons=[],
            processing_time_ms=10.5,
            metadata={"providers_used": ["heuristic"]}
        ))
        return detector

    @pytest.fixture
    def mock_router(self):
        """Create a mock IntelligentRouter."""
        router = MagicMock(spec=IntelligentRouter)
        router.route_detection = AsyncMock(return_value=(
            DetectionResponse(
                verdict=Verdict.ALLOW,
                confidence=0.95,
                reasons=[],
                processing_time_ms=10.5,
                metadata={"providers_used": ["llm"]}
            ),
            {"method": "llm", "reason": "complex_prompt"}
        ))
        return router

    @pytest.fixture
    def streaming_detector(self, mock_detector, mock_router):
        """Create a StreamingDetector instance."""
        return StreamingDetector(mock_detector, mock_router)

    @pytest.mark.asyncio
    async def test_process_detection_simple_prompt(self, streaming_detector, mock_detector):
        """Test processing detection with simple prompt."""
        request_data = {
            "prompt": "Test prompt",
            "request_id": "req_123"
        }
        client_id = "client_123"
        
        result = await streaming_detector.process_detection(request_data, client_id)
        
        assert result["type"] == "detection_response"
        assert result["request_id"] == "req_123"
        assert "response" in result
        assert "timestamp" in result
        
        # Check detector was called
        mock_detector.detect.assert_called_once()
        call_args = mock_detector.detect.call_args
        messages = call_args[1]["messages"]
        assert len(messages) == 1
        assert messages[0].content == "Test prompt"

    @pytest.mark.asyncio
    async def test_process_detection_structured_messages(self, streaming_detector, mock_detector):
        """Test processing detection with structured messages."""
        request_data = {
            "messages": [
                {"role": "system", "content": "You are a helper"},
                {"role": "user", "content": "Help me"}
            ],
            "check_format": True
        }
        client_id = "client_123"
        
        result = await streaming_detector.process_detection(request_data, client_id)
        
        assert result["type"] == "detection_response"
        
        # Check detector was called with correct messages
        mock_detector.detect.assert_called_once()
        call_args = mock_detector.detect.call_args
        messages = call_args[1]["messages"]
        assert len(messages) == 2
        assert messages[0].role == "system"
        assert messages[1].role == "user"

    @pytest.mark.asyncio
    async def test_process_detection_with_router(self, streaming_detector, mock_router):
        """Test processing detection with router."""
        request_data = {
            "prompt": "Test prompt",
            "use_router": True
        }
        client_id = "client_123"
        
        result = await streaming_detector.process_detection(request_data, client_id)
        
        assert result["type"] == "detection_response"
        
        # Check router was called
        mock_router.route_detection.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_detection_invalid_request(self, streaming_detector):
        """Test processing detection with invalid request."""
        request_data = {}  # Missing prompt or messages
        client_id = "client_123"
        
        result = await streaming_detector.process_detection(request_data, client_id)
        
        assert result["type"] == "error"
        assert result["error"] == "invalid_request"
        assert "details" in result

    @pytest.mark.asyncio
    async def test_process_detection_exception(self, streaming_detector, mock_detector):
        """Test processing detection with exception."""
        mock_detector.detect = AsyncMock(side_effect=Exception("Detection failed"))
        
        request_data = {"prompt": "Test"}
        client_id = "client_123"
        
        with patch('prompt_sentinel.api.websocket.logger') as mock_logger:
            result = await streaming_detector.process_detection(request_data, client_id)
        
        assert result["type"] == "error"
        assert result["error"] == "detection_failed"
        mock_logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_detection_usage_tracking(self, streaming_detector, mock_detector):
        """Test that usage is tracked properly."""
        mock_detector.detect = AsyncMock(return_value=DetectionResponse(
            verdict=Verdict.ALLOW,
            confidence=0.95,
            reasons=[],
            processing_time_ms=10.5,
            metadata={
                "providers_used": ["heuristic", "llm"],
                "prompt_tokens": 10,
                "completion_tokens": 20
            }
        ))
        
        request_data = {"prompt": "Test"}
        client_id = "client_123"
        
        with patch.object(streaming_detector.usage_tracker, 'track_api_call', new=AsyncMock()) as mock_track:
            result = await streaming_detector.process_detection(request_data, client_id)
        
        # Should track usage for each provider
        assert mock_track.call_count == 2

    @pytest.mark.asyncio
    async def test_process_analysis(self, streaming_detector, mock_detector):
        """Test processing analysis request."""
        mock_detector.detect = AsyncMock(return_value=DetectionResponse(
            verdict=Verdict.FLAG,
            confidence=0.75,
            reasons=[
                DetectionReason(
                    category=DetectionCategory.INDIRECT_INJECTION,
                    description="Potential indirect injection",
                    confidence=0.75,
                    source="heuristic",
                    patterns_matched=["pattern1"]
                )
            ],
            processing_time_ms=15.0,
            metadata={"test": "metadata"}
        ))
        
        request_data = {
            "messages": [
                {"role": "user", "content": "Analyze this"}
            ]
        }
        client_id = "client_123"
        
        result = await streaming_detector.process_analysis(request_data, client_id)
        
        assert result["type"] == "analysis_result"
        assert "verdict" in result
        assert "confidence" in result
        assert "reasons" in result
        assert "overall_risk_assessment" in result
        
        # Check overall risk assessment structure
        risk_assessment = result["overall_risk_assessment"]
        assert "threat_level" in risk_assessment
        assert "confidence_breakdown" in risk_assessment
        assert "mitigation_suggestions" in risk_assessment

    @pytest.mark.asyncio
    async def test_process_analysis_exception(self, streaming_detector, mock_detector):
        """Test processing analysis with exception."""
        mock_detector.detect = AsyncMock(side_effect=Exception("Analysis failed"))
        
        request_data = {
            "messages": [{"role": "user", "content": "Test"}]
        }
        client_id = "client_123"
        
        with patch('prompt_sentinel.api.websocket.logger') as mock_logger:
            result = await streaming_detector.process_analysis(request_data, client_id)
        
        assert result["type"] == "error"
        assert result["error"] == "analysis_failed"

    def test_calculate_threat_level(self, streaming_detector):
        """Test threat level calculation."""
        # Test different verdict levels
        response_allow = DetectionResponse(
            verdict=Verdict.ALLOW,
            confidence=0.95,
            reasons=[],
            processing_time_ms=10.0
        )
        assert streaming_detector._calculate_threat_level(response_allow) == "none"
        
        response_flag = DetectionResponse(
            verdict=Verdict.FLAG,
            confidence=0.75,
            reasons=[],
            processing_time_ms=10.0
        )
        assert streaming_detector._calculate_threat_level(response_flag) == "low"
        
        response_strip = DetectionResponse(
            verdict=Verdict.STRIP,
            confidence=0.80,
            reasons=[],
            processing_time_ms=10.0
        )
        assert streaming_detector._calculate_threat_level(response_strip) == "medium"
        
        response_block = DetectionResponse(
            verdict=Verdict.BLOCK,
            confidence=0.90,
            reasons=[],
            processing_time_ms=10.0
        )
        assert streaming_detector._calculate_threat_level(response_block) == "high"

    def test_get_confidence_breakdown(self, streaming_detector):
        """Test confidence breakdown generation."""
        response = DetectionResponse(
            verdict=Verdict.FLAG,
            confidence=0.75,
            reasons=[
                DetectionReason(
                    category=DetectionCategory.INDIRECT_INJECTION,
                    description="Test1",
                    confidence=0.80,
                    source="heuristic",
                    patterns_matched=[]
                ),
                DetectionReason(
                    category=DetectionCategory.ROLE_MANIPULATION,
                    description="Test2",
                    confidence=0.70,
                    source="llm",
                    patterns_matched=[]
                )
            ],
            processing_time_ms=10.0
        )
        
        breakdown = streaming_detector._get_confidence_breakdown(response)
        
        assert breakdown["overall"] == 0.75
        assert "heuristic" in breakdown
        assert "llm" in breakdown
        assert breakdown["heuristic"] == 0.80
        assert breakdown["llm"] == 0.70

    def test_get_mitigation_suggestions(self, streaming_detector):
        """Test mitigation suggestions generation."""
        response = DetectionResponse(
            verdict=Verdict.BLOCK,
            confidence=0.90,
            reasons=[
                DetectionReason(
                    category=DetectionCategory.DIRECT_INJECTION,
                    description="Direct injection detected",
                    confidence=0.90,
                    source="heuristic",
                    patterns_matched=[]
                )
            ],
            processing_time_ms=10.0
        )
        
        suggestions = streaming_detector._get_mitigation_suggestions(response)
        
        assert len(suggestions) > 0
        assert any("role separation" in s for s in suggestions)


class TestWebSocketFunctions:
    """Test suite for WebSocket module functions."""

    @pytest.fixture
    def mock_websocket(self):
        """Create a mock WebSocket."""
        websocket = MagicMock(spec=WebSocket)
        websocket.accept = AsyncMock()
        websocket.close = AsyncMock()
        websocket.send_json = AsyncMock()
        websocket.receive_json = AsyncMock()
        websocket.client_state = WebSocketState.CONNECTED
        return websocket

    @pytest.fixture
    def mock_detector(self):
        """Create a mock PromptDetector."""
        detector = MagicMock(spec=PromptDetector)
        detector.detect = AsyncMock(return_value=DetectionResponse(
            verdict=Verdict.ALLOW,
            confidence=0.95,
            reasons=[],
            processing_time_ms=10.5
        ))
        return detector

    @pytest.mark.asyncio
    async def test_handle_websocket_connection_success(self, mock_websocket, mock_detector):
        """Test successful WebSocket connection handling."""
        client_id = "test_client"
        
        # Mock receive to return a detection request then disconnect
        mock_websocket.receive_json = AsyncMock(side_effect=[
            {
                "type": "detection",
                "data": {"prompt": "Test prompt"}
            },
            Exception("WebSocket disconnected")  # Simulate disconnect
        ])
        
        with patch('prompt_sentinel.api.websocket.connection_manager') as mock_manager:
            mock_manager.connect = AsyncMock(return_value=True)
            mock_manager.send_json = AsyncMock(return_value=True)
            mock_manager.disconnect = AsyncMock()
            mock_manager.connection_metadata = {client_id: {"messages_processed": 0}}
            
            await handle_websocket_connection(mock_websocket, mock_detector, client_id=client_id)
            
            # Check connection was established
            mock_manager.connect.assert_called_once()
            
            # Check disconnection
            mock_manager.disconnect.assert_called_once_with(client_id)

    @pytest.mark.asyncio
    async def test_handle_websocket_connection_failed_connect(self, mock_websocket, mock_detector):
        """Test handling failed connection."""
        client_id = "test_client"
        
        with patch('prompt_sentinel.api.websocket.connection_manager') as mock_manager:
            mock_manager.connect = AsyncMock(return_value=False)
            
            await handle_websocket_connection(mock_websocket, mock_detector, client_id=client_id)
            
            # Should return early without processing messages
            mock_websocket.receive_json.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_websocket_connection_auto_client_id(self, mock_websocket, mock_detector):
        """Test connection with auto-generated client ID."""
        mock_websocket.receive_json = AsyncMock(side_effect=Exception("Disconnect"))
        
        with patch('prompt_sentinel.api.websocket.connection_manager') as mock_manager:
            mock_manager.connect = AsyncMock(return_value=True)
            mock_manager.disconnect = AsyncMock()
            
            await handle_websocket_connection(mock_websocket, mock_detector)
            
            # Check that a client_id was generated
            call_args = mock_manager.connect.call_args
            client_id = call_args[0][1]
            assert len(client_id) > 0  # UUID string

    @pytest.mark.asyncio
    async def test_handle_websocket_connection_with_auth(self, mock_websocket, mock_detector):
        """Test connection with authenticated client."""
        client_id = "test_client"
        
        # Mock authenticated client object
        mock_client = MagicMock()
        mock_client.is_authenticated = True
        mock_client.auth_method = MagicMock(value="api_key")
        mock_client.rate_limits = {"requests_per_minute": 100}
        
        mock_websocket.receive_json = AsyncMock(side_effect=Exception("Disconnect"))
        
        with patch('prompt_sentinel.api.websocket.connection_manager') as mock_manager:
            mock_manager.connect = AsyncMock(return_value=True)
            mock_manager.disconnect = AsyncMock()
            mock_manager.connection_metadata = {client_id: {}}
            
            await handle_websocket_connection(
                mock_websocket, mock_detector, client=mock_client, client_id=client_id
            )
            
            # Check auth metadata was updated
            metadata = mock_manager.connection_metadata[client_id]
            assert metadata["authenticated"] is True
            assert metadata["auth_method"] == "api_key"
            assert metadata["rate_limits"] == {"requests_per_minute": 100}

    @pytest.mark.asyncio
    async def test_handle_websocket_connection_message_types(self, mock_websocket, mock_detector):
        """Test handling different message types."""
        client_id = "test_client"
        
        # Mock various message types
        mock_websocket.receive_json = AsyncMock(side_effect=[
            {"type": "ping", "data": {}},
            {"type": "detection", "data": {"prompt": "Test"}},
            {"type": "analysis", "data": {"messages": [{"role": "user", "content": "Test"}]}},
            {"type": "stats", "data": {}},
            {"type": "unknown", "data": {}},
            Exception("Disconnect")
        ])
        
        with patch('prompt_sentinel.api.websocket.connection_manager') as mock_manager:
            mock_manager.connect = AsyncMock(return_value=True)
            mock_manager.send_json = AsyncMock(return_value=True)
            mock_manager.disconnect = AsyncMock()
            mock_manager.connection_metadata = {client_id: {"messages_processed": 0}}
            mock_manager.get_connection_stats = MagicMock(return_value={"active": 1})
            
            with patch('prompt_sentinel.api.websocket.StreamingDetector') as mock_sd_class:
                mock_sd = MagicMock()
                mock_sd.process_detection = AsyncMock(return_value={"type": "detection_response"})
                mock_sd.process_analysis = AsyncMock(return_value={"type": "analysis_result"})
                mock_sd_class.return_value = mock_sd
                
                await handle_websocket_connection(mock_websocket, mock_detector, client_id=client_id)
                
                # Check all message types were handled
                assert mock_manager.send_json.call_count >= 5  # Welcome + 5 responses
                
                # Check message counter was incremented
                assert mock_manager.connection_metadata[client_id]["messages_processed"] == 5

    @pytest.mark.asyncio
    async def test_handle_websocket_connection_batch_detection(self, mock_websocket, mock_detector):
        """Test handling batch detection request."""
        client_id = "test_client"
        
        mock_websocket.receive_json = AsyncMock(side_effect=[
            {
                "type": "batch_detection",
                "request_id": "batch_123",
                "prompts": [
                    {"prompt": "Test 1"},
                    {"prompt": "Test 2"},
                    {"prompt": "Test 3"}
                ]
            },
            Exception("Disconnect")
        ])
        
        with patch('prompt_sentinel.api.websocket.connection_manager') as mock_manager:
            mock_manager.connect = AsyncMock(return_value=True)
            mock_manager.send_json = AsyncMock(return_value=True)
            mock_manager.disconnect = AsyncMock()
            mock_manager.connection_metadata = {client_id: {"messages_processed": 0}}
            
            with patch('prompt_sentinel.api.websocket.StreamingDetector') as mock_sd_class:
                mock_sd = MagicMock()
                mock_sd.process_detection = AsyncMock(return_value={"type": "detection_response"})
                mock_sd_class.return_value = mock_sd
                
                await handle_websocket_connection(mock_websocket, mock_detector, client_id=client_id)
                
                # Should process all 3 prompts
                assert mock_sd.process_detection.call_count == 3
                
                # Check that send_json was called (batch processing sends responses)
                assert mock_manager.send_json.called

    @pytest.mark.asyncio
    async def test_broadcast_system_message(self):
        """Test broadcasting system messages."""
        with patch('prompt_sentinel.api.websocket.connection_manager') as mock_manager:
            mock_manager.broadcast = AsyncMock()
            
            await broadcast_system_message("System maintenance", level="warning")
            
            mock_manager.broadcast.assert_called_once()
            broadcast_data = mock_manager.broadcast.call_args[0][0]
            
            assert broadcast_data["type"] == "system_message"
            assert broadcast_data["level"] == "warning"
            assert broadcast_data["message"] == "System maintenance"
            assert "timestamp" in broadcast_data

    @pytest.mark.asyncio
    async def test_broadcast_system_message_default_level(self):
        """Test broadcasting system message with default level."""
        with patch('prompt_sentinel.api.websocket.connection_manager') as mock_manager:
            mock_manager.broadcast = AsyncMock()
            
            await broadcast_system_message("Info message")
            
            broadcast_data = mock_manager.broadcast.call_args[0][0]
            assert broadcast_data["level"] == "info"