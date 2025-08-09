"""WebSocket support for streaming detection and real-time monitoring."""

import asyncio
import uuid
from datetime import datetime
from typing import Any

import structlog
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState
from pydantic import ValidationError

from prompt_sentinel.detection.detector import PromptDetector
from prompt_sentinel.models.schemas import (
    DetectionResponse,
    Message,
)
from prompt_sentinel.monitoring.usage_tracker import UsageTracker
from prompt_sentinel.routing.router import IntelligentRouter

logger = structlog.get_logger()


class ConnectionManager:
    """Manages WebSocket connections for streaming detection."""

    def __init__(self):
        """Initialize the connection manager."""
        self.active_connections: dict[str, WebSocket] = {}
        self.connection_metadata: dict[str, dict[str, Any]] = {}
        self.message_queues: dict[str, asyncio.Queue] = {}
        self.usage_tracker = UsageTracker()

    async def connect(self, websocket: WebSocket, client_id: str) -> bool:
        """Accept and register a new WebSocket connection.

        Args:
            websocket: The WebSocket connection
            client_id: Unique identifier for the client

        Returns:
            True if connection successful, False otherwise
        """
        try:
            await websocket.accept()
            self.active_connections[client_id] = websocket
            self.message_queues[client_id] = asyncio.Queue()
            self.connection_metadata[client_id] = {
                "connected_at": datetime.utcnow().isoformat(),
                "messages_processed": 0,
                "last_activity": datetime.utcnow().isoformat(),
                "authenticated": False,
                "auth_method": None,
                "rate_limits": {},
            }

            logger.info("WebSocket client connected", client_id=client_id)

            # Send welcome message
            await self.send_json(
                client_id,
                {
                    "type": "connection",
                    "status": "connected",
                    "client_id": client_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "capabilities": [
                        "streaming_detection",
                        "batch_detection",
                        "analysis",
                        "monitoring",
                    ],
                },
            )

            return True

        except Exception as e:
            logger.error("Failed to connect WebSocket client", client_id=client_id, error=str(e))
            return False

    async def disconnect(self, client_id: str):
        """Disconnect and cleanup a WebSocket client.

        Args:
            client_id: Client identifier to disconnect
        """
        if client_id in self.active_connections:
            websocket = self.active_connections[client_id]

            # Close connection if still open
            if websocket.client_state == WebSocketState.CONNECTED:
                await websocket.close()

            # Cleanup
            del self.active_connections[client_id]
            if client_id in self.message_queues:
                del self.message_queues[client_id]
            if client_id in self.connection_metadata:
                del self.connection_metadata[client_id]

            logger.info("WebSocket client disconnected", client_id=client_id)

    async def send_json(self, client_id: str, data: dict) -> bool:
        """Send JSON data to a specific client.

        Args:
            client_id: Target client identifier
            data: Data to send

        Returns:
            True if sent successfully, False otherwise
        """
        if client_id not in self.active_connections:
            return False

        try:
            websocket = self.active_connections[client_id]

            # Check if WebSocket is still connected
            if websocket.client_state != WebSocketState.CONNECTED:
                return False

            await websocket.send_json(data)

            # Update activity timestamp
            if client_id in self.connection_metadata:
                self.connection_metadata[client_id]["last_activity"] = datetime.utcnow().isoformat()

            return True

        except Exception as e:
            logger.error("Failed to send message to client", client_id=client_id, error=str(e))
            await self.disconnect(client_id)
            return False

    async def broadcast(self, data: dict, exclude: set[str] | None = None):
        """Broadcast message to all connected clients.

        Args:
            data: Data to broadcast
            exclude: Set of client IDs to exclude from broadcast
        """
        exclude = exclude or set()
        disconnected = []

        for client_id in self.active_connections:
            if client_id not in exclude:
                success = await self.send_json(client_id, data)
                if not success:
                    disconnected.append(client_id)

        # Clean up disconnected clients
        for client_id in disconnected:
            await self.disconnect(client_id)

    def get_connection_stats(self) -> dict:
        """Get statistics about active connections.

        Returns:
            Connection statistics
        """
        total_messages = sum(
            meta.get("messages_processed", 0) for meta in self.connection_metadata.values()
        )

        return {
            "active_connections": len(self.active_connections),
            "total_messages_processed": total_messages,
            "connections": [
                {
                    "client_id": client_id,
                    "connected_at": meta.get("connected_at"),
                    "messages_processed": meta.get("messages_processed", 0),
                    "last_activity": meta.get("last_activity"),
                }
                for client_id, meta in self.connection_metadata.items()
            ],
        }


class StreamingDetector:
    """Handles streaming detection for WebSocket connections."""

    def __init__(self, detector: PromptDetector, router: IntelligentRouter | None = None):
        """Initialize the streaming detector.

        Args:
            detector: The prompt detector instance
            router: Optional intelligent router for optimized detection
        """
        self.detector = detector
        self.router = router
        self.usage_tracker = UsageTracker()

    async def process_detection(self, request_data: dict, client_id: str) -> dict:
        """Process a detection request from WebSocket.

        Args:
            request_data: The detection request data
            client_id: Client identifier

        Returns:
            Detection response data
        """
        try:
            # Parse request based on type
            if "prompt" in request_data:
                # Simple string detection
                messages = [Message(role="user", content=request_data["prompt"])]
                check_format = False
            elif "messages" in request_data:
                # Structured messages
                messages = [
                    Message(role=msg["role"], content=msg["content"])
                    for msg in request_data["messages"]
                ]
                check_format = request_data.get("check_format", True)
            else:
                raise ValueError("Request must contain either 'prompt' or 'messages'")

            # Determine detection method
            if self.router and request_data.get("use_router", False):
                # Use intelligent routing
                response, routing_decision = await self.router.route_detection(
                    messages=messages, user_id=client_id
                )
            else:
                # Direct detection
                response = await self.detector.detect(messages=messages, check_format=check_format)

            # Track usage
            if hasattr(response, "metadata") and response.metadata:
                providers_used = response.metadata.get("providers_used", [])
                for provider in providers_used:
                    await self.usage_tracker.track_api_call(
                        provider=provider,
                        model="websocket",
                        prompt_tokens=response.metadata.get("prompt_tokens", 0),
                        completion_tokens=response.metadata.get("completion_tokens", 0),
                        latency_ms=response.processing_time_ms or 0,
                        success=True,
                        endpoint="websocket_detection",
                    )

            return {
                "type": "detection_response",
                "request_id": request_data.get("request_id", str(uuid.uuid4())),
                "response": response.model_dump(mode="json"),
                "timestamp": datetime.utcnow().isoformat(),
            }

        except (ValidationError, ValueError) as e:
            return {
                "type": "error",
                "error": "invalid_request",
                "details": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.error("Detection processing error", client_id=client_id, error=str(e))
            return {
                "type": "error",
                "error": "detection_failed",
                "details": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    async def process_analysis(self, request_data: dict, client_id: str) -> dict:
        """Process an analysis request from WebSocket.

        Args:
            request_data: The analysis request data
            client_id: Client identifier

        Returns:
            Analysis response data
        """
        try:
            # Extract messages from request
            messages = []
            if "messages" in request_data:
                for msg in request_data["messages"]:
                    messages.append(Message(role=msg["role"], content=msg["content"]))

            # Perform detection
            detection_response = await self.detector.detect(messages=messages, check_format=True)

            # Build analysis response
            analysis_result = {
                "verdict": detection_response.verdict,
                "confidence": detection_response.confidence,
                "reasons": [reason.model_dump() for reason in detection_response.reasons],
                "processing_time_ms": detection_response.processing_time_ms,
                "metadata": detection_response.metadata or {},
                "overall_risk_assessment": {
                    "threat_level": self._calculate_threat_level(detection_response),
                    "confidence_breakdown": self._get_confidence_breakdown(detection_response),
                    "mitigation_suggestions": self._get_mitigation_suggestions(detection_response),
                },
                "overall_risk_score": detection_response.confidence,
                "recommendations": self._get_mitigation_suggestions(detection_response),
            }

            return {
                "type": "analysis_result",
                "request_id": request_data.get("request_id", str(uuid.uuid4())),
                **analysis_result,
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error("Analysis processing error", client_id=client_id, error=str(e))
            return {
                "type": "error",
                "error": "analysis_failed",
                "details": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    def _calculate_threat_level(self, response: DetectionResponse) -> str:
        """Calculate threat level from detection response."""
        from prompt_sentinel.models.schemas import Verdict

        if response.verdict == Verdict.BLOCK:
            return "high"
        elif response.verdict == Verdict.STRIP:
            return "medium"
        elif response.verdict == Verdict.FLAG:
            return "low"
        else:
            return "none"

    def _get_confidence_breakdown(self, response: DetectionResponse) -> dict:
        """Get confidence breakdown by detection method."""
        breakdown = {"overall": response.confidence}

        source_confidences = {}
        if response.reasons:
            for reason in response.reasons:
                source = reason.source
                if source not in source_confidences:
                    source_confidences[source] = []
                source_confidences[source].append(reason.confidence)

        # Calculate average confidence per source
        for source, confidences in source_confidences.items():
            breakdown[source] = sum(confidences) / len(confidences) if confidences else 0.0

        return breakdown

    def _get_mitigation_suggestions(self, response: DetectionResponse) -> list:
        """Get mitigation suggestions based on detection results."""
        from prompt_sentinel.models.schemas import DetectionCategory

        suggestions = []

        # Check categories in reasons
        reason_categories = (
            [reason.category for reason in response.reasons] if response.reasons else []
        )

        if DetectionCategory.DIRECT_INJECTION in reason_categories:
            suggestions.append("Use strict role separation between system and user messages")
        if DetectionCategory.JAILBREAK in reason_categories:
            suggestions.append("Implement additional context validation")
        if DetectionCategory.PII_DETECTED in reason_categories:
            suggestions.append("Enable automatic PII redaction before processing")

        if not suggestions:
            suggestions.append("Consider reviewing prompt content for security best practices")

        return suggestions


# Global connection manager instance
connection_manager = ConnectionManager()


async def handle_websocket_connection(
    websocket: WebSocket,
    detector: PromptDetector,
    router: IntelligentRouter | None = None,
    client: Any | None = None,
    client_id: str | None = None,
):
    """Handle a WebSocket connection for streaming detection.

    Args:
        websocket: The WebSocket connection
        detector: Prompt detector instance
        router: Optional intelligent router
        client: Optional authenticated client object
        client_id: Optional client identifier
    """
    # Use provided client_id or generate one
    if not client_id:
        client_id = str(uuid.uuid4())
    streaming_detector = StreamingDetector(detector, router)

    # Connect client
    connected = await connection_manager.connect(websocket, client_id)
    if not connected:
        return

    # Update connection metadata with auth info if available
    if client:
        connection_manager.connection_metadata[client_id].update(
            {
                "authenticated": (
                    client.is_authenticated if hasattr(client, "is_authenticated") else False
                ),
                "auth_method": client.auth_method.value if hasattr(client, "auth_method") else None,
                "rate_limits": client.rate_limits if hasattr(client, "rate_limits") else {},
            }
        )

    try:
        while True:
            # Receive message
            data = await websocket.receive_json()

            # Update message count
            if client_id in connection_manager.connection_metadata:
                connection_manager.connection_metadata[client_id]["messages_processed"] += 1

            # Process based on message type
            message_type = data.get("type", "detection")

            if message_type == "ping":
                # Heartbeat
                await connection_manager.send_json(
                    client_id, {"type": "pong", "timestamp": datetime.utcnow().isoformat()}
                )

            elif message_type == "detection":
                # Process detection request
                response = await streaming_detector.process_detection(data, client_id)
                await connection_manager.send_json(client_id, response)

            elif message_type == "analysis":
                # Process analysis request
                response = await streaming_detector.process_analysis(data, client_id)
                await connection_manager.send_json(client_id, response)

            elif message_type == "batch_detection":
                # Process batch detection
                prompts = data.get("prompts", [])
                results = []

                for prompt_data in prompts:
                    result = await streaming_detector.process_detection(prompt_data, client_id)
                    results.append(result)

                await connection_manager.send_json(
                    client_id,
                    {
                        "type": "batch_detection_response",
                        "request_id": data.get("request_id", str(uuid.uuid4())),
                        "results": results,
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                )

            elif message_type == "stats":
                # Get connection statistics
                stats = connection_manager.get_connection_stats()
                await connection_manager.send_json(
                    client_id,
                    {
                        "type": "stats_response",
                        "stats": stats,
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                )

            else:
                # Unknown message type
                await connection_manager.send_json(
                    client_id,
                    {
                        "type": "error",
                        "error": "unknown_message_type",
                        "details": f"Unknown message type: {message_type}",
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                )

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected normally", client_id=client_id)
    except Exception as e:
        logger.error("WebSocket error", client_id=client_id, error=str(e))
    finally:
        await connection_manager.disconnect(client_id)


async def broadcast_system_message(message: str, level: str = "info"):
    """Broadcast a system message to all connected clients.

    Args:
        message: The message to broadcast
        level: Message level (info, warning, error)
    """
    await connection_manager.broadcast(
        {
            "type": "system_message",
            "level": level,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
        }
    )
