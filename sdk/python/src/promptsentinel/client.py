"""PromptSentinel client implementation."""

import os
from typing import Any
from urllib.parse import urljoin

import httpx

from .models import (
    AuthenticationError,
    BatchDetectionResponse,
    BudgetStatus,
    ComplexityAnalysis,
    DetectionMode,
    DetectionResponse,
    HealthStatus,
    Message,
    PromptSentinelError,
    RateLimitError,
    Role,
    ServiceUnavailableError,
    UsageMetrics,
    ValidationError,
)
from .version import __version__


class BaseClient:
    """Base client with common functionality."""

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        """
        Initialize the PromptSentinel client.

        Args:
            base_url: Base URL of PromptSentinel API
            api_key: API key for authentication (if required)
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.getenv("PROMPTSENTINEL_API_KEY")
        self.timeout = timeout
        self.max_retries = max_retries

        # Set up headers
        self.headers = {
            "User-Agent": f"PromptSentinel-Python-SDK/{__version__}",
            "Content-Type": "application/json",
        }
        if self.api_key:
            self.headers["X-API-Key"] = self.api_key

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        """Handle API response and errors."""
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400:
            raise ValidationError(f"Bad request: {response.text}")
        elif response.status_code == 401:
            raise AuthenticationError("Authentication failed. Check your API key.")
        elif response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                "Rate limit exceeded", retry_after=int(retry_after) if retry_after else None
            )
        elif response.status_code == 503:
            raise ServiceUnavailableError("Service temporarily unavailable")
        else:
            raise PromptSentinelError(f"Unexpected error: {response.status_code} - {response.text}")


class PromptSentinel(BaseClient):
    """Synchronous PromptSentinel client."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client = httpx.Client(
            timeout=self.timeout,
            headers=self.headers,
        )

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        """Close the HTTP client."""
        self.client.close()

    def detect(
        self,
        prompt: str | None = None,
        messages: list[Message] | None = None,
        check_format: bool = True,
        use_cache: bool = True,
        detection_mode: DetectionMode | None = None,
        use_intelligent_routing: bool = False,
    ) -> DetectionResponse:
        """
        Detect prompt injection in text or messages.

        Args:
            prompt: Simple text prompt (for v1 API)
            messages: List of messages with roles (for v2/v3 API)
            check_format: Whether to check format security
            use_cache: Whether to use cached results
            detection_mode: Override default detection mode
            use_intelligent_routing: Use intelligent routing based on prompt complexity

        Returns:
            DetectionResponse with verdict and details
        """
        if prompt and messages:
            raise ValueError("Provide either 'prompt' or 'messages', not both")

        if not prompt and not messages:
            raise ValueError("Either 'prompt' or 'messages' is required")

        # Determine endpoint and prepare request
        if prompt:
            # Use unified API
            endpoint = "/api/v1/detect"
            data = {"prompt": prompt}
        else:
            # Use unified API with optional intelligent routing
            endpoint = "/api/v1/detect/intelligent" if use_intelligent_routing else "/api/v1/detect"
            data = {
                "messages": [msg.model_dump() for msg in messages],
                "check_format": check_format,
                "use_cache": use_cache,
            }
            if detection_mode:
                data["detection_mode"] = detection_mode.value

        # Make request
        url = urljoin(self.base_url, endpoint)
        response = self.client.post(url, json=data)
        result = self._handle_response(response)

        return DetectionResponse(**result)

    def detect_simple(self, prompt: str) -> DetectionResponse:
        """Simple detection for a text prompt."""
        return self.detect(prompt=prompt)

    def detect_messages(self, messages: list[Message], **kwargs) -> DetectionResponse:
        """Detect with role-separated messages."""
        return self.detect(messages=messages, **kwargs)

    def batch_detect(self, prompts: list[dict[str, str]]) -> BatchDetectionResponse:
        """
        Process multiple prompts in batch.

        Args:
            prompts: List of dicts with 'id' and 'prompt' keys

        Returns:
            BatchDetectionResponse with results for each prompt
        """
        url = urljoin(self.base_url, "/api/v1/batch")
        response = self.client.post(url, json={"prompts": prompts})
        result = self._handle_response(response)
        return BatchDetectionResponse(**result)

    def analyze_complexity(
        self, prompt: str | None = None, messages: list[Message] | None = None
    ) -> ComplexityAnalysis:
        """
        Analyze prompt complexity without detection.

        Args:
            prompt: Text prompt to analyze
            messages: Messages to analyze

        Returns:
            ComplexityAnalysis with metrics and risk indicators
        """
        url = urljoin(self.base_url, "/api/v1/metrics/complexity")
        params = {}

        if prompt:
            params["prompt"] = prompt
        elif messages:
            # Convert messages to string for analysis
            text = "\n".join([f"{msg.role}: {msg.content}" for msg in messages])
            params["prompt"] = text

        response = self.client.get(url, params=params)
        result = self._handle_response(response)
        return ComplexityAnalysis(**result)

    def get_usage(self, time_window_hours: int = 24) -> UsageMetrics:
        """
        Get API usage metrics.

        Args:
            time_window_hours: Time window for metrics

        Returns:
            UsageMetrics with usage statistics
        """
        url = urljoin(self.base_url, "/api/v1/monitoring/usage")
        response = self.client.get(url, params={"time_window_hours": time_window_hours})
        result = self._handle_response(response)
        return UsageMetrics(**result)

    def get_budget_status(self) -> BudgetStatus:
        """Get current budget status and alerts."""
        url = urljoin(self.base_url, "/api/v1/monitoring/budget")
        response = self.client.get(url)
        result = self._handle_response(response)
        return BudgetStatus(**result)

    def health_check(self) -> HealthStatus:
        """Check service health status."""
        url = urljoin(self.base_url, "/api/v1/health")
        response = self.client.get(url)
        result = self._handle_response(response)
        return HealthStatus(**result)

    # Convenience methods
    def create_message(self, role: str | Role, content: str) -> Message:
        """Create a message object."""
        if isinstance(role, str):
            role = Role(role)
        return Message(role=role, content=content)

    def create_conversation(
        self, system_prompt: str | None = None, user_prompt: str = None
    ) -> list[Message]:
        """Create a conversation with system and user messages."""
        messages = []
        if system_prompt:
            messages.append(self.create_message(Role.SYSTEM, system_prompt))
        if user_prompt:
            messages.append(self.create_message(Role.USER, user_prompt))
        return messages


class AsyncPromptSentinel(BaseClient):
    """Asynchronous PromptSentinel client."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            headers=self.headers,
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()

    async def detect(
        self,
        prompt: str | None = None,
        messages: list[Message] | None = None,
        check_format: bool = True,
        use_cache: bool = True,
        detection_mode: DetectionMode | None = None,
        use_intelligent_routing: bool = False,
    ) -> DetectionResponse:
        """
        Detect prompt injection in text or messages (async).

        Args:
            prompt: Simple text prompt (for v1 API)
            messages: List of messages with roles (for v2/v3 API)
            check_format: Whether to check format security
            use_cache: Whether to use cached results
            detection_mode: Override default detection mode
            use_intelligent_routing: Use intelligent routing based on prompt complexity

        Returns:
            DetectionResponse with verdict and details
        """
        if prompt and messages:
            raise ValueError("Provide either 'prompt' or 'messages', not both")

        if not prompt and not messages:
            raise ValueError("Either 'prompt' or 'messages' is required")

        # Determine endpoint and prepare request
        if prompt:
            endpoint = "/v1/detect"
            data = {"prompt": prompt}
        else:
            endpoint = "/v3/detect" if use_intelligent_routing else "/v2/detect"
            data = {
                "messages": [msg.model_dump() for msg in messages],
                "check_format": check_format,
                "use_cache": use_cache,
            }
            if detection_mode:
                data["detection_mode"] = detection_mode.value

        # Make request
        url = urljoin(self.base_url, endpoint)
        response = await self.client.post(url, json=data)
        result = self._handle_response(response)

        return DetectionResponse(**result)

    async def detect_simple(self, prompt: str) -> DetectionResponse:
        """Simple detection for a text prompt (async)."""
        return await self.detect(prompt=prompt)

    async def detect_messages(self, messages: list[Message], **kwargs) -> DetectionResponse:
        """Detect with role-separated messages (async)."""
        return await self.detect(messages=messages, **kwargs)

    async def batch_detect(self, prompts: list[dict[str, str]]) -> BatchDetectionResponse:
        """Process multiple prompts in batch (async)."""
        url = urljoin(self.base_url, "/api/v1/batch")
        response = await self.client.post(url, json={"prompts": prompts})
        result = self._handle_response(response)
        return BatchDetectionResponse(**result)

    async def analyze_complexity(
        self, prompt: str | None = None, messages: list[Message] | None = None
    ) -> ComplexityAnalysis:
        """Analyze prompt complexity without detection (async)."""
        url = urljoin(self.base_url, "/api/v1/metrics/complexity")
        params = {}

        if prompt:
            params["prompt"] = prompt
        elif messages:
            text = "\n".join([f"{msg.role}: {msg.content}" for msg in messages])
            params["prompt"] = text

        response = await self.client.get(url, params=params)
        result = self._handle_response(response)
        return ComplexityAnalysis(**result)

    async def get_usage(self, time_window_hours: int = 24) -> UsageMetrics:
        """Get API usage metrics (async)."""
        url = urljoin(self.base_url, "/api/v1/monitoring/usage")
        response = await self.client.get(url, params={"time_window_hours": time_window_hours})
        result = self._handle_response(response)
        return UsageMetrics(**result)

    async def get_budget_status(self) -> BudgetStatus:
        """Get current budget status and alerts (async)."""
        url = urljoin(self.base_url, "/api/v1/monitoring/budget")
        response = await self.client.get(url)
        result = self._handle_response(response)
        return BudgetStatus(**result)

    async def health_check(self) -> HealthStatus:
        """Check service health status (async)."""
        url = urljoin(self.base_url, "/api/v1/health")
        response = await self.client.get(url)
        result = self._handle_response(response)
        return HealthStatus(**result)

    # Convenience methods (same as sync)
    def create_message(self, role: str | Role, content: str) -> Message:
        """Create a message object."""
        if isinstance(role, str):
            role = Role(role)
        return Message(role=role, content=content)

    def create_conversation(
        self, system_prompt: str | None = None, user_prompt: str = None
    ) -> list[Message]:
        """Create a conversation with system and user messages."""
        messages = []
        if system_prompt:
            messages.append(self.create_message(Role.SYSTEM, system_prompt))
        if user_prompt:
            messages.append(self.create_message(Role.USER, user_prompt))
        return messages
