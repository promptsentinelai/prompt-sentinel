# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Structured logging for observability."""

import asyncio
import time
from typing import Any


class StructuredLogger:
    """Structured logging with context propagation."""

    def __init__(self, name: str = "prompt_sentinel"):
        """Initialize structured logger."""
        self.name = name
        self.context: dict[str, Any] = {}
        self.logs: list[dict[str, Any]] = []

    def log(self, level: str, message: str, **kwargs) -> None:
        """Log a structured message."""
        log_entry = {
            "timestamp": time.time(),
            "level": level,
            "logger": self.name,
            "message": message,
            "context": self.context.copy(),
            **kwargs,
        }
        self.logs.append(log_entry)
        # In production, would write to actual log output

    def info(self, message: str, **kwargs) -> None:
        """Log info message."""
        self.log("INFO", message, **kwargs)

    def error(self, message: str, **kwargs) -> None:
        """Log error message."""
        self.log("ERROR", message, **kwargs)

    def warning(self, message: str, **kwargs) -> None:
        """Log warning message."""
        self.log("WARNING", message, **kwargs)

    def debug(self, message: str, **kwargs) -> None:
        """Log debug message."""
        self.log("DEBUG", message, **kwargs)

    def with_context(self, **kwargs) -> "StructuredLogger":
        """Create logger with additional context."""
        new_logger = StructuredLogger(self.name)
        new_logger.context = {**self.context, **kwargs}
        new_logger.logs = self.logs
        return new_logger

    def get_logs(self) -> list[dict[str, Any]]:
        """Get all logged messages."""
        return self.logs

    async def flush(self) -> None:
        """Flush logs to output."""
        await asyncio.sleep(0.001)  # Stub flush
