# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""OWASP-compliant input validation middleware."""

import re
from typing import Any

import structlog
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.base import BaseHTTPMiddleware

logger = structlog.get_logger()


class SecurityValidationMiddleware(BaseHTTPMiddleware):
    """OWASP-compliant input validation middleware."""

    async def dispatch(self, request: Request, call_next):
        """Validate incoming requests for security."""
        if request.scope["type"] == "http":
            try:
                # 1. Size validation (OWASP recommendation)
                if "content-length" in request.headers:
                    content_length = int(request.headers["content-length"])
                    if content_length > 10_000_000:  # 10MB limit
                        logger.warning(
                            "Request too large",
                            content_length=content_length,
                            path=request.url.path,
                        )
                        raise HTTPException(status_code=413, detail="Request too large")

                # 2. Content-Type validation
                if request.method in ["POST", "PUT", "PATCH"]:
                    content_type = request.headers.get("content-type", "")
                    if not content_type.startswith(
                        (
                            "application/json",
                            "application/x-www-form-urlencoded",
                            "multipart/form-data",
                        )
                    ):
                        logger.warning(
                            "Unsupported media type",
                            content_type=content_type,
                            path=request.url.path,
                        )
                        raise HTTPException(status_code=415, detail="Unsupported media type")

                # 3. Header validation
                for header, value in request.headers.items():
                    if len(header) > 256 or len(value) > 4096:
                        logger.warning("Header too long", header=header[:50], length=len(value))
                        raise HTTPException(status_code=400, detail="Header too long")

                    # Check for suspicious patterns in headers
                    if re.search(r'[<>"\'\x00-\x1f\x7f-\x9f]', value):
                        # Skip known safe headers with special chars
                        if header.lower() not in ["user-agent", "referer", "cookie"]:
                            logger.warning("Invalid characters in header", header=header)
                            raise HTTPException(
                                status_code=400, detail="Invalid characters in header"
                            )

                # 4. Path validation
                path = str(request.url.path)
                # Check for path traversal attempts
                if ".." in path or "//" in path:
                    logger.warning("Path traversal attempt", path=path)
                    raise HTTPException(status_code=400, detail="Invalid path")

                # Check for suspicious file extensions
                suspicious_extensions = [".env", ".git", ".bak", ".config", ".sql", ".db"]
                if any(path.endswith(ext) for ext in suspicious_extensions):
                    logger.warning("Suspicious file access attempt", path=path)
                    raise HTTPException(status_code=403, detail="Access denied")

            except HTTPException:
                raise
            except Exception as e:
                logger.error("Validation middleware error", error=str(e))
                # Allow request to proceed on unexpected errors

        response = await call_next(request)
        return response


class EnhancedPromptRequest(BaseModel):
    """Enhanced prompt request with OWASP validation."""

    prompt: str = Field(..., min_length=1, max_length=50000, description="Input prompt to analyze")
    detection_mode: str | None = Field(
        default="moderate",
        pattern="^(strict|moderate|permissive)$",
        description="Detection sensitivity mode",
    )
    include_pii_detection: bool | None = Field(
        default=True, description="Include PII detection in analysis"
    )

    @field_validator("prompt")
    @classmethod
    def validate_prompt_content(cls, v: str) -> str:
        """Validate prompt content for security issues."""
        # 1. Character encoding validation
        try:
            v.encode("utf-8")
        except UnicodeEncodeError as e:
            raise ValueError(f"Invalid character encoding: {e}") from e

        # 2. Control character check (except newlines and tabs)
        if re.search(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]", v):
            raise ValueError("Control characters not allowed")

        # 3. Check for extremely long lines (potential DoS)
        lines = v.split("\n")
        if any(len(line) > 10000 for line in lines):
            raise ValueError("Individual lines too long (max 10000 chars per line)")

        # 4. SQL injection patterns (basic check - not for blocking SQL, but obvious attacks)
        dangerous_sql_patterns = [
            r"(\bEXEC\b.*\bxp_cmdshell\b)",  # SQL Server command execution
            r"(\bINTO\b.*\bOUTFILE\b)",  # MySQL file write
            r"(\bLOAD_FILE\b.*\()",  # MySQL file read
            r"(;\s*DROP\s+DATABASE\b)",  # Database drop
        ]
        for pattern in dangerous_sql_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                logger.warning("Potentially dangerous SQL pattern detected", pattern=pattern[:50])
                # Don't block - this is a security service that might analyze SQL
                # Just log for monitoring

        # 5. Script injection check (for prompts that might be displayed)
        script_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:\s*[^\"'\s]+",
            r"on\w+\s*=\s*[\"'][^\"']+[\"']",  # Event handlers
        ]
        for pattern in script_patterns:
            if re.search(pattern, v, re.IGNORECASE | re.DOTALL):
                # Log but don't block - we're analyzing potentially malicious content
                logger.info("Script pattern detected in prompt", pattern=pattern[:30])

        return v

    @field_validator("detection_mode")
    @classmethod
    def validate_detection_mode(cls, v: str | None) -> str:
        """Validate detection mode."""
        if v and v not in ["strict", "moderate", "permissive"]:
            raise ValueError("Invalid detection mode")
        return v or "moderate"


class BatchPromptRequest(BaseModel):
    """Batch prompt request with validation."""

    prompts: list[str] = Field(
        ...,
        min_items=1,
        max_items=100,
        description="List of prompts to analyze",
    )
    detection_mode: str | None = Field(
        default="moderate",
        pattern="^(strict|moderate|permissive)$",
        description="Detection sensitivity mode",
    )

    @field_validator("prompts")
    @classmethod
    def validate_prompts(cls, v: list[str]) -> list[str]:
        """Validate all prompts in batch."""
        if len(v) > 100:
            raise ValueError("Too many prompts (max 100)")

        total_length = sum(len(prompt) for prompt in v)
        if total_length > 500000:  # 500KB total limit
            raise ValueError("Total batch size too large")

        # Validate each prompt
        for i, prompt in enumerate(v):
            if len(prompt) > 50000:
                raise ValueError(f"Prompt {i} too long (max 50000 chars)")

            # Basic encoding check
            try:
                prompt.encode("utf-8")
            except UnicodeEncodeError as e:
                raise ValueError(f"Prompt {i} has invalid encoding") from e

        return v


def sanitize_output(value: Any) -> Any:
    """Sanitize output values to prevent injection."""
    if isinstance(value, str):
        # Remove null bytes and control characters
        value = re.sub(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]", "", value)

        # Escape HTML entities if needed
        # This is conservative - only for values that might be rendered
        if "<" in value or ">" in value:
            value = value.replace("<", "&lt;").replace(">", "&gt;")

    elif isinstance(value, dict):
        return {k: sanitize_output(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [sanitize_output(item) for item in value]

    return value
