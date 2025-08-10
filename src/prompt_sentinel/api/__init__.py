"""API module for PromptSentinel REST endpoints and middleware.

This module contains the API layer for the PromptSentinel service,
including route definitions, middleware, and request/response handling.
All API endpoints are defined in the main module due to the current
application structure.

The API provides a unified interface under /api/v1/* that supports:
- Simple string-based detection for basic use cases
- Advanced detection with role separation and comprehensive analysis
- Intelligent routing based on prompt complexity
- Batch processing and format assistance
"""
