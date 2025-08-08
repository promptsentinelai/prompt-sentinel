/**
 * Custom error classes for PromptSentinel SDK
 */

export class PromptSentinelError extends Error {
  public statusCode?: number;
  public details?: any;

  constructor(message: string, statusCode?: number, details?: any) {
    super(message);
    this.name = 'PromptSentinelError';
    this.statusCode = statusCode;
    this.details = details;
    Object.setPrototypeOf(this, PromptSentinelError.prototype);
  }
}

export class AuthenticationError extends PromptSentinelError {
  constructor(message: string = 'Authentication failed') {
    super(message, 401);
    this.name = 'AuthenticationError';
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

export class RateLimitError extends PromptSentinelError {
  public retryAfter?: number;

  constructor(message: string = 'Rate limit exceeded', retryAfter?: number) {
    super(message, 429);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
    Object.setPrototypeOf(this, RateLimitError.prototype);
  }
}

export class ValidationError extends PromptSentinelError {
  constructor(message: string = 'Validation error') {
    super(message, 422);
    this.name = 'ValidationError';
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

export class ServiceUnavailableError extends PromptSentinelError {
  constructor(message: string = 'Service unavailable') {
    super(message, 503);
    this.name = 'ServiceUnavailableError';
    Object.setPrototypeOf(this, ServiceUnavailableError.prototype);
  }
}