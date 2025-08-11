package promptsentinel

import "fmt"

// PromptSentinelError is the base error type for all SDK errors.
// It provides a consistent error structure with message, HTTP status code,
// and optional additional details for debugging.
type PromptSentinelError struct {
	Message    string
	StatusCode int
	Details    interface{}
}

func (e *PromptSentinelError) Error() string {
	return fmt.Sprintf("PromptSentinel error: %s (status: %d)", e.Message, e.StatusCode)
}

// NewPromptSentinelError creates a new base error with message, status code, and details.
// This is typically used internally; prefer using specific error types like
// AuthenticationError or ValidationError for better error handling.
func NewPromptSentinelError(message string, statusCode int, details interface{}) *PromptSentinelError {
	return &PromptSentinelError{
		Message:    message,
		StatusCode: statusCode,
		Details:    details,
	}
}

// AuthenticationError indicates API key validation failed or is missing.
// Check that your API key is correct and properly configured.
//
// Common causes:
//   - Invalid or expired API key
//   - Missing API key when authentication is required
//   - Incorrect API key format (should start with 'psk_')
type AuthenticationError struct {
	*PromptSentinelError
}

// NewAuthenticationError creates an authentication error with optional message.
// If no message is provided, uses a default "Authentication failed" message.
func NewAuthenticationError(message string) *AuthenticationError {
	if message == "" {
		message = "Authentication failed"
	}
	return &AuthenticationError{
		PromptSentinelError: NewPromptSentinelError(message, 401, nil),
	}
}

// RateLimitError indicates API rate limits have been exceeded.
// The RetryAfter field indicates how many seconds to wait before retrying.
//
// Example handling:
//
//	if err, ok := err.(*RateLimitError); ok {
//		if err.RetryAfter != nil {
//			time.Sleep(time.Duration(*err.RetryAfter) * time.Second)
//			// Retry the request
//		}
//	}
type RateLimitError struct {
	*PromptSentinelError
	RetryAfter *int
}

// NewRateLimitError creates a rate limit error with optional retry-after duration.
// The retryAfter parameter specifies seconds to wait before retrying.
func NewRateLimitError(message string, retryAfter *int) *RateLimitError {
	if message == "" {
		message = "Rate limit exceeded"
	}
	return &RateLimitError{
		PromptSentinelError: NewPromptSentinelError(message, 429, nil),
		RetryAfter:          retryAfter,
	}
}

// ValidationError indicates the request failed validation checks.
// This typically means invalid parameters, missing required fields,
// or incorrectly formatted data.
//
// Common causes:
//   - Missing both prompt and messages in detection request
//   - Invalid detection mode value
//   - Malformed message structure
type ValidationError struct {
	*PromptSentinelError
}

// NewValidationError creates a validation error with descriptive message.
// The message should indicate which validation rule was violated.
func NewValidationError(message string) *ValidationError {
	if message == "" {
		message = "Validation error"
	}
	return &ValidationError{
		PromptSentinelError: NewPromptSentinelError(message, 422, nil),
	}
}

// ServiceUnavailableError indicates the PromptSentinel service is temporarily unavailable.
// This may occur during maintenance, high load, or dependency failures.
//
// Recommended handling:
//   - Implement exponential backoff retry logic
//   - Fall back to cache-only mode if available
//   - Queue requests for later processing
type ServiceUnavailableError struct {
	*PromptSentinelError
}

// NewServiceUnavailableError creates a service unavailability error.
// Typically includes information about the cause of unavailability.
func NewServiceUnavailableError(message string) *ServiceUnavailableError {
	if message == "" {
		message = "Service unavailable"
	}
	return &ServiceUnavailableError{
		PromptSentinelError: NewPromptSentinelError(message, 503, nil),
	}
}