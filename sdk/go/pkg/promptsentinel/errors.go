package promptsentinel

import "fmt"

// PromptSentinelError is the base error type for SDK errors
type PromptSentinelError struct {
	Message    string
	StatusCode int
	Details    interface{}
}

func (e *PromptSentinelError) Error() string {
	return fmt.Sprintf("PromptSentinel error: %s (status: %d)", e.Message, e.StatusCode)
}

// NewPromptSentinelError creates a new PromptSentinelError
func NewPromptSentinelError(message string, statusCode int, details interface{}) *PromptSentinelError {
	return &PromptSentinelError{
		Message:    message,
		StatusCode: statusCode,
		Details:    details,
	}
}

// AuthenticationError represents authentication failures
type AuthenticationError struct {
	*PromptSentinelError
}

// NewAuthenticationError creates a new AuthenticationError
func NewAuthenticationError(message string) *AuthenticationError {
	if message == "" {
		message = "Authentication failed"
	}
	return &AuthenticationError{
		PromptSentinelError: NewPromptSentinelError(message, 401, nil),
	}
}

// RateLimitError represents rate limiting errors
type RateLimitError struct {
	*PromptSentinelError
	RetryAfter *int
}

// NewRateLimitError creates a new RateLimitError
func NewRateLimitError(message string, retryAfter *int) *RateLimitError {
	if message == "" {
		message = "Rate limit exceeded"
	}
	return &RateLimitError{
		PromptSentinelError: NewPromptSentinelError(message, 429, nil),
		RetryAfter:          retryAfter,
	}
}

// ValidationError represents validation errors
type ValidationError struct {
	*PromptSentinelError
}

// NewValidationError creates a new ValidationError
func NewValidationError(message string) *ValidationError {
	if message == "" {
		message = "Validation error"
	}
	return &ValidationError{
		PromptSentinelError: NewPromptSentinelError(message, 422, nil),
	}
}

// ServiceUnavailableError represents service unavailability errors
type ServiceUnavailableError struct {
	*PromptSentinelError
}

// NewServiceUnavailableError creates a new ServiceUnavailableError
func NewServiceUnavailableError(message string) *ServiceUnavailableError {
	if message == "" {
		message = "Service unavailable"
	}
	return &ServiceUnavailableError{
		PromptSentinelError: NewPromptSentinelError(message, 503, nil),
	}
}