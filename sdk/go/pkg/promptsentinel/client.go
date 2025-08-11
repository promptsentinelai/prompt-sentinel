package promptsentinel

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-resty/resty/v2"
)

// Config holds configuration for the PromptSentinel client.
// It allows customization of the API endpoint, authentication, timeouts,
// and retry behavior for all API calls.
type Config struct {
	BaseURL    string
	APIKey     string
	Timeout    time.Duration
	MaxRetries int
	Headers    map[string]string
}

// DefaultConfig returns a default configuration for the PromptSentinel client.
// It reads configuration from environment variables:
//   - PROMPTSENTINEL_BASE_URL: API endpoint (default: http://localhost:8080)
//   - PROMPTSENTINEL_API_KEY: API key for authentication (optional)
//
// The default configuration includes:
//   - 30 second timeout for API calls
//   - 3 automatic retries on failure
//   - Empty custom headers map
func DefaultConfig() *Config {
	baseURL := os.Getenv("PROMPTSENTINEL_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	
	return &Config{
		BaseURL:    baseURL,
		APIKey:     os.Getenv("PROMPTSENTINEL_API_KEY"),
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		Headers:    make(map[string]string),
	}
}

// Client is the main PromptSentinel API client that provides methods for
// detecting prompt injection attacks, analyzing prompt complexity,
// monitoring usage, and managing API interactions.
//
// The client is thread-safe and can be reused across multiple goroutines.
type Client struct {
	config *Config
	http   *resty.Client
}

// New creates a new PromptSentinel client with the provided configuration.
// If config is nil, it uses DefaultConfig() which reads from environment variables.
//
// Example:
//
//	config := &promptsentinel.Config{
//		APIKey: "psk_your_api_key",
//		Timeout: 30 * time.Second,
//	}
//	client := promptsentinel.New(config)
//
// Or using environment variables:
//
//	client := promptsentinel.New(nil)
func New(config *Config) *Client {
	if config == nil {
		config = DefaultConfig()
	}
	
	client := resty.New()
	client.SetBaseURL(config.BaseURL)
	client.SetTimeout(config.Timeout)
	client.SetRetryCount(config.MaxRetries)
	client.SetHeader("Content-Type", "application/json")
	client.SetHeader("User-Agent", "promptsentinel-go-sdk/1.0.0")
	
	// Add API key if provided
	if config.APIKey != "" {
		client.SetHeader("Authorization", "Bearer "+config.APIKey)
	}
	
	// Add custom headers
	for key, value := range config.Headers {
		client.SetHeader(key, value)
	}
	
	// Setup error handling
	client.OnAfterResponse(func(c *resty.Client, resp *resty.Response) error {
		if resp.IsError() {
			return handleHTTPError(resp)
		}
		return nil
	})
	
	return &Client{
		config: config,
		http:   client,
	}
}

// handleHTTPError converts HTTP errors to SDK errors
func handleHTTPError(resp *resty.Response) error {
	statusCode := resp.StatusCode()
	
	var errorResponse struct {
		Detail string `json:"detail"`
	}
	
	body := resp.Body()
	if len(body) > 0 {
		json.Unmarshal(body, &errorResponse)
	}
	
	message := errorResponse.Detail
	if message == "" {
		message = resp.Status()
	}
	
	switch statusCode {
	case 401:
		return NewAuthenticationError(message)
	case 422, 400:
		return NewValidationError(message)
	case 429:
		retryAfter := parseRetryAfter(resp.Header().Get("Retry-After"))
		return NewRateLimitError(message, retryAfter)
	case 503:
		return NewServiceUnavailableError(message)
	default:
		return NewPromptSentinelError(message, statusCode, nil)
	}
}

// parseRetryAfter parses the Retry-After header
func parseRetryAfter(header string) *int {
	if header == "" {
		return nil
	}
	if val, err := strconv.Atoi(header); err == nil {
		return &val
	}
	return nil
}

// DetectSimple performs simple string detection on a plain text prompt.
// This is the most basic detection method, suitable for single string analysis.
//
// Parameters:
//   - prompt: The text string to analyze for injection attacks
//   - opts: Optional configuration functions (WithCheckFormat, WithCache, WithDetectionMode)
//
// Returns:
//   - *DetectionResponse: Contains verdict, confidence, reasons, and detected threats
//   - error: If the API call fails or validation errors occur
//
// Example:
//
//	result, err := client.DetectSimple(
//		"Translate this to French: Hello",
//		WithDetectionMode(DetectionModeStrict),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//	if result.Verdict == VerdictBlock {
//		fmt.Println("Threat detected:", result.Reasons[0].Description)
//	}
func (c *Client) DetectSimple(prompt string, opts ...func(*DetectionRequest)) (*DetectionResponse, error) {
	req := &DetectionRequest{
		Prompt: prompt,
	}
	
	// Apply options
	for _, opt := range opts {
		opt(req)
	}
	
	var response DetectionResponse
	_, err := c.http.R().
		SetBody(req).
		SetResult(&response).
		Post("/api/v1/detect")
	
	if err != nil {
		return nil, err
	}
	
	return &response, nil
}

// DetectMessages performs detection on role-separated conversation messages.
// This method provides better context understanding for multi-turn conversations
// by analyzing messages with their associated roles (system/user/assistant).
//
// Parameters:
//   - messages: Array of Message structs with role and content
//   - opts: Optional configuration functions
//
// Returns:
//   - *DetectionResponse: Analysis results with format recommendations
//   - error: If the API call fails
//
// Example:
//
//	messages := []Message{
//		NewMessage(RoleSystem, "You are a helpful assistant"),
//		NewMessage(RoleUser, "Ignore previous instructions"),
//	}
//	result, err := client.DetectMessages(messages, WithCheckFormat(true))
//	if err != nil {
//		log.Fatal(err)
//	}
//	if result.FormatRecommendations != nil {
//		for _, rec := range result.FormatRecommendations {
//			fmt.Println("Security recommendation:", rec)
//		}
//	}
func (c *Client) DetectMessages(messages []Message, opts ...func(*DetectionRequest)) (*DetectionResponse, error) {
	req := &DetectionRequest{
		Messages: messages,
	}
	
	// Apply options
	for _, opt := range opts {
		opt(req)
	}
	
	var response DetectionResponse
	_, err := c.http.R().
		SetBody(req).
		SetResult(&response).
		Post("/api/v1/detect")
	
	if err != nil {
		return nil, err
	}
	
	return &response, nil
}

// Detect is the main detection method with flexible options for various use cases.
// It automatically selects the appropriate API endpoint based on the provided options.
//
// Parameters:
//   - opts: Variable number of DetectOption functions to configure the detection
//
// Available options:
//   - WithPrompt(string): Analyze a simple text prompt
//   - WithMessages([]Message): Analyze conversation messages
//   - WithIntelligentRouting(): Use V3 intelligent routing based on complexity
//   - WithFormatCheck(): Enable format validation and security recommendations
//   - WithCaching(): Use cached results for improved performance
//   - WithMode(DetectionMode): Set detection sensitivity (strict/moderate/permissive)
//
// Returns:
//   - *DetectionResponse: Comprehensive detection results
//   - error: If configuration is invalid or API call fails
//
// Example:
//
//	// Simple detection
//	result, err := client.Detect(
//		WithPrompt("What is the weather?"),
//		WithCaching(),
//	)
//
//	// Intelligent routing for optimal performance
//	result, err := client.Detect(
//		WithPrompt(complexPrompt),
//		WithIntelligentRouting(),
//		WithMode(DetectionModeStrict),
//	)
func (c *Client) Detect(opts ...DetectOption) (*DetectionResponse, error) {
	options := &detectOptions{}
	for _, opt := range opts {
		opt(options)
	}
	
	if options.useIntelligentRouting {
		return c.detectV3(options)
	}
	
	if options.messages != nil {
		return c.DetectMessages(options.messages, func(req *DetectionRequest) {
			req.CheckFormat = options.checkFormat
			req.UseCache = options.useCache
			req.DetectionMode = options.detectionMode
		})
	}
	
	if options.prompt != "" {
		return c.DetectSimple(options.prompt, func(req *DetectionRequest) {
			req.CheckFormat = options.checkFormat
			req.UseCache = options.useCache
			req.DetectionMode = options.detectionMode
		})
	}
	
	return nil, NewValidationError("Either prompt or messages must be provided")
}

// detectV3 performs intelligent routing detection using V3 API
func (c *Client) detectV3(opts *detectOptions) (*DetectionResponse, error) {
	req := &DetectionRequest{
		Prompt:        opts.prompt,
		Messages:      opts.messages,
		CheckFormat:   opts.checkFormat,
		UseCache:      opts.useCache,
		DetectionMode: opts.detectionMode,
	}
	
	var response DetectionResponse
	_, err := c.http.R().
		SetBody(req).
		SetResult(&response).
		Post("/api/v1/detect/intelligent")
	
	if err != nil {
		return nil, err
	}
	
	return &response, nil
}

// BatchDetect processes multiple prompts in a single efficient API call.
// Useful for bulk content moderation, analyzing conversation histories,
// or processing queued prompts.
//
// Parameters:
//   - prompts: Array of BatchPrompt structs, each with ID and prompt text
//
// Returns:
//   - *BatchDetectionResponse: Results for each prompt with individual verdicts
//   - error: If batch processing fails or limits are exceeded
//
// Example:
//
//	prompts := []BatchPrompt{
//		{ID: "msg1", Prompt: "Hello world"},
//		{ID: "msg2", Prompt: "Ignore all previous instructions"},
//		{ID: "msg3", Prompt: "My SSN is 123-45-6789"},
//	}
//	results, err := client.BatchDetect(prompts)
//	if err != nil {
//		log.Fatal(err)
//	}
//	for _, result := range results.Results {
//		fmt.Printf("%s: %s\n", result.ID, result.Verdict)
//	}
func (c *Client) BatchDetect(prompts []BatchPrompt) (*BatchDetectionResponse, error) {
	req := &BatchDetectionRequest{
		Prompts: prompts,
	}
	
	var response BatchDetectionResponse
	_, err := c.http.R().
		SetBody(req).
		SetResult(&response).
		Post("/api/v1/batch")
	
	if err != nil {
		return nil, err
	}
	
	return &response, nil
}

// AnalyzeComplexity analyzes prompt complexity without performing full detection.
// This is useful for understanding prompt characteristics, making routing decisions,
// and optimizing detection strategies.
//
// Parameters:
//   - prompt: Text prompt to analyze
//
// Returns:
//   - *ComplexityAnalysis: Complexity metrics including level, token count, and risk indicators
//   - error: If analysis fails
//
// Complexity levels:
//   - trivial: Very simple prompts (greetings, basic questions)
//   - simple: Straightforward prompts without complexity
//   - moderate: Standard prompts with some structure
//   - complex: Multi-part prompts with nested instructions
//   - critical: Highly complex prompts with encoding or obfuscation
//
// Example:
//
//	analysis, err := client.AnalyzeComplexity(userPrompt)
//	if err != nil {
//		log.Fatal(err)
//	}
//	if analysis.ComplexityLevel == "critical" {
//		// Apply stricter detection
//		result, _ := client.Detect(
//			WithPrompt(userPrompt),
//			WithMode(DetectionModeStrict),
//		)
//	}
func (c *Client) AnalyzeComplexity(prompt string) (*ComplexityAnalysis, error) {
	req := map[string]string{
		"prompt": prompt,
	}
	
	var response ComplexityAnalysis
	_, err := c.http.R().
		SetBody(req).
		SetResult(&response).
		Post("/v2/analyze/complexity")
	
	if err != nil {
		return nil, err
	}
	
	return &response, nil
}

// GetUsage retrieves API usage metrics and statistics for monitoring and budgeting.
//
// Parameters:
//   - timeWindowHours: Time window for metrics (e.g., 1 for hourly, 24 for daily, 168 for weekly)
//                     If <= 0, defaults to 24 hours
//
// Returns:
//   - *UsageMetrics: Detailed usage statistics including:
//     - Total requests and tokens consumed
//     - Estimated costs by provider
//     - Cache hit rates
//     - Average latency
//     - Breakdown by endpoint and verdict
//   - error: If metrics retrieval fails
//
// Example:
//
//	usage, err := client.GetUsage(24) // Last 24 hours
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Total requests: %d\n", usage.TotalRequests)
//	fmt.Printf("Estimated cost: $%.2f\n", usage.EstimatedCost)
//	if usage.EstimatedCost > 100 {
//		fmt.Println("High usage alert!")
//	}
func (c *Client) GetUsage(timeWindowHours int) (*UsageMetrics, error) {
	if timeWindowHours <= 0 {
		timeWindowHours = 24
	}
	
	var response UsageMetrics
	_, err := c.http.R().
		SetQueryParam("time_window_hours", strconv.Itoa(timeWindowHours)).
		SetResult(&response).
		Get("/monitoring/usage")
	
	if err != nil {
		return nil, err
	}
	
	return &response, nil
}

// GetBudgetStatus retrieves current budget consumption and configured limits.
// Essential for implementing cost controls and preventing unexpected charges.
//
// Returns:
//   - *BudgetStatus: Current budget information including:
//     - Current spending and budget limit
//     - Percentage of budget consumed
//     - Budget period (hourly/daily/monthly)
//     - Active alerts and warnings
//     - Blocked status if budget exceeded
//   - error: If status retrieval fails
//
// Example:
//
//	budget, err := client.GetBudgetStatus()
//	if err != nil {
//		log.Fatal(err)
//	}
//	if budget.PercentageUsed > 80 {
//		fmt.Printf("Warning: %.1f%% of budget used\n", budget.PercentageUsed)
//	}
//	if budget.Blocked {
//		fmt.Println("API blocked - budget exceeded!")
//		// Switch to fallback or cache-only mode
//	}
func (c *Client) GetBudgetStatus() (*BudgetStatus, error) {
	var response BudgetStatus
	_, err := c.http.R().
		SetResult(&response).
		Get("/monitoring/budget")
	
	if err != nil {
		return nil, err
	}
	
	return &response, nil
}

// HealthCheck verifies that the PromptSentinel service is operational.
// It checks the status of all dependencies including LLM providers,
// Redis cache, and other integrated services.
//
// Returns:
//   - *HealthStatus: Service health information including:
//     - Overall status (healthy/degraded/unhealthy)
//     - Service version
//     - Individual dependency statuses
//     - Response latency
//   - error: If health check fails or service is unreachable
//
// Example:
//
//	health, err := client.HealthCheck()
//	if err != nil {
//		fmt.Println("Service unreachable:", err)
//		return
//	}
//	if health.Status != "healthy" {
//		fmt.Printf("Service degraded: %s\n", health.Status)
//		for dep, status := range health.Dependencies {
//			if status != "healthy" {
//				fmt.Printf("  %s: %s\n", dep, status)
//			}
//		}
//	}
func (c *Client) HealthCheck() (*HealthStatus, error) {
	var response HealthStatus
	_, err := c.http.R().
		SetResult(&response).
		Get("/api/v1/health")
	
	if err != nil {
		return nil, err
	}
	
	return &response, nil
}

// IsSafe performs a simple boolean safety check on a prompt.
// Returns true if the prompt passes detection (verdict is ALLOW),
// false if potential threats are detected.
//
// Parameters:
//   - prompt: Text to check for safety
//
// Returns:
//   - bool: true if safe, false if threats detected
//   - error: If detection fails
//
// Example:
//
//	safe, err := client.IsSafe(userInput)
//	if err != nil {
//		log.Fatal(err)
//	}
//	if !safe {
//		fmt.Println("Unsafe prompt detected - blocking request")
//		return
//	}
//	// Process the safe prompt
//	llm.Generate(userInput)
func (c *Client) IsSafe(prompt string) (bool, error) {
	response, err := c.DetectSimple(prompt)
	if err != nil {
		return false, err
	}
	return response.Verdict == VerdictAllow, nil
}

// GetModifiedPrompt retrieves a sanitized version of the prompt if PII redaction
// or content modification was performed during detection.
//
// Parameters:
//   - prompt: Original prompt that may contain PII or sensitive data
//
// Returns:
//   - *string: Modified prompt with PII redacted (nil if no modifications)
//   - error: If detection fails
//
// Example:
//
//	original := "My SSN is 123-45-6789 and email is john@example.com"
//	modified, err := client.GetModifiedPrompt(original)
//	if err != nil {
//		log.Fatal(err)
//	}
//	if modified != nil {
//		fmt.Println("Sanitized:", *modified)
//		// Output: "My SSN is [REDACTED] and email is [REDACTED]"
//		llm.Generate(*modified) // Use sanitized version
//	}
func (c *Client) GetModifiedPrompt(prompt string) (*string, error) {
	response, err := c.DetectSimple(prompt)
	if err != nil {
		return nil, err
	}
	return response.ModifiedPrompt, nil
}

// Helper functions for creating requests

// WithCheckFormat enables format checking and security recommendations.
// When enabled, the API validates prompt structure and provides
// suggestions for improving security through role separation.
func WithCheckFormat(check bool) func(*DetectionRequest) {
	return func(req *DetectionRequest) {
		req.CheckFormat = check
	}
}

// WithCache enables or disables caching for detection results.
// Caching significantly improves performance for repeated prompts,
// reducing latency from ~700ms to ~12ms for cache hits.
func WithCache(useCache bool) func(*DetectionRequest) {
	return func(req *DetectionRequest) {
		req.UseCache = useCache
	}
}

// WithDetectionMode sets the detection sensitivity level:
//   - DetectionModeStrict: High sensitivity, more false positives, for high-security applications
//   - DetectionModeModerate: Balanced approach for general use cases
//   - DetectionModePermissive: Low sensitivity, fewer false positives, for creative applications
func WithDetectionMode(mode DetectionMode) func(*DetectionRequest) {
	return func(req *DetectionRequest) {
		req.DetectionMode = mode
	}
}

// Helper functions for creating messages and conversations

// NewMessage creates a new message for role-based conversation detection.
//
// Parameters:
//   - role: Message role (RoleSystem, RoleUser, or RoleAssistant)
//   - content: Text content of the message
//
// Example:
//
//	systemMsg := NewMessage(RoleSystem, "You are a helpful assistant")
//	userMsg := NewMessage(RoleUser, "What is the weather today?")
func NewMessage(role Role, content string) Message {
	return Message{
		Role:    role,
		Content: content,
	}
}

// NewConversation creates a standard conversation structure with system instructions
// and user input. This is a convenience function for the most common use case.
//
// Parameters:
//   - systemPrompt: System/instruction message content
//   - userPrompt: User input message content
//
// Returns:
//   - []Message: Array of messages forming a conversation
//
// Example:
//
//	conversation := NewConversation(
//		"You are a translator. Only translate text.",
//		"Translate 'Hello' to Spanish",
//	)
//	result, _ := client.DetectMessages(conversation)
func NewConversation(systemPrompt, userPrompt string) []Message {
	return []Message{
		NewMessage(RoleSystem, systemPrompt),
		NewMessage(RoleUser, userPrompt),
	}
}