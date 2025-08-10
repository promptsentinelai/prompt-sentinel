package promptsentinel

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-resty/resty/v2"
)

// Config holds configuration for the PromptSentinel client
type Config struct {
	BaseURL    string
	APIKey     string
	Timeout    time.Duration
	MaxRetries int
	Headers    map[string]string
}

// DefaultConfig returns a default configuration
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

// Client is the PromptSentinel API client
type Client struct {
	config *Config
	http   *resty.Client
}

// New creates a new PromptSentinel client
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

// DetectSimple performs simple string detection using V1 API
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

// DetectMessages performs role-based detection using V2 API
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

// Detect is the main detection method with flexible options
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

// BatchDetect processes multiple prompts in a single request
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

// AnalyzeComplexity analyzes prompt complexity without performing detection
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

// GetUsage retrieves usage metrics for a specified time window
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

// GetBudgetStatus retrieves current budget status
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

// HealthCheck performs a health check on the service
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

// IsSafe checks if a prompt is safe (verdict is ALLOW)
func (c *Client) IsSafe(prompt string) (bool, error) {
	response, err := c.DetectSimple(prompt)
	if err != nil {
		return false, err
	}
	return response.Verdict == VerdictAllow, nil
}

// GetModifiedPrompt returns a modified version of the prompt if available
func (c *Client) GetModifiedPrompt(prompt string) (*string, error) {
	response, err := c.DetectSimple(prompt)
	if err != nil {
		return nil, err
	}
	return response.ModifiedPrompt, nil
}

// Helper functions for creating requests

// WithCheckFormat enables format checking
func WithCheckFormat(check bool) func(*DetectionRequest) {
	return func(req *DetectionRequest) {
		req.CheckFormat = check
	}
}

// WithCache enables or disables caching
func WithCache(useCache bool) func(*DetectionRequest) {
	return func(req *DetectionRequest) {
		req.UseCache = useCache
	}
}

// WithDetectionMode sets the detection mode
func WithDetectionMode(mode DetectionMode) func(*DetectionRequest) {
	return func(req *DetectionRequest) {
		req.DetectionMode = mode
	}
}

// Helper functions for creating messages and conversations

// NewMessage creates a new message with the specified role and content
func NewMessage(role Role, content string) Message {
	return Message{
		Role:    role,
		Content: content,
	}
}

// NewConversation creates a conversation with system and user messages
func NewConversation(systemPrompt, userPrompt string) []Message {
	return []Message{
		NewMessage(RoleSystem, systemPrompt),
		NewMessage(RoleUser, userPrompt),
	}
}