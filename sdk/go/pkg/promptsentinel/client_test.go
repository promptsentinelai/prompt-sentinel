package promptsentinel

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestServer() *httptest.Server {
	mux := http.NewServeMux()
	
	// V1 detect endpoint
	mux.HandleFunc("/v1/detect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"verdict": "allow",
			"confidence": 0.95,
			"reasons": [],
			"categories": [],
			"pii_detected": false,
			"pii_types": [],
			"format_issues": [],
			"recommendations": [],
			"processing_time_ms": 50,
			"timestamp": "2025-01-08T10:00:00Z",
			"metadata": {}
		}`))
	})
	
	// V2 detect endpoint
	mux.HandleFunc("/v2/detect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"verdict": "allow",
			"confidence": 0.99,
			"reasons": [],
			"categories": [],
			"pii_detected": false,
			"pii_types": [],
			"format_issues": [],
			"recommendations": [],
			"processing_time_ms": 75,
			"timestamp": "2025-01-08T10:00:00Z",
			"metadata": {}
		}`))
	})
	
	// V3 detect endpoint
	mux.HandleFunc("/v3/detect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"verdict": "allow",
			"confidence": 0.98,
			"reasons": [],
			"categories": [],
			"pii_detected": false,
			"pii_types": [],
			"format_issues": [],
			"recommendations": [],
			"processing_time_ms": 25,
			"timestamp": "2025-01-08T10:00:00Z",
			"metadata": {},
			"routing_metadata": {
				"strategy": "heuristic_only",
				"complexity_level": "simple"
			}
		}`))
	})
	
	// Batch detect endpoint
	mux.HandleFunc("/v2/batch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"results": [
				{"id": "1", "verdict": "allow", "confidence": 0.95},
				{"id": "2", "verdict": "block", "confidence": 0.89}
			],
			"processed": 2,
			"timestamp": "2025-01-08T10:00:00Z"
		}`))
	})
	
	// Complexity analysis endpoint
	mux.HandleFunc("/v2/analyze/complexity", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"complexity_level": "moderate",
			"complexity_score": 0.65,
			"metrics": {
				"length": 50,
				"entropy": 4.2
			},
			"risk_indicators": ["multiple_instructions"],
			"recommendations": ["Use role separation"]
		}`))
	})
	
	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": "healthy",
			"version": "1.0.0",
			"providers": {
				"anthropic": {"status": "healthy"}
			},
			"cache": {
				"redis": {"status": "connected"}
			},
			"detection_methods": ["heuristic", "llm"]
		}`))
	})
	
	// Error endpoints for testing
	mux.HandleFunc("/error/401", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"detail": "Authentication failed"}`))
	})
	
	mux.HandleFunc("/error/429", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"detail": "Rate limit exceeded"}`))
	})
	
	return httptest.NewServer(mux)
}

func TestClient_DetectSimple(t *testing.T) {
	server := setupTestServer()
	defer server.Close()
	
	config := &Config{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	}
	client := New(config)
	
	response, err := client.DetectSimple("Hello, world!")
	require.NoError(t, err)
	assert.Equal(t, VerdictAllow, response.Verdict)
	assert.Equal(t, 0.95, response.Confidence)
}

func TestClient_DetectMessages(t *testing.T) {
	server := setupTestServer()
	defer server.Close()
	
	config := &Config{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	}
	client := New(config)
	
	messages := []Message{
		{Role: RoleSystem, Content: "You are a helpful assistant"},
		{Role: RoleUser, Content: "Hello!"},
	}
	
	response, err := client.DetectMessages(messages)
	require.NoError(t, err)
	assert.Equal(t, VerdictAllow, response.Verdict)
	assert.Equal(t, 0.99, response.Confidence)
}

func TestClient_Detect_WithIntelligentRouting(t *testing.T) {
	server := setupTestServer()
	defer server.Close()
	
	config := &Config{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	}
	client := New(config)
	
	response, err := client.Detect(
		WithPrompt("Test prompt"),
		WithIntelligentRouting(true),
		WithFormatCheck(true),
	)
	require.NoError(t, err)
	assert.Equal(t, VerdictAllow, response.Verdict)
	assert.Equal(t, 0.98, response.Confidence)
	assert.NotNil(t, response.RoutingMetadata)
}

func TestClient_BatchDetect(t *testing.T) {
	server := setupTestServer()
	defer server.Close()
	
	config := &Config{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	}
	client := New(config)
	
	prompts := []BatchPrompt{
		{ID: "1", Prompt: "Hello"},
		{ID: "2", Prompt: "Dangerous prompt"},
	}
	
	response, err := client.BatchDetect(prompts)
	require.NoError(t, err)
	assert.Equal(t, 2, response.Processed)
	assert.Len(t, response.Results, 2)
	assert.Equal(t, "1", response.Results[0].ID)
	assert.Equal(t, "allow", *response.Results[0].Verdict)
}

func TestClient_AnalyzeComplexity(t *testing.T) {
	server := setupTestServer()
	defer server.Close()
	
	config := &Config{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	}
	client := New(config)
	
	analysis, err := client.AnalyzeComplexity("Complex prompt with multiple instructions")
	require.NoError(t, err)
	assert.Equal(t, "moderate", analysis.ComplexityLevel)
	assert.Equal(t, 0.65, analysis.ComplexityScore)
	assert.Contains(t, analysis.RiskIndicators, "multiple_instructions")
}

func TestClient_HealthCheck(t *testing.T) {
	server := setupTestServer()
	defer server.Close()
	
	config := &Config{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	}
	client := New(config)
	
	health, err := client.HealthCheck()
	require.NoError(t, err)
	assert.Equal(t, "healthy", health.Status)
	assert.Equal(t, "1.0.0", health.Version)
	assert.Contains(t, health.DetectionMethods, "heuristic")
}

func TestClient_IsSafe(t *testing.T) {
	server := setupTestServer()
	defer server.Close()
	
	config := &Config{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	}
	client := New(config)
	
	isSafe, err := client.IsSafe("Hello, world!")
	require.NoError(t, err)
	assert.True(t, isSafe)
}

func TestClient_ErrorHandling_Authentication(t *testing.T) {
	server := setupTestServer()
	defer server.Close()
	
	config := &Config{
		BaseURL: server.URL + "/error/401",
		Timeout: 5 * time.Second,
	}
	client := New(config)
	
	_, err := client.DetectSimple("test")
	require.Error(t, err)
	assert.IsType(t, &AuthenticationError{}, err)
}

func TestClient_ErrorHandling_RateLimit(t *testing.T) {
	server := setupTestServer()
	defer server.Close()
	
	config := &Config{
		BaseURL: server.URL + "/error/429",
		Timeout: 5 * time.Second,
	}
	client := New(config)
	
	_, err := client.DetectSimple("test")
	require.Error(t, err)
	rateLimitErr, ok := err.(*RateLimitError)
	require.True(t, ok)
	assert.NotNil(t, rateLimitErr.RetryAfter)
	assert.Equal(t, 60, *rateLimitErr.RetryAfter)
}

func TestNewMessage(t *testing.T) {
	message := NewMessage(RoleUser, "Hello")
	assert.Equal(t, RoleUser, message.Role)
	assert.Equal(t, "Hello", message.Content)
}

func TestNewConversation(t *testing.T) {
	messages := NewConversation("You are helpful", "Help me")
	assert.Len(t, messages, 2)
	assert.Equal(t, RoleSystem, messages[0].Role)
	assert.Equal(t, RoleUser, messages[1].Role)
	assert.Equal(t, "You are helpful", messages[0].Content)
	assert.Equal(t, "Help me", messages[1].Content)
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	assert.Equal(t, "http://localhost:8080", config.BaseURL)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 3, config.MaxRetries)
	assert.NotNil(t, config.Headers)
}