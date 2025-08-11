package promptsentinel

import "time"

// Version is the current version of the PromptSentinel Go SDK
const Version = "1.0.0"

// Role represents the role of a message in a conversation.
// Used to provide context for role-based detection and proper
// separation of system instructions from user input.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Verdict represents the security decision made by the detection system.
// Different verdicts trigger different handling strategies in your application.
type Verdict string

const (
	// VerdictAllow indicates the prompt is safe to process
	VerdictAllow  Verdict = "allow"
	// VerdictBlock indicates a high-confidence threat requiring blocking
	VerdictBlock  Verdict = "block"
	// VerdictFlag indicates suspicious content requiring manual review
	VerdictFlag   Verdict = "flag"
	// VerdictStrip suggests removing harmful parts while keeping safe content
	VerdictStrip  Verdict = "strip"
	// VerdictRedact indicates PII or sensitive data should be masked
	VerdictRedact Verdict = "redact"
)

// DetectionMode controls the sensitivity level of threat detection.
// Choose based on your application's security requirements and
// tolerance for false positives.
type DetectionMode string

const (
	// DetectionModeStrict provides maximum security with higher false positive rate.
	// Use for high-security contexts like banking, healthcare, or admin interfaces.
	DetectionModeStrict     DetectionMode = "strict"
	// DetectionModeModerate offers balanced detection for general applications.
	// Default mode suitable for customer service, content generation, etc.
	DetectionModeModerate   DetectionMode = "moderate"
	// DetectionModePermissive minimizes false positives for creative applications.
	// Use for entertainment, creative writing, or low-risk contexts.
	DetectionModePermissive DetectionMode = "permissive"
)

// Message represents a single message in a conversation with role and content.
// Proper role separation improves detection accuracy and security.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
}

// DetectionReason provides detailed information about detected threats.
// Each reason includes the threat category, description, confidence score,
// detection source (heuristic/llm), and specific patterns that matched.
type DetectionReason struct {
	Category        string   `json:"category"`
	Description     string   `json:"description"`
	Confidence      float64  `json:"confidence"`
	Source          string   `json:"source"`
	PatternsMatched []string `json:"patterns_matched"`
}

// DetectionRequest represents a request to analyze content for threats.
// Can contain either a simple prompt or role-separated messages.
type DetectionRequest struct {
	Messages      []Message     `json:"messages,omitempty"`
	Prompt        string        `json:"prompt,omitempty"`
	CheckFormat   bool          `json:"check_format,omitempty"`
	UseCache      bool          `json:"use_cache,omitempty"`
	DetectionMode DetectionMode `json:"detection_mode,omitempty"`
}

// DetectionResponse represents the response from a detection request
type DetectionResponse struct {
	Verdict          Verdict                `json:"verdict"`
	Confidence       float64                `json:"confidence"`
	Reasons          []DetectionReason      `json:"reasons"`
	Categories       []string               `json:"categories"`
	ModifiedPrompt   *string                `json:"modified_prompt,omitempty"`
	PIIDetected      bool                   `json:"pii_detected"`
	PIITypes         []string               `json:"pii_types"`
	FormatIssues     []string               `json:"format_issues"`
	Recommendations  []string               `json:"recommendations"`
	ProcessingTimeMs int64                  `json:"processing_time_ms"`
	Timestamp        string                 `json:"timestamp"`
	Metadata         map[string]interface{} `json:"metadata"`
	RoutingMetadata  map[string]interface{} `json:"routing_metadata,omitempty"`
}

// BatchPrompt represents a single prompt in a batch request
type BatchPrompt struct {
	ID     string `json:"id"`
	Prompt string `json:"prompt"`
}

// BatchDetectionRequest represents a batch detection request
type BatchDetectionRequest struct {
	Prompts []BatchPrompt `json:"prompts"`
}

// BatchResult represents a single result in a batch response
type BatchResult struct {
	ID         string   `json:"id"`
	Verdict    *string  `json:"verdict,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
	Error      *string  `json:"error,omitempty"`
}

// BatchDetectionResponse represents the response from a batch detection request
type BatchDetectionResponse struct {
	Results   []BatchResult `json:"results"`
	Processed int           `json:"processed"`
	Timestamp string        `json:"timestamp"`
}

// ComplexityAnalysis represents prompt complexity analysis
type ComplexityAnalysis struct {
	ComplexityLevel   string                 `json:"complexity_level"`
	ComplexityScore   float64                `json:"complexity_score"`
	Metrics           map[string]float64     `json:"metrics"`
	RiskIndicators    []string               `json:"risk_indicators"`
	Recommendations   []string               `json:"recommendations"`
}

// UsageMetrics represents API usage statistics
type UsageMetrics struct {
	RequestCount    int                    `json:"request_count"`
	TokenUsage      map[string]int         `json:"token_usage"`
	CostBreakdown   map[string]float64     `json:"cost_breakdown"`
	ProviderStats   map[string]interface{} `json:"provider_stats"`
	TimePeriod      string                 `json:"time_period"`
}

// BudgetAlert represents a budget alert
type BudgetAlert struct {
	Level       string    `json:"level"`
	Message     string    `json:"message"`
	Percentage  float64   `json:"percentage"`
	Period      string    `json:"period"`
	Timestamp   time.Time `json:"timestamp"`
}

// BudgetStatus represents current budget status
type BudgetStatus struct {
	CurrentUsage  map[string]float64     `json:"current_usage"`
	BudgetLimits  map[string]float64     `json:"budget_limits"`
	Alerts        []BudgetAlert          `json:"alerts"`
	Projections   map[string]float64     `json:"projections"`
}

// HealthStatus represents service health information
type HealthStatus struct {
	Status            string                            `json:"status"`
	Version           string                            `json:"version"`
	Providers         map[string]map[string]interface{} `json:"providers"`
	Cache             map[string]interface{}            `json:"cache"`
	DetectionMethods  []string                          `json:"detection_methods"`
}