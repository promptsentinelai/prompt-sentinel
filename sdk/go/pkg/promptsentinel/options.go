package promptsentinel

// detectOptions holds configuration options for the main Detect method.
// These options control detection behavior, caching, and routing strategies.
type detectOptions struct {
	prompt                 string
	messages              []Message
	checkFormat           bool
	useCache              bool
	detectionMode         DetectionMode
	useIntelligentRouting bool
}

// DetectOption is a functional option pattern for configuring detection parameters.
// This pattern allows for flexible and extensible configuration without breaking
// backward compatibility when new options are added.
type DetectOption func(*detectOptions)

// WithPrompt sets a simple text prompt for detection.
// Use this option for analyzing plain strings without role context.
//
// Example:
//
//	result, err := client.Detect(
//		WithPrompt("Translate this text to French"),
//	)
func WithPrompt(prompt string) DetectOption {
	return func(opts *detectOptions) {
		opts.prompt = prompt
	}
}

// WithMessages sets role-separated conversation messages for detection.
// This provides better context understanding for multi-turn conversations
// and enables more accurate threat detection.
//
// Example:
//
//	messages := []Message{
//		NewMessage(RoleSystem, "You are a helpful assistant"),
//		NewMessage(RoleUser, "What is the capital of France?"),
//	}
//	result, err := client.Detect(
//		WithMessages(messages),
//	)
func WithMessages(messages []Message) DetectOption {
	return func(opts *detectOptions) {
		opts.messages = messages
	}
}

// WithFormatCheck enables format validation and security recommendations.
// When enabled, the API analyzes the prompt structure and provides
// suggestions for improving security through proper role separation
// and format best practices.
//
// Example:
//
//	result, err := client.Detect(
//		WithPrompt(prompt),
//		WithFormatCheck(true),
//	)
//	if result.FormatRecommendations != nil {
//		for _, rec := range result.FormatRecommendations {
//			fmt.Println("Recommendation:", rec)
//		}
//	}
func WithFormatCheck(check bool) DetectOption {
	return func(opts *detectOptions) {
		opts.checkFormat = check
	}
}

// WithCacheUsage enables or disables caching for detection results.
// Caching significantly improves performance for repeated prompts,
// reducing API latency from ~700ms to ~12ms for cache hits.
// Enabled by default.
//
// Example:
//
//	// Disable cache for dynamic content
//	result, err := client.Detect(
//		WithPrompt(dynamicPrompt),
//		WithCacheUsage(false),
//	)
func WithCacheUsage(useCache bool) DetectOption {
	return func(opts *detectOptions) {
		opts.useCache = useCache
	}
}

// WithMode sets the detection sensitivity level to control the
// trade-off between security and false positives.
//
// Available modes:
//   - DetectionModeStrict: Maximum security, more false positives
//     Use for: Banking, healthcare, high-security applications
//   - DetectionModeModerate: Balanced detection (default)
//     Use for: General applications, customer service
//   - DetectionModePermissive: Minimal false positives
//     Use for: Creative writing, entertainment
//
// Example:
//
//	result, err := client.Detect(
//		WithPrompt(userInput),
//		WithMode(DetectionModeStrict), // High security context
//	)
func WithMode(mode DetectionMode) DetectOption {
	return func(opts *detectOptions) {
		opts.detectionMode = mode
	}
}

// WithIntelligentRouting enables intelligent routing using the V3 API.
// This feature automatically analyzes prompt complexity and routes to
// the optimal detection strategy for best performance:
//   - Simple prompts: Fast heuristic detection only
//   - Complex prompts: Comprehensive multi-strategy analysis
//   - Critical prompts: Full LLM-based classification
//
// This can reduce detection time by 50-80% for simple prompts while
// maintaining high accuracy for complex threats.
//
// Example:
//
//	result, err := client.Detect(
//		WithPrompt(prompt),
//		WithIntelligentRouting(true), // Auto-optimize detection
//	)
//	fmt.Printf("Strategy used: %s\n", result.DetectionStrategy)
//	fmt.Printf("Complexity: %s\n", result.ComplexityAnalysis.Level)
func WithIntelligentRouting(enable bool) DetectOption {
	return func(opts *detectOptions) {
		opts.useIntelligentRouting = enable
	}
}