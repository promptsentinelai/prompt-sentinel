package promptsentinel

// detectOptions holds options for the main Detect method
type detectOptions struct {
	prompt                 string
	messages              []Message
	checkFormat           bool
	useCache              bool
	detectionMode         DetectionMode
	useIntelligentRouting bool
}

// DetectOption is a function that configures detectOptions
type DetectOption func(*detectOptions)

// WithPrompt sets the prompt for detection
func WithPrompt(prompt string) DetectOption {
	return func(opts *detectOptions) {
		opts.prompt = prompt
	}
}

// WithMessages sets the messages for detection
func WithMessages(messages []Message) DetectOption {
	return func(opts *detectOptions) {
		opts.messages = messages
	}
}

// WithFormatCheck enables format checking
func WithFormatCheck(check bool) DetectOption {
	return func(opts *detectOptions) {
		opts.checkFormat = check
	}
}

// WithCacheUsage enables or disables cache usage
func WithCacheUsage(useCache bool) DetectOption {
	return func(opts *detectOptions) {
		opts.useCache = useCache
	}
}

// WithMode sets the detection mode
func WithMode(mode DetectionMode) DetectOption {
	return func(opts *detectOptions) {
		opts.detectionMode = mode
	}
}

// WithIntelligentRouting enables intelligent routing (V3 API)
func WithIntelligentRouting(enable bool) DetectOption {
	return func(opts *detectOptions) {
		opts.useIntelligentRouting = enable
	}
}