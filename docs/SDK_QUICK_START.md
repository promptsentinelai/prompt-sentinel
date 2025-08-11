# SDK Quick Start Guide

Get started with PromptSentinel SDKs in under 5 minutes across Python, JavaScript/TypeScript, and Go.

## Table of Contents
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Common Patterns](#common-patterns)
- [Advanced Features](#advanced-features)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)
- [Migration Guide](#migration-guide)
- [SDK Comparison](#sdk-comparison)

## Installation

### Python

```bash
# Using pip
pip install promptsentinel

# Using uv (faster)
uv pip install promptsentinel

# Using poetry
poetry add promptsentinel

# From source
git clone https://github.com/promptsentinel/python-sdk
cd python-sdk
pip install -e .
```

### JavaScript/TypeScript

```bash
# Using npm
npm install promptsentinel

# Using yarn
yarn add promptsentinel

# Using pnpm
pnpm add promptsentinel

# TypeScript types included
npm install --save-dev @types/node  # If needed
```

### Go

```bash
# Using go get
go get github.com/promptsentinel/sdk-go

# In go.mod
require github.com/promptsentinel/sdk-go v1.0.0

# Update dependencies
go mod tidy
```

## Basic Usage

### Quick Detection - All Languages

<table>
<tr>
<th>Python</th>
<th>JavaScript</th>
<th>Go</th>
</tr>
<tr>
<td>

```python
from promptsentinel import PromptSentinel

# Initialize
client = PromptSentinel(
    api_key="psk_your_key"
)

# Detect
result = client.detect(
    prompt="Hello world"
)

if result.verdict == "allow":
    print("Safe")
else:
    print("Blocked")
```

</td>
<td>

```javascript
import { PromptSentinel } from 'promptsentinel';

// Initialize
const client = new PromptSentinel({
  apiKey: 'psk_your_key'
});

// Detect
const result = await client.detect({
  prompt: 'Hello world'
});

if (result.verdict === 'allow') {
  console.log('Safe');
} else {
  console.log('Blocked');
}
```

</td>
<td>

```go
import "github.com/promptsentinel/sdk-go"

// Initialize
client := promptsentinel.New(&Config{
    APIKey: "psk_your_key",
})

// Detect
result, err := client.DetectSimple(
    "Hello world",
)

if result.Verdict == "allow" {
    fmt.Println("Safe")
} else {
    fmt.Println("Blocked")
}
```

</td>
</tr>
</table>

### Environment-Based Configuration

<table>
<tr>
<th>Python</th>
<th>JavaScript</th>
<th>Go</th>
</tr>
<tr>
<td>

```python
# .env file
PROMPTSENTINEL_API_KEY=psk_key
PROMPTSENTINEL_BASE_URL=http://localhost:8080

# Code
from promptsentinel import PromptSentinel
import os

# Auto-loads from env
client = PromptSentinel()

# Or explicit
client = PromptSentinel(
    api_key=os.getenv("PROMPTSENTINEL_API_KEY"),
    base_url=os.getenv("PROMPTSENTINEL_BASE_URL")
)
```

</td>
<td>

```javascript
// .env file
PROMPTSENTINEL_API_KEY=psk_key
PROMPTSENTINEL_BASE_URL=http://localhost:8080

// Code
import { PromptSentinel } from 'promptsentinel';

// Auto-loads from env
const client = new PromptSentinel();

// Or explicit
const client = new PromptSentinel({
  apiKey: process.env.PROMPTSENTINEL_API_KEY,
  baseUrl: process.env.PROMPTSENTINEL_BASE_URL
});
```

</td>
<td>

```go
// Environment variables
// PROMPTSENTINEL_API_KEY=psk_key
// PROMPTSENTINEL_BASE_URL=http://localhost:8080

import (
    "os"
    ps "github.com/promptsentinel/sdk-go"
)

// Auto-loads from env
client := ps.New(nil)

// Or explicit
client := ps.New(&ps.Config{
    APIKey: os.Getenv("PROMPTSENTINEL_API_KEY"),
    BaseURL: os.Getenv("PROMPTSENTINEL_BASE_URL"),
})
```

</td>
</tr>
</table>

## Common Patterns

### 1. Simple String Detection

<table>
<tr>
<th>Python</th>
<th>JavaScript</th>
<th>Go</th>
</tr>
<tr>
<td>

```python
# Quick safety check
def process_user_input(text):
    result = client.detect(prompt=text)
    
    if result.verdict == "block":
        return "Request blocked for security"
    
    # Use sanitized version if available
    safe_text = result.modified_prompt or text
    return generate_response(safe_text)

# One-liner safety check
is_safe = client.detect(prompt=text).verdict == "allow"
```

</td>
<td>

```javascript
// Quick safety check
async function processUserInput(text) {
  const result = await client.detect({ prompt: text });
  
  if (result.verdict === 'block') {
    return 'Request blocked for security';
  }
  
  // Use sanitized version if available
  const safeText = result.modified_prompt || text;
  return generateResponse(safeText);
}

// One-liner safety check
const isSafe = (await client.detect({ prompt: text })).verdict === 'allow';
```

</td>
<td>

```go
// Quick safety check
func processUserInput(text string) string {
    result, err := client.DetectSimple(text)
    if err != nil {
        return "Error checking input"
    }
    
    if result.Verdict == "block" {
        return "Request blocked for security"
    }
    
    // Use sanitized version if available
    safeText := text
    if result.ModifiedPrompt != nil {
        safeText = *result.ModifiedPrompt
    }
    return generateResponse(safeText)
}

// Boolean safety check
safe, _ := client.IsSafe(text)
```

</td>
</tr>
</table>

### 2. Role-Based Conversations

<table>
<tr>
<th>Python</th>
<th>JavaScript</th>
<th>Go</th>
</tr>
<tr>
<td>

```python
from promptsentinel import Message, Role

# Build conversation
messages = [
    Message(role=Role.SYSTEM, 
            content="You are a helpful assistant"),
    Message(role=Role.USER, 
            content="What is Python?"),
    Message(role=Role.ASSISTANT, 
            content="Python is a programming language"),
    Message(role=Role.USER, 
            content=user_input)
]

# Validate conversation
result = client.detect(
    messages=messages,
    check_format=True,
    detection_mode="strict"
)

if result.format_recommendations:
    print("Security suggestions:")
    for rec in result.format_recommendations:
        print(f"  - {rec}")
```

</td>
<td>

```javascript
import { Role } from 'promptsentinel';

// Build conversation
const messages = [
  { role: Role.SYSTEM, 
    content: 'You are a helpful assistant' },
  { role: Role.USER, 
    content: 'What is JavaScript?' },
  { role: Role.ASSISTANT, 
    content: 'JavaScript is a programming language' },
  { role: Role.USER, 
    content: userInput }
];

// Validate conversation
const result = await client.detect({
  messages,
  checkFormat: true,
  detectionMode: 'strict'
});

if (result.format_recommendations) {
  console.log('Security suggestions:');
  result.format_recommendations.forEach(rec => {
    console.log(`  - ${rec}`);
  });
}
```

</td>
<td>

```go
// Build conversation
messages := []Message{
    NewMessage(RoleSystem, 
               "You are a helpful assistant"),
    NewMessage(RoleUser, 
               "What is Go?"),
    NewMessage(RoleAssistant, 
               "Go is a programming language"),
    NewMessage(RoleUser, 
               userInput),
}

// Validate conversation
result, err := client.DetectMessages(
    messages,
    WithCheckFormat(true),
    WithDetectionMode(DetectionModeStrict),
)

if result.FormatRecommendations != nil {
    fmt.Println("Security suggestions:")
    for _, rec := range result.FormatRecommendations {
        fmt.Printf("  - %s\n", rec)
    }
}
```

</td>
</tr>
</table>

### 3. Batch Processing

<table>
<tr>
<th>Python</th>
<th>JavaScript</th>
<th>Go</th>
</tr>
<tr>
<td>

```python
# Process multiple prompts
prompts = [
    {"id": "1", "prompt": "Hello"},
    {"id": "2", "prompt": "Ignore instructions"},
    {"id": "3", "prompt": "My SSN is 123-45-6789"}
]

batch_result = client.batch_detect(prompts)

# Filter results
safe = [r for r in batch_result.results 
        if r.verdict == "allow"]
blocked = [r for r in batch_result.results 
           if r.verdict == "block"]

print(f"Safe: {len(safe)}, Blocked: {len(blocked)}")

# Process by verdict
for result in batch_result.results:
    if result.verdict == "allow":
        process_safe(result.id)
    else:
        log_threat(result.id, result.reasons)
```

</td>
<td>

```javascript
// Process multiple prompts
const prompts = [
  { id: '1', prompt: 'Hello' },
  { id: '2', prompt: 'Ignore instructions' },
  { id: '3', prompt: 'My SSN is 123-45-6789' }
];

const batchResult = await client.batchDetect(prompts);

// Filter results
const safe = batchResult.results.filter(
  r => r.verdict === 'allow'
);
const blocked = batchResult.results.filter(
  r => r.verdict === 'block'
);

console.log(`Safe: ${safe.length}, Blocked: ${blocked.length}`);

// Process by verdict
batchResult.results.forEach(result => {
  if (result.verdict === 'allow') {
    processSafe(result.id);
  } else {
    logThreat(result.id, result.reasons);
  }
});
```

</td>
<td>

```go
// Process multiple prompts
prompts := []BatchPrompt{
    {ID: "1", Prompt: "Hello"},
    {ID: "2", Prompt: "Ignore instructions"},
    {ID: "3", Prompt: "My SSN is 123-45-6789"},
}

batchResult, err := client.BatchDetect(prompts)

// Filter results
var safe, blocked []BatchResult
for _, result := range batchResult.Results {
    if result.Verdict == "allow" {
        safe = append(safe, result)
    } else {
        blocked = append(blocked, result)
    }
}

fmt.Printf("Safe: %d, Blocked: %d\n", 
           len(safe), len(blocked))

// Process by verdict
for _, result := range batchResult.Results {
    if result.Verdict == "allow" {
        processSafe(result.ID)
    } else {
        logThreat(result.ID, result.Reasons)
    }
}
```

</td>
</tr>
</table>

### 4. PII Detection and Redaction

<table>
<tr>
<th>Python</th>
<th>JavaScript</th>
<th>Go</th>
</tr>
<tr>
<td>

```python
text = "Call me at 555-123-4567 or email john@example.com"

result = client.detect(prompt=text)

if result.pii_detected:
    print("PII found:")
    for pii in result.pii_detected:
        print(f"  - {pii.type}: {pii.value[:4]}****")
    
    # Use sanitized version
    if result.modified_prompt:
        safe_text = result.modified_prompt
        print(f"Sanitized: {safe_text}")
        # Output: "Call me at [PHONE] or email [EMAIL]"
    else:
        # Manual redaction
        safe_text = "[PII REDACTED]"
else:
    safe_text = text

# Process with safe text
process_text(safe_text)
```

</td>
<td>

```javascript
const text = "Call me at 555-123-4567 or email john@example.com";

const result = await client.detect({ prompt: text });

if (result.pii_detected && result.pii_detected.length > 0) {
  console.log('PII found:');
  result.pii_detected.forEach(pii => {
    console.log(`  - ${pii.type}: ${pii.value.slice(0, 4)}****`);
  });
  
  // Use sanitized version
  let safeText;
  if (result.modified_prompt) {
    safeText = result.modified_prompt;
    console.log(`Sanitized: ${safeText}`);
    // Output: "Call me at [PHONE] or email [EMAIL]"
  } else {
    // Manual redaction
    safeText = '[PII REDACTED]';
  }
} else {
  safeText = text;
}

// Process with safe text
processText(safeText);
```

</td>
<td>

```go
text := "Call me at 555-123-4567 or email john@example.com"

result, _ := client.DetectSimple(text)

var safeText string
if result.PIIDetected != nil && len(result.PIIDetected) > 0 {
    fmt.Println("PII found:")
    for _, pii := range result.PIIDetected {
        fmt.Printf("  - %s: %s****\n", 
                   pii.Type, pii.Value[:4])
    }
    
    // Use sanitized version
    if result.ModifiedPrompt != nil {
        safeText = *result.ModifiedPrompt
        fmt.Printf("Sanitized: %s\n", safeText)
        // Output: "Call me at [PHONE] or email [EMAIL]"
    } else {
        // Manual redaction
        safeText = "[PII REDACTED]"
    }
} else {
    safeText = text
}

// Process with safe text
processText(safeText)
```

</td>
</tr>
</table>

## Advanced Features

### Intelligent Routing

<table>
<tr>
<th>Python</th>
<th>JavaScript</th>
<th>Go</th>
</tr>
<tr>
<td>

```python
# Automatic performance optimization
result = client.detect(
    prompt=user_input,
    use_intelligent_routing=True
)

# Check what strategy was used
print(f"Strategy: {result.detection_strategy}")
print(f"Complexity: {result.complexity_analysis.level}")

# Manual complexity analysis
analysis = client.analyze_complexity(prompt)
if analysis.complexity_level == "trivial":
    # Skip expensive checks
    result = client.detect(
        prompt=prompt,
        detection_mode="permissive"
    )
else:
    # Full analysis for complex prompts
    result = client.detect(
        prompt=prompt,
        detection_mode="strict"
    )
```

</td>
<td>

```javascript
// Automatic performance optimization
const result = await client.detect({
  prompt: userInput,
  useIntelligentRouting: true
});

// Check what strategy was used
console.log(`Strategy: ${result.detection_strategy}`);
console.log(`Complexity: ${result.complexity_analysis?.level}`);

// Manual complexity analysis
const analysis = await client.analyzeComplexity(prompt);
if (analysis.complexity_level === 'trivial') {
  // Skip expensive checks
  const result = await client.detect({
    prompt,
    detectionMode: 'permissive'
  });
} else {
  // Full analysis for complex prompts
  const result = await client.detect({
    prompt,
    detectionMode: 'strict'
  });
}
```

</td>
<td>

```go
// Automatic performance optimization
result, _ := client.Detect(
    WithPrompt(userInput),
    WithIntelligentRouting(true),
)

// Check what strategy was used
fmt.Printf("Strategy: %s\n", result.DetectionStrategy)
fmt.Printf("Complexity: %s\n", 
           result.ComplexityAnalysis.Level)

// Manual complexity analysis
analysis, _ := client.AnalyzeComplexity(prompt)
if analysis.ComplexityLevel == "trivial" {
    // Skip expensive checks
    result, _ = client.Detect(
        WithPrompt(prompt),
        WithMode(DetectionModePermissive),
    )
} else {
    // Full analysis for complex prompts
    result, _ = client.Detect(
        WithPrompt(prompt),
        WithMode(DetectionModeStrict),
    )
}
```

</td>
</tr>
</table>

### Monitoring and Metrics

<table>
<tr>
<th>Python</th>
<th>JavaScript</th>
<th>Go</th>
</tr>
<tr>
<td>

```python
# Get usage metrics
usage = client.get_usage(24)  # Last 24 hours
print(f"Requests: {usage.total_requests}")
print(f"Tokens: {usage.total_tokens}")
print(f"Cost: ${usage.estimated_cost:.2f}")
print(f"Cache hit rate: {usage.cache_hit_rate}%")

# Check budget
budget = client.get_budget_status()
if budget.percentage_used > 80:
    print(f"Warning: {budget.percentage_used}% of budget used")
    # Implement cost-saving measures
    client.detect(prompt, use_cache=True)

# Health check
health = client.health_check()
if health.status != "healthy":
    print(f"Service degraded: {health.status}")
    for dep, status in health.dependencies.items():
        if status != "healthy":
            print(f"  {dep}: {status}")
```

</td>
<td>

```javascript
// Get usage metrics
const usage = await client.getUsage(24); // Last 24 hours
console.log(`Requests: ${usage.total_requests}`);
console.log(`Tokens: ${usage.total_tokens}`);
console.log(`Cost: $${usage.estimated_cost.toFixed(2)}`);
console.log(`Cache hit rate: ${usage.cache_hit_rate}%`);

// Check budget
const budget = await client.getBudgetStatus();
if (budget.percentage_used > 80) {
  console.log(`Warning: ${budget.percentage_used}% of budget used`);
  // Implement cost-saving measures
  await client.detect({ prompt, useCache: true });
}

// Health check
const health = await client.healthCheck();
if (health.status !== 'healthy') {
  console.log(`Service degraded: ${health.status}`);
  Object.entries(health.dependencies).forEach(([dep, status]) => {
    if (status !== 'healthy') {
      console.log(`  ${dep}: ${status}`);
    }
  });
}
```

</td>
<td>

```go
// Get usage metrics
usage, _ := client.GetUsage(24) // Last 24 hours
fmt.Printf("Requests: %d\n", usage.TotalRequests)
fmt.Printf("Tokens: %d\n", usage.TotalTokens)
fmt.Printf("Cost: $%.2f\n", usage.EstimatedCost)
fmt.Printf("Cache hit rate: %.1f%%\n", usage.CacheHitRate)

// Check budget
budget, _ := client.GetBudgetStatus()
if budget.PercentageUsed > 80 {
    fmt.Printf("Warning: %.1f%% of budget used\n", 
               budget.PercentageUsed)
    // Implement cost-saving measures
    client.Detect(
        WithPrompt(prompt),
        WithCacheUsage(true),
    )
}

// Health check
health, _ := client.HealthCheck()
if health.Status != "healthy" {
    fmt.Printf("Service degraded: %s\n", health.Status)
    for dep, status := range health.Dependencies {
        if status != "healthy" {
            fmt.Printf("  %s: %s\n", dep, status)
        }
    }
}
```

</td>
</tr>
</table>

### Async/Concurrent Operations

<table>
<tr>
<th>Python (Async)</th>
<th>JavaScript (Promises)</th>
<th>Go (Goroutines)</th>
</tr>
<tr>
<td>

```python
import asyncio
from promptsentinel import AsyncPromptSentinel

# Async client
async_client = AsyncPromptSentinel(
    api_key="psk_your_key"
)

# Concurrent detection
async def process_many(prompts):
    tasks = [
        async_client.detect(prompt=p) 
        for p in prompts
    ]
    results = await asyncio.gather(*tasks)
    return results

# Stream processing
async def stream_process(prompt_stream):
    async for prompt in prompt_stream:
        result = await async_client.detect(
            prompt=prompt
        )
        if result.verdict == "allow":
            yield result

# Context manager
async def main():
    async with AsyncPromptSentinel() as client:
        result = await client.detect(prompt="test")
        print(result.verdict)

asyncio.run(main())
```

</td>
<td>

```javascript
// Concurrent detection
async function processMany(prompts) {
  const promises = prompts.map(p => 
    client.detect({ prompt: p })
  );
  const results = await Promise.all(promises);
  return results;
}

// Stream processing
async function* streamProcess(promptStream) {
  for await (const prompt of promptStream) {
    const result = await client.detect({ prompt });
    if (result.verdict === 'allow') {
      yield result;
    }
  }
}

// Error handling with Promise.allSettled
async function safeProcessMany(prompts) {
  const results = await Promise.allSettled(
    prompts.map(p => client.detect({ prompt: p }))
  );
  
  const successful = results
    .filter(r => r.status === 'fulfilled')
    .map(r => r.value);
  
  const failed = results
    .filter(r => r.status === 'rejected')
    .map(r => r.reason);
  
  return { successful, failed };
}
```

</td>
<td>

```go
import (
    "sync"
    "context"
)

// Concurrent detection
func processMany(prompts []string) []Result {
    var wg sync.WaitGroup
    results := make([]Result, len(prompts))
    
    for i, prompt := range prompts {
        wg.Add(1)
        go func(idx int, p string) {
            defer wg.Done()
            result, _ := client.DetectSimple(p)
            results[idx] = result
        }(i, prompt)
    }
    
    wg.Wait()
    return results
}

// Channel-based streaming
func streamProcess(prompts <-chan string) <-chan Result {
    results := make(chan Result)
    
    go func() {
        defer close(results)
        for prompt := range prompts {
            result, _ := client.DetectSimple(prompt)
            if result.Verdict == "allow" {
                results <- result
            }
        }
    }()
    
    return results
}

// Context with timeout
func detectWithTimeout(prompt string) (*Result, error) {
    ctx, cancel := context.WithTimeout(
        context.Background(), 
        5*time.Second,
    )
    defer cancel()
    
    return client.DetectWithContext(ctx, prompt)
}
```

</td>
</tr>
</table>

## Error Handling

### Comprehensive Error Management

<table>
<tr>
<th>Python</th>
<th>JavaScript</th>
<th>Go</th>
</tr>
<tr>
<td>

```python
from promptsentinel import (
    AuthenticationError,
    RateLimitError,
    ValidationError,
    ServiceUnavailableError
)
import time

def safe_detect(prompt, max_retries=3):
    """Detect with retry logic."""
    
    for attempt in range(max_retries):
        try:
            return client.detect(prompt=prompt)
            
        except AuthenticationError:
            print("Invalid API key")
            # Get new key or fail
            raise
            
        except RateLimitError as e:
            wait_time = e.retry_after or 60
            print(f"Rate limited, waiting {wait_time}s")
            time.sleep(wait_time)
            
        except ValidationError as e:
            print(f"Invalid request: {e}")
            # Fix request or fail
            raise
            
        except ServiceUnavailableError:
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                print(f"Service down, retry in {wait_time}s")
                time.sleep(wait_time)
            else:
                print("Service unavailable")
                raise
                
        except Exception as e:
            print(f"Unexpected error: {e}")
            raise
    
    return None
```

</td>
<td>

```javascript
import {
  AuthenticationError,
  RateLimitError,
  ValidationError,
  ServiceUnavailableError
} from 'promptsentinel';

async function safeDetect(prompt, maxRetries = 3) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await client.detect({ prompt });
      
    } catch (error) {
      if (error instanceof AuthenticationError) {
        console.error('Invalid API key');
        throw error;
        
      } else if (error instanceof RateLimitError) {
        const waitTime = error.retryAfter || 60;
        console.log(`Rate limited, waiting ${waitTime}s`);
        await new Promise(r => setTimeout(r, waitTime * 1000));
        
      } else if (error instanceof ValidationError) {
        console.error(`Invalid request: ${error.message}`);
        throw error;
        
      } else if (error instanceof ServiceUnavailableError) {
        if (attempt < maxRetries - 1) {
          const waitTime = Math.pow(2, attempt);
          console.log(`Service down, retry in ${waitTime}s`);
          await new Promise(r => setTimeout(r, waitTime * 1000));
        } else {
          console.error('Service unavailable');
          throw error;
        }
        
      } else {
        console.error(`Unexpected error: ${error}`);
        throw error;
      }
    }
  }
  
  return null;
}
```

</td>
<td>

```go
import (
    "fmt"
    "time"
)

func safeDetect(prompt string, maxRetries int) (*Result, error) {
    var lastErr error
    
    for attempt := 0; attempt < maxRetries; attempt++ {
        result, err := client.DetectSimple(prompt)
        
        if err == nil {
            return result, nil
        }
        
        lastErr = err
        
        switch e := err.(type) {
        case *AuthenticationError:
            fmt.Println("Invalid API key")
            return nil, err
            
        case *RateLimitError:
            waitTime := 60
            if e.RetryAfter != nil {
                waitTime = *e.RetryAfter
            }
            fmt.Printf("Rate limited, waiting %ds\n", waitTime)
            time.Sleep(time.Duration(waitTime) * time.Second)
            
        case *ValidationError:
            fmt.Printf("Invalid request: %v\n", err)
            return nil, err
            
        case *ServiceUnavailableError:
            if attempt < maxRetries-1 {
                waitTime := time.Duration(1<<uint(attempt)) * time.Second
                fmt.Printf("Service down, retry in %v\n", waitTime)
                time.Sleep(waitTime)
            } else {
                fmt.Println("Service unavailable")
                return nil, err
            }
            
        default:
            fmt.Printf("Unexpected error: %v\n", err)
            return nil, err
        }
    }
    
    return nil, lastErr
}
```

</td>
</tr>
</table>

## Best Practices

### 1. Always Handle Errors

```python
# Python
try:
    result = client.detect(prompt=user_input)
except Exception as e:
    logger.error(f"Detection failed: {e}")
    # Fallback to safe mode
    return "Service temporarily unavailable"
```

```javascript
// JavaScript
client.detect({ prompt: userInput })
  .then(result => processResult(result))
  .catch(error => {
    console.error('Detection failed:', error);
    // Fallback to safe mode
    return 'Service temporarily unavailable';
  });
```

```go
// Go
result, err := client.DetectSimple(userInput)
if err != nil {
    log.Printf("Detection failed: %v", err)
    // Fallback to safe mode
    return "Service temporarily unavailable"
}
```

### 2. Use Appropriate Detection Modes

```python
# Python
USE_CASES = {
    "chat": "moderate",      # Balanced
    "code": "strict",        # High security
    "creative": "permissive" # Low false positives
}

mode = USE_CASES.get(use_case, "moderate")
result = client.detect(prompt=text, detection_mode=mode)
```

### 3. Enable Caching for Performance

```python
# Python - 98% faster for repeated prompts
result = client.detect(prompt=text, use_cache=True)
```

```javascript
// JavaScript
const result = await client.detect({ 
  prompt: text, 
  useCache: true 
});
```

### 4. Implement Timeout Handling

```python
# Python
client = PromptSentinel(timeout=10.0)  # 10 second timeout
```

```javascript
// JavaScript
const client = new PromptSentinel({ 
  timeout: 10000  // 10 second timeout
});
```

```go
// Go
client := promptsentinel.New(&Config{
    Timeout: 10 * time.Second,
})
```

### 5. Monitor Usage and Costs

```python
# Python - Regular monitoring
import schedule

def check_usage():
    usage = client.get_usage(1)  # Last hour
    if usage.estimated_cost > 10:
        send_alert(f"High usage: ${usage.estimated_cost}")

schedule.every().hour.do(check_usage)
```

## Migration Guide

### Migrating from v0.x to v1.x

```python
# Old (v0.x)
from promptsentinel import detect_prompt
result = detect_prompt("text")

# New (v1.x)
from promptsentinel import PromptSentinel
client = PromptSentinel()
result = client.detect(prompt="text")
```

### Migrating from Other Solutions

```python
# From OpenAI Moderation API
# Old
import openai
response = openai.Moderation.create(input="text")
if response.results[0].flagged:
    print("Blocked")

# New with PromptSentinel
from promptsentinel import PromptSentinel
client = PromptSentinel()
result = client.detect(prompt="text")
if result.verdict == "block":
    print("Blocked")
```

## SDK Comparison

| Feature | Python | JavaScript | Go |
|---------|--------|------------|-----|
| Sync Support | ✅ | ✅ (with await) | ✅ |
| Async Support | ✅ | ✅ | ✅ (goroutines) |
| Type Safety | ✅ (with types) | ✅ (TypeScript) | ✅ |
| Auto-retry | ❌ | ❌ | ❌ |
| Streaming | ✅ | ✅ | ✅ |
| Batch API | ✅ | ✅ | ✅ |
| Caching | ✅ | ✅ | ✅ |
| Metrics | ✅ | ✅ | ✅ |
| Health Check | ✅ | ✅ | ✅ |
| Context Manager | ✅ | ❌ | ❌ |
| Environment Config | ✅ | ✅ | ✅ |

## Quick Reference

### Common Methods - All SDKs

| Method | Description | Returns |
|--------|-------------|---------|
| `detect()` | Main detection method | DetectionResponse |
| `detectSimple()` | Simple string detection | DetectionResponse |
| `detectMessages()` | Role-based detection | DetectionResponse |
| `batchDetect()` | Process multiple prompts | BatchResponse |
| `analyzeComplexity()` | Analyze prompt complexity | ComplexityAnalysis |
| `getUsage()` | Get usage metrics | UsageMetrics |
| `getBudgetStatus()` | Check budget status | BudgetStatus |
| `healthCheck()` | Service health check | HealthStatus |
| `isSafe()` | Boolean safety check | boolean |
| `getModifiedPrompt()` | Get sanitized version | string |

### Response Fields

```typescript
interface DetectionResponse {
  verdict: 'allow' | 'block' | 'review';
  confidence: number;        // 0.0 - 1.0
  reasons: DetectionReason[]; // Threat details
  pii_detected?: PII[];      // Found PII
  modified_prompt?: string;   // Sanitized version
  processing_time_ms: number; // Latency
  cached?: boolean;          // From cache
}
```

## Next Steps

1. **Install the SDK** for your language
2. **Get your API key** from [PromptSentinel Dashboard](https://dashboard.promptsentinel.com)
3. **Run the examples** in this guide
4. **Read the full documentation**:
   - [API Examples](./API_EXAMPLES.md)
   - [Integration Guides](./integrations/)
   - [Troubleshooting](./TROUBLESHOOTING.md)
5. **Join the community** on [Discord](https://discord.gg/promptsentinel)

## Support

- **Documentation**: [docs.promptsentinel.com](https://docs.promptsentinel.com)
- **GitHub**: [github.com/promptsentinel](https://github.com/promptsentinel)
- **Email**: support@promptsentinel.com
- **Discord**: [discord.gg/promptsentinel](https://discord.gg/promptsentinel)