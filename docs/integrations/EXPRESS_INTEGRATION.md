# Express.js Integration Guide

This guide demonstrates how to integrate PromptSentinel with Express.js applications for comprehensive prompt injection detection and security.

## Table of Contents
- [Installation](#installation)
- [Basic Setup](#basic-setup)
- [Middleware Integration](#middleware-integration)
- [Advanced Patterns](#advanced-patterns)
- [WebSocket Support](#websocket-support)
- [Error Handling](#error-handling)
- [Performance Optimization](#performance-optimization)
- [Production Deployment](#production-deployment)

## Installation

```bash
# Install Express and PromptSentinel SDK
npm install express promptsentinel

# With TypeScript support
npm install --save-dev @types/express @types/node typescript

# Additional recommended packages
npm install cors helmet express-rate-limit dotenv
```

## Basic Setup

### Simple Integration

```javascript
const express = require('express');
const { PromptSentinel } = require('promptsentinel');

const app = express();
app.use(express.json());

// Initialize PromptSentinel client
const sentinel = new PromptSentinel({
  apiKey: process.env.PROMPTSENTINEL_API_KEY,
  baseUrl: 'http://localhost:8080' // Or your deployment URL
});

app.post('/api/generate', async (req, res) => {
  try {
    const { prompt } = req.body;
    
    // Detect threats before processing
    const detection = await sentinel.detect({ prompt });
    
    if (detection.verdict === 'block') {
      return res.status(400).json({
        error: 'Security threat detected',
        reason: detection.reasons[0].description
      });
    }
    
    // Process safe prompt
    const result = await processWithLLM(prompt);
    
    res.json({
      result,
      safe: detection.verdict === 'allow'
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

### TypeScript Setup

```typescript
import express, { Request, Response, NextFunction } from 'express';
import { PromptSentinel, DetectionResponse, Verdict } from 'promptsentinel';

const app = express();
app.use(express.json());

// Initialize with type safety
const sentinel = new PromptSentinel({
  apiKey: process.env.PROMPTSENTINEL_API_KEY!,
  baseUrl: process.env.PROMPTSENTINEL_BASE_URL || 'http://localhost:8080'
});

interface GenerateRequest {
  prompt: string;
  maxTokens?: number;
}

interface GenerateResponse {
  result: string;
  safe: boolean;
  modifiedPrompt?: string;
}

app.post<{}, GenerateResponse, GenerateRequest>(
  '/api/generate',
  async (req, res) => {
    const { prompt } = req.body;
    
    if (!prompt) {
      return res.status(400).json({ 
        error: 'Prompt is required' 
      } as any);
    }
    
    try {
      const detection: DetectionResponse = await sentinel.detect({ prompt });
      
      if (detection.verdict === Verdict.BLOCK) {
        return res.status(400).json({
          error: 'Security threat detected',
          threats: detection.reasons.map(r => r.category)
        } as any);
      }
      
      // Use sanitized prompt if available
      const safePrompt = detection.modified_prompt || prompt;
      const result = await processWithLLM(safePrompt);
      
      res.json({
        result,
        safe: detection.verdict === Verdict.ALLOW,
        modifiedPrompt: detection.modified_prompt
      });
    } catch (error) {
      console.error('Detection error:', error);
      res.status(500).json({ error: 'Internal server error' } as any);
    }
  }
);
```

## Middleware Integration

### Custom Security Middleware

Create reusable middleware for automatic prompt validation:

```javascript
// middleware/promptSecurity.js
const { PromptSentinel } = require('promptsentinel');

class PromptSecurityMiddleware {
  constructor(config = {}) {
    this.sentinel = new PromptSentinel({
      apiKey: config.apiKey || process.env.PROMPTSENTINEL_API_KEY,
      baseUrl: config.baseUrl || 'http://localhost:8080'
    });
    
    this.protectedPaths = config.protectedPaths || ['/api/'];
    this.promptFields = config.promptFields || ['prompt', 'query', 'input', 'message', 'text'];
    this.detectionMode = config.detectionMode || 'moderate';
  }
  
  middleware() {
    return async (req, res, next) => {
      // Check if path needs protection
      const needsProtection = this.protectedPaths.some(path => 
        req.path.startsWith(path)
      );
      
      if (!needsProtection || req.method !== 'POST') {
        return next();
      }
      
      try {
        // Check all prompt fields in request body
        for (const field of this.promptFields) {
          if (req.body && req.body[field]) {
            const detection = await this.sentinel.detect({
              prompt: req.body[field],
              detectionMode: this.detectionMode
            });
            
            if (detection.verdict === 'block') {
              return res.status(400).json({
                error: 'Security threat detected',
                field,
                category: detection.reasons[0].category,
                description: detection.reasons[0].description
              });
            }
            
            // Add detection results to request
            req.promptDetection = req.promptDetection || {};
            req.promptDetection[field] = detection;
            
            // Replace with sanitized version if available
            if (detection.modified_prompt) {
              req.body[`${field}_original`] = req.body[field];
              req.body[field] = detection.modified_prompt;
            }
          }
        }
        
        next();
      } catch (error) {
        console.error('PromptSentinel middleware error:', error);
        
        // Fail open or closed based on configuration
        if (config.failClosed) {
          return res.status(503).json({
            error: 'Security validation unavailable'
          });
        }
        
        next();
      }
    };
  }
}

// Usage
const promptSecurity = new PromptSecurityMiddleware({
  detectionMode: 'strict',
  protectedPaths: ['/api/', '/v1/'],
  failClosed: true
});

app.use(promptSecurity.middleware());
```

### Rate Limiting with Security

```javascript
const rateLimit = require('express-rate-limit');

// Create rate limiter with security context
const createSecurityLimiter = (sentinel) => {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: async (req, res) => {
      // Check if previous requests had threats
      const threatCount = req.session?.threatCount || 0;
      
      if (threatCount > 5) {
        return 5; // Strict limit for suspicious users
      }
      return 100; // Normal limit
    },
    handler: async (req, res) => {
      res.status(429).json({
        error: 'Too many requests',
        retryAfter: res.getHeader('Retry-After')
      });
    },
    skip: async (req) => {
      // Skip rate limiting for safe, cached requests
      if (req.promptDetection?.cached) {
        return true;
      }
      return false;
    }
  });
};

app.use('/api/', createSecurityLimiter(sentinel));
```

## Advanced Patterns

### Request Validation Pipeline

```javascript
// validation/pipeline.js
class ValidationPipeline {
  constructor(sentinel) {
    this.sentinel = sentinel;
    this.validators = [];
  }
  
  add(validator) {
    this.validators.push(validator);
    return this;
  }
  
  async validate(req, res, next) {
    const context = {
      req,
      res,
      sentinel: this.sentinel,
      errors: [],
      warnings: []
    };
    
    try {
      for (const validator of this.validators) {
        const result = await validator(context);
        
        if (result === false) {
          return res.status(400).json({
            errors: context.errors,
            warnings: context.warnings
          });
        }
      }
      
      req.validationContext = context;
      next();
    } catch (error) {
      console.error('Validation pipeline error:', error);
      res.status(500).json({ error: 'Validation failed' });
    }
  }
}

// Validators
const promptLengthValidator = async (context) => {
  const { req } = context;
  if (req.body.prompt && req.body.prompt.length > 10000) {
    context.errors.push('Prompt exceeds maximum length');
    return false;
  }
  return true;
};

const injectionDetector = async (context) => {
  const { req, sentinel } = context;
  if (req.body.prompt) {
    const detection = await sentinel.detect({
      prompt: req.body.prompt,
      checkFormat: true
    });
    
    if (detection.verdict === 'block') {
      context.errors.push(`Security threat: ${detection.reasons[0].description}`);
      return false;
    }
    
    if (detection.format_recommendations) {
      context.warnings.push(...detection.format_recommendations);
    }
    
    context.detection = detection;
  }
  return true;
};

const piiDetector = async (context) => {
  const { detection } = context;
  if (detection?.pii_detected && detection.pii_detected.length > 0) {
    context.warnings.push('PII detected in prompt');
    
    // Use sanitized version
    if (detection.modified_prompt) {
      context.req.body.prompt = detection.modified_prompt;
      context.req.body.pii_redacted = true;
    }
  }
  return true;
};

// Setup pipeline
const pipeline = new ValidationPipeline(sentinel)
  .add(promptLengthValidator)
  .add(injectionDetector)
  .add(piiDetector);

app.post('/api/secure-generate', 
  (req, res, next) => pipeline.validate(req, res, next),
  async (req, res) => {
    // Process validated request
    const { prompt, pii_redacted } = req.body;
    const { warnings } = req.validationContext;
    
    const result = await generateResponse(prompt);
    
    res.json({
      result,
      warnings,
      pii_redacted: pii_redacted || false
    });
  }
);
```

### Conversation Context Management

```javascript
// services/conversationService.js
class ConversationService {
  constructor(sentinel) {
    this.sentinel = sentinel;
    this.conversations = new Map();
  }
  
  async processMessage(sessionId, message, role = 'user') {
    // Get or create conversation
    if (!this.conversations.has(sessionId)) {
      this.conversations.set(sessionId, {
        messages: [],
        threats: [],
        startedAt: new Date()
      });
    }
    
    const conversation = this.conversations.get(sessionId);
    
    // Add message to history
    conversation.messages.push({ role, content: message });
    
    // Validate entire conversation context
    const detection = await this.sentinel.detectMessages(
      conversation.messages,
      {
        checkFormat: true,
        detectionMode: 'strict'
      }
    );
    
    if (detection.verdict === 'block') {
      conversation.threats.push({
        timestamp: new Date(),
        category: detection.reasons[0].category,
        message: message
      });
      
      // Check for escalation patterns
      if (conversation.threats.length > 3) {
        this.flagSession(sessionId, 'Multiple threat attempts');
      }
      
      throw new SecurityError('Conversation contains threats', detection);
    }
    
    return {
      safe: true,
      messageCount: conversation.messages.length,
      detection
    };
  }
  
  flagSession(sessionId, reason) {
    console.warn(`Session flagged: ${sessionId} - ${reason}`);
    // Implement alerting/blocking logic
  }
  
  clearSession(sessionId) {
    this.conversations.delete(sessionId);
  }
}

// Usage in routes
const conversationService = new ConversationService(sentinel);

app.post('/api/chat', async (req, res) => {
  const { sessionId, message, role } = req.body;
  
  try {
    const result = await conversationService.processMessage(
      sessionId, 
      message, 
      role
    );
    
    if (result.safe) {
      const response = await generateChatResponse(message);
      
      // Add assistant response to conversation
      await conversationService.processMessage(
        sessionId,
        response,
        'assistant'
      );
      
      res.json({ response });
    }
  } catch (error) {
    if (error instanceof SecurityError) {
      res.status(400).json({
        error: 'Security threat detected',
        details: error.detection.reasons
      });
    } else {
      res.status(500).json({ error: 'Chat processing failed' });
    }
  }
});
```

## WebSocket Support

### Real-time Detection with Socket.io

```javascript
const { Server } = require('socket.io');
const http = require('http');

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:3001'
  }
});

// WebSocket authentication
io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  
  try {
    // Verify token
    const user = await verifyToken(token);
    socket.userId = user.id;
    next();
  } catch (error) {
    next(new Error('Authentication failed'));
  }
});

// Handle connections
io.on('connection', (socket) => {
  console.log(`User connected: ${socket.userId}`);
  
  // Real-time prompt validation
  socket.on('validate-prompt', async (data, callback) => {
    try {
      const detection = await sentinel.detect({
        prompt: data.prompt,
        useCache: true
      });
      
      callback({
        valid: detection.verdict !== 'block',
        verdict: detection.verdict,
        confidence: detection.confidence,
        warnings: detection.reasons?.map(r => r.description)
      });
    } catch (error) {
      callback({ error: 'Validation failed' });
    }
  });
  
  // Streaming detection
  socket.on('stream-detection', async (data) => {
    try {
      const chunks = data.prompt.match(/.{1,100}/g) || [];
      
      for (const chunk of chunks) {
        const detection = await sentinel.detect({
          prompt: chunk,
          useCache: true
        });
        
        socket.emit('detection-chunk', {
          chunk,
          verdict: detection.verdict,
          safe: detection.verdict === 'allow'
        });
        
        if (detection.verdict === 'block') {
          socket.emit('detection-complete', {
            blocked: true,
            reason: detection.reasons[0].description
          });
          break;
        }
      }
      
      socket.emit('detection-complete', { blocked: false });
    } catch (error) {
      socket.emit('detection-error', { error: error.message });
    }
  });
  
  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.userId}`);
  });
});

server.listen(3000, () => {
  console.log('Server with WebSocket support running on port 3000');
});
```

## Error Handling

### Comprehensive Error Management

```javascript
// errors/handlers.js
const {
  PromptSentinelError,
  AuthenticationError,
  RateLimitError,
  ValidationError,
  ServiceUnavailableError
} = require('promptsentinel');

// Retry with exponential backoff
async function withRetry(fn, options = {}) {
  const {
    maxRetries = 3,
    backoffFactor = 2,
    initialDelay = 1000
  } = options;
  
  let lastError;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      if (error instanceof RateLimitError) {
        const waitTime = error.retryAfter * 1000 || 
                        initialDelay * Math.pow(backoffFactor, attempt);
        console.log(`Rate limited, waiting ${waitTime}ms...`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
      } else if (error instanceof ServiceUnavailableError) {
        const waitTime = initialDelay * Math.pow(backoffFactor, attempt);
        console.log(`Service unavailable, retrying in ${waitTime}ms...`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
      } else if (error instanceof AuthenticationError || 
                 error instanceof ValidationError) {
        // Don't retry these errors
        throw error;
      } else {
        // Unknown error, retry with backoff
        const waitTime = initialDelay * Math.pow(backoffFactor, attempt);
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    }
  }
  
  throw lastError;
}

// Global error handler middleware
function errorHandler(err, req, res, next) {
  console.error('Error:', err);
  
  if (err instanceof AuthenticationError) {
    return res.status(401).json({
      error: 'Authentication failed',
      message: 'Please check your API key'
    });
  }
  
  if (err instanceof RateLimitError) {
    return res.status(429).json({
      error: 'Rate limit exceeded',
      retryAfter: err.retryAfter,
      message: 'Too many requests, please slow down'
    });
  }
  
  if (err instanceof ValidationError) {
    return res.status(422).json({
      error: 'Validation failed',
      message: err.message
    });
  }
  
  if (err instanceof ServiceUnavailableError) {
    return res.status(503).json({
      error: 'Service temporarily unavailable',
      message: 'Please try again later'
    });
  }
  
  // Default error response
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'An error occurred'
  });
}

// Usage
app.post('/api/generate-with-retry', async (req, res, next) => {
  try {
    const result = await withRetry(async () => {
      const detection = await sentinel.detect({
        prompt: req.body.prompt
      });
      
      if (detection.verdict === 'block') {
        throw new ValidationError('Prompt contains security threats');
      }
      
      return await generateResponse(req.body.prompt);
    });
    
    res.json({ result });
  } catch (error) {
    next(error);
  }
});

app.use(errorHandler);
```

## Performance Optimization

### Caching Strategy

```javascript
const NodeCache = require('node-cache');

class CachedSentinel {
  constructor(sentinel, options = {}) {
    this.sentinel = sentinel;
    this.cache = new NodeCache({
      stdTTL: options.ttl || 3600,
      checkperiod: options.checkPeriod || 600,
      maxKeys: options.maxKeys || 10000
    });
    
    this.stats = {
      hits: 0,
      misses: 0,
      errors: 0
    };
  }
  
  async detect(options) {
    const cacheKey = this.getCacheKey(options);
    
    // Check cache
    const cached = this.cache.get(cacheKey);
    if (cached) {
      this.stats.hits++;
      return { ...cached, cached: true };
    }
    
    // Cache miss, perform detection
    this.stats.misses++;
    try {
      const result = await this.sentinel.detect(options);
      
      // Cache successful results
      if (result.verdict) {
        this.cache.set(cacheKey, result);
      }
      
      return result;
    } catch (error) {
      this.stats.errors++;
      throw error;
    }
  }
  
  getCacheKey(options) {
    const { prompt, messages, detectionMode = 'moderate' } = options;
    const content = prompt || JSON.stringify(messages);
    
    // Simple hash for cache key
    const crypto = require('crypto');
    return crypto
      .createHash('md5')
      .update(`${content}:${detectionMode}`)
      .digest('hex');
  }
  
  getStats() {
    const total = this.stats.hits + this.stats.misses;
    return {
      ...this.stats,
      hitRate: total > 0 ? (this.stats.hits / total) * 100 : 0
    };
  }
  
  clearCache() {
    this.cache.flushAll();
    this.stats = { hits: 0, misses: 0, errors: 0 };
  }
}

// Usage
const cachedSentinel = new CachedSentinel(sentinel, {
  ttl: 3600,
  maxKeys: 5000
});

app.post('/api/cached-generate', async (req, res) => {
  const detection = await cachedSentinel.detect({
    prompt: req.body.prompt
  });
  
  if (detection.cached) {
    res.set('X-Cache', 'HIT');
  } else {
    res.set('X-Cache', 'MISS');
  }
  
  if (detection.verdict === 'block') {
    return res.status(400).json({ error: 'Unsafe prompt' });
  }
  
  const result = await generateResponse(req.body.prompt);
  res.json({ result });
});

// Cache stats endpoint
app.get('/api/cache-stats', (req, res) => {
  res.json(cachedSentinel.getStats());
});
```

### Connection Pooling

```javascript
class SentinelPool {
  constructor(config, poolSize = 5) {
    this.clients = [];
    this.currentIndex = 0;
    
    for (let i = 0; i < poolSize; i++) {
      this.clients.push(new PromptSentinel(config));
    }
  }
  
  getClient() {
    const client = this.clients[this.currentIndex];
    this.currentIndex = (this.currentIndex + 1) % this.clients.length;
    return client;
  }
  
  async detect(options) {
    const client = this.getClient();
    return client.detect(options);
  }
  
  async healthCheck() {
    const checks = await Promise.allSettled(
      this.clients.map(client => client.healthCheck())
    );
    
    return {
      healthy: checks.filter(c => c.status === 'fulfilled').length,
      total: this.clients.length
    };
  }
}

// Usage
const sentinelPool = new SentinelPool(
  { apiKey: process.env.PROMPTSENTINEL_API_KEY },
  10
);

app.post('/api/pooled-detection', async (req, res) => {
  const detection = await sentinelPool.detect({
    prompt: req.body.prompt
  });
  
  res.json({ verdict: detection.verdict });
});
```

## Production Deployment

### Environment Configuration

```javascript
// config/index.js
require('dotenv').config();

const config = {
  app: {
    name: process.env.APP_NAME || 'Secure AI Service',
    port: parseInt(process.env.PORT || '3000'),
    env: process.env.NODE_ENV || 'development'
  },
  
  promptSentinel: {
    apiKey: process.env.PROMPTSENTINEL_API_KEY,
    baseUrl: process.env.PROMPTSENTINEL_BASE_URL || 'http://localhost:8080',
    timeout: parseInt(process.env.PROMPTSENTINEL_TIMEOUT || '30000'),
    maxRetries: parseInt(process.env.PROMPTSENTINEL_MAX_RETRIES || '3')
  },
  
  security: {
    detectionMode: process.env.DETECTION_MODE || 'moderate',
    enablePiiDetection: process.env.ENABLE_PII_DETECTION === 'true',
    maxPromptLength: parseInt(process.env.MAX_PROMPT_LENGTH || '10000'),
    failClosed: process.env.FAIL_CLOSED === 'true'
  },
  
  performance: {
    enableCaching: process.env.ENABLE_CACHING !== 'false',
    cacheTTL: parseInt(process.env.CACHE_TTL || '3600'),
    connectionPoolSize: parseInt(process.env.CONNECTION_POOL_SIZE || '10')
  }
};

module.exports = config;
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy application
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

USER nodejs

EXPOSE 3000

CMD ["node", "server.js"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PROMPTSENTINEL_API_KEY=${PROMPTSENTINEL_API_KEY}
      - PROMPTSENTINEL_BASE_URL=http://promptsentinel:8080
      - REDIS_URL=redis://redis:6379
    depends_on:
      - promptsentinel
      - redis
    restart: unless-stopped
    
  promptsentinel:
    image: promptsentinel/promptsentinel:latest
    ports:
      - "8080:8080"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - REDIS_URL=redis://redis:6379
    restart: unless-stopped
    
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

### Health Monitoring

```javascript
// health/monitoring.js
const express = require('express');
const router = express.Router();

router.get('/health', async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    services: {}
  };
  
  // Check PromptSentinel
  try {
    const sentinelHealth = await sentinel.healthCheck();
    health.services.promptsentinel = sentinelHealth.status;
  } catch (error) {
    health.services.promptsentinel = 'unhealthy';
    health.status = 'degraded';
  }
  
  // Check database
  try {
    await db.ping();
    health.services.database = 'healthy';
  } catch (error) {
    health.services.database = 'unhealthy';
    health.status = 'degraded';
  }
  
  const statusCode = health.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(health);
});

router.get('/metrics', async (req, res) => {
  const [usage, budget] = await Promise.all([
    sentinel.getUsage(24),
    sentinel.getBudgetStatus()
  ]);
  
  res.json({
    usage: {
      totalRequests: usage.total_requests,
      totalTokens: usage.total_tokens,
      estimatedCost: usage.estimated_cost,
      cacheHitRate: usage.cache_hit_rate
    },
    budget: {
      currentSpend: budget.current_spend,
      limit: budget.budget_limit,
      percentageUsed: budget.percentage_used
    },
    app: {
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      cpuUsage: process.cpuUsage()
    }
  });
});

app.use('/health', router);
```

### Complete Example Application

```javascript
// server.js
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { PromptSentinel } = require('promptsentinel');
const config = require('./config');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*'
}));
app.use(express.json({ limit: '1mb' }));

// Initialize PromptSentinel
const sentinel = new PromptSentinel(config.promptSentinel);

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.path} - ${res.statusCode} - ${duration}ms`);
  });
  
  next();
});

// Validation middleware
async function validatePrompt(req, res, next) {
  const { prompt } = req.body;
  
  if (!prompt) {
    return res.status(400).json({ error: 'Prompt is required' });
  }
  
  if (prompt.length > config.security.maxPromptLength) {
    return res.status(400).json({ error: 'Prompt too long' });
  }
  
  try {
    const detection = await sentinel.detect({
      prompt,
      detectionMode: config.security.detectionMode
    });
    
    if (detection.verdict === 'block') {
      return res.status(400).json({
        error: 'Security threat detected',
        threats: detection.reasons.map(r => ({
          category: r.category,
          description: r.description
        }))
      });
    }
    
    req.detection = detection;
    req.safePrompt = detection.modified_prompt || prompt;
    next();
  } catch (error) {
    console.error('Detection error:', error);
    
    if (config.security.failClosed) {
      return res.status(503).json({
        error: 'Security validation unavailable'
      });
    }
    
    // Fail open - proceed with caution
    req.safePrompt = prompt;
    next();
  }
}

// API routes
app.post('/api/generate', validatePrompt, async (req, res) => {
  try {
    const result = await generateWithLLM(req.safePrompt);
    
    res.json({
      result,
      metadata: {
        safe: req.detection?.verdict === 'allow',
        confidence: req.detection?.confidence,
        processingTime: req.detection?.processing_time_ms
      }
    });
  } catch (error) {
    console.error('Generation error:', error);
    res.status(500).json({ error: 'Generation failed' });
  }
});

// Health check
app.get('/health', async (req, res) => {
  try {
    const health = await sentinel.healthCheck();
    res.json({
      status: health.status,
      version: '1.0.0',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: config.app.env === 'development' ? err.message : undefined
  });
});

// Start server
const PORT = config.app.port;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${config.app.env}`);
  console.log(`Detection mode: ${config.security.detectionMode}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});
```

## Best Practices

1. **Always validate before processing** - Never send unvalidated input to LLMs
2. **Implement proper error handling** - Handle all error types gracefully
3. **Use middleware for consistency** - Apply security checks uniformly
4. **Enable caching strategically** - Cache detection results for performance
5. **Monitor and log threats** - Track blocked attempts for security analysis
6. **Implement rate limiting** - Prevent abuse and DoS attacks
7. **Use connection pooling** - Improve performance under load
8. **Set appropriate timeouts** - Prevent hanging requests
9. **Fail securely** - Decide between fail-open and fail-closed
10. **Keep dependencies updated** - Regularly update security patches

## Additional Resources

- [PromptSentinel Documentation](https://github.com/promptsentinel/promptsentinel)
- [Express.js Documentation](https://expressjs.com/)
- [API Examples](../API_EXAMPLES.md)
- [Security Best Practices](../../README.md#security-best-practices)