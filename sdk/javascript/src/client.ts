/**
 * PromptSentinel JavaScript/TypeScript Client
 */

import axios, { AxiosInstance, AxiosError, AxiosRequestConfig } from 'axios';
import {
  Message,
  DetectionRequest,
  DetectionResponse,
  BatchDetectionRequest,
  BatchDetectionResponse,
  ComplexityAnalysis,
  UsageMetrics,
  BudgetStatus,
  HealthStatus,
  Role,
  Verdict,
  DetectionMode,
} from './types';
import {
  PromptSentinelError,
  AuthenticationError,
  RateLimitError,
  ValidationError,
  ServiceUnavailableError,
} from './errors';

export interface PromptSentinelConfig {
  baseUrl?: string;
  apiKey?: string;
  timeout?: number;
  maxRetries?: number;
  headers?: Record<string, string>;
}

export class PromptSentinel {
  private client: AxiosInstance;
  private config: Required<PromptSentinelConfig>;

  constructor(config: PromptSentinelConfig = {}) {
    this.config = {
      baseUrl: config.baseUrl || process.env.PROMPTSENTINEL_BASE_URL || 'http://localhost:8080',
      apiKey: config.apiKey || process.env.PROMPTSENTINEL_API_KEY || '',
      timeout: config.timeout || 30000,
      maxRetries: config.maxRetries || 3,
      headers: config.headers || {},
    };

    this.client = axios.create({
      baseURL: this.config.baseUrl,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        ...this.config.headers,
        ...(this.config.apiKey ? { Authorization: `Bearer ${this.config.apiKey}` } : {}),
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    this.client.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };
        
        if (error.response) {
          const status = error.response.status;
          const data = error.response.data as any;

          if (status === 401) {
            throw new AuthenticationError(data?.detail || 'Authentication failed');
          } else if (status === 429) {
            const retryAfter = error.response.headers['retry-after'];
            throw new RateLimitError(
              data?.detail || 'Rate limit exceeded',
              retryAfter ? parseInt(retryAfter) : undefined
            );
          } else if (status === 422 || status === 400) {
            throw new ValidationError(data?.detail || 'Validation error');
          } else if (status === 503) {
            throw new ServiceUnavailableError(data?.detail || 'Service unavailable');
          } else if (status >= 500 && !originalRequest._retry && this.config.maxRetries > 0) {
            originalRequest._retry = true;
            await this.delay(1000);
            return this.client(originalRequest);
          }
        }

        throw new PromptSentinelError(
          error.message || 'Request failed',
          error.response?.status
        );
      }
    );
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Main detection method
   */
  async detect(
    options: {
      prompt?: string;
      messages?: Message[];
      checkFormat?: boolean;
      useCache?: boolean;
      detectionMode?: DetectionMode;
      useIntelligentRouting?: boolean;
    } = {}
  ): Promise<DetectionResponse> {
    if (options.useIntelligentRouting) {
      return this.detectV3(options);
    }
    
    if (options.messages) {
      return this.detectMessages(options.messages, {
        checkFormat: options.checkFormat,
        useCache: options.useCache,
        detectionMode: options.detectionMode,
      });
    }
    
    if (options.prompt) {
      return this.detectSimple(options.prompt, {
        checkFormat: options.checkFormat,
        useCache: options.useCache,
        detectionMode: options.detectionMode,
      });
    }
    
    throw new ValidationError('Either prompt or messages must be provided');
  }

  /**
   * Simple string detection (V1 API)
   */
  async detectSimple(
    prompt: string,
    options: {
      checkFormat?: boolean;
      useCache?: boolean;
      detectionMode?: DetectionMode;
    } = {}
  ): Promise<DetectionResponse> {
    const response = await this.client.post<DetectionResponse>('/v1/detect', {
      prompt,
      check_format: options.checkFormat,
      use_cache: options.useCache,
      detection_mode: options.detectionMode,
    });
    return response.data;
  }

  /**
   * Role-based detection (V2 API)
   */
  async detectMessages(
    messages: Message[],
    options: {
      checkFormat?: boolean;
      useCache?: boolean;
      detectionMode?: DetectionMode;
    } = {}
  ): Promise<DetectionResponse> {
    const response = await this.client.post<DetectionResponse>('/v2/detect', {
      messages,
      check_format: options.checkFormat,
      use_cache: options.useCache,
      detection_mode: options.detectionMode,
    });
    return response.data;
  }

  /**
   * Intelligent routing detection (V3 API)
   */
  private async detectV3(
    options: {
      prompt?: string;
      messages?: Message[];
      checkFormat?: boolean;
      useCache?: boolean;
      detectionMode?: DetectionMode;
    } = {}
  ): Promise<DetectionResponse> {
    const response = await this.client.post<DetectionResponse>('/v3/detect', {
      prompt: options.prompt,
      messages: options.messages,
      check_format: options.checkFormat,
      use_cache: options.useCache,
      detection_mode: options.detectionMode,
    });
    return response.data;
  }

  /**
   * Batch detection
   */
  async batchDetect(prompts: Array<{ id: string; prompt: string }>): Promise<BatchDetectionResponse> {
    const response = await this.client.post<BatchDetectionResponse>('/v2/batch', {
      prompts,
    });
    return response.data;
  }

  /**
   * Analyze prompt complexity
   */
  async analyzeComplexity(prompt: string): Promise<ComplexityAnalysis> {
    const response = await this.client.post<ComplexityAnalysis>('/v2/analyze/complexity', {
      prompt,
    });
    return response.data;
  }

  /**
   * Get usage metrics
   */
  async getUsage(timeWindowHours: number = 24): Promise<UsageMetrics> {
    const response = await this.client.get<UsageMetrics>('/monitoring/usage', {
      params: { time_window_hours: timeWindowHours },
    });
    return response.data;
  }

  /**
   * Get budget status
   */
  async getBudgetStatus(): Promise<BudgetStatus> {
    const response = await this.client.get<BudgetStatus>('/monitoring/budget');
    return response.data;
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<HealthStatus> {
    const response = await this.client.get<HealthStatus>('/health');
    return response.data;
  }

  /**
   * Helper method to create a message
   */
  createMessage(role: Role, content: string): Message {
    return { role, content };
  }

  /**
   * Helper method to create a conversation
   */
  createConversation(systemPrompt: string, userPrompt: string): Message[] {
    return [
      { role: Role.SYSTEM, content: systemPrompt },
      { role: Role.USER, content: userPrompt },
    ];
  }

  /**
   * Check if a prompt is safe
   */
  async isSafe(prompt: string): Promise<boolean> {
    const response = await this.detectSimple(prompt);
    return response.verdict === Verdict.ALLOW;
  }

  /**
   * Get modified prompt if available
   */
  async getModifiedPrompt(prompt: string): Promise<string | undefined> {
    const response = await this.detectSimple(prompt);
    return response.modified_prompt;
  }
}