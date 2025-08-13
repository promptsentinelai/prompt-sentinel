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
    const response = await this.client.post<DetectionResponse>('/api/v1/detect', {
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
    const response = await this.client.post<DetectionResponse>('/api/v1/detect', {
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
    const response = await this.client.post<DetectionResponse>('/api/v1/detect', {
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
    const response = await this.client.post<BatchDetectionResponse>('/api/v1/batch', {
      prompts,
    });
    return response.data;
  }

  /**
   * Analyze prompt complexity
   */
  async analyzeComplexity(prompt: string): Promise<ComplexityAnalysis> {
    const response = await this.client.post<ComplexityAnalysis>('/api/v1/analyze', {
      prompt,
    });
    return response.data;
  }

  /**
   * Get usage metrics
   */
  async getUsage(timeWindowHours: number = 24): Promise<UsageMetrics> {
    const response = await this.client.get<UsageMetrics>('/api/v1/monitoring/usage', {
      params: { time_window_hours: timeWindowHours },
    });
    return response.data;
  }

  /**
   * Get budget status
   */
  async getBudgetStatus(): Promise<BudgetStatus> {
    const response = await this.client.get<BudgetStatus>('/api/v1/monitoring/budget');
    return response.data;
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<HealthStatus> {
    const response = await this.client.get<HealthStatus>('/api/v1/health');
    return response.data;
  }

  // Threat Intelligence Methods

  /**
   * Add a new threat intelligence feed
   */
  async addThreatFeed(feedData: any): Promise<any> {
    const response = await this.client.post('/api/v1/threat/feeds', feedData);
    return response.data;
  }

  /**
   * List all threat intelligence feeds
   */
  async listThreatFeeds(): Promise<any[]> {
    const response = await this.client.get('/api/v1/threat/feeds');
    return response.data;
  }

  /**
   * Get a specific threat feed by ID
   */
  async getThreatFeed(feedId: string): Promise<any> {
    const response = await this.client.get(`/api/v1/threat/feeds/${feedId}`);
    return response.data;
  }

  /**
   * Manually trigger update of a threat feed
   */
  async updateThreatFeed(feedId: string): Promise<any> {
    const response = await this.client.post(`/api/v1/threat/feeds/${feedId}/update`);
    return response.data;
  }

  /**
   * Remove a threat feed
   */
  async removeThreatFeed(feedId: string): Promise<boolean> {
    const response = await this.client.delete(`/api/v1/threat/feeds/${feedId}`);
    return response.status === 204;
  }

  /**
   * Get active threat indicators
   */
  async getThreatIndicators(params?: {
    technique?: string;
    minConfidence?: number;
    limit?: number;
  }): Promise<any[]> {
    const response = await this.client.get('/api/v1/threat/indicators', {
      params: {
        technique: params?.technique,
        min_confidence: params?.minConfidence || 0.0,
        limit: params?.limit || 100,
      },
    });
    return response.data;
  }

  /**
   * Search threat indicators
   */
  async searchThreatIndicators(query: string, limit: number = 100): Promise<any[]> {
    const response = await this.client.get('/api/v1/threat/indicators/search', {
      params: { query, limit },
    });
    return response.data;
  }

  /**
   * Report a false positive for a threat indicator
   */
  async reportFalsePositive(indicatorId: string, reason?: string): Promise<any> {
    const response = await this.client.post(
      `/api/v1/threat/indicators/${indicatorId}/false-positive`,
      reason ? { reason } : {}
    );
    return response.data;
  }

  /**
   * Confirm a true positive detection
   */
  async confirmTruePositive(indicatorId: string, details?: string): Promise<any> {
    const response = await this.client.post(
      `/api/v1/threat/indicators/${indicatorId}/true-positive`,
      details ? { details } : {}
    );
    return response.data;
  }

  /**
   * Get overall threat intelligence statistics
   */
  async getThreatStatistics(): Promise<any> {
    const response = await this.client.get('/api/v1/threat/statistics');
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