/**
 * Type definitions for PromptSentinel SDK
 */

export enum Role {
  SYSTEM = 'system',
  USER = 'user',
  ASSISTANT = 'assistant',
}

export enum Verdict {
  ALLOW = 'allow',
  BLOCK = 'block',
  FLAG = 'flag',
  STRIP = 'strip',
  REDACT = 'redact',
}

export enum DetectionMode {
  STRICT = 'strict',
  MODERATE = 'moderate',
  PERMISSIVE = 'permissive',
}

export interface Message {
  role: Role;
  content: string;
}

export interface DetectionReason {
  category: string;
  description: string;
  confidence: number;
  source: string;
  patterns_matched: string[];
}

export interface DetectionRequest {
  messages?: Message[];
  prompt?: string;
  check_format?: boolean;
  use_cache?: boolean;
  detection_mode?: DetectionMode;
}

export interface DetectionResponse {
  verdict: Verdict;
  confidence: number;
  reasons: DetectionReason[];
  categories: string[];
  modified_prompt?: string;
  pii_detected: boolean;
  pii_types: string[];
  format_issues: string[];
  recommendations: string[];
  processing_time_ms: number;
  timestamp: string;
  metadata: Record<string, any>;
  routing_metadata?: Record<string, any>;
}

export interface BatchDetectionRequest {
  prompts: Array<{ id: string; prompt: string }>;
}

export interface BatchDetectionResponse {
  results: Array<{
    id: string;
    verdict?: string;
    confidence?: number;
    error?: string;
  }>;
  processed: number;
  timestamp: string;
}

export interface ComplexityAnalysis {
  complexity_level: string;
  complexity_score: number;
  metrics: Record<string, number>;
  risk_indicators: string[];
  recommendations: string[];
}

export interface UsageMetrics {
  request_count: number;
  token_usage: Record<string, number>;
  cost_breakdown: Record<string, number>;
  provider_stats: Record<string, any>;
  time_period: string;
}

export interface BudgetStatus {
  current_usage: Record<string, number>;
  budget_limits: Record<string, number>;
  alerts: Array<Record<string, any>>;
  projections: Record<string, number>;
}

export interface HealthStatus {
  status: string;
  version: string;
  providers: Record<string, Record<string, any>>;
  cache: Record<string, any>;
  detection_methods: string[];
}