/**
 * PromptSentinel JavaScript/TypeScript SDK
 */

export { PromptSentinel, PromptSentinelConfig } from './client';
export {
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
  DetectionReason,
} from './types';
export {
  PromptSentinelError,
  AuthenticationError,
  RateLimitError,
  ValidationError,
  ServiceUnavailableError,
} from './errors';
export { VERSION } from './version';