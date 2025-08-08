import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';
import { PromptSentinel } from '../src/client';
import { Role, Verdict, DetectionMode } from '../src/types';
import { ValidationError, RateLimitError } from '../src/errors';

describe('PromptSentinel Client', () => {
  let client: PromptSentinel;
  let mock: MockAdapter;

  beforeEach(() => {
    client = new PromptSentinel({ baseUrl: 'http://test.local' });
    mock = new MockAdapter(axios);
  });

  afterEach(() => {
    mock.restore();
  });

  describe('detectSimple', () => {
    it('should detect simple prompt', async () => {
      const mockResponse = {
        verdict: Verdict.ALLOW,
        confidence: 0.95,
        reasons: [],
        categories: [],
        pii_detected: false,
        pii_types: [],
        format_issues: [],
        recommendations: [],
        processing_time_ms: 50,
        timestamp: '2025-01-08T10:00:00Z',
        metadata: {},
      };

      mock.onPost('http://test.local/v1/detect').reply(200, mockResponse);

      const result = await client.detectSimple('Hello, world!');
      expect(result.verdict).toBe(Verdict.ALLOW);
      expect(result.confidence).toBe(0.95);
    });

    it('should handle validation error', async () => {
      mock.onPost('http://test.local/v1/detect').reply(422, {
        detail: 'Invalid prompt format',
      });

      await expect(client.detectSimple('')).rejects.toThrow(ValidationError);
    });
  });

  describe('detectMessages', () => {
    it('should detect messages with roles', async () => {
      const messages = [
        { role: Role.SYSTEM, content: 'You are a helpful assistant' },
        { role: Role.USER, content: 'Hello!' },
      ];

      const mockResponse = {
        verdict: Verdict.ALLOW,
        confidence: 0.99,
        reasons: [],
        categories: [],
        pii_detected: false,
        pii_types: [],
        format_issues: [],
        recommendations: [],
        processing_time_ms: 75,
        timestamp: '2025-01-08T10:00:00Z',
        metadata: {},
      };

      mock.onPost('http://test.local/v2/detect').reply(200, mockResponse);

      const result = await client.detectMessages(messages);
      expect(result.verdict).toBe(Verdict.ALLOW);
    });
  });

  describe('batchDetect', () => {
    it('should process batch of prompts', async () => {
      const prompts = [
        { id: '1', prompt: 'Hello' },
        { id: '2', prompt: 'World' },
      ];

      const mockResponse = {
        results: [
          { id: '1', verdict: 'allow', confidence: 0.95 },
          { id: '2', verdict: 'allow', confidence: 0.98 },
        ],
        processed: 2,
        timestamp: '2025-01-08T10:00:00Z',
      };

      mock.onPost('http://test.local/v2/batch').reply(200, mockResponse);

      const result = await client.batchDetect(prompts);
      expect(result.processed).toBe(2);
      expect(result.results.length).toBe(2);
    });
  });

  describe('rate limiting', () => {
    it('should handle rate limit errors', async () => {
      mock.onPost('http://test.local/v1/detect').reply(429, 
        { detail: 'Rate limit exceeded' },
        { 'retry-after': '60' }
      );

      try {
        await client.detectSimple('test');
        fail('Should have thrown RateLimitError');
      } catch (error) {
        expect(error).toBeInstanceOf(RateLimitError);
        expect((error as RateLimitError).retryAfter).toBe(60);
      }
    });
  });

  describe('helper methods', () => {
    it('should create message correctly', () => {
      const message = client.createMessage(Role.USER, 'Hello');
      expect(message.role).toBe(Role.USER);
      expect(message.content).toBe('Hello');
    });

    it('should create conversation correctly', () => {
      const messages = client.createConversation(
        'You are helpful',
        'Help me'
      );
      expect(messages.length).toBe(2);
      expect(messages[0].role).toBe(Role.SYSTEM);
      expect(messages[1].role).toBe(Role.USER);
    });

    it('should check if prompt is safe', async () => {
      mock.onPost('http://test.local/v1/detect').reply(200, {
        verdict: Verdict.ALLOW,
        confidence: 0.95,
        reasons: [],
        categories: [],
        pii_detected: false,
        pii_types: [],
        format_issues: [],
        recommendations: [],
        processing_time_ms: 50,
        timestamp: '2025-01-08T10:00:00Z',
        metadata: {},
      });

      const isSafe = await client.isSafe('Hello');
      expect(isSafe).toBe(true);
    });
  });
});