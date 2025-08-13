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
    // Mock the client's axios instance, not the global one
    mock = new MockAdapter((client as any).client);
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

      mock.onPost('http://test.local/api/v1/detect').reply(200, mockResponse);

      const result = await client.detectSimple('Hello, world!');
      expect(result.verdict).toBe(Verdict.ALLOW);
      expect(result.confidence).toBe(0.95);
    });

    it('should handle validation error', async () => {
      mock.onPost('http://test.local/api/v1/detect').reply(422, {
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

      mock.onPost('http://test.local/api/v1/detect').reply(200, mockResponse);

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

      mock.onPost('http://test.local/api/v1/batch').reply(200, mockResponse);

      const result = await client.batchDetect(prompts);
      expect(result.processed).toBe(2);
      expect(result.results.length).toBe(2);
    });
  });

  describe('rate limiting', () => {
    it('should handle rate limit errors', async () => {
      mock.onPost('http://test.local/api/v1/detect').reply(429, 
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
      mock.onPost('http://test.local/api/v1/detect').reply(200, {
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

  describe('Threat Intelligence Methods', () => {
    describe('addThreatFeed', () => {
      it('should add a new threat feed', async () => {
        const feedData = {
          name: 'Test Feed',
          description: 'Test threat feed',
          type: 'json',
          url: 'https://example.com/feed.json',
          refresh_interval: 3600,
          priority: 5,
        };

        const mockResponse = {
          id: 'test_feed',
          ...feedData,
          enabled: true,
          last_fetch: null,
          statistics: {},
        };

        mock.onPost('http://test.local/api/v1/threat/feeds').reply(200, mockResponse);

        const result = await client.addThreatFeed(feedData);
        expect(result.id).toBe('test_feed');
        expect(result.name).toBe('Test Feed');
      });
    });

    describe('listThreatFeeds', () => {
      it('should list all threat feeds', async () => {
        const mockFeeds = [
          { id: 'feed1', name: 'Feed 1', type: 'json' },
          { id: 'feed2', name: 'Feed 2', type: 'csv' },
        ];

        mock.onGet('http://test.local/api/v1/threat/feeds').reply(200, mockFeeds);

        const result = await client.listThreatFeeds();
        expect(result).toHaveLength(2);
        expect(result[0].name).toBe('Feed 1');
      });
    });

    describe('getThreatFeed', () => {
      it('should get a specific threat feed', async () => {
        const mockFeed = {
          id: 'test_feed',
          name: 'Test Feed',
          type: 'json',
          enabled: true,
        };

        mock.onGet('http://test.local/api/v1/threat/feeds/test_feed').reply(200, mockFeed);

        const result = await client.getThreatFeed('test_feed');
        expect(result.id).toBe('test_feed');
        expect(result.name).toBe('Test Feed');
      });
    });

    describe('updateThreatFeed', () => {
      it('should trigger feed update', async () => {
        const mockResponse = {
          success: true,
          indicators_added: 10,
          indicators_updated: 5,
        };

        mock.onPost('http://test.local/api/v1/threat/feeds/test_feed/update').reply(200, mockResponse);

        const result = await client.updateThreatFeed('test_feed');
        expect(result.success).toBe(true);
        expect(result.indicators_added).toBe(10);
      });
    });

    describe('removeThreatFeed', () => {
      it('should remove a threat feed', async () => {
        mock.onDelete('http://test.local/api/v1/threat/feeds/test_feed').reply(204);

        const result = await client.removeThreatFeed('test_feed');
        expect(result).toBe(true);
      });
    });

    describe('getThreatIndicators', () => {
      it('should get active threat indicators', async () => {
        const mockIndicators = [
          {
            id: 'ind1',
            pattern: 'ignore.*instructions',
            confidence: 0.9,
            technique: 'jailbreak',
          },
          {
            id: 'ind2',
            pattern: 'DAN mode',
            confidence: 0.95,
            technique: 'jailbreak',
          },
        ];

        mock.onGet('http://test.local/api/v1/threat/indicators').reply(200, mockIndicators);

        const result = await client.getThreatIndicators();
        expect(result).toHaveLength(2);
        expect(result[0].pattern).toBe('ignore.*instructions');
      });

      it('should filter indicators by technique', async () => {
        const mockIndicators = [
          {
            id: 'ind1',
            pattern: 'role play',
            confidence: 0.85,
            technique: 'role_play',
          },
        ];

        mock.onGet('http://test.local/api/v1/threat/indicators', {
          params: { technique: 'role_play', min_confidence: 0.0, limit: 100 },
        }).reply(200, mockIndicators);

        const result = await client.getThreatIndicators({ technique: 'role_play' });
        expect(result).toHaveLength(1);
        expect(result[0].technique).toBe('role_play');
      });
    });

    describe('searchThreatIndicators', () => {
      it('should search threat indicators', async () => {
        const mockResults = [
          {
            id: 'ind1',
            pattern: 'jailbreak attempt',
            description: 'Common jailbreak pattern',
          },
        ];

        mock.onGet('http://test.local/api/v1/threat/indicators/search').reply(200, mockResults);

        const result = await client.searchThreatIndicators('jailbreak');
        expect(result).toHaveLength(1);
        expect(result[0].pattern).toContain('jailbreak');
      });
    });

    describe('reportFalsePositive', () => {
      it('should report a false positive', async () => {
        const mockResponse = {
          success: true,
          indicator_id: 'ind1',
          false_positive_count: 3,
          confidence_adjusted: 0.75,
        };

        mock.onPost('http://test.local/api/v1/threat/indicators/ind1/false-positive').reply(200, mockResponse);

        const result = await client.reportFalsePositive('ind1', 'Not actually malicious');
        expect(result.success).toBe(true);
        expect(result.confidence_adjusted).toBe(0.75);
      });
    });

    describe('confirmTruePositive', () => {
      it('should confirm a true positive', async () => {
        const mockResponse = {
          success: true,
          indicator_id: 'ind1',
          true_positive_count: 10,
          confidence_adjusted: 0.98,
        };

        mock.onPost('http://test.local/api/v1/threat/indicators/ind1/true-positive').reply(200, mockResponse);

        const result = await client.confirmTruePositive('ind1', 'Confirmed malicious');
        expect(result.success).toBe(true);
        expect(result.confidence_adjusted).toBe(0.98);
      });
    });

    describe('getThreatStatistics', () => {
      it('should get threat statistics', async () => {
        const mockStats = {
          total_feeds: 5,
          active_feeds: 4,
          total_indicators: 1500,
          active_indicators: 1200,
          false_positives_last_7d: 15,
          true_positives_last_7d: 85,
          average_confidence: 0.87,
        };

        mock.onGet('http://test.local/api/v1/threat/statistics').reply(200, mockStats);

        const result = await client.getThreatStatistics();
        expect(result.total_feeds).toBe(5);
        expect(result.active_indicators).toBe(1200);
        expect(result.average_confidence).toBe(0.87);
      });
    });
  });
});