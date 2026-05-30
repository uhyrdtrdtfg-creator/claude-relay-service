jest.mock(
  '../config/config',
  () => ({
    claude: {
      apiVersion: '2023-06-01',
      betaHeader: '',
      systemPrompt: ''
    },
    requestTimeout: 600000
  }),
  {
    virtual: true
  }
)

jest.mock('../src/utils/logger', () => ({
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
}))

jest.mock('../src/models/redis', () => ({
  getClientSafe: jest.fn(),
  getClient: jest.fn()
}))

jest.mock('../src/utils/proxyHelper', () => ({
  createProxyAgent: jest.fn()
}))

jest.mock('../src/services/account/claudeAccountService', () => ({
  getAccount: jest.fn(),
  getValidAccessToken: jest.fn(),
  isAccountOpusRateLimited: jest.fn()
}))

jest.mock('../src/services/scheduler/unifiedClaudeScheduler', () => ({
  selectAccount: jest.fn()
}))

jest.mock('../src/services/claudeCodeHeadersService', () => ({
  getAccountHeaders: jest.fn()
}))

jest.mock('../src/validators/clients/claudeCodeValidator', () => ({
  includesClaudeCodeSystemPrompt: jest.fn(() => true)
}))

jest.mock('../src/services/requestIdentityService', () => ({
  transform: jest.fn(({ body, headers }) => ({ body, headers }))
}))

jest.mock('../src/utils/testPayloadHelper', () => ({
  createClaudeTestPayload: jest.fn()
}))

jest.mock('../src/services/userMessageQueueService', () => ({
  isUserMessageRequest: jest.fn(() => false),
  acquireQueueLock: jest.fn(),
  releaseQueueLock: jest.fn()
}))

jest.mock('../src/utils/streamHelper', () => ({
  isStreamWritable: jest.fn(() => true)
}))

jest.mock('../src/utils/upstreamErrorHelper', () => ({
  parseUpstreamError: jest.fn()
}))

jest.mock('../src/utils/performanceOptimizer', () => ({
  getHttpsAgentForStream: jest.fn(),
  getHttpsAgentForNonStream: jest.fn(),
  getPricingData: jest.fn(() => null)
}))

const claudeRelayService = require('../src/services/relay/claudeRelayService')

const clone = (value) => JSON.parse(JSON.stringify(value))

describe('claudeRelayService thinking block preservation', () => {
  beforeEach(() => {
    claudeRelayService.systemPrompt = ''
  })

  it('keeps thinking and redacted_thinking blocks opaque during request cleanup', () => {
    const thinkingBlock = {
      type: 'thinking',
      thinking: 'private chain of thought',
      signature: 'sig-thinking',
      cache_control: { type: 'ephemeral', ttl: '5m' }
    }
    const redactedThinkingBlock = {
      type: 'redacted_thinking',
      data: 'opaque-redacted-data',
      cache_control: { type: 'ephemeral', ttl: '5m' }
    }

    const body = {
      model: 'claude-sonnet-4-5',
      max_tokens: 1024,
      messages: [
        {
          role: 'assistant',
          content: [
            clone(thinkingBlock),
            clone(redactedThinkingBlock),
            { type: 'text', text: 'a', cache_control: { type: 'ephemeral', ttl: '5m' } },
            { type: 'text', text: 'b', cache_control: { type: 'ephemeral', ttl: '5m' } },
            { type: 'text', text: 'c', cache_control: { type: 'ephemeral', ttl: '5m' } },
            { type: 'text', text: 'd', cache_control: { type: 'ephemeral', ttl: '5m' } },
            { type: 'text', text: 'e', cache_control: { type: 'ephemeral', ttl: '5m' } }
          ]
        },
        {
          role: 'user',
          content: [{ type: 'text', text: 'continue' }]
        }
      ]
    }

    const processed = claudeRelayService._processRequestBody(body, null, true)

    expect(processed.messages[0].content[0]).toEqual(thinkingBlock)
    expect(processed.messages[0].content[1]).toEqual(redactedThinkingBlock)
  })

  it('continues to strip cache_control ttl from non-thinking blocks', () => {
    const body = {
      model: 'claude-sonnet-4-5',
      max_tokens: 1024,
      system: [{ type: 'text', text: 'system', cache_control: { type: 'ephemeral', ttl: '5m' } }],
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'hello', cache_control: { type: 'ephemeral', ttl: '5m' } }
          ]
        }
      ]
    }

    const processed = claudeRelayService._processRequestBody(body, null, true)

    expect(processed.system[0].cache_control).toEqual({ type: 'ephemeral' })
    expect(processed.messages[0].content[0].cache_control).toEqual({ type: 'ephemeral' })
  })
})
