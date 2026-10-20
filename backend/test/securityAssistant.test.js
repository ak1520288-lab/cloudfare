const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecurityAssistant } = require('../src/services/securityAssistant');

test('security assistant sends questions through OpenRouter using a server-side key', async () => {
  let request;
  const assistant = createSecurityAssistant({
    apiKey: 'test-openrouter-key',
    model: 'openrouter/free',
    fetchImpl: async (url, options) => {
      request = { url, options };
      return {
        ok: true,
        async json() {
          return { choices: [{ message: { content: 'Use a rate limiter.' } }] };
        },
      };
    },
  });

  const history = [{ role: 'user', content: 'What is a WAF?' }];
  assert.equal(await assistant('How can I reduce brute-force logins?', history), 'Use a rate limiter.');
  assert.equal(request.url, 'https://openrouter.ai/api/v1/chat/completions');
  assert.equal(request.options.headers.Authorization, 'Bearer test-openrouter-key');
  const payload = JSON.parse(request.options.body);
  assert.equal(payload.model, 'openrouter/free');
  assert.equal(payload.messages[2].content, 'How can I reduce brute-force logins?');
  assert.deepEqual(payload.messages.slice(0, 3), [
    payload.messages[0],
    { role: 'user', content: 'What is a WAF?' },
    { role: 'user', content: 'How can I reduce brute-force logins?' },
  ]);
  assert.equal(payload.messages[0].role, 'system');
});

test('security assistant reports missing OpenRouter configuration without calling the provider', async () => {
  const assistant = createSecurityAssistant({
    apiKey: '',
    model: 'openrouter/free',
    fetchImpl: async () => {
      throw new Error('Should not be called.');
    },
  });

  await assert.rejects(assistant('What is a WAF?'), {
    status: 503,
    message: /OPENROUTER_API_KEY/,
  });
});
