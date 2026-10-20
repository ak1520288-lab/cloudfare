const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';

const SYSTEM_PROMPT = [
  'You are AntiFlair Security Assistant, a concise educational cybersecurity helper.',
  'Answer defensive security questions, explain concepts, and help with authorized local labs.',
  'Prefer practical, safe mitigations. Do not provide instructions for unauthorized access, credential theft, malware, evasion, or attacking real systems.',
  'Be honest about uncertainty and distinguish general guidance from features actually implemented in AntiFlair.',
  'AntiFlair is a learning project with an Express reverse proxy, Redis-backed IP blocks and rate limiting, basic pattern-based WAF checks, admin sessions, and MongoDB audit logs.',
  'Bot scoring, CAPTCHA, predictive alerts, and production-grade protection are not implemented.',
].join(' ');

function createSecurityAssistant({ apiKey, model, fetchImpl = fetch }) {
  return async function answerSecurityQuestion(question, history = []) {
    if (!apiKey) {
      const error = new Error('The security assistant is not configured. Add OPENROUTER_API_KEY to backend/.env and restart the backend.');
      error.status = 503;
      throw error;
    }

    let response;
    try {
      response = await fetchImpl(OPENROUTER_URL, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'http://localhost',
          'X-Title': 'AntiFlair Security Assistant',
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            ...history.map(({ role, content }) => ({ role, content })),
            { role: 'user', content: question },
          ],
          max_tokens: 700,
          temperature: 0.3,
        }),
        signal: AbortSignal.timeout(30000),
      });
    } catch (cause) {
      const error = new Error('Could not reach OpenRouter. Check the backend internet connection and try again.', { cause });
      error.status = 502;
      throw error;
    }

    if (response.status === 401 || response.status === 403) {
      const error = new Error('OpenRouter rejected the configured API key. Check OPENROUTER_API_KEY in backend/.env.');
      error.status = 502;
      throw error;
    }
    if (response.status === 429) {
      const error = new Error('OpenRouter rate limit reached. Please wait a moment and try again.');
      error.status = 429;
      throw error;
    }
    if (!response.ok) {
      const error = new Error('The security assistant provider is temporarily unavailable.');
      error.status = 502;
      throw error;
    }

    let data;
    try {
      data = await response.json();
    } catch (cause) {
      const error = new Error('The security assistant returned an invalid response.', { cause });
      error.status = 502;
      throw error;
    }

    const answer = data?.choices?.[0]?.message?.content;
    if (typeof answer !== 'string' || !answer.trim()) {
      const error = new Error('The security assistant returned an empty answer. Please try again.');
      error.status = 502;
      throw error;
    }
    return answer.trim().slice(0, 12000);
  };
}

module.exports = { createSecurityAssistant };
