// Provider-agnostic, dependency-free LLM client used for AI-assisted workflows.
// Each provider is called over plain HTTPS with a JSON-schema constrained response.

export const LLM_PROVIDERS = Object.freeze({
  anthropic: {
    defaultModel: 'claude-opus-5-5',
    keyEnv: ['ANTHROPIC_API_KEY'],
  },
  openai: {
    defaultModel: 'gpt-5',
    keyEnv: ['OPENAI_API_KEY'],
  },
  gemini: {
    defaultModel: 'gemini-2.5-pro',
    keyEnv: ['GEMINI_API_KEY', 'GOOGLE_API_KEY'],
  },
});

const PROVIDER_ALIASES = { claude: 'anthropic', google: 'gemini' };

function normalizeProvider(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) return null;
  const name = PROVIDER_ALIASES[raw] || raw;
  if (!LLM_PROVIDERS[name]) {
    throw new Error(
      `Unsupported LLM provider "${value}". Use one of: ${Object.keys(LLM_PROVIDERS).join(', ')}`
    );
  }
  return name;
}

function providerKeyFromEnv(provider, env) {
  for (const name of LLM_PROVIDERS[provider].keyEnv) {
    if (env[name]) return env[name];
  }
  return null;
}

// Resolution order:
//   provider: --provider flag, PERIAPSIS_LLM_PROVIDER, then the first provider with a key in env
//   apiKey:   PERIAPSIS_LLM_API_KEY, then the provider-specific variable
//   model:    --model flag, PERIAPSIS_LLM_MODEL, then the provider default
// API keys are intentionally never read from CLI flags so they stay out of shell history and logs.
export function resolveLlmConfig({ provider, model } = {}, env = process.env) {
  let resolvedProvider = normalizeProvider(provider) || normalizeProvider(env.PERIAPSIS_LLM_PROVIDER);

  if (!resolvedProvider) {
    if (env.PERIAPSIS_LLM_API_KEY) {
      throw new Error(
        'PERIAPSIS_LLM_API_KEY is set but no provider was given. Set PERIAPSIS_LLM_PROVIDER or pass --provider (anthropic, openai, gemini).'
      );
    }
    resolvedProvider = Object.keys(LLM_PROVIDERS).find((p) => providerKeyFromEnv(p, env)) || null;
  }

  if (!resolvedProvider) {
    throw new Error(
      'No LLM API key found. Set PERIAPSIS_LLM_PROVIDER and PERIAPSIS_LLM_API_KEY, or one of ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY.'
    );
  }

  const apiKey = env.PERIAPSIS_LLM_API_KEY || providerKeyFromEnv(resolvedProvider, env);
  if (!apiKey) {
    const names = ['PERIAPSIS_LLM_API_KEY', ...LLM_PROVIDERS[resolvedProvider].keyEnv].join(' or ');
    throw new Error(`No API key found for provider "${resolvedProvider}". Set ${names}.`);
  }

  const resolvedModel =
    String(model || '').trim() ||
    String(env.PERIAPSIS_LLM_MODEL || '').trim() ||
    LLM_PROVIDERS[resolvedProvider].defaultModel;

  return { provider: resolvedProvider, model: resolvedModel, apiKey };
}

async function postJson(url, headers, body, fetchImpl, label) {
  const response = await fetchImpl(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`${label} API error: ${response.status} ${response.statusText}${text ? ' - ' + text : ''}`);
  }
  return response.json();
}

async function callAnthropic({ apiKey, model, system, prompt, schema }, fetchImpl) {
  const data = await postJson(
    'https://api.anthropic.com/v1/messages',
    {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      // Security-analysis prompts can trip safety classifiers; let the API reroute declined requests.
      'anthropic-beta': 'server-side-fallback-2026-07-01',
    },
    {
      model,
      max_tokens: 16000,
      system,
      messages: [{ role: 'user', content: prompt }],
      output_config: {
        effort: 'high',
        format: { type: 'json_schema', schema },
      },
      fallbacks: 'default',
    },
    fetchImpl,
    'Anthropic'
  );

  if (data.stop_reason === 'refusal') {
    const category = data.stop_details?.category;
    throw new Error(`Anthropic declined the request${category ? ` (category: ${category})` : ''}.`);
  }
  if (data.stop_reason === 'max_tokens') {
    throw new Error('Anthropic response was truncated (max_tokens reached).');
  }
  const text = (data.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('');
  return { text, model: data.model || model };
}

async function callOpenAi({ apiKey, model, system, prompt, schema }, fetchImpl) {
  const data = await postJson(
    'https://api.openai.com/v1/chat/completions',
    { Authorization: `Bearer ${apiKey}` },
    {
      model,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: prompt },
      ],
      response_format: {
        type: 'json_schema',
        json_schema: { name: 'periapsis_result', strict: true, schema },
      },
    },
    fetchImpl,
    'OpenAI'
  );

  const choice = data.choices?.[0];
  if (choice?.message?.refusal) {
    throw new Error(`OpenAI declined the request: ${choice.message.refusal}`);
  }
  if (choice?.finish_reason === 'length') {
    throw new Error('OpenAI response was truncated (length limit reached).');
  }
  return { text: choice?.message?.content || '', model: data.model || model };
}

async function callGemini({ apiKey, model, system, prompt }, fetchImpl) {
  // Gemini's responseSchema uses an OpenAPI subset that rejects additionalProperties, so we request
  // JSON output and rely on the prompt + local validation for the shape.
  const data = await postJson(
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
    { 'x-goog-api-key': apiKey },
    {
      systemInstruction: { parts: [{ text: system }] },
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { responseMimeType: 'application/json' },
    },
    fetchImpl,
    'Gemini'
  );

  const candidate = data.candidates?.[0];
  if (!candidate) {
    const reason = data.promptFeedback?.blockReason;
    throw new Error(`Gemini returned no candidates${reason ? ` (blocked: ${reason})` : ''}.`);
  }
  if (candidate.finishReason === 'MAX_TOKENS') {
    throw new Error('Gemini response was truncated (MAX_TOKENS reached).');
  }
  const text = (candidate.content?.parts || []).map((p) => p.text || '').join('');
  return { text, model: data.modelVersion || model };
}

const CALLERS = { anthropic: callAnthropic, openai: callOpenAi, gemini: callGemini };

function parseJsonText(text) {
  const trimmed = String(text || '').trim();
  // Tolerate a fenced ```json block from providers without hard schema enforcement.
  const fenced = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/);
  return JSON.parse(fenced ? fenced[1] : trimmed);
}

export async function requestStructuredJson(
  { provider, model, apiKey, system, prompt, schema },
  { fetchImpl = fetch } = {}
) {
  const caller = CALLERS[provider];
  if (!caller) {
    throw new Error(`Unsupported LLM provider "${provider}".`);
  }
  const { text, model: usedModel } = await caller({ apiKey, model, system, prompt, schema }, fetchImpl);
  let json;
  try {
    json = parseJsonText(text);
  } catch (err) {
    throw new Error(`${provider} returned a response that is not valid JSON: ${err.message}`);
  }
  return { json, model: usedModel };
}
