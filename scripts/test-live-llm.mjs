import assert from 'node:assert/strict';
import { ConfigStore } from '../apps/adapter/dist/config.js';
import { startAdapter } from '../apps/adapter/dist/server.js';
import { SseParser } from '../apps/adapter/dist/sse.js';

async function main() {
// Run only with operator authorization: this sends up to three billable requests.
// Config contains secrets/envelopes; output intentionally excludes prompts and responses.
const configPath = process.env.WS_PROXY_LIVE_CONFIG;
const model = process.env.WS_PROXY_LIVE_MODEL;
if (!configPath || !model) throw new Error('Set WS_PROXY_LIVE_CONFIG and WS_PROXY_LIVE_MODEL');
const configStore = new ConfigStore(configPath);
const config = await configStore.load();
assert(config.models.some((entry) => entry.id === model), 'Configured model alias is required');
const adapter = await startAdapter({ configStore, portOverride: 0, maxGatewaySessions: 1 });
const results = [];
const headers = { authorization: `Bearer ${config.localBearerToken}`, 'content-type': 'application/json' };
let current = 'chat-json';
function usageCounters(value) {
  return Object.fromEntries(['prompt_tokens', 'completion_tokens', 'total_tokens'].filter((key) => Number.isSafeInteger(value?.[key]) && value[key] >= 0).map((key) => [key, value[key]]));
}
async function send(body) {
  const response = await fetch(`http://127.0.0.1:${adapter.port}/v1/chat/completions`, {
    method: 'POST', headers, body: JSON.stringify({ model, max_tokens: 512, ...body }), signal: AbortSignal.timeout(120_000),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const code = /^[a-z_]+$/.test(body.error?.code ?? '') ? body.error.code : 'unknown';
    const upstream = /^The provider returned HTTP (\d{3})\.$/.exec(body.error?.message ?? '')?.[1];
    throw new Error(`HTTP ${response.status}; code=${code}${upstream ? '; upstream=' + upstream : ''}`);
  }
  return response;
}
async function readStream(response) {
  assert.match(response.headers.get('content-type') ?? '', /text\/event-stream/);
  const parser = new SseParser();
  const decoder = new TextDecoder();
  const events = [];
  const accept = (event) => {
    if (event.data === '[DONE]') { events.push({ done: true }); return; }
    const value = JSON.parse(event.data);
    if (value.error) {
      const code = /^[a-z_]+$/.test(value.error.code ?? '') ? value.error.code : 'unknown';
      throw new Error(`SSE error; code=${code}`);
    }
    events.push(value);
  };
  for await (const chunk of response.body) for (const event of parser.push(decoder.decode(chunk, { stream: true }))) accept(event);
  for (const event of parser.push(decoder.decode())) accept(event);
  for (const event of parser.finish()) accept(event);
  assert.equal(events.at(-1)?.done, true, 'Missing successful DONE sentinel');
  return events;
}
try {
  let started = performance.now();
  const json = await (await send({ messages: [{ role: 'user', content: 'Reply with exactly the word OK.' }], stream: false })).json();
  assert.equal(json.object, 'chat.completion');
  assert.equal(json.model, model);
  assert.equal(json.choices?.[0]?.finish_reason, 'stop');
  assert.equal(json.choices?.[0]?.message?.content?.trim(), 'OK');
  assert(Number.isSafeInteger(json.usage?.total_tokens), 'Provider usage is required');
  results.push({ test: current, success: true, wallMs: Math.round(performance.now() - started), usage: usageCounters(json.usage) });

  current = 'chat-stream'; started = performance.now();
  const events = await readStream(await send({ messages: [{ role: 'user', content: 'Reply with exactly the word OK.' }], stream: true, stream_options: { include_usage: true } }));
  const choices = events.flatMap((event) => event.choices ?? []);
  assert.equal(choices.map((choice) => choice.delta?.content ?? '').join('').trim(), 'OK');
  assert(choices.some((choice) => choice.finish_reason === 'stop'));
  const usage = events.findLast((event) => event.usage)?.usage;
  assert(Number.isSafeInteger(usage?.total_tokens), 'Streaming provider usage is required');
  results.push({ test: current, success: true, wallMs: Math.round(performance.now() - started), chunks: events.length, usage: usageCounters(usage) });

  current = 'chat-tool-stream'; started = performance.now();
  const toolEvents = await readStream(await send({
    messages: [{ role: 'user', content: 'Call echo with the value OK. Do not answer in text.' }], stream: true, stream_options: { include_usage: true },
    tools: [{ type: 'function', function: { name: 'echo', description: 'Return a provided string.', parameters: { type: 'object', properties: { value: { type: 'string' } }, required: ['value'], additionalProperties: false } } }],
    tool_choice: { type: 'function', function: { name: 'echo' } },
  }));
  const toolChoices = toolEvents.flatMap((event) => event.choices ?? []);
  const deltas = toolChoices.flatMap((choice) => choice.delta?.tool_calls ?? []);
  assert.equal(deltas.map((delta) => delta.function?.name ?? '').join(''), 'echo');
  assert(deltas.some((delta) => typeof delta.id === 'string'));
  assert.equal(JSON.parse(deltas.map((delta) => delta.function?.arguments ?? '').join('')).value, 'OK');
  assert(toolChoices.some((choice) => choice.finish_reason === 'tool_calls'));
  results.push({ test: current, success: true, wallMs: Math.round(performance.now() - started), toolDeltaCount: deltas.length, usage: usageCounters(toolEvents.findLast((event) => event.usage)?.usage) });
  console.log(JSON.stringify({ realProvider: true, results, automaticRetries: 0 }));
} catch (error) {
  const message = error instanceof Error && /^(HTTP \d{3}; code=[a-z_]+(?:; upstream=\d{3})?|SSE error; code=[a-z_]+)$/.test(error.message) ? error.message : 'Result did not satisfy the live test assertions';
  console.log(JSON.stringify({ realProvider: true, results, failedTest: current, message, automaticRetries: 0 }));
  process.exitCode = 1;
} finally {
  await adapter.close();
}

}

main().catch(() => {
  console.log(JSON.stringify({ success: false, message: 'Live test setup or cleanup failed; no credential details were printed.' }));
  process.exitCode = 1;
});
