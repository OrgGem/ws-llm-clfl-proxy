import { createServer as createHttpServer, type Server } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createInitialConfig, validateConfig } from "./config.js";
import { handleResponses } from "./responses.js";
import type { GatewayExecutor } from "./server.js";
import type { AdapterConfig } from "./types.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

describe("native OpenAI Responses HTTP handler", () => {
  it("buffers native output items and usage, rewrites model aliases, and sends stateless payload to Gateway", async () => {
    const responseObject = {
      id: "resp_01",
      object: "response",
      status: "completed",
      model: "provider-upstream-name",
      output: [
        { id: "rs_1", type: "reasoning", summary: [{ type: "summary_text", text: "Use the tool." }] },
        { id: "fc_1", type: "function_call", call_id: "call_1", name: "lookup", arguments: "{\"key\":\"x\"}", status: "completed" },
      ],
      usage: { input_tokens: 14, output_tokens: 6, total_tokens: 20 },
    };
    let gatewayInput: Record<string, unknown> | undefined;
    const gateway = fakeGateway(async (input, callbacks) => {
      gatewayInput = input as unknown as Record<string, unknown>;
      const body = JSON.stringify({ type: "response.completed", response: responseObject });
      await callbacks.onChunk(0, `event: response.created\ndata: ${JSON.stringify({ type: "response.created", response: { id: "resp_01", object: "response", status: "in_progress", model: "upstream" } })}\n\n` + `event: response.completed\ndata: ${body}\n\n`);
      await callbacks.onEnd({ event: "response.end", requestId: input.requestId, lastSeq: 0 });
    });
    const { url } = await listen(gateway);
    const inputItems = [{ type: "function_call_output", call_id: "call_previous", output: [{ type: "input_text", text: "result" }] }];
    const response = await post(url, {
      model: "local-responses",
      input: inputItems,
      stream: false,
      store: false,
      previous_response_id: null,
      conversation: null,
      instructions: "Use the prior tool result.",
      tools: [{ type: "function", name: "lookup", parameters: { type: "object" } }],
    });
    const body = await response.json() as Record<string, unknown>;
    const result = body as typeof responseObject;

    expect(response.status).toBe(200);
    expect(result.id).toBe("resp_01");
    expect(result.model).toBe("local-responses");
    expect(result.output).toEqual(responseObject.output);
    expect(result.usage).toEqual(responseObject.usage);
    expect(gatewayInput).toMatchObject({
      api: "responses",
      provider: "vendor_x",
      model: "local-responses",
      payload: {
        input: inputItems,
        store: false,
        instructions: "Use the prior tool result.",
        tools: [{ type: "function", name: "lookup", parameters: { type: "object" } }],
      },
    });
    const payload = gatewayInput?.payload as Record<string, unknown>;
    expect(payload).not.toHaveProperty("model");
    expect(payload).not.toHaveProperty("stream");
    expect(payload).not.toHaveProperty("previous_response_id");
    expect(payload).not.toHaveProperty("conversation");
  });

  it("forwards typed SSE events through arbitrary chunk boundaries and holds the terminal until Gateway end", async () => {
    const terminal = JSON.stringify({ type: "response.completed", response: { id: "resp_stream", object: "response", status: "completed", model: "provider-model", output: [] } });
    const initialEvents = [
      sse("response.created", { type: "response.created", sequence_number: 0, response: { id: "resp_stream", object: "response", status: "in_progress", model: "provider-model" } }),
      sse("response.output_item.added", { type: "response.output_item.added", sequence_number: 1, output_index: 0, item: { id: "fc_1", type: "function_call", call_id: "call_1", name: "lookup", arguments: "" } }),
      sse("response.function_call_arguments.delta", { type: "response.function_call_arguments.delta", sequence_number: 2, item_id: "fc_1", output_index: 0, delta: "{\"q\":" }),
      sse("response.output_text.done", { type: "response.output_text.done", sequence_number: 3, item_id: "msg_1", output_index: 1, content_index: 0, text: "tool result", logprobs: [] }),
    ].join("");
    const ready = deferred<void>();
    const releaseTerminal = deferred<void>();
    const gateway = fakeGateway(async (input, callbacks) => {
      for (const piece of [...initialEvents]) await callbacks.onChunk(0, piece);
      ready.resolve();
      await releaseTerminal.promise;
      await callbacks.onChunk(1, sse("response.completed", { ...JSON.parse(terminal), sequence_number: 4 }));
      await callbacks.onEnd({ event: "response.end", requestId: input.requestId, lastSeq: 1 });
    });
    const { url } = await listen(gateway);
    const fetchPromise = post(url, { model: "local-responses", input: "run tool", stream: true });
    await ready.promise;
    const response = await fetchPromise;
    const reader = response.body!.getReader();
    let received = "";
    while (!received.includes("response.function_call_arguments.delta")) {
      const chunk = await reader.read();
      if (chunk.done) break;
      received += new TextDecoder().decode(chunk.value);
    }
    expect(response.status).toBe(200);
    expect(received).toContain("event: response.created");
    expect(received).toContain('"model":"local-responses"');
    expect(received).toContain("event: response.function_call_arguments.delta");
    expect(received).not.toContain("response.completed");

    releaseTerminal.resolve();
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      received += new TextDecoder().decode(chunk.value);
    }
    expect(received).toContain("event: response.completed");
    expect(received).toContain("event: response.output_text.done");
    expect(received).toContain('"text":"tool result"');
    expect(received).not.toContain("[DONE]");
  });

  it("returns response.incomplete as a native terminal without inventing a success sentinel", async () => {
    const gateway = fakeGateway(async (input, callbacks) => {
      await callbacks.onChunk(0, sse("response.created", { type: "response.created", response: { id: "resp_inc", status: "in_progress" } }) +
        sse("response.incomplete", { type: "response.incomplete", response: { id: "resp_inc", object: "response", status: "incomplete", model: "upstream", output: [], incomplete_details: { reason: "max_output_tokens" } } }));
      await callbacks.onEnd({ event: "response.end", requestId: input.requestId, lastSeq: 0 });
    });
    const { url } = await listen(gateway);
    const response = await post(url, { model: "local-responses", input: "short", stream: true });
    const text = await response.text();
    expect(response.status).toBe(200);
    expect(text).toContain("event: response.incomplete");
    expect(text).toContain('"status":"incomplete"');
    expect(text).not.toContain("[DONE]");
  });

  it("reports missing, duplicate, and inconsistent terminal events as safe errors", async () => {
    const missing = fakeGateway(async (input, callbacks) => {
      await callbacks.onChunk(0, sse("response.created", { type: "response.created", response: { id: "resp_missing", status: "in_progress" } }));
      try { await callbacks.onEnd({ event: "response.end", requestId: input.requestId, lastSeq: 0 }); }
      catch (error) { await callbacks.onLocalFailure(error as Error); }
    });
    const { url: missingUrl } = await listen(missing);
    const missingResponse = await post(missingUrl, { model: "local-responses", input: "hello", stream: true });
    const missingText = await missingResponse.text();
    expect(missingText).toContain("event: error");
    const missingEvent = missingText.split("data: ").at(-1)?.split("\n")[0];
    expect(JSON.parse(missingEvent ?? "{}")).toMatchObject({ type: "error", code: "invalid_upstream_response", message: expect.any(String), sequence_number: 1 });
    expect(JSON.parse(missingEvent ?? "{}")).not.toHaveProperty("error");
    expect(missingText).not.toContain("response.completed");

    const duplicate = fakeGateway(async (_input, callbacks) => {
      const terminal = sse("response.completed", { type: "response.completed", response: { id: "resp_dup", object: "response", status: "completed", output: [] } });
      const data = sse("response.created", { type: "response.created", response: { id: "resp_dup", status: "in_progress" } }) + terminal + terminal;
      try { await callbacks.onChunk(0, data); }
      catch (error) { await callbacks.onLocalFailure(error as Error); }
    });
    const { url: duplicateUrl } = await listen(duplicate);
    const duplicateResponse = await post(duplicateUrl, { model: "local-responses", input: "hello", stream: true });
    const duplicateText = await duplicateResponse.text();
    expect(duplicateText).toContain("event: error");
    expect(duplicateText).not.toContain("event: response.completed");
    const duplicateError = duplicateText.split("data: ").at(-1)?.split("\n")[0];
    expect(JSON.parse(duplicateError ?? "{}")).toMatchObject({ type: "error", sequence_number: 1 });

    const inconsistent = fakeGateway(async (_input, callbacks) => {
      const data = sse("response.created", { type: "response.created", response: { id: "resp_a", status: "in_progress" } }) +
        sse("response.completed", { type: "response.completed", response: { id: "resp_b", object: "response", status: "completed", output: [] } });
      try { await callbacks.onChunk(0, data); }
      catch (error) { await callbacks.onLocalFailure(error as Error); }
    });
    const { url: inconsistentUrl } = await listen(inconsistent);
    const inconsistentResponse = await post(inconsistentUrl, { model: "local-responses", input: "hello", stream: true });
    const inconsistentText = await inconsistentResponse.text();
    expect(inconsistentText).toContain("event: error");
    expect(inconsistentText).not.toContain("event: response.completed");

    const missingId = fakeGateway(async (_input, callbacks) => {
      const data = sse("response.created", { type: "response.created", response: { id: "resp_missing_id", status: "in_progress" } }) +
        sse("response.completed", { type: "response.completed", response: { object: "response", status: "completed", output: [] } });
      try { await callbacks.onChunk(0, data); }
      catch (error) { await callbacks.onLocalFailure(error as Error); }
    });
    const { url: missingIdUrl } = await listen(missingId);
    const missingIdResponse = await post(missingIdUrl, { model: "local-responses", input: "hello", stream: true });
    const missingIdText = await missingIdResponse.text();
    expect(missingIdText).toContain("event: error");
    expect(missingIdText).not.toContain("event: response.completed");
  });

  it("rejects mismatched SSE event names and emits native sanitized gateway error events", async () => {
    const mismatch = fakeGateway(async (_input, callbacks) => {
      try {
        await callbacks.onChunk(0, "event: response.created\ndata: {\"type\":\"response.in_progress\",\"response\":{\"id\":\"resp_bad\"}}\n\n");
      } catch (error) { await callbacks.onLocalFailure(error as Error); }
    });
    const { url: mismatchUrl } = await listen(mismatch);
    const mismatchResponse = await post(mismatchUrl, { model: "local-responses", input: "hello", stream: true });
    const mismatchText = await mismatchResponse.text();
    expect(mismatchResponse.status).toBe(502);
    expect(mismatchText).toContain("invalid_upstream_response");
    expect(mismatchText).not.toContain("response.in_progress");

    const secret = "gateway-private-error-detail";
    const gatewayFailure = fakeGateway(async (input, callbacks) => {
      await callbacks.onChunk(0, sse("response.created", { type: "response.created", response: { id: "resp_gateway", status: "in_progress" } }));
      await callbacks.onError({
        event: "response.error",
        requestId: input.requestId,
        lastSeq: 0,
        code: "upstream_rate_limited",
        message: secret,
        upstreamStarted: true,
        retryable: true,
      });
    });
    const { url: gatewayFailureUrl } = await listen(gatewayFailure);
    const gatewayResponse = await post(gatewayFailureUrl, { model: "local-responses", input: "hello", stream: true });
    const gatewayText = await gatewayResponse.text();
    expect(gatewayText).toContain("event: error");
    const errorData = gatewayText.split("data: ").at(-1)?.split("\n")[0];
    expect(JSON.parse(errorData ?? "{}")).toMatchObject({
      type: "error",
      code: "upstream_rate_limited",
      message: "The provider is rate limiting this request.",
      param: null,
      sequence_number: 1,
    });
    expect(gatewayText).not.toContain(secret);
    expect(gatewayText).not.toContain("response.completed");

    const bufferedGatewayResponse = await post(gatewayFailureUrl, { model: "local-responses", input: "hello", stream: false });
    const bufferedGatewayText = await bufferedGatewayResponse.text();
    expect(bufferedGatewayResponse.status).toBe(429);
    expect(bufferedGatewayText).toContain("upstream_rate_limited");
    expect(bufferedGatewayText).not.toContain(secret);
  });

  it("sanitizes provider failures and rejects unsupported persistence/conversation semantics before dispatch", async () => {
    const gateway = fakeGateway(async (_input, callbacks) => {
      const body = JSON.stringify({ type: "response.failed", response: { id: "resp_fail", status: "failed", error: { message: "provider echoed secret prompt" } } });
      try { await callbacks.onChunk(0, sse("response.failed", JSON.parse(body))); }
      catch (error) { await callbacks.onLocalFailure(error as Error); }
    });
    const { url } = await listen(gateway);
    const failure = await post(url, { model: "local-responses", input: "hello" });
    const failureText = await failure.text();
    expect(failure.status).toBe(502);
    expect(failureText).toContain("provider_error");
    expect(failureText).not.toContain("secret prompt");

    const secret = "provider-echoed-secret-sentinel";
    const terminalError = fakeGateway(async (_input, callbacks) => {
      const events = sse("response.created", { type: "response.created", response: { id: "resp_error", status: "in_progress" } }) +
        sse("response.completed", { type: "response.completed", response: { id: "resp_error", object: "response", status: "completed", output: [], error: { message: secret } } });
      try { await callbacks.onChunk(0, events); }
      catch (error) { await callbacks.onLocalFailure(error as Error); }
    });
    const { url: terminalErrorUrl } = await listen(terminalError);
    const terminalErrorResponse = await post(terminalErrorUrl, { model: "local-responses", input: "hello", stream: true });
    const terminalErrorText = await terminalErrorResponse.text();
    expect(terminalErrorText).toContain("event: error");
    expect(terminalErrorText).not.toContain(secret);
    expect(terminalErrorText).not.toContain("event: response.completed");

    const execute = vi.fn(async () => undefined);
    const unused = fakeGateway(execute);
    const { url: unusedUrl } = await listen(unused);
    for (const body of [
      { model: "local-responses", input: "hello", background: true },
      { model: "local-responses", input: "hello", background: "false" },
      { model: "local-responses", input: "hello", store: true },
      { model: "local-responses", input: "hello", store: "false" },
      { model: "local-responses", input: "hello", previous_response_id: "resp_remote" },
      { model: "local-responses", input: "hello", conversation: { id: "conv_remote" } },
      { model: "local-responses", input: [{ type: "item_reference", id: "resp_remote" }] },
    ]) {
      expect((await post(unusedUrl, body)).status).toBe(400);
    }
    expect(execute).not.toHaveBeenCalled();
  });

  it("rejects Anthropic Responses calls and malformed request parameters before Gateway dispatch", async () => {
    const execute = vi.fn(async () => undefined);
    const gateway = fakeGateway(execute);
    const anthropicConfig = makeConfig({ id: "local-responses", provider: "anthropic", protocol: "anthropic", credentialId: "credential_test" });
    const { url: anthropicUrl } = await listen(gateway, anthropicConfig);
    expect((await post(anthropicUrl, { model: "local-responses", input: "hello" })).status).toBe(400);

    const { url } = await listen(gateway);
    const deeplyNested: Record<string, unknown> = {};
    let nested: Record<string, unknown> = deeplyNested;
    for (let index = 0; index < 66; index += 1) {
      const child: Record<string, unknown> = {};
      nested.next = child;
      nested = child;
    }
    for (const body of [
      { model: "local-responses", input: { text: "not a string or array" } },
      { model: "local-responses", input: "hello", stream: "true" },
      { model: "local-responses", input: "hello", endpoint: "https://attacker.example/" },
      { model: "local-responses", input: "hello", metadata: deeplyNested },
    ]) {
      expect((await post(url, body)).status).toBe(400);
    }
    expect(execute).not.toHaveBeenCalled();
  });

  it("cancels Gateway work when the local HTTP caller disconnects", async () => {
    const started = deferred<void>();
    const cancelled = deferred<void>();
    const gateway = fakeGateway(async (_input, _callbacks, signal) => {
      started.resolve();
      if (signal?.aborted) {
        cancelled.resolve();
        return;
      }
      await new Promise<void>((resolve) => signal?.addEventListener("abort", () => {
        cancelled.resolve();
        resolve();
      }, { once: true }));
    });
    const { url } = await listen(gateway);
    const controller = new AbortController();
    const request = post(url, { model: "local-responses", input: "hello", stream: true }, controller.signal).catch(() => undefined);
    await started.promise;
    controller.abort();
    await cancelled.promise;
    await request;
  });
});

function fakeGateway(run: GatewayExecutor["execute"]): GatewayExecutor {
  return { execute: run, close: () => undefined };
}

async function listen(gateway: GatewayExecutor, config = makeConfig()): Promise<{ url: string }> {
  const server = createHttpServer((request, response) => {
    void handleResponses(request, response, config, gateway).catch(() => {
      if (!response.headersSent) {
        response.statusCode = 500;
        response.end(JSON.stringify({ error: "unexpected test handler failure" }));
      } else response.destroy();
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Test server did not bind to a TCP port");
  return { url: `http://127.0.0.1:${address.port}/v1/responses` };
}

function makeConfig(model = { id: "local-responses", provider: "vendor_x", protocol: "openai", credentialId: "credential_test" }): AdapterConfig {
  const initial = createInitialConfig({
    identityUrl: "http://127.0.0.1:3000",
    gatewayUrl: "ws://127.0.0.1:8787/v1/socket",
    auth: { type: "public", clientId: "client_test", refreshToken: "refresh-token-test" },
  });
  return validateConfig({
    ...initial,
    models: [model],
    envelopes: [{
      v: 1,
      alg: "A256GCM",
      kid: "test-key",
      credentialId: "credential_test",
      userId: "user_test",
      projectId: "project_test",
      provider: model.provider,
      exp: Math.floor(Date.now() / 1000) + 3600,
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
    }],
  });
}

async function post(url: string, body: unknown, signal?: AbortSignal): Promise<Response> {
  return fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    ...(signal ? { signal } : {}),
  });
}

function sse(event: string, body: Record<string, unknown>): string {
  return `event: ${event}\ndata: ${JSON.stringify(body)}\n\n`;
}

function deferred<T = void>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
