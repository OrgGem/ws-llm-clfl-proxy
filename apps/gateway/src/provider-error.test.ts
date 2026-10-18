import { afterEach, describe, expect, it, vi } from "vitest";
import { classifyProviderError, type ProviderErrorReason } from "./provider-error.js";

const encoder = new TextEncoder();

function jsonResponse(value: unknown, contentType = "application/json"): Response {
  return new Response(JSON.stringify(value), { status: 400, headers: { "content-type": contentType } });
}

describe("safe provider error classification", () => {
  afterEach(() => vi.useRealTimers());

  it.each([
    ["OrgRequired", "org_required"],
    ["Forbidden", "forbidden"],
    ["Unauthorized", "invalid_api_key"],
    ["invalid_api_key", "invalid_api_key"],
    ["InsufficientBalance", "billing_rejected"],
    ["InsufficientFunds", "billing_rejected"],
    ["InsufficientCredit", "billing_rejected"],
    ["InsufficientAccountFunds", "billing_rejected"],
    ["CreditError", "billing_rejected"],
    ["BudgetExceeded", "budget_exceeded"],
    ["ModelNotFound", "model_not_found"],
    ["ModelNotAllowed", "model_not_allowed"],
    ["PermissionDenied", "model_not_allowed"],
    ["SubscriptionRequired", "subscription_required"],
    ["GoRequired", "subscription_required"],
    ["FreeModelNotAllowed", "free_model_restricted"],
    ["FreeTierError", "free_model_restricted"],
    ["invalid_request_error", "invalid_request"],
  ] as const)("maps known nested error type %s to %s", async (tag, expected) => {
    const response = jsonResponse({ error: { type: tag } });
    await expect(classifyProviderError(response)).resolves.toBe(expected satisfies ProviderErrorReason);
  });

  it("reads known code and tag fields at the top level and in nested errors", async () => {
    await expect(classifyProviderError(jsonResponse({ code: "model_not_found" }))).resolves.toBe("model_not_found");
    await expect(classifyProviderError(jsonResponse({ error: { code: "budget_exceeded" } }))).resolves.toBe("budget_exceeded");
    await expect(classifyProviderError(jsonResponse({ tag: "FreeTierError" }))).resolves.toBe("free_model_restricted");
    await expect(classifyProviderError(jsonResponse({ _tag: "Forbidden" }))).resolves.toBe("forbidden");
    await expect(classifyProviderError(jsonResponse({ error: { _tag: "FreeTierError" } }))).resolves.toBe("free_model_restricted");
  });

  it("classifies only exact funds messages and does not infer reasons from longer text", async () => {
    await expect(classifyProviderError(jsonResponse({ error: { message: "Insufficient account funds." } })))
      .resolves.toBe("billing_rejected");
    await expect(classifyProviderError(jsonResponse({ error: { message: "Insufficient balance" } })))
      .resolves.toBe("billing_rejected");
    await expect(classifyProviderError(jsonResponse({ error: { message: "Free tier only within OpenCode." } })))
      .resolves.toBeUndefined();
    await expect(classifyProviderError(jsonResponse({ error: { message: "The workspace is required for this feature." } })))
      .resolves.toBeUndefined();
    await expect(classifyProviderError(jsonResponse({ error: { message: "Your monthly budget has been exceeded." } })))
      .resolves.toBeUndefined();
    await expect(classifyProviderError(jsonResponse({ error: { message: "Quota limit exceeded." } }))).resolves.toBeUndefined();
    await expect(classifyProviderError(jsonResponse({ error: { type: "insufficient_quota" } }))).resolves.toBeUndefined();
    await expect(classifyProviderError(jsonResponse({ error: { message: "Invalid input: user prompt says insufficient funds" } })))
      .resolves.toBeUndefined();
  });

  it("never returns provider-controlled strings or classifies unknown tags", async () => {
    const secret = "sk-provider-secret-that-must-not-escape";
    const response = jsonResponse({ error: { type: "PrivateVendorException", code: "unknown_failure", message: secret } });
    const reason = await classifyProviderError(response);
    expect(reason).toBeUndefined();
    expect(JSON.stringify(reason ?? null)).not.toContain(secret);

    const known = await classifyProviderError(jsonResponse({ error: { type: "invalid_api_key", message: secret } }));
    expect(known).toBe("invalid_api_key");
    expect(JSON.stringify(known)).not.toContain(secret);
  });

  it("returns a fixed non-JSON reason for HTML edge responses and cancels their body", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode("<html>secret edge details</html>"));
      },
      cancel() {
        cancelled = true;
      },
    });
    const response = new Response(body, { status: 502, headers: { "content-type": "text/html; charset=utf-8" } });
    await expect(classifyProviderError(response)).resolves.toBe("non_json_error");
    await Promise.resolve();
    expect(cancelled).toBe(true);
  });

  it("does not parse text/plain or untyped bodies as provider diagnostics", async () => {
    const body = JSON.stringify({ error: { type: "FreeTierError", message: "secret body" } });
    await expect(classifyProviderError(new Response(body, { headers: { "content-type": "text/plain" } })))
      .resolves.toBeUndefined();
    await expect(classifyProviderError(new Response(body))).resolves.toBeUndefined();
  });

  it("cancels bodies that exceed the 16 KiB limit", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(16 * 1024 + 1));
      },
      cancel() {
        cancelled = true;
      },
    });
    const response = new Response(body, { headers: { "content-type": "application/json" } });
    await expect(classifyProviderError(response)).resolves.toBeUndefined();
    expect(cancelled).toBe(true);
  });

  it("bounds an endless stream of zero-byte chunks without waiting for the timer", async () => {
    let cancelled = false;
    let pulls = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        controller.enqueue(new Uint8Array());
      },
      cancel() {
        cancelled = true;
      },
    });
    const response = new Response(body, { headers: { "content-type": "application/json" } });
    await expect(classifyProviderError(response)).resolves.toBeUndefined();
    await Promise.resolve();
    expect(pulls).toBeLessThanOrEqual(258);
    expect(cancelled).toBe(true);
  });

  it("also bounds many tiny nonempty chunks", async () => {
    let cancelled = false;
    let pulls = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        controller.enqueue(new Uint8Array([0x78]));
      },
      cancel() {
        cancelled = true;
      },
    });
    const response = new Response(body, { headers: { "content-type": "application/json" } });
    await expect(classifyProviderError(response)).resolves.toBeUndefined();
    await Promise.resolve();
    expect(pulls).toBeLessThanOrEqual(258);
    expect(cancelled).toBe(true);
  });

  it("accepts a valid classifier tag at the inclusive 16 KiB body boundary", async () => {
    const prefix = '{"error":{"type":"Forbidden","message":"';
    const suffix = '"}}';
    const raw = `${prefix}${"x".repeat(16 * 1024 - prefix.length - suffix.length)}${suffix}`;
    const bytes = encoder.encode(raw);
    expect(bytes.byteLength).toBe(16 * 1024);
    let offset = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (offset >= bytes.byteLength) {
          controller.close();
          return;
        }
        controller.enqueue(bytes.subarray(offset, offset + 64));
        offset += 64;
      },
    });
    await expect(classifyProviderError(new Response(body, { headers: { "content-type": "application/json" } })))
      .resolves.toBe("forbidden");
  });

  it("cancels a body that stalls beyond the whole-body timeout", async () => {
    vi.useFakeTimers();
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull() {
        return new Promise<void>(() => undefined);
      },
      cancel() {
        cancelled = true;
      },
    });
    const response = new Response(body, { headers: { "content-type": "application/json" } });
    const result = classifyProviderError(response);
    await vi.advanceTimersByTimeAsync(2_001);
    await expect(result).resolves.toBeUndefined();
    expect(cancelled).toBe(true);
  });

  it("returns undefined when the body reader fails", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new Error("provider response secret"));
      },
    });
    const response = new Response(body, { headers: { "content-type": "application/json" } });
    await expect(classifyProviderError(response)).resolves.toBeUndefined();
  });
});
