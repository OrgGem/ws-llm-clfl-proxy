export type ProviderErrorReason =
  | "org_required"
  | "forbidden"
  | "invalid_api_key"
  | "billing_rejected"
  | "budget_exceeded"
  | "model_not_found"
  | "model_not_allowed"
  | "subscription_required"
  | "free_model_restricted"
  | "invalid_request"
  | "non_json_error";

const MAX_ERROR_BODY_BYTES = 16 * 1024;
const MAX_ERROR_BODY_CHUNKS = 256;
const ERROR_BODY_TIMEOUT_MS = 2_000;
const MAX_ERROR_OBJECT_DEPTH = 32;
const MAX_ERROR_OBJECTS = 512;

const TAG_REASONS = new Map<string, ProviderErrorReason>([
  ["orgrequired", "org_required"],
  ["organizationrequired", "org_required"],
  ["forbidden", "forbidden"],
  ["unauthorized", "invalid_api_key"],
  ["invalidapikey", "invalid_api_key"],
  ["insufficientbalance", "billing_rejected"],
  ["insufficientfunds", "billing_rejected"],
  ["insufficientcredit", "billing_rejected"],
  ["insufficientaccountfunds", "billing_rejected"],
  ["crediterror", "billing_rejected"],
  ["billingrejected", "billing_rejected"],
  ["budgetexceeded", "budget_exceeded"],
  ["modelnotfound", "model_not_found"],
  ["modelnotallowed", "model_not_allowed"],
  ["permissiondenied", "model_not_allowed"],
  ["subscriptionrequired", "subscription_required"],
  ["gorequired", "subscription_required"],
  ["freemodelnotallowed", "free_model_restricted"],
  ["freetiererror", "free_model_restricted"],
  ["invalidrequest", "invalid_request"],
  ["invalidrequesterror", "invalid_request"],
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function normalizeTag(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function reasonForTag(value: unknown): ProviderErrorReason | undefined {
  return typeof value === "string" ? TAG_REASONS.get(normalizeTag(value)) : undefined;
}

function reasonForMessage(value: string): ProviderErrorReason | undefined {
  const message = value.trim().replace(/\s+/g, " ");
  if (/^insufficient account funds[.!]?$/i.test(message) ||
      /^insufficient (?:balance|funds|credits?)[.!]?$/i.test(message)) {
    return "billing_rejected";
  }
  return undefined;
}

interface ErrorObject {
  value: Record<string, unknown>;
  depth: number;
  order: number;
}

function errorObjects(root: Record<string, unknown>): ErrorObject[] {
  const output: ErrorObject[] = [];
  const pending: Array<{ value: Record<string, unknown>; depth: number }> = [{ value: root, depth: 0 }];
  let order = 0;
  while (pending.length > 0 && output.length < MAX_ERROR_OBJECTS) {
    const current = pending.pop();
    if (!current) break;
    output.push({ ...current, order: order++ });
    if (current.depth >= MAX_ERROR_OBJECT_DEPTH) continue;
    const maxChildren = MAX_ERROR_OBJECTS - output.length - pending.length;
    if (maxChildren <= 0) continue;

    const childErrors = current.value.errors;
    if (Array.isArray(childErrors)) {
      const limit = Math.min(childErrors.length, maxChildren);
      for (let index = limit - 1; index >= 0; index -= 1) {
        const item = childErrors[index];
        if (isRecord(item)) pending.push({ value: item, depth: current.depth + 1 });
      }
    }
    const childError = current.value.error;
    if (isRecord(childError)) {
      if (pending.length < MAX_ERROR_OBJECTS - output.length) pending.push({ value: childError, depth: current.depth + 1 });
    } else if (Array.isArray(childError)) {
      const limit = Math.min(childError.length, MAX_ERROR_OBJECTS - output.length - pending.length);
      for (let index = limit - 1; index >= 0; index -= 1) {
        const item = childError[index];
        if (isRecord(item)) pending.push({ value: item, depth: current.depth + 1 });
      }
    }
  }
  // Specific nested error objects take precedence over wrapper-level labels.
  return output.sort((left, right) => right.depth - left.depth || left.order - right.order);
}

function classifyJsonError(value: unknown): ProviderErrorReason | undefined {
  if (!isRecord(value)) return undefined;
  const objects = errorObjects(value);
  for (const { value: object } of objects) {
    for (const field of ["code", "_tag", "tag", "type"] as const) {
      const reason = reasonForTag(object[field]);
      if (reason) return reason;
    }
  }
  for (const { value: object } of objects) {
    for (const field of ["message", "error_description", "detail", "description"] as const) {
      if (typeof object[field] === "string") {
        const reason = reasonForMessage(object[field] as string);
        if (reason) return reason;
      }
    }
  }
  return undefined;
}

function cancelBody(body: ReadableStream<Uint8Array> | null): void {
  if (!body) return;
  try {
    void body.cancel().catch(() => undefined);
  } catch {
    // Cancellation is best-effort; the caller only receives a fixed reason enum.
  }
}

function cancelReader(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  try {
    void reader.cancel().catch(() => undefined);
  } catch {
    // Cancellation is best-effort; the caller only receives a fixed reason enum.
  }
}

async function readBoundedBody(body: ReadableStream<Uint8Array> | null): Promise<Uint8Array | undefined> {
  if (!body) return undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array>;
  try {
    reader = body.getReader();
  } catch {
    cancelBody(body);
    return undefined;
  }

  let timeout: ReturnType<typeof setTimeout> | undefined;
  const deadline = performance.now() + ERROR_BODY_TIMEOUT_MS;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => reject(new Error("provider error body timeout")), ERROR_BODY_TIMEOUT_MS);
  });
  const readPromise = (async (): Promise<Uint8Array> => {
    const chunks: Uint8Array[] = [];
    let size = 0;
    let chunkCount = 0;
    while (true) {
      if (performance.now() >= deadline) throw new Error("provider error body timeout");
      const { done, value } = await reader.read();
      if (performance.now() >= deadline) throw new Error("provider error body timeout");
      if (done) break;
      chunkCount += 1;
      if (chunkCount > MAX_ERROR_BODY_CHUNKS || !(value instanceof Uint8Array) || size + value.byteLength > MAX_ERROR_BODY_BYTES) {
        throw new Error("provider error body limit exceeded");
      }
      size += value.byteLength;
      if (value.byteLength > 0) chunks.push(value);
    }
    const output = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      output.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return output;
  })();

  try {
    return await Promise.race([readPromise, timeoutPromise]);
  } catch {
    cancelReader(reader);
    return undefined;
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
    try {
      reader.releaseLock();
    } catch {
      // A pending read can retain the lock until stream cancellation settles.
    }
  }
}

/** Return only a fixed provider-error category; raw upstream data never escapes. */
export async function classifyProviderError(response: Response): Promise<ProviderErrorReason | undefined> {
  let contentType: string | null;
  let body: ReadableStream<Uint8Array> | null;
  try {
    contentType = response.headers.get("content-type");
    body = response.body;
  } catch {
    return undefined;
  }

  const mediaType = contentType?.split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType === "text/html" || mediaType === "application/xhtml+xml") {
    cancelBody(body);
    return "non_json_error";
  }
  if (!mediaType || (mediaType !== "application/json" && !mediaType.endsWith("+json"))) {
    cancelBody(body);
    return undefined;
  }

  const bytes = await readBoundedBody(body);
  if (!bytes) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return undefined;
  }
  return classifyJsonError(parsed);
}
