import { describe, expect, it } from "vitest";
import { readJson, readTextBody } from "../src/security.js";

function streamRequest(url: string, chunkSize: number): { request: Request; wasCancelled: () => boolean } {
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new Uint8Array(chunkSize).fill(0x78));
    },
    cancel() {
      cancelled = true;
    },
  });
  return { request: new Request(url, { method: "POST", body, duplex: "half" } as RequestInit), wasCancelled: () => cancelled };
}

describe("bounded request body readers", () => {
  it("rejects oversized JSON from a chunked body without Content-Length", async () => {
    const { request, wasCancelled } = streamRequest("https://identity.example.test/api/clients", 20_000);
    expect(request.headers.has("content-length")).toBe(false);
    await expect(readJson(request, 16_384)).rejects.toMatchObject({ code: "request_too_large", status: 413 });
    expect(wasCancelled()).toBe(true);
  });

  it("rejects oversized form bodies from a chunked body without Content-Length", async () => {
    const { request, wasCancelled } = streamRequest("https://identity.example.test/oauth/token", 5_000);
    expect(request.headers.has("content-length")).toBe(false);
    await expect(readTextBody(request, 4_096)).rejects.toMatchObject({ code: "request_too_large", status: 413 });
    expect(wasCancelled()).toBe(true);
  });
});
