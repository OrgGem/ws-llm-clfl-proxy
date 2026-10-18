import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ProviderEndpointSecurityError,
  assertPublicEndpointResolution,
  buildProviderEndpoint,
  normalizeBaseUrl,
} from "./provider-config.js";

type DnsRecord = { type: number; data: string };

function dnsFetcher(options: {
  A?: { status?: number; answers?: DnsRecord[]; httpStatus?: number; contentLength?: string };
  AAAA?: { status?: number; answers?: DnsRecord[]; httpStatus?: number; contentLength?: string };
} = {}) {
  const calls: Array<{ url: URL; init: RequestInit | undefined }> = [];
  const fetcher: typeof fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    calls.push({ url, init });
    const family = url.searchParams.get("type") as "A" | "AAAA";
    const fixture = options[family] ?? {};
    return new Response(JSON.stringify({ Status: fixture.status ?? 0, Answer: fixture.answers }), {
      status: fixture.httpStatus ?? 200,
      headers: {
        "content-type": "application/dns-json",
        ...(fixture.contentLength ? { "content-length": fixture.contentLength } : {}),
      },
    });
  };
  return { fetcher, calls };
}

describe("custom provider endpoint configuration", () => {
  it("canonicalizes HTTPS API roots while preserving root and explicit paths", () => {
    expect(normalizeBaseUrl("https://API.Vendor.example.com")).toBe("https://api.vendor.example.com/");
    expect(normalizeBaseUrl("https://api.vendor.example.com/")).toBe("https://api.vendor.example.com/");
    expect(normalizeBaseUrl("https://api.vendor.example.com/openai/v1")).toBe("https://api.vendor.example.com/openai/v1/");
    expect(normalizeBaseUrl("https://api.vendor.example.com:443/v1/")).toBe("https://api.vendor.example.com/v1/");
    expect(normalizeBaseUrl("https://custom-llm.workers.dev/v1")).toBe("https://custom-llm.workers.dev/v1/");
  });

  it("appends only the fixed protocol operation path", () => {
    expect(buildProviderEndpoint("openai", "https://api.vendor.example.com/v1"))
      .toBe("https://api.vendor.example.com/v1/chat/completions");
    expect(buildProviderEndpoint("anthropic", "https://api.vendor.example.com/anthropic/v1/"))
      .toBe("https://api.vendor.example.com/anthropic/v1/messages");
    expect(buildProviderEndpoint("openai", "https://api.vendor.example.com"))
      .toBe("https://api.vendor.example.com/chat/completions");
  });

  it("rejects credentials, queries, fragments, insecure schemes, and non-default ports", () => {
    for (const input of [
      "http://api.vendor.example.com/v1",
      "https://user:password@api.vendor.example.com/v1",
      "https://api.vendor.example.com/v1?target=elsewhere",
      "https://api.vendor.example.com/v1#fragment",
      "https://api.vendor.example.com:8443/v1",
      " https://api.vendor.example.com/v1",
    ]) {
      expect(() => normalizeBaseUrl(input), input).toThrow(ProviderEndpointSecurityError);
    }
    try {
      normalizeBaseUrl("http://api.vendor.example.com/v1");
    } catch (caught) {
      expect(caught).toMatchObject({ code: "invalid_base_url", stage: "normalize" });
    }
  });

  it("rejects IP literals, URL-normalized numeric IPs, and non-public hostnames", () => {
    for (const input of [
      "https://127.0.0.1/v1",
      "https://[::1]/v1",
      "https://2130706433/v1",
      "https://0x7f000001/v1",
      "https://metadata.google.internal/v1",
      "https://localhost./v1",
      "https://one-label/v1",
    ]) {
      expect(() => normalizeBaseUrl(input), input).toThrow(ProviderEndpointSecurityError);
    }
  });

  it("rejects service origins and operation URLs supplied as BaseURLs", () => {
    expect(() => normalizeBaseUrl("https://identity.vendor.com/v1", {
      forbiddenOrigins: ["https://identity.vendor.com"],
    })).toThrowError(expect.objectContaining({ code: "forbidden_service_origin" }));
    expect(() => normalizeBaseUrl("https://gateway.vendor.com/v1", {
      forbiddenOrigins: ["wss://gateway.vendor.com/v1/socket"],
    })).toThrowError(expect.objectContaining({ code: "forbidden_service_origin" }));
    for (const input of [
      "https://api.vendor.example.com/v1/chat/completions",
      "https://api.vendor.example.com/v1/messages/",
    ]) {
      expect(() => normalizeBaseUrl(input)).toThrowError(expect.objectContaining({ code: "base_url_is_endpoint" }));
    }
  });

  it("rejects encoded, traversing, oversized, and ambiguous path prefixes", () => {
    for (const input of [
      "https://api.vendor.example.com/%2fadmin",
      "https://api.vendor.example.com/%252e%252e/private",
      "https://api.vendor.example.com/v1/../private",
      "https://api.vendor.example.com/v1\\private",
      `https://api.vendor.example.com/${"a".repeat(257)}`,
    ]) {
      expect(() => normalizeBaseUrl(input), input).toThrowError(expect.objectContaining({ code: "unsafe_provider_path" }));
    }
  });
});

describe("custom provider public DNS guard", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("queries both address families through fixed DoH and accepts a public address", async () => {
    const { fetcher, calls } = dnsFetcher({ A: { answers: [{ type: 1, data: "8.8.8.8" }] }, AAAA: { answers: [] } });

    await expect(assertPublicEndpointResolution("https://api.vendor.example.com/v1/chat/completions", fetcher)).resolves.toBeUndefined();

    expect(calls).toHaveLength(2);
    expect(calls.map(({ url }) => url.origin)).toEqual([
      "https://cloudflare-dns.com",
      "https://cloudflare-dns.com",
    ]);
    expect(calls.every(({ url }) => url.pathname === "/dns-query")).toBe(true);
    expect(calls.map(({ url }) => url.searchParams.get("type")).sort()).toEqual(["A", "AAAA"]);
    expect(calls.every(({ url }) => url.searchParams.get("name") === "api.vendor.example.com")).toBe(true);
    expect(calls.every(({ init }) => init?.redirect === "manual" && init.signal instanceof AbortSignal)).toBe(true);
  });

  it("invokes the native global fetch with its Worker receiver when no test fetcher is supplied", async () => {
    const receivers: unknown[] = [];
    const workerFetch = function (this: unknown, input: RequestInfo | URL): Promise<Response> {
      receivers.push(this);
      if (this !== globalThis) throw new TypeError("Illegal invocation");
      const url = new URL(input instanceof Request ? input.url : String(input));
      const type = url.searchParams.get("type");
      return Promise.resolve(new Response(JSON.stringify({
        Status: 0,
        ...(type === "A" ? { Answer: [{ type: 1, data: "8.8.8.8" }] } : {}),
      }), { status: 200, headers: { "content-type": "application/dns-json" } }));
    } as typeof fetch;
    vi.stubGlobal("fetch", workerFetch);

    await expect(assertPublicEndpointResolution("https://api.vendor.example.com/v1")).resolves.toBeUndefined();
    expect(receivers).toHaveLength(2);
    expect(receivers.every((receiver) => receiver === globalThis)).toBe(true);
  });

  it("rejects any private, reserved, transition, or mapped-private answer", async () => {
    const unsafeAddresses = [
      ["A", "127.0.0.1", 1],
      ["A", "10.1.2.3", 1],
      ["A", "100.64.1.1", 1],
      ["A", "192.0.2.1", 1],
      ["AAAA", "::1", 28],
      ["AAAA", "::ffff:192.168.1.10", 28],
      ["AAAA", "::ffff:8.8.8.8", 28],
      ["AAAA", "2002:0808:0808::1", 28],
      ["AAAA", "2001::1", 28],
    ] as const;

    for (const [family, address, type] of unsafeAddresses) {
      const { fetcher } = dnsFetcher({ [family]: { answers: [{ type, data: address }] } });
      await expect(assertPublicEndpointResolution("https://api.vendor.example.com/v1", fetcher))
        .rejects.toThrowError(expect.objectContaining({ code: "provider_dns_non_public_address" }));
    }
  });

  it("validates unexpected address-family records and rejects truncated DNS responses", async () => {
    const privateUnexpectedFamily = dnsFetcher({
      A: { answers: [{ type: 1, data: "8.8.8.8" }, { type: 28, data: "fd00::1" }] },
      AAAA: { answers: [] },
    });
    await expect(assertPublicEndpointResolution("https://api.vendor.example.com/v1", privateUnexpectedFamily.fetcher))
      .rejects.toThrowError(expect.objectContaining({ code: "provider_dns_non_public_address" }));

    const truncated = {
      fetcher: (async (input: RequestInfo | URL) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        const type = url.searchParams.get("type");
        return new Response(JSON.stringify({ Status: 0, TC: true, Answer: type === "A" ? [{ type: 1, data: "8.8.8.8" }] : [] }), {
          status: 200,
          headers: { "content-type": "application/dns-json" },
        });
      }) as typeof fetch,
    };
    await expect(assertPublicEndpointResolution("https://api.vendor.example.com/v1", truncated.fetcher))
      .rejects.toThrowError(expect.objectContaining({ code: "provider_dns_validation_failed" }));
  });

  it("fails closed on resolver errors, malformed answers, and no public answers", async () => {
    const cases = [
      { A: { status: 3 }, AAAA: { status: 0 } },
      { A: { httpStatus: 503 }, AAAA: { answers: [{ type: 28, data: "2606:4700:4700::1111" }] } },
      { A: { answers: [{ type: 1, data: "not-an-ip" }] }, AAAA: {} },
      { A: { answers: [{ type: 1, data: "8.8.8.8" }] }, AAAA: { answers: [{ type: 28, data: "2606:4700:4700::1111%eth0" }] } },
    ];
    for (const fixture of cases) {
      const { fetcher } = dnsFetcher(fixture);
      await expect(assertPublicEndpointResolution("https://api.vendor.example.com/v1", fetcher))
        .rejects.toThrow(ProviderEndpointSecurityError);
    }
    const noAnswers = dnsFetcher({ A: {}, AAAA: {} });
    await expect(assertPublicEndpointResolution("https://api.vendor.example.com/v1", noAnswers.fetcher))
      .rejects.toThrowError(expect.objectContaining({ code: "provider_dns_no_public_address" }));
  });

  it("rejects oversized resolver bodies and never includes the hostname in safe errors", async () => {
    const { fetcher } = dnsFetcher({ A: { contentLength: "65537" } });
    try {
      await assertPublicEndpointResolution("https://secret-hostname.vendor.example.com/v1", fetcher);
      throw new Error("expected DNS guard failure");
    } catch (caught) {
      expect(caught).toBeInstanceOf(ProviderEndpointSecurityError);
      expect((caught as Error).message).not.toContain("secret-hostname");
    }
  });

  it("reports fixed, bounded stages for DoH failures without retaining resolver details", async () => {
    const fetchFailure = (async () => {
      throw new Error("secret resolver URL and credentials");
    }) as typeof fetch;
    await expect(assertPublicEndpointResolution("https://api.vendor.example.com/v1", fetchFailure))
      .rejects.toMatchObject({ code: "provider_dns_validation_failed", stage: "fetch" });

    const httpFailure = (async () => new Response("resolver secret body", { status: 503 })) as typeof fetch;
    await expect(assertPublicEndpointResolution("https://api.vendor.example.com/v1", httpFailure))
      .rejects.toMatchObject({ code: "provider_dns_validation_failed", stage: "http", httpStatus: 503 });

    const malformedJson = (async () => new Response("not-json", { status: 200 })) as typeof fetch;
    await expect(assertPublicEndpointResolution("https://api.vendor.example.com/v1", malformedJson))
      .rejects.toMatchObject({ code: "provider_dns_validation_failed", stage: "json" });

    const dnsError = dnsFetcher({ A: { status: 3 }, AAAA: { answers: [{ type: 28, data: "2606:4700:4700::1111" }] } });
    await expect(assertPublicEndpointResolution("https://api.vendor.example.com/v1", dnsError.fetcher))
      .rejects.toMatchObject({ code: "provider_dns_validation_failed", stage: "dns_status", dnsStatus: 3 });

    const privateAnswer = dnsFetcher({ A: { answers: [{ type: 1, data: "10.1.2.3" }] } });
    await expect(assertPublicEndpointResolution("https://api.vendor.example.com/v1", privateAnswer.fetcher))
      .rejects.toMatchObject({ code: "provider_dns_non_public_address", stage: "address" });
  });

  it("omits out-of-range numeric statuses from public diagnostics", async () => {
    const invalidHttpStatus = new ProviderEndpointSecurityError("provider_dns_validation_failed", "http", { httpStatus: 700 });
    const invalidDnsStatus = new ProviderEndpointSecurityError("provider_dns_validation_failed", "dns_status", { dnsStatus: -1 });
    expect(invalidHttpStatus).not.toHaveProperty("httpStatus");
    expect(invalidDnsStatus).not.toHaveProperty("dnsStatus");
    expect(invalidHttpStatus.message).toBe("Provider endpoint DNS validation failed.");
  });
});
