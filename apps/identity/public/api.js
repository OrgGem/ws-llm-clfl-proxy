const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export class ApiError extends Error {
  constructor(status, message = `Request failed (${status})`) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/** Same-origin JSON client. It keeps CSRF in memory and never stores responses. */
export function createApiClient({
  origin = globalThis.location?.origin,
  fetchImpl = globalThis.fetch,
  getCsrfToken = () => undefined,
} = {}) {
  if (!origin || typeof fetchImpl !== "function") {
    throw new TypeError("An origin and fetch implementation are required");
  }
  const baseOrigin = new URL(origin).origin;

  async function request(path, { method = "GET", body, headers: suppliedHeaders } = {}) {
    const target = new URL(path, baseOrigin);
    if (target.origin !== baseOrigin || !target.pathname.startsWith("/api/")) {
      throw new TypeError("API requests must use the same origin and stay under /api/");
    }

    const normalizedMethod = method.toUpperCase();
    if (!SAFE_METHODS.has(normalizedMethod) && target.search) {
      throw new TypeError("State-changing API requests must not put data in the URL");
    }
    const headers = new Headers(suppliedHeaders);
    headers.set("Accept", "application/json");
    if (body !== undefined) headers.set("Content-Type", "application/json");
    if (!SAFE_METHODS.has(normalizedMethod)) {
      const csrfToken = getCsrfToken();
      if (!csrfToken) throw new ApiError(403, "Your session expired. Sign in again.");
      headers.set("X-CSRF-Token", csrfToken);
    }

    let response;
    try {
      response = await fetchImpl(target, {
        method: normalizedMethod,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "same-origin",
      });
    } catch {
      throw new ApiError(0, "Identity is unreachable. Try again in a moment.");
    }

    let payload;
    try {
      payload = await response.json();
    } catch {
      payload = undefined;
    }
    if (!response.ok) {
      throw new ApiError(response.status, safeErrorMessage(response.status));
    }
    return payload;
  }

  return {
    request,
    get(path, query) {
      const target = new URL(path, baseOrigin);
      if (target.origin !== baseOrigin || !target.pathname.startsWith("/api/")) {
        throw new TypeError("API requests must use the same origin and stay under /api/");
      }
      if (query) {
        for (const [key, value] of Object.entries(query)) {
          if (value !== undefined && value !== null && value !== "") {
            target.searchParams.set(key, String(value));
          }
        }
      }
      return request(`${target.pathname}${target.search}`, { method: "GET" });
    },
    post(path, body) {
      return request(path, { method: "POST", body });
    },
    put(path, body) {
      return request(path, { method: "PUT", body });
    },
    delete(path) {
      return request(path, { method: "DELETE" });
    },
  };
}

function safeErrorMessage(status) {
  if (status === 401) return "Your session expired. Sign in again.";
  if (status === 403) return "You do not have permission to make that change.";
  if (status === 404) return "This item is no longer available.";
  if (status === 409) return "This change conflicts with the current state.";
  if (status === 429) return "Too many requests. Wait a moment and try again.";
  return "The request could not be completed. Try again.";
}
