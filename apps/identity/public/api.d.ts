export class ApiError extends Error {
  status: number;
  constructor(status: number, message?: string);
}

export interface ApiClientOptions {
  origin?: string;
  fetchImpl?: typeof fetch;
  getCsrfToken?: () => string | undefined;
}

export interface ApiClient {
  request(path: string, options?: { method?: string; body?: unknown; headers?: HeadersInit }): Promise<unknown>;
  get(path: string, query?: Record<string, string | number | boolean | undefined | null>): Promise<unknown>;
  post(path: string, body?: unknown): Promise<unknown>;
  put(path: string, body?: unknown): Promise<unknown>;
  delete(path: string): Promise<unknown>;
}

export function createApiClient(options?: ApiClientOptions): ApiClient;
