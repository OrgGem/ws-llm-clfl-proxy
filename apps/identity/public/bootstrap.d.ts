export interface BootstrapMetadata {
  version: 1;
  identityUrl: string;
  gatewayUrl: string;
  client: { clientId: string; kind: "confidential" | "public" };
  projectId: string;
  models: Array<{ id: string; provider: "openai" | "anthropic" }>;
  limits: { maxPayloadBytes: number; maxConcurrency: number; maxSessionSeconds: number };
}

export function safeBootstrapMetadata(response: unknown): BootstrapMetadata;
