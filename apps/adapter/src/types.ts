import type { CredentialEnvelope } from "@ws-proxy/shared";

export type Provider = string;
export type ProviderProtocol = "openai" | "anthropic";
export type { CredentialEnvelope } from "@ws-proxy/shared";

export type MachineAuth =
  | { type: "confidential"; clientId: string; clientSecret: string }
  | { type: "public"; clientId: string; refreshToken: string };

export interface ModelConfig {
  id: string;
  provider: Provider;
  protocol: ProviderProtocol;
  credentialId: string;
}

export interface AdapterConfig {
  version: 1;
  identityUrl: string;
  gatewayUrl: string;
  auth: MachineAuth;
  localBearerToken: string;
  port: number;
  models: ModelConfig[];
  envelopes: CredentialEnvelope[];
}

export type GatewayProviderPayload = Record<string, unknown>;
