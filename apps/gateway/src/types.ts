export interface MachineClaims {
  sub: string;
  sid: string;
  project_id: string;
  client_id: string;
  jti: string;
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nbf: number;
}

export interface ProjectLimits {
  maxPayloadBytes: number;
  maxConcurrency: number;
  maxSessionSeconds: number;
}

export interface IdentityValidationResult {
  valid: boolean;
  claims?: unknown;
  reasonCode?: string;
  limits?: unknown;
}

export interface AuthorizedPrincipal {
  userId: string;
  projectId: string;
  clientId: string;
  sessionId: string;
}

export interface AuthorizedCredentialMetadata {
  credentialKind?: "api_key" | "oauth_access_token";
  credentialId: string;
  userId: string;
  projectId: string;
  provider: string;
  expiresAt: number;
  keyVersion: string;
}

export interface AuthorizedModel {
  alias: string;
  upstreamModel: string;
}

export interface AuthorizedProvider {
  id: string;
  displayName: string;
  protocol: "openai" | "anthropic";
  baseUrl: string;
  custom: boolean;
}

export interface IdentityAuthorizationResult {
  allowed: boolean;
  principal?: AuthorizedPrincipal;
  credentialMetadata?: AuthorizedCredentialMetadata;
  authorizedModel?: AuthorizedModel;
  authorizedProvider?: AuthorizedProvider;
  limits?: unknown;
  reasonCode?: string;
}

export interface IdentityAuthorizeRequest {
  accessToken: string;
  credentialId: string;
  provider: string;
  model: string;
}

/**
 * RPC methods exposed only through the Identity service binding's named
 * WorkerEntrypoint. The generated service type cannot import another Worker's
 * entrypoint declaration, so the adapter narrows that binding to this contract.
 */
export interface IdentityInternalBinding extends Fetcher {
  validateToken(accessToken: string): Promise<IdentityValidationResult>;
  authorizeTokenRequest(input: IdentityAuthorizeRequest): Promise<IdentityAuthorizationResult>;
}

export interface GatewayDependencies {
  identity: IdentityInternalBinding;
  machineIssuer: string;
  envelopeKeys: string;
  fetcher: typeof fetch;
  /** Test injection for the shared Cloudflare DoH endpoint resolver. */
  endpointDnsFetcher?: typeof fetch;
  /** Optional configured public Gateway origin to prevent registry self-targeting. */
  gatewayOrigin?: string;
}
