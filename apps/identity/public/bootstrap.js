function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requiredString(value, field) {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(`Client setup metadata is missing ${field}`);
  return value;
}

/** Project a backend response onto the adapter's strict, secret-free v1 schema. */
export function safeBootstrapMetadata(response) {
  if (!isRecord(response) || response.version !== 1 || !isRecord(response.client)
    || !Array.isArray(response.models) || !isRecord(response.limits)) {
    throw new TypeError("Client setup metadata is invalid");
  }
  const { client, limits } = response;
  if (client.kind !== "confidential" && client.kind !== "public") throw new TypeError("Client setup metadata has an invalid client kind");
  if (response.models.length > 256) throw new TypeError("Client setup metadata has too many model grants");
  const models = response.models.map((model) => {
    if (!isRecord(model) || typeof model.id !== "string" || !model.id.trim()
      || (model.provider !== "openai" && model.provider !== "anthropic")) {
      throw new TypeError("Client setup metadata contains an invalid model grant");
    }
    return { id: model.id, provider: model.provider };
  });
  for (const key of ["maxPayloadBytes", "maxConcurrency", "maxSessionSeconds"]) {
    if (!Number.isInteger(limits[key])) throw new TypeError("Client setup metadata has invalid project limits");
  }

  return {
    version: 1,
    identityUrl: requiredString(response.identityUrl, "Identity URL"),
    gatewayUrl: requiredString(response.gatewayUrl, "Gateway URL"),
    client: {
      clientId: requiredString(client.clientId, "client ID"),
      kind: client.kind,
    },
    projectId: requiredString(response.projectId, "project ID"),
    models,
    limits: {
      maxPayloadBytes: limits.maxPayloadBytes,
      maxConcurrency: limits.maxConcurrency,
      maxSessionSeconds: limits.maxSessionSeconds,
    },
  };
}
