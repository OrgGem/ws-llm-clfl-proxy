import { applyD1Migrations } from "cloudflare:test";
import identityMigrationSql from "../apps/identity/migrations/0001_identity.sql?raw";
import setupMigrationSql from "../apps/identity/migrations/0002_bootstrap_setup.sql?raw";
import providerRegistryMigrationSql from "../apps/identity/migrations/0003_provider_registry.sql?raw";
import oauthConnectorsMigrationSql from "../apps/identity/migrations/0004_oauth_connectors.sql?raw";

function migrationQueries(sql: string): string[] {
  return sql
    .split(";")
    .map((query) => query.trim())
    .filter((query) => query.length > 0 && !/^PRAGMA\b/i.test(query));
}

export async function migrateIdentityDatabase(db: D1Database): Promise<void> {
  const migrations = [
    { name: "0001_identity.sql", queries: migrationQueries(identityMigrationSql) },
    { name: "0002_bootstrap_setup.sql", queries: migrationQueries(setupMigrationSql) },
    { name: "0003_provider_registry.sql", queries: migrationQueries(providerRegistryMigrationSql) },
    { name: "0004_oauth_connectors.sql", queries: migrationQueries(oauthConnectorsMigrationSql) },
  ];
  for (const migration of migrations) {
    try {
      await applyD1Migrations(db, [migration]);
    } catch (cause) {
      throw new Error(`Failed to apply ${migration.name}`, { cause });
    }
  }
}

export function decodeBase64Url(value: string): Uint8Array {
  const standard = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = standard + "=".repeat((4 - (standard.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function randomProviderSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function randomId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID()}`;
}
