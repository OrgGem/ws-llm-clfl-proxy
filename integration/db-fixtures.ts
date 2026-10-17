import { applyD1Migrations } from "cloudflare:test";
import migrationSql from "../apps/identity/migrations/0001_identity.sql?raw";

const migrationQueries = migrationSql
  .split(";")
  .map((query) => query.trim())
  .filter((query) => query.length > 0 && !/^PRAGMA\b/i.test(query));

export async function migrateIdentityDatabase(db: D1Database): Promise<void> {
  await applyD1Migrations(db, [{ name: "0001_identity.sql", queries: migrationQueries }]);
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
