import { randomUUID, randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { chmod, lstat, mkdir, open, rename, rm, type FileHandle } from "node:fs/promises";
import path from "node:path";
import type { OAuthModelSummary } from "./oauth.js";

export interface StoredChatGptProfile {
  profileId: string;
  clientId: string;
  subject: string;
  email?: string;
  connectedAt: number;
  scopes: string[];
  refreshToken?: string;
  projectId?: string;
  identityOrigin?: string;
  modelCache?: OAuthModelSummary[];
}

export interface OAuthStorage {
  version: 1;
  hostId: string;
  profiles: StoredChatGptProfile[];
}

const LOCK_MAX_AGE_MS = 120_000;
const LOCK_WAIT_MS = 40_000;

/** Stores refresh tokens separately from adapter.json; access tokens are never persisted. */
export class OAuthProfileStore {
  readonly filePath: string;
  private readonly lockPath: string;

  constructor(adapterConfigPath: string) {
    this.filePath = `${adapterConfigPath}.oauth.json`;
    this.lockPath = `${this.filePath}.lock`;
  }

  async snapshot(): Promise<OAuthStorage> {
    await this.ensureDirectory();
    await this.rejectSymlink(this.filePath);
    try {
      const parsed = JSON.parse(await this.readPrivateFile()) as unknown;
      return validateStorage(parsed);
    } catch (error) {
      if (isCode(error, "ENOENT")) return emptyStorage();
      throw new OAuthStoreError("OAuth profile storage is unreadable or has unsafe permissions");
    }
  }

  async transaction<T>(action: (current: OAuthStorage) => Promise<{ value: T; next?: OAuthStorage }> | { value: T; next?: OAuthStorage }): Promise<T> {
    await this.ensureDirectory();
    const release = await this.acquireLock();
    try {
      await this.rejectSymlink(this.filePath);
      const current = await this.readUnlocked();
      const outcome = await action(current);
      if (outcome.next) await this.writeUnlocked(validateStorage(outcome.next));
      return outcome.value;
    } finally {
      await release();
    }
  }

  async update(mutator: (current: OAuthStorage) => Promise<OAuthStorage> | OAuthStorage): Promise<OAuthStorage> {
    return this.transaction(async (current) => {
      const next = await mutator(current);
      return { value: next, next };
    });
  }

  private async readUnlocked(): Promise<OAuthStorage> {
    await this.rejectSymlink(this.filePath);
    try {
      return validateStorage(JSON.parse(await this.readPrivateFile()) as unknown);
    } catch (error) {
      if (isCode(error, "ENOENT")) return emptyStorage();
      throw new OAuthStoreError("OAuth profile storage is unreadable or has unsafe permissions");
    }
  }

  private async writeUnlocked(value: OAuthStorage): Promise<void> {
    const tempPath = `${this.filePath}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
    try {
      const handle = await open(tempPath, "wx", 0o600);
      try {
        await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
      if (process.platform !== "win32") await chmod(tempPath, 0o600);
      await rename(tempPath, this.filePath);
      if (process.platform !== "win32") await chmod(this.filePath, 0o600);
      try {
        const dirHandle = await open(path.dirname(this.filePath), "r");
        try { await dirHandle.sync(); } finally { await dirHandle.close(); }
      } catch {
        // Directory fsync is not supported by every host filesystem.
      }
    } catch {
      await rm(tempPath, { force: true }).catch(() => undefined);
      throw new OAuthStoreError("Could not safely save OAuth profile state");
    }
  }

  private async readPrivateFile(): Promise<string> {
    let handle: FileHandle | undefined;
    try {
      const noFollow = fsConstants.O_NOFOLLOW ?? 0;
      handle = await open(this.filePath, fsConstants.O_RDONLY | noFollow);
      const fileStat = await handle.stat();
      if (!fileStat.isFile() || fileStat.size > 4 * 1024 * 1024 || (process.platform !== "win32" && (fileStat.mode & 0o077) !== 0)) {
        throw new Error("unsafe file");
      }
      return await handle.readFile("utf8");
    } finally {
      await handle?.close();
    }
  }

  private async ensureDirectory(): Promise<void> {
    const directory = path.dirname(this.filePath);
    const created = await mkdir(directory, { recursive: true, mode: 0o700 }).catch(() => undefined);
    if (process.platform !== "win32" && created && path.resolve(created) === path.resolve(directory)) {
      await chmod(directory, 0o700);
    }
    try {
      const directoryStat = await lstat(directory);
      if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) throw new Error("unsafe directory");
      if (process.platform !== "win32" && (directoryStat.mode & 0o077) !== 0) throw new Error("broad permissions");
    } catch {
      throw new OAuthStoreError("OAuth profile directory must be a real, private (0700) directory");
    }
  }

  private async rejectSymlink(filePath: string): Promise<void> {
    try {
      const info = await lstat(filePath);
      if (info.isSymbolicLink()) throw new OAuthStoreError("OAuth profile storage refuses symbolic links");
    } catch (error) {
      if (error instanceof OAuthStoreError) throw error;
      if (!isCode(error, "ENOENT")) throw new OAuthStoreError("OAuth profile storage cannot be inspected safely");
    }
  }

  private async acquireLock(): Promise<() => Promise<void>> {
    const started = Date.now();
    while (Date.now() - started < LOCK_WAIT_MS) {
      await this.rejectSymlink(this.lockPath);
      let handle: FileHandle | undefined;
      try {
        handle = await open(this.lockPath, "wx", 0o600);
        await handle.writeFile(JSON.stringify({ pid: process.pid, createdAt: Date.now() }), "utf8");
        await handle.sync();
        if (process.platform !== "win32") await chmod(this.lockPath, 0o600);
        const inode = await handle.stat();
        return async () => {
          await handle?.close().catch(() => undefined);
          try {
            const current = await lstat(this.lockPath);
            if (current.ino === inode.ino && current.dev === inode.dev) await rm(this.lockPath);
          } catch (error) {
            if (!isCode(error, "ENOENT")) throw new OAuthStoreError("Could not release OAuth profile lock safely");
          }
        };
      } catch (error) {
        if (handle) await handle.close().catch(() => undefined);
        if (!isCode(error, "EEXIST")) throw new OAuthStoreError("Could not acquire OAuth profile lock");
        if (await this.removeStaleLock()) continue;
        await new Promise((resolve) => setTimeout(resolve, 80));
      }
    }
    throw new OAuthStoreError("OAuth profile storage is busy in another adapter process; retry shortly");
  }

  private async removeStaleLock(): Promise<boolean> {
    try {
      await this.rejectSymlink(this.lockPath);
      const before = await lstat(this.lockPath);
      if (!before.isFile() || Date.now() - before.mtimeMs <= LOCK_MAX_AGE_MS) return false;
      const after = await lstat(this.lockPath);
      if (after.ino !== before.ino || after.dev !== before.dev) return false;
      await rm(this.lockPath);
      return true;
    } catch (error) {
      if (error instanceof OAuthStoreError) throw error;
      if (isCode(error, "ENOENT")) return true;
      return false;
    }
  }
}

export class OAuthStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OAuthStoreError";
  }
}

function emptyStorage(): OAuthStorage {
  return { version: 1, hostId: `urn:uuid:${randomUUID()}`, profiles: [] };
}

function validateStorage(value: unknown): OAuthStorage {
  if (!isRecord(value) || value.version !== 1 || typeof value.hostId !== "string" || !/^urn:uuid:[0-9a-f-]{36}$/i.test(value.hostId) || !Array.isArray(value.profiles) || value.profiles.length > 32) {
    throw new OAuthStoreError("OAuth profile storage has an unsupported format");
  }
  const profileIds = new Set<string>();
  const profiles = value.profiles.map((entry): StoredChatGptProfile => {
    if (!isRecord(entry)) throw new OAuthStoreError("OAuth profile storage has an unsupported format");
    const profileId = string(entry.profileId, /^[A-Za-z0-9_-]{20,64}$/);
    const clientId = string(entry.clientId, /^[A-Za-z0-9._:-]{1,512}$/);
    const subject = string(entry.subject, /^.{1,512}$/s);
    const connectedAt = integer(entry.connectedAt, 1, Number.MAX_SAFE_INTEGER);
    if (!Array.isArray(entry.scopes) || entry.scopes.length > 32 || !entry.scopes.every((scope) => typeof scope === "string" && scope.length <= 128)) {
      throw new OAuthStoreError("OAuth profile storage has an unsupported format");
    }
    if (profileIds.has(profileId)) throw new OAuthStoreError("OAuth profile IDs must be unique");
    profileIds.add(profileId);
    const profile: StoredChatGptProfile = { profileId, clientId, subject, connectedAt, scopes: [...entry.scopes] as string[] };
    if (entry.email !== undefined) {
      if (typeof entry.email !== "string" || entry.email.length > 320) throw new OAuthStoreError("OAuth profile storage has an unsupported format");
      profile.email = entry.email;
    }
    if (entry.refreshToken !== undefined) profile.refreshToken = string(entry.refreshToken, /^.{32,8192}$/s);
    if (entry.projectId !== undefined) profile.projectId = string(entry.projectId, /^[A-Za-z0-9._:-]{1,128}$/);
    if (entry.identityOrigin !== undefined) {
      if (typeof entry.identityOrigin !== "string") throw new OAuthStoreError("OAuth profile storage has an unsupported format");
      let parsed: URL;
      try { parsed = new URL(entry.identityOrigin); } catch { throw new OAuthStoreError("OAuth profile storage has an unsupported format"); }
      if (parsed.origin !== entry.identityOrigin || (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLoopbackOrigin(parsed.hostname)))) {
        throw new OAuthStoreError("OAuth profile storage has an unsupported format");
      }
      profile.identityOrigin = entry.identityOrigin;
    }
    if (entry.modelCache !== undefined) {
      if (!Array.isArray(entry.modelCache) || entry.modelCache.length > 500) throw new OAuthStoreError("OAuth profile model cache is invalid");
      profile.modelCache = entry.modelCache.map(validateCachedModel);
    }
    return profile;
  });
  return { version: 1, hostId: value.hostId, profiles };
}

function isLoopbackOrigin(hostname: string): boolean {
  const value = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  return value === "localhost" || value === "::1" || /^127(?:\.\d{1,3}){3}$/.test(value);
}

function validateCachedModel(value: unknown): OAuthModelSummary {
  if (!isRecord(value)) throw new OAuthStoreError("OAuth profile model cache is invalid");
  const id = string(value.id, /^[^\u0000-\u0020]{1,256}$/);
  const model: OAuthModelSummary = { id, inputModalities: [], reasoningEfforts: [] };
  if (value.displayName !== undefined) model.displayName = string(value.displayName, /^.{1,256}$/s);
  if (value.contextWindow !== undefined) model.contextWindow = integer(value.contextWindow, 1, 10_000_000);
  if (!Array.isArray(value.inputModalities) || value.inputModalities.length > 16 || !value.inputModalities.every((item) => typeof item === "string" && item.length <= 32)) {
    throw new OAuthStoreError("OAuth profile model cache is invalid");
  }
  if (!Array.isArray(value.reasoningEfforts) || value.reasoningEfforts.length > 32 || !value.reasoningEfforts.every((item) => typeof item === "string" && item.length <= 64)) {
    throw new OAuthStoreError("OAuth profile model cache is invalid");
  }
  model.inputModalities = [...value.inputModalities] as string[];
  model.reasoningEfforts = [...value.reasoningEfforts] as string[];
  return model;
}

function string(value: unknown, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new OAuthStoreError("OAuth profile storage has an unsupported format");
  return value;
}

function integer(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new OAuthStoreError("OAuth profile storage has an unsupported format");
  return Number(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isCode(error: unknown, code: string): boolean {
  return error !== null && typeof error === "object" && "code" in error && (error as NodeJS.ErrnoException).code === code;
}
