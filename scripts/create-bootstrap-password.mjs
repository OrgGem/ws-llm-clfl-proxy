import { createHash, randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

// High-entropy setup credential, never a shared application default.
const directory = path.resolve(".local/bootstrap");
await mkdir(path.dirname(directory), { recursive: true, mode: 0o700 });
// Claim a new private directory before creating either file. Partial previous
// output is never mixed with a newly generated password/verifier pair.
await mkdir(directory, { mode: 0o700 });
const password = randomBytes(24).toString("base64url");
const expiresAt = Math.floor(Date.now() / 1000) + 24 * 60 * 60;
const hash = createHash("sha256").update(password).digest("base64url");
const secrets = { BOOTSTRAP_PASSWORD_HASH: hash, BOOTSTRAP_PASSWORD_EXPIRES_AT: String(expiresAt) };
await writeFile(path.join(directory, "secrets.json"), JSON.stringify(secrets), { mode: 0o600, flag: "wx" });
await writeFile(path.join(directory, "password.txt"), [
  "UI: https://llm.gemslab.id.vn/ui",
  `Temporary setup password: ${password}`,
  `Expires: ${new Date(expiresAt * 1000).toISOString()}`,
  "Open Initial setup, enter this password, then configure Google/OIDC.",
  "This credential grants OIDC setup only. It is disabled after the first successful OIDC administrator login.",
  "Delete this file after setup. Never commit or share it.",
  "",
].join("\n"), { mode: 0o600, flag: "wx" });
console.log("Created private .local/bootstrap/password.txt and secrets.json (24-hour expiry). Existing files are never overwritten.");
