#!/usr/bin/env node
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { readFile, open, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MAX_TASK_BYTES = 32 * 1024;
const MAX_SYSTEM_BYTES = 16 * 1024;
const MAX_REQUEST_BYTES = 1024 * 1024;
const SYSTEM_FILE = new URL("./agent.system.md", import.meta.url);

class SafeInputError extends Error {}

function usage() {
  process.stdout.write("Usage: node agent.mjs --config-env .env [--task-file task.txt]\n\n");
  process.stdout.write("Without --task-file, the task is read from stdin. The task is sent to the adapter over stdin, never as a process argument.\n");
}

function parseArgs(args) {
  const parsed = { envFile: undefined, taskFile: undefined };
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--help" || arg === "-h") return { help: true };
    if (arg === "--config-env" || arg === "--task-file") {
      const value = args[i + 1];
      if (!value || value.startsWith("--")) throw new SafeInputError(`Expected a path after ${arg}`);
      i += 1;
      if (arg === "--config-env") {
        if (parsed.envFile) throw new SafeInputError("Use --config-env once");
        parsed.envFile = value;
      } else {
        if (parsed.taskFile) throw new SafeInputError("Use --task-file once");
        parsed.taskFile = value;
      }
      continue;
    }
    throw new SafeInputError("Unknown option. Use --help for usage.");
  }
  if (!parsed.envFile) throw new SafeInputError("Set --config-env to the protected adapter environment file.");
  return parsed;
}

async function readBoundedFile(filename, maxBytes, label) {
  const absolutePath = path.resolve(filename);
  let fileStat;
  try {
    fileStat = await stat(absolutePath);
  } catch {
    throw new SafeInputError(`${label} file cannot be read.`);
  }
  if (!fileStat.isFile() || fileStat.size > maxBytes) throw new SafeInputError(`${label} file must be a regular file no larger than ${maxBytes} bytes.`);
  let file;
  try {
    file = await open(absolutePath, "r");
  } catch {
    throw new SafeInputError(`${label} file cannot be read.`);
  }
  const buffer = Buffer.alloc(maxBytes + 1);
  let length = 0;
  try {
    while (length < buffer.byteLength) {
      const { bytesRead } = await file.read(buffer, length, buffer.byteLength - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
  } catch {
    throw new SafeInputError(`${label} file cannot be read.`);
  } finally {
    await file.close().catch(() => {});
  }
  if (length > maxBytes) throw new SafeInputError(`${label} file must be a regular file no larger than ${maxBytes} bytes.`);
  return buffer.subarray(0, length).toString("utf8");
}

async function readBoundedStdin(maxBytes) {
  const chunks = [];
  let size = 0;
  try {
    for await (const chunk of process.stdin) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.byteLength;
      if (size > maxBytes) throw new SafeInputError(`Task input exceeds the ${maxBytes}-byte limit.`);
      chunks.push(bytes);
    }
  } catch (error) {
    if (error instanceof SafeInputError) throw error;
    throw new SafeInputError("Task input could not be read from stdin.");
  }
  return Buffer.concat(chunks, size).toString("utf8");
}

async function loadAdapterCli() {
  const require = createRequire(import.meta.url);
  let packageJsonPath;
  try {
    packageJsonPath = require.resolve("@ws-proxy/adapter/package.json");
  } catch {
    throw new SafeInputError("The @ws-proxy/adapter package is not installed. Follow README.md to install the built adapter package.");
  }
  let packageJson;
  try {
    packageJson = JSON.parse(await readFile(packageJsonPath, "utf8"));
  } catch {
    throw new SafeInputError("The installed adapter package metadata cannot be read.");
  }
  const bin = typeof packageJson.bin === "string" ? packageJson.bin : packageJson.bin?.["ws-llm-adapter"];
  if (typeof bin !== "string") throw new SafeInputError("The installed adapter package does not expose ws-llm-adapter.");
  return path.resolve(path.dirname(packageJsonPath), bin);
}

function signalExitCode(signal) {
  if (signal === "SIGINT") return 130;
  if (signal === "SIGTERM") return 143;
  return 1;
}

async function run() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    usage();
    return;
  }

  const task = options.taskFile && options.taskFile !== "-"
    ? await readBoundedFile(options.taskFile, MAX_TASK_BYTES, "Task")
    : await readBoundedStdin(MAX_TASK_BYTES);
  if (!task.trim()) throw new SafeInputError("Task input is empty.");

  const system = await readBoundedFile(fileURLToPath(SYSTEM_FILE), MAX_SYSTEM_BYTES, "Trusted agent instructions");
  const request = {
    messages: [
      { role: "system", content: system.trim() },
      { role: "user", content: task },
    ],
    stream: false,
  };
  const requestJson = JSON.stringify(request);
  if (Buffer.byteLength(requestJson, "utf8") > MAX_REQUEST_BYTES) throw new SafeInputError("The encoded request exceeds the Gateway request limit.");

  const adapterCli = await loadAdapterCli();
  const envFile = path.resolve(options.envFile);
  let child;
  try {
    child = spawn(process.execPath, [
      adapterCli,
      "--config-env",
      envFile,
      "request",
      "--api",
      "chat.completions",
    ], {
      cwd: process.cwd(),
      env: process.env,
      shell: false,
      stdio: ["pipe", "inherit", "inherit"],
    });
  } catch {
    throw new SafeInputError("Unable to start the adapter CLI. Check that it is installed correctly.");
  }

  let interruptedBy;
  const forwardSignal = (signal) => {
    interruptedBy = signal;
    if (!child.killed) child.kill(signal);
  };
  const onSigint = () => forwardSignal("SIGINT");
  const onSigterm = () => forwardSignal("SIGTERM");
  process.once("SIGINT", onSigint);
  process.once("SIGTERM", onSigterm);
  child.stdin.on("error", () => {});

  const result = await new Promise((resolve) => {
    child.once("error", () => resolve({ spawnFailed: true }));
    child.once("close", (code, signal) => resolve({ code, signal }));
    child.stdin.end(requestJson);
  }).finally(() => {
    process.removeListener("SIGINT", onSigint);
    process.removeListener("SIGTERM", onSigterm);
  });

  if (result.spawnFailed) {
    process.stderr.write("Unable to start the adapter CLI. Check that it is installed correctly.\n");
    process.exitCode = 1;
    return;
  }
  const { code, signal } = result;
  if (code === 0 && !interruptedBy && !signal) return;
  process.exitCode = typeof code === "number" && code !== 0 ? code : signalExitCode(interruptedBy ?? signal);
}

run().catch((error) => {
  const message = error instanceof SafeInputError ? error.message : "The agent request could not be prepared. Check the input and adapter installation.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
