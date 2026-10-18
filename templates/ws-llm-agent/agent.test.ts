import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const templateDir = path.dirname(fileURLToPath(import.meta.url));
let sandbox: string;

beforeEach(async () => {
  sandbox = await mkdtemp(path.join(os.tmpdir(), "ws-llm-agent-test-"));
  await Promise.all([
    copy("agent.mjs"),
    copy("agent.system.md"),
  ]);
  const packageRoot = path.join(sandbox, "node_modules", "@ws-proxy", "adapter");
  await mkdir(path.join(packageRoot, "dist"), { recursive: true });
  await writeFile(path.join(packageRoot, "package.json"), JSON.stringify({
    name: "@ws-proxy/adapter",
    bin: { "ws-llm-adapter": "./dist/bin.js" },
  }));
  await writeFile(path.join(packageRoot, "dist", "bin.js"), `
const chunks = [];
process.stdin.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
process.stdin.on("end", () => {
  process.stdout.write(JSON.stringify({ args: process.argv.slice(2), request: JSON.parse(Buffer.concat(chunks).toString("utf8")) }));
  process.exitCode = Number(process.env.FAKE_ADAPTER_EXIT ?? 0);
});
`);
  await writeFile(path.join(sandbox, "adapter.env"), "WS_PROXY_CONFIG_SOURCE=env\n");
});

afterEach(async () => {
  await rm(sandbox, { recursive: true, force: true });
});

describe("agent.mjs", () => {
  it("sends bounded Chat JSON on stdin without putting task text in argv or adding tools", async () => {
    const task = "TASK_TEXT_SENTINEL: summarize only this input";
    const taskFile = path.join(sandbox, "task.txt");
    await writeFile(taskFile, task, { mode: 0o600 });

    const result = runAgent(["--config-env", path.join(sandbox, "adapter.env"), "--task-file", taskFile]);
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    const child = JSON.parse(result.stdout) as {
      args: string[];
      request: { messages: Array<{ role: string; content: string }>; stream: boolean; model?: string; tools?: unknown[] };
    };
    expect(child.args).toEqual(["--config-env", path.join(sandbox, "adapter.env"), "request", "--api", "chat.completions"]);
    expect(child.args.join(" ")).not.toContain(task);
    expect(child.request.messages).toHaveLength(2);
    expect(child.request.messages[0]).toMatchObject({ role: "system" });
    expect(child.request.messages[0]?.content).toContain("You have no tools in this request");
    expect(child.request.messages[1]).toEqual({ role: "user", content: task });
    expect(child.request.stream).toBe(false);
    expect(child.request).not.toHaveProperty("model");
    expect(child.request).not.toHaveProperty("tools");
  });

  it("propagates the adapter's nonzero exit status", async () => {
    const result = runAgent(["--config-env", path.join(sandbox, "adapter.env")], {
      input: "one bounded task from stdin",
      env: { FAKE_ADAPTER_EXIT: "7" },
    });
    expect(result.status).toBe(7);
    expect(JSON.parse(result.stdout).request.messages[1].content).toBe("one bounded task from stdin");
  });

  it("rejects oversized task files without echoing their contents or path", async () => {
    const sentinel = "OVERSIZE_TASK_SECRET_SENTINEL";
    const taskFile = path.join(sandbox, "private-task.txt");
    await writeFile(taskFile, `${sentinel}${"x".repeat(32 * 1024)}`, { mode: 0o600 });

    const result = runAgent(["--config-env", path.join(sandbox, "adapter.env"), "--task-file", taskFile]);
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Task file must be a regular file");
    expect(result.stderr).not.toContain(sentinel);
    expect(result.stderr).not.toContain(taskFile);
  });
});

function runAgent(args: string[], options: { input?: string; env?: Record<string, string> } = {}) {
  return spawnSync(process.execPath, [path.join(sandbox, "agent.mjs"), ...args], {
    cwd: sandbox,
    encoding: "utf8",
    input: options.input,
    env: { ...process.env, FAKE_ADAPTER_EXIT: "0", ...options.env },
    timeout: 10_000,
  });
}

async function copy(filename: string): Promise<void> {
  await writeFile(path.join(sandbox, filename), await readFile(path.join(templateDir, filename)));
}
