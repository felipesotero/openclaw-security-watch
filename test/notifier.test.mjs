import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { buildMessage, cliStrategy, notifyCommandStrategy, redactSubject, runNotifier } from "../lib/notifier.js";

function makeChild({ code = 0, stderrText = "" } = {}) {
  const child = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = () => { child.killed = true; };
  queueMicrotask(() => {
    if (stderrText) child.stderr.emit("data", stderrText);
    child.emit("exit", code, null);
  });
  return child;
}

test("buildMessage includes agent and tool", () => {
  const msg = buildMessage({ agentId: "agent-1", sessionKey: "sess-9", toolName: "write", subject: "/tmp/a.md" });
  assert.match(msg, /Agente: agent-1/);
  assert.match(msg, /Sessão: sess-9/);
  assert.match(msg, /Ferramenta: write/);
});

test("buildMessage includes redacted subject", () => {
  const msg = buildMessage({ agentId: "agent-1", sessionKey: "sess-9", toolName: "write", subject: "https://api.example.com/v1?token=abc123def456ghijklmnopqrstuvwxyz1234", reasons: ["fora do horário"] });
  assert.match(msg, /Assunto: https:\/\/api\.example\.com\/v1/);
  assert.doesNotMatch(msg, /token=/i);
});

test("buildMessage truncates per redaction rules", () => {
  const msg = buildMessage({ agentId: "agent-1", sessionKey: "sess-9", toolName: "bash", subject: `bash: curl -H "Authorization: Bearer xyz" ${"a".repeat(400)}` });
  assert.ok(msg.length < 500);
});

test("buildMessage handles missing subject gracefully", () => {
  const msg = buildMessage({ agentId: "agent-1", sessionKey: "sess-9", toolName: "write" });
  assert.match(msg, /Assunto: ?$/m);
});

test("redacts bearer token in url", () => {
  assert.equal(redactSubject("https://api.example.com/v1?token=abc123def456ghijklmnopqrstuvwxyz1234", "write"), "https://api.example.com/v1");
});

test("redacts authorization header in bash command", () => {
  const subject = redactSubject('bash: curl -H "Authorization: Bearer xyz123xyz123xyz123xyz123xyz123" https://x', "bash");
  assert.doesNotMatch(subject, /Bearer|Authorization|xyz123/);
});

test("redacts long base64-like blob", () => {
  assert.equal(redactSubject(`value ${"A".repeat(40)}`, "write"), "value [REDACTED]");
});

test("redacts path with /secrets/", () => {
  assert.equal(redactSubject("/home/openclaw/.openclaw/secrets/token.txt", "write"), "[redacted-sensitive-path]");
});

test("redacts .env path", () => {
  assert.equal(redactSubject("/tmp/project/.env", "write"), "[redacted-sensitive-path]");
});

test("truncates very long subject to 200 chars", () => {
  assert.equal(redactSubject("z".repeat(220), "write").length, 201);
});

test("preserves short safe subject untouched", () => {
  assert.equal(redactSubject("/tmp/a.md", "write"), "/tmp/a.md");
});

test("runNotifier returns explicit strategy name on success", async () => {
  const result = await runNotifier([
    { name: "cli", run: async () => ({ ok: true, strategy: "cli" }) },
  ], {});
  assert.deepEqual(result, { ok: true, strategy: "cli" });
});

test("runNotifier returns explicit strategy name on each attempted failure", async () => {
  const result = await runNotifier([
    { name: "cli", run: async () => { throw new Error("first"); } },
    { name: "notifyCommand", run: async () => { throw new Error("last"); } },
  ], {});
  assert.deepEqual(result.attempted.map((x) => x.name), ["cli", "notifyCommand"]);
});

test("runNotifier failure includes list of attempted strategies and their errors", async () => {
  const result = await runNotifier([
    { name: "cli", run: async () => { throw new Error("x".repeat(900)); } },
  ], {});
  assert.equal(result.ok, false);
  assert.equal(typeof result.error, "string");
  assert.ok(result.error.length <= 501);
  assert.equal(result.attempted.length, 1);
  assert.equal(typeof result.attempted[0].error, "string");
  assert.ok(result.attempted[0].error.length <= 501);
});

test("cliStrategy throws when no channel", async () => {
  const notify = cliStrategy({ execImpl: () => makeChild() });
  await assert.rejects(() => notify({ agentId: "a" }), /channel\.kind/);
});

test("cliStrategy passes message containing $() and backticks raw via argv", async () => {
  const calls = [];
  const notify = cliStrategy({ execImpl: (cmd, args) => { calls.push({ cmd, args }); return makeChild(); } });
  await notify({ channel: { kind: "slack", target: "chan-1" }, agentId: "a", message: 'hello $(whoami) `rm -rf /`' });
  assert.equal(calls[0].cmd, "openclaw");
  assert.deepEqual(calls[0].args, ["slack", "send", "--agent", "a", "--to", "chan-1", "--text", 'hello $(whoami) `rm -rf /`']);
});

test("cliStrategy passes message containing semicolons and quotes raw via argv", async () => {
  const calls = [];
  const notify = cliStrategy({ execImpl: (cmd, args) => { calls.push({ cmd, args }); return makeChild(); } });
  await notify({ channel: { kind: "slack" }, agentId: "a", message: 'a; b "c"' });
  assert.equal(calls[0].args.at(-1), 'a; b "c"');
});

test("cliStrategy kills child on timeout", async () => {
  let killed = false;
  const child = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = () => { killed = true; };
  const notify = cliStrategy({ execImpl: () => child, timeoutMs: 1 });
  await assert.rejects(() => notify({ channel: { kind: "slack" }, agentId: "a", message: "m" }), /timed out/);
  assert.equal(killed, true);
});

test("cliStrategy includes --to <target> when target provided", async () => {
  const calls = [];
  const notify = cliStrategy({ execImpl: (cmd, args) => { calls.push(args); return makeChild(); } });
  await notify({ channel: { kind: "slack", target: "t" }, agentId: "a", message: "m" });
  assert.ok(calls[0].includes("--to"));
  assert.ok(calls[0].includes("t"));
});

test("cliStrategy omits --to when target absent", async () => {
  const calls = [];
  const notify = cliStrategy({ execImpl: (cmd, args) => { calls.push(args); return makeChild(); } });
  await notify({ channel: { kind: "slack" }, agentId: "a", message: "m" });
  assert.equal(calls[0].includes("--to"), false);
});

test("notifyCommandStrategy throws when no template", () => {
  assert.throws(() => notifyCommandStrategy({}), /requires template/);
});

test("notifyCommandStrategy supports argv template substitution", async () => {
  const calls = [];
  const notify = notifyCommandStrategy({
    template: ["./my-script", "{kind}", "{text}", "{subject}", "{target}"],
    execImpl: (cmd, args) => { calls.push({ cmd, args }); return makeChild(); },
  });
  await notify({ kind: "slack", text: "hello", subject: "s", target: "t" });
  assert.deepEqual(calls[0], { cmd: "./my-script", args: ["slack", "hello", "s", "t"] });
});

test("notifyCommandStrategy rejects legacy string templates with spaces", () => {
  const notify = notifyCommandStrategy({ template: "./my script" });
  assert.rejects(() => notify({}), /argv-array template/);
});

test("notifyCommandStrategy passes message via argv and not shell", async () => {
  const calls = [];
  const notify = notifyCommandStrategy({
    template: ["./notify", "{text}"],
    execImpl: (cmd, args) => { calls.push({ cmd, args }); return makeChild(); },
  });
  await notify({ text: '$(touch x) `rm` ; "quoted"' });
  assert.deepEqual(calls[0], { cmd: "./notify", args: ['$(touch x) `rm` ; "quoted"'] });
});

test("notifyCommandStrategy clears timeout on early child exit", async () => {
  let clearCalls = 0;
  const originalClearTimeout = globalThis.clearTimeout;
  globalThis.clearTimeout = (...args) => { clearCalls += 1; return originalClearTimeout(...args); };
  try {
    const notify = notifyCommandStrategy({ template: ["./notify"], execImpl: () => makeChild(), timeoutMs: 1000 });
    await notify({});
    assert.equal(clearCalls > 0, true);
  } finally {
    globalThis.clearTimeout = originalClearTimeout;
  }
});
