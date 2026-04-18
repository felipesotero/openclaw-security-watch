import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import plugin from "../index.js";

function makeHarness({ pluginConfig = {}, config = {}, deps = {} } = {}) {
  const handlers = {};
  const api = { pluginConfig, config, logger: { warn() {} }, on(name, handler) { handlers[name] = handler; } };
  plugin.register(api, deps);
  return { api, handlers };
}

function readAudit(logPath) {
  return fs.readFileSync(logPath, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

test("automation approval notifies slack and still returns approval", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-index-"));
  const logPath = path.join(tempDir, "audit.jsonl");
  const notifyCalls = [];
  const { handlers } = makeHarness({
    pluginConfig: { logPath, notifyCommand: ["echo", "notify", "{channel}", "{text}"] },
    config: {
      agents: {
        list: [{ id: "comercial", workspace: "~/workspace/comercial", channels: [{ kind: "slack", id: "slack-main", enabled: true }] }]
      },
      channels: { slack: { "slack-main": { target: "#approvals" } } }
    },
    deps: {
      evaluateToolCall: () => ({ outcome: "approval", severity: "warning", reasons: ["approval_path:outside_trusted_workspace"], subject: "/tmp/secret.txt", toolName: "read" }),
      notifierRun: async (_strategies, payload) => {
        notifyCalls.push(payload);
        return { ok: true, strategy: "cli" };
      }
    }
  });

  const result = await handlers.before_tool_call({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/secret.txt" } }, { sessionKey: "agent:comercial:cron:123", agentId: "comercial", sessionId: "session-1", runId: "run-1", jobId: "job-1" });
  assert.ok(result?.requireApproval);
  assert.match(result.requireApproval.description, /Notified slack for approval/);
  assert.equal(notifyCalls.length, 1);
  await new Promise((resolve) => setImmediate(resolve));
  const audit = readAudit(logPath);
  assert.equal(audit.filter((entry) => entry.phase === "before_tool_call").length, 1);
  assert.equal(audit.filter((entry) => entry.audit_event === "notification_resolution").length, 1);
});

test("notification failure still returns requireApproval and does not become validator_failure", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-index-"));
  const logPath = path.join(tempDir, "audit.jsonl");
  const { handlers } = makeHarness({
    pluginConfig: { logPath },
    config: { agents: { list: [{ id: "a1", channels: [{ kind: "slack", id: "s1", enabled: true }] }] }, channels: {} },
    deps: {
      evaluateToolCall: () => ({ outcome: "approval", severity: "warning", reasons: ["x"], subject: "/tmp/x", toolName: "read" }),
      notifierRun: async () => ({ ok: false, error: "boom", attempted: [{ name: "cli", error: "boom" }] })
    }
  });
  const result = await handlers.before_tool_call({ toolName: "read", params: { filePath: "/tmp/x" } }, { sessionKey: "agent:a1:cron:1", agentId: "a1", sessionId: "s", runId: "r", jobId: "j" });
  assert.ok(result?.requireApproval);
  await new Promise((r) => setImmediate(r));
  const audit = readAudit(logPath);
  assert.ok(!audit.some((entry) => entry.classification === "validator_failure"));
});

test("malformed channel config does not block approval flow", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-index-"));
  const logPath = path.join(tempDir, "audit.jsonl");
  const { handlers } = makeHarness({
    pluginConfig: { logPath, channelPriority: ["slack"] },
    config: { agents: { list: [{ id: "a1", channels: [{ kind: "slack", id: "s1", enabled: true }] }] }, channels: null },
    deps: { evaluateToolCall: () => ({ outcome: "approval", severity: "warning", reasons: ["x"], subject: "/tmp/x", toolName: "read" }) }
  });
  const result = await handlers.before_tool_call({ toolName: "read", params: { filePath: "/tmp/x" } }, { sessionKey: "agent:a1:cron:1", agentId: "a1", sessionId: "s", runId: "r", jobId: "j" });
  assert.ok(result?.requireApproval);
});

test("no human channel records notifyError and still returns approval", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-index-"));
  const logPath = path.join(tempDir, "audit.jsonl");
  const { handlers } = makeHarness({
    pluginConfig: { logPath },
    config: { agents: { list: [{ id: "a1", channels: [] }] }, channels: {} },
    deps: { evaluateToolCall: () => ({ outcome: "approval", severity: "warning", reasons: ["x"], subject: "/tmp/x", toolName: "read" }) }
  });
  const result = await handlers.before_tool_call({ toolName: "read", params: { filePath: "/tmp/x" } }, { sessionKey: "agent:a1:cron:1", agentId: "a1", sessionId: "s", runId: "r", jobId: "j" });
  assert.ok(result?.requireApproval);
  await new Promise((r) => setImmediate(r));
  const audit = readAudit(logPath);
  assert.equal(audit.find((e) => e.audit_event === "notification_resolution")?.notifySent, false);
});

test("monitor mode does not notify even when automation decision is approval", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-index-"));
  const logPath = path.join(tempDir, "audit.jsonl");
  let notifyCount = 0;
  const { handlers } = makeHarness({
    pluginConfig: { logPath, mode: "monitor" },
    config: { agents: { list: [{ id: "a1", channels: [{ kind: "slack", id: "s1", enabled: true }] }] }, channels: {} },
    deps: {
      evaluateToolCall: () => ({ outcome: "approval", severity: "warning", reasons: ["x"], subject: "/tmp/x", toolName: "read" }),
      notifierRun: async () => { notifyCount += 1; return { ok: true, strategy: "cli" }; }
    }
  });
  const result = await handlers.before_tool_call({ toolName: "read", params: { filePath: "/tmp/x" } }, { sessionKey: "agent:a1:cron:1", agentId: "a1", sessionId: "s", runId: "r", jobId: "j" });
  assert.equal(result, undefined);
  assert.equal(notifyCount, 0);
});

test("uses ctx.workspaceDir when provided by runtime", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-index-"));
  const logPath = path.join(tempDir, "audit.jsonl");
  let seen;
  const { handlers } = makeHarness({
    pluginConfig: { logPath },
    deps: {
      evaluateToolCall: (_event, _policy, ctx) => { seen = ctx.workspaceDir; return { outcome: "allow", severity: "info", reasons: [], subject: "x", toolName: "read" }; }
    }
  });
  await handlers.before_tool_call({ toolName: "read", params: { filePath: "x" } }, { sessionKey: "s", agentId: "a1", sessionId: "sid", workspaceDir: "/runtime/ws" });
  assert.equal(seen, "/runtime/ws");
});

test("records cronJobId as jobId in audit/preapproval context", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-index-"));
  const logPath = path.join(tempDir, "audit.jsonl");
  const { handlers } = makeHarness({
    pluginConfig: { logPath },
    deps: { evaluateToolCall: () => ({ outcome: "allow", severity: "info", reasons: [], subject: "x", toolName: "read" }) }
  });
  await handlers.before_tool_call({ toolName: "read", params: { filePath: "x" } }, { sessionKey: "agent:a1:cron:123", agentId: "a1", sessionId: "sid", cronJobId: "cron-1", runId: "run-1" });
  const audit = readAudit(logPath);
  assert.equal(audit[0].jobId, "cron-1");
});

test("simultaneous identical automation approvals do not dispatch duplicate notifications", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-index-"));
  const logPath = path.join(tempDir, "audit.jsonl");
  let notifyCount = 0;
  const { handlers } = makeHarness({
    pluginConfig: { logPath },
    config: { agents: { list: [{ id: "a1", channels: [{ kind: "slack", id: "s1", enabled: true }] }] }, channels: {} },
    deps: {
      evaluateToolCall: () => ({ outcome: "approval", severity: "warning", reasons: ["x"], subject: "/tmp/x", toolName: "read" }),
      notifierRun: async () => { notifyCount += 1; await new Promise((r) => setTimeout(r, 50)); return { ok: true, strategy: "cli" }; }
    }
  });
  await Promise.all([
    handlers.before_tool_call({ toolName: "read", params: { filePath: "/tmp/x" } }, { sessionKey: "agent:a1:cron:1", agentId: "a1", sessionId: "sid", jobId: "j" }),
    handlers.before_tool_call({ toolName: "read", params: { filePath: "/tmp/x" } }, { sessionKey: "agent:a1:cron:1", agentId: "a1", sessionId: "sid", jobId: "j" })
  ]);
  assert.equal(notifyCount, 1);
});
