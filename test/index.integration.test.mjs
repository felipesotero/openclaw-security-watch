import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import plugin from "../index.js";

test("automation approval notifies slack and still returns approval", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-index-"));
  const logPath = path.join(tempDir, "audit.jsonl");
  const notifyCalls = [];
  const handlers = {};
  const api = {
    pluginConfig: { logPath, notifyCommand: "echo notify {channel} {text}" },
    config: {
      agents: {
        list: [{ id: "comercial", workspace: "~/workspace/comercial", channels: [{ kind: "slack", id: "slack-main", enabled: true }] }]
      },
      channels: { slack: { "slack-main": { target: "#approvals" } } }
    },
    logger: { warn() {} },
    on(name, handler) { handlers[name] = handler; }
  };

  plugin.register(api, {
    evaluateToolCall: () => ({ outcome: "approval", severity: "warning", reasons: ["approval_path:outside_trusted_workspace"], subject: "/tmp/secret.txt", toolName: "read" }),
    notifierRun: async (_strategies, payload) => {
      notifyCalls.push(payload);
      return { ok: true, strategy: "cli" };
    }
  });

  const result = await handlers.before_tool_call({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/secret.txt" } }, { sessionKey: "agent:comercial:cron:123", agentId: "comercial", sessionId: "session-1", runId: "run-1", jobId: "job-1" });
  assert.ok(result?.requireApproval);
  assert.match(result.requireApproval.description, /Notified slack for approval/);
  assert.equal(notifyCalls.length, 1);
  await new Promise((resolve) => setImmediate(resolve));
  const audit = fs.readFileSync(logPath, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.ok(audit.some((entry) => entry.notifyChannel === "slack"));
});
