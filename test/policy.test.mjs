import test from "node:test";
import assert from "node:assert/strict";
import { evaluateToolCall, loadPolicy } from "../lib/policy.js";

const policy = loadPolicy({ mode: "approval" });

test("blocks destructive root delete command", () => {
  const result = evaluateToolCall({ toolName: "bash", params: { command: "rm -rf /" } }, policy);
  assert.equal(result.outcome, "block");
});

test("requires approval for sensitive read", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/openclaw.json" } }, policy);
  assert.equal(result.outcome, "approval");
});

test("allows trusted docs host", () => {
  const result = evaluateToolCall({ toolName: "webfetch", params: { url: "https://docs.openclaw.ai/plugins/sdk-overview" } }, policy);
  assert.equal(result.outcome, "allow");
});
