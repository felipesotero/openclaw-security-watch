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

test("allows bundled skill docs outside workspace after path normalization", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "~/.local/lib/node_modules/openclaw/skills/gog/SKILL.md" } }, policy);
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_external_doc");
});

test("allows plugin manifest outside workspace", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "~/.openclaw/extensions/security-watch/openclaw.plugin.json" } }, policy);
  assert.equal(result.outcome, "allow");
});

test("still requires approval for arbitrary package tree reads", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "~/.local/lib/node_modules/openclaw/node_modules/foo/SKILL.md" } }, policy);
  assert.equal(result.outcome, "approval");
});

test("allows trusted docs host", () => {
  const result = evaluateToolCall({ toolName: "webfetch", params: { url: "https://docs.openclaw.ai/plugins/sdk-overview" } }, policy);
  assert.equal(result.outcome, "allow");
});

test("resolves relative HEARTBEAT.md read via readAllow", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "HEARTBEAT.md" } }, policy);
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_external_doc");
});

test("resolves absolute workspace HEARTBEAT.md read via readAllow", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/HEARTBEAT.md" } }, policy);
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_external_doc");
});

test("relative path is resolved to absolute for workspace trust check", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "somefile.txt" } }, policy);
  assert.equal(result.outcome, "approval");
  assert.ok(result.subject.startsWith("/"), "subject should be absolute after normalization");
});
