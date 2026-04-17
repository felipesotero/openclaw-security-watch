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

test("allows relative ICP.md read via readAllow", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "ICP.md" } }, policy);
  assert.equal(result.outcome, "allow");
});

test("allows relative TOOLS.md read via readAllow", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "TOOLS.md" } }, policy);
  assert.equal(result.outcome, "allow");
});

test("allows relative AGENTS.md read via readAllow", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "AGENTS.md" } }, policy);
  assert.equal(result.outcome, "allow");
});

test("allows absolute workspace ICP.md read via trusted workspace", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/ICP.md" } }, policy);
  assert.equal(result.outcome, "allow");
  assert.ok(result.reasons[0].includes("trusted"), "should be allowed via trusted workspace or readAllow");
});

test("allows workspace state file read via readAllow", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "state/comercial_heartbeat_seen_messages.txt" } }, policy);
  assert.equal(result.outcome, "allow");
});

test("allows workspace memory file read via readAllow", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "memory/2026-03-19.md" } }, policy);
  assert.equal(result.outcome, "allow");
});

test("allows workspace draft file read via readAllow", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "work/drafts/2026-04-07 - Lead - Alpha Lead Academy (Lucy Mae).md" } }, policy);
  assert.equal(result.outcome, "allow");
});

test("still requires approval for write to trusted workspace", () => {
  const result = evaluateToolCall({ toolName: "write", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/ICP.md" } }, policy);
  assert.equal(result.outcome, "approval");
});

test("still requires approval for read of openclaw.json (not in workspace)", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/openclaw.json" } }, policy);
  assert.equal(result.outcome, "approval");
});

test("relative path is resolved to absolute for workspace trust check", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "somefile.txt" } }, policy);
  assert.equal(result.outcome, "approval");
  assert.ok(result.subject.startsWith("/"), "subject should be absolute after normalization");
});
