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

test("allows absolute workspace reads regardless of filename allowlist", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/client-brief.md" } }, policy);
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_workspace");
});

test("allows another absolute workspace read regardless of filename", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/notes/project-notes.md" } }, policy);
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_workspace");
});

test("allows relative workspace file reads regardless of filename", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "notes/custom-playbook.md" } }, policy);
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_workspace_relative");
});

test("allows relative workspace state file reads", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "state/comercial_heartbeat_seen_messages.txt" } }, policy);
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_workspace_relative");
});

test("requires approval for relative parent traversal outside workspace", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "../.openclaw/openclaw.json" } }, policy);
  assert.equal(result.outcome, "approval");
});

test("still allows explicit external docs outside workspace", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "~/.openclaw/extensions/security-watch/README.md" } }, policy);
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_external_doc");
});

test("still requires approval for write to trusted workspace", () => {
  const result = evaluateToolCall({ toolName: "write", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/client-brief.md" } }, policy);
  assert.equal(result.outcome, "approval");
});

test("still requires approval for edit to trusted workspace", () => {
  const result = evaluateToolCall({ toolName: "edit", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/notes/custom-playbook.md" } }, policy);
  assert.equal(result.outcome, "approval");
});

test("still requires approval for read of openclaw.json (not in workspace)", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/openclaw.json" } }, policy);
  assert.equal(result.outcome, "approval");
});

test("relative workspace path is normalized to absolute subject before allow", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "somefile.txt" } }, policy);
  assert.equal(result.outcome, "allow");
  assert.ok(result.subject.startsWith("/"), "subject should be absolute after normalization");
});
