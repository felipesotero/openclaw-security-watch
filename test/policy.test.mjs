import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SessionApprovalCache, buildAuditRecord, computePolicyHash, evaluateToolCall, extractJobId, isAutomationContext, loadPolicy, normalizePolicyPath, summarizeDecision } from "../lib/policy.js";
import { addPendingGrant, findMatchingGrant, loadPreapprovals } from "../lib/preapprovals.js";

const policy = loadPolicy({ mode: "approval" });
const baseDir = "/tmp/security-watch-workspace";

test("relative path with baseDir resolves against baseDir", () => {
  const p = normalizePolicyPath("work/drafts/x.md", { baseDir });
  assert.equal(p, "/tmp/security-watch-workspace/work/drafts/x.md");
});

test("relative path without baseDir does not use cwd", () => {
  const p = normalizePolicyPath("work/drafts/x.md");
  assert.equal(p, "work/drafts/x.md");
});

test("absolute path unaffected by baseDir", () => {
  const p = normalizePolicyPath("/etc/hosts", { baseDir });
  assert.equal(p, "/etc/hosts");
});

test("relative path normalization is exact", () => {
  assert.equal(normalizePolicyPath("a/../b.txt"), "b.txt");
  assert.equal(normalizePolicyPath("./foo/bar"), "foo/bar");
  assert.equal(normalizePolicyPath("/abs/path"), "/abs/path");
  assert.equal(normalizePolicyPath("rel/path", { baseDir: "/ws" }), "/ws/rel/path");
});

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

test("allows repo root README reads", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/repos/openclaw-security-watch/README.md" } }, policy);
  assert.equal(result.outcome, "allow");
});

test("allows repo docs tree reads", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/repos/openclaw-security-watch/docs/reference/policy.md" } }, policy);
  assert.equal(result.outcome, "allow");
});

test("allows repo agent instruction reads", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/repos/openclaw-security-watch/AGENTS.md" } }, policy);
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
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/client-brief.md" } }, policy, { workspaceDir: "/home/openclaw/.openclaw/workspace-comercial" });
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_workspace");
});

test("trusts exact workspace root path", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/workspace" } }, policy, { workspaceDir: "/home/openclaw/.openclaw/workspace" });
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_workspace");
});

test("trusts nested file inside workspace", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/workspace/nested/file.txt" } }, policy, { workspaceDir: "/home/openclaw/.openclaw/workspace" });
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_workspace");
});

test("does not trust sibling directory that only shares workspace prefix", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/workspace-evil/secret.txt" } }, policy, { workspaceDir: "/home/openclaw/.openclaw/workspace" });
  assert.notEqual(result.reasons[0], "read_allow:trusted_workspace");
});

test("rejects symlink inside trusted workspace whose realpath escapes prefix", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-watch-symlink-"));
  const workspace = path.join(tempDir, "workspace");
  const linkPath = path.join(workspace, "hostname-link");
  try {
    fs.mkdirSync(workspace, { recursive: true });
    fs.symlinkSync("/etc/hostname", linkPath);
  } catch {
    return;
  }
  const result = evaluateToolCall({ toolName: "read", params: { filePath: linkPath } }, policy, { workspaceDir: workspace });
  assert.notEqual(result.reasons[0], "read_allow:trusted_workspace");
});

test("allows another absolute workspace read regardless of filename", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/notes/project-notes.md" } }, policy, { workspaceDir: "/home/openclaw/.openclaw/workspace-comercial" });
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_workspace");
});

test("workspace-relative read allowed when baseDir trusted", () => {
  const trustedPolicy = { ...policy, trustedWorkspacePrefixes: [baseDir] };
  const result = evaluateToolCall({ toolName: "read", params: { path: "notes/custom-playbook.md" } }, trustedPolicy, { workspaceDir: baseDir });
  assert.equal(result.outcome, "allow");
});

test("relative workspace state file reads outside trusted prefixes require approval", () => {
  const restrictivePolicy = { ...policy, trustedWorkspacePrefixes: ["/nonexistent/workspace"] };
  const result = evaluateToolCall({ toolName: "read", params: { path: "state/comercial_heartbeat_seen_messages.txt" } }, restrictivePolicy, { workspaceDir: baseDir });
  assert.equal(result.outcome, "approval");
});

test("relative path that resolves outside all workspace prefixes requires approval", () => {
  const restrictivePolicy = {
    ...policy,
    trustedWorkspacePrefixes: ["/nonexistent/workspace"]
  };
  const result = evaluateToolCall(
    { toolName: "read", params: { path: "notes/meeting.md" } },
    restrictivePolicy
  );
  assert.equal(result.outcome, "approval");
});

test("relative path with deep traversal outside workspace requires approval", () => {
  const result = evaluateToolCall(
    { toolName: "read", params: { path: "../../etc/passwd" } },
    policy,
    { workspaceDir: baseDir }
  );
  assert.equal(result.outcome, "approval");
});

test("requires approval for relative parent traversal outside workspace", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "../.openclaw/openclaw.json" } }, policy, { workspaceDir: baseDir });
  assert.equal(result.outcome, "approval");
});

test("still allows explicit external docs outside workspace", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "~/.openclaw/extensions/security-watch/README.md" } }, policy);
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_external_doc");
});

test("still requires approval for write to trusted workspace", () => {
  const result = evaluateToolCall({ toolName: "write", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/client-brief.md" } }, policy, { workspaceDir: "/home/openclaw/.openclaw/workspace-comercial" });
  assert.equal(result.outcome, "approval");
});

test("allows write to work drafts inside trusted workspace", () => {
  const result = evaluateToolCall({ toolName: "write", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/work/drafts/file.md" } }, policy, { workspaceDir: "/home/openclaw/.openclaw/workspace-comercial" });
  assert.equal(result.outcome, "allow");
});

test("blocks write to nonexistent file beneath symlinked operational parent", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-watch-symlink-write-"));
  const workspace = path.join(tempDir, "workspace");
  const outside = path.join(tempDir, "outside");
  const linkParent = path.join(workspace, "work", "drafts");
  const target = path.join(linkParent, "new-note.md");
  try {
    fs.mkdirSync(path.join(workspace, "work"), { recursive: true });
    fs.mkdirSync(outside, { recursive: true });
    fs.symlinkSync(outside, linkParent);
  } catch {
    return;
  }
  const result = evaluateToolCall({ toolName: "write", params: { filePath: target } }, policy, { workspaceDir: workspace });
  assert.equal(result.outcome, "approval");
});

test("allows write to memory inside trusted workspace", () => {
  const result = evaluateToolCall({ toolName: "write", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/memory/2026-04-19.md" } }, policy, { workspaceDir: "/home/openclaw/.openclaw/workspace-comercial" });
  assert.equal(result.outcome, "allow");
});

test("allows write to work attachments inside trusted workspace", () => {
  const result = evaluateToolCall({ toolName: "write", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/work/attachments/invoice.pdf" } }, policy, { workspaceDir: "/home/openclaw/.openclaw/workspace-comercial" });
  assert.equal(result.outcome, "allow");
});

test("allows edit to trusted workspace operational outputs", () => {
  const result = evaluateToolCall({ toolName: "edit", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/work/drafts/file.md" } }, policy, { workspaceDir: "/home/openclaw/.openclaw/workspace-comercial" });
  assert.equal(result.outcome, "allow");
});

test("still requires approval for sibling write outside trusted workspace", () => {
  const result = evaluateToolCall({ toolName: "write", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial-evil/work/drafts/file.md" } }, policy, { workspaceDir: "/home/openclaw/.openclaw/workspace-comercial" });
  assert.equal(result.outcome, "approval");
});

test("still blocks secret write inside trusted workspace", () => {
  const result = evaluateToolCall({ toolName: "write", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/work/drafts/.env" } }, policy, { workspaceDir: "/home/openclaw/.openclaw/workspace-comercial" });
  assert.equal(result.outcome, "block");
});

test("still requires approval for edit to trusted workspace", () => {
  const result = evaluateToolCall({ toolName: "edit", params: { filePath: "/home/openclaw/.openclaw/workspace-comercial/notes/custom-playbook.md" } }, policy, { workspaceDir: "/home/openclaw/.openclaw/workspace-comercial" });
  assert.equal(result.outcome, "approval");
});

test("still requires approval for read of openclaw.json (not in workspace)", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/openclaw.json" } }, policy);
  assert.equal(result.outcome, "approval");
});

test("relative workspace path is normalized to absolute subject before approval", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "somefile.txt" } }, policy, { workspaceDir: baseDir });
  assert.equal(result.outcome, "approval");
  assert.ok(result.subject.startsWith("/"), "subject should be absolute after normalization");
});

test("approval summary includes tool and path for reads", () => {
  const decision = { outcome: "approval", reasons: ["approval_path:outside_trusted_workspace"], toolName: "read", subject: "/tmp/file.txt" };
  const summary = summarizeDecision(policy, decision);
  assert.match(summary, /Tool: read/);
  assert.match(summary, /Path: \/tmp\/file\.txt/);
});

test("approval summary includes tool and target for bash", () => {
  const decision = { outcome: "approval", reasons: ["approval_command:danger"], toolName: "bash", subject: "rm -rf /" };
  const summary = summarizeDecision(policy, decision);
  assert.match(summary, /Tool: bash/);
  assert.match(summary, /Target: rm -rf \/$/);
});

test("buildAuditRecord includes all passed fields", () => {
  const record = buildAuditRecord({
    phase: "before_tool_call",
    toolName: "read",
    subject: "/tmp/file.txt",
    decision: "allow",
    grantId: "grant-123",
    jobId: "cron-456",
    agentId: "comercial",
    policyHash: "sha256:abc123def456"
  });
  assert.equal(record.pluginId, "security-watch");
  assert.equal(record.grantId, "grant-123");
  assert.equal(record.jobId, "cron-456");
  assert.equal(record.agentId, "comercial");
  assert.equal(record.policyHash, "sha256:abc123def456");
  assert.ok(record.timestamp);
});

test("computePolicyHash returns stable hash for same policy", () => {
  const hash1 = computePolicyHash(policy);
  const hash2 = computePolicyHash(policy);
  assert.equal(hash1, hash2);
  assert.match(hash1, /^sha256:[a-f0-9]+$/);
});

test("computePolicyHash changes when policy changes", () => {
  const hash1 = computePolicyHash(policy);
  const modifiedPolicy = { ...policy, trustedDomains: [...policy.trustedDomains, "evil.com"] };
  const hash2 = computePolicyHash(modifiedPolicy);
  assert.notEqual(hash1, hash2);
});

test("default approval timeout is ten minutes", () => {
  const loaded = loadPolicy({});
  assert.equal(loaded.approvalTimeoutMs, 600000);
});

test("evaluateToolCall requires approval for relative path when no baseDir", () => {
  const result = evaluateToolCall({ toolName: "read", params: { path: "work/drafts/a.md" } }, policy, {});
  assert.equal(result.outcome, "approval");
});

test("isAutomationContext detects cron, heartbeat, main, and job ids", () => {
  assert.equal(isAutomationContext({ sessionKey: "agent:x:CRON:abc" }), true);
  assert.equal(isAutomationContext({ sessionKey: "agent:x:Heartbeat:abc" }), true);
  assert.equal(isAutomationContext({ sessionKey: "agent:x:cronjob" }), false);
  assert.equal(isAutomationContext({ sessionKey: "agent:cronfish:main" }), false);
  assert.equal(isAutomationContext({ sessionKey: "agent:x:main", jobId: "j" }), true);
  assert.equal(isAutomationContext({ sessionKey: "agent:x:main", cronJobId: "c" }), true);
  assert.equal(isAutomationContext({ sessionKey: "agent:x:main" }), false);
});

test("extractJobId prefers jobId then cronJobId", () => {
  assert.equal(extractJobId({ jobId: "job-1", cronJobId: "cron-2", runId: "run-3" }), "job-1");
  assert.equal(extractJobId({ cronJobId: "cron-2", runId: "run-3" }), "cron-2");
  assert.equal(extractJobId({ runId: "run-3" }), null);
});

test("automation blocks when matching preapproval is missing", () => {
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/secret.txt" } }, policy, { isAutomation: true, jobId: "job-1", agentId: "agent-1" });
  assert.equal(result.outcome, "block");
  assert.ok(result.reasons.includes("preapproval:missing_or_drifted"));
});

test("automation context: blocks bash with preapproval:missing when no grant exists", () => {
  const result = evaluateToolCall(
    { toolName: "bash", params: { command: "curl https://api.example.com" } },
    policy,
    { isAutomation: true, jobId: "cron-123", agentId: "comercial" }
  );
  assert.equal(result.outcome, "block");
  assert.ok(result.reasons.includes("preapproval:missing_or_drifted"));
});

test("interactive context: prompts approval for same command", () => {
  const result = evaluateToolCall(
    { toolName: "bash", params: { command: "curl https://api.example.com" } },
    policy,
    { isAutomation: false }
  );
  assert.equal(result.outcome, "approval");
});

test("automation without jobId is treated as interactive", () => {
  const result = evaluateToolCall(
    { toolName: "bash", params: { command: "curl https://api.example.com" } },
    policy,
    { isAutomation: true }
  );
  assert.equal(result.outcome, "approval");
});

test("automation allows when matching approved preapproval exists", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-watch-preapproval-"));
  const storePath = path.join(tempDir, "preapprovals.json");
  const data = addPendingGrant({ jobId: "job-1", agentId: "agent-1", toolName: "read", subjectPattern: "secret\\.txt$" }, { version: 1, grants: [] });
  data.grants[0].status = "approved";
  data.grants[0].approvedAt = new Date().toISOString();
  fs.writeFileSync(storePath, JSON.stringify(data), "utf8");
  const policyWithPreapprovals = { ...policy, preapprovals: { storePath } };
  const result = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/secret.txt" } }, policyWithPreapprovals, { isAutomation: true, jobId: "job-1", agentId: "agent-1" });
  assert.equal(result.outcome, "allow");
  assert.ok(result.reasons.includes("preapproval:granted"));
});

test("automation without context behaves like normal evaluation", () => {
  const baseline = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/secret.txt" } }, policy);
  const withContext = evaluateToolCall({ toolName: "read", params: { filePath: "/home/openclaw/.openclaw/secret.txt" } }, policy, { isAutomation: false });
  const { timestamp: _baselineTs, ...baselineRest } = baseline;
  const { timestamp: _withContextTs, ...withContextRest } = withContext;
  assert.deepEqual(withContextRest, baselineRest);
});

test("SessionApprovalCache records and retrieves approvals", () => {
  const cache = new SessionApprovalCache();
  cache.record("session-1", "read", "/home/openclaw/.openclaw/openclaw.json");
  assert.ok(cache.has("session-1", "read", "/home/openclaw/.openclaw/openclaw.json"));
  assert.ok(!cache.has("session-1", "write", "/home/openclaw/.openclaw/openclaw.json"));
  assert.ok(!cache.has("session-2", "read", "/home/openclaw/.openclaw/openclaw.json"));
});

test("SessionApprovalCache clear removes session entries only", () => {
  const cache = new SessionApprovalCache();
  cache.record("session-1", "read", "/tmp/a.txt");
  cache.record("session-2", "read", "/tmp/b.txt");
  cache.clear("session-1");
  assert.ok(!cache.has("session-1", "read", "/tmp/a.txt"));
  assert.ok(cache.has("session-2", "read", "/tmp/b.txt"));
});

test("SessionApprovalCache does not match different subjects", () => {
  const cache = new SessionApprovalCache();
  cache.record("s1", "read", "/tmp/a.txt");
  assert.ok(!cache.has("s1", "read", "/tmp/b.txt"));
});
