# Security Watch v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade security-watch from a stateless classifier to a context-aware authorization system with durable grants, proper relative-path resolution, session-scoped dedup, and enhanced audit.

**Architecture:** Six focused tasks that build on each other: (1) execution context model, (2) safe relative-path resolution, (3) durable grant engine, (4) session-scoped approval dedup, (5) enhanced audit schema, (6) remove `approvalTimeoutBehavior: allow`. Each task follows TDD.

**Tech Stack:** Node.js (ESM), node:test, node:assert/strict, node:fs, node:path, node:crypto

**Repo:** `/home/openclaw/repos/openclaw-security-watch`

**Test command:** `node --test`

---

### Task 1: Execution Context Model

Distinguish interactive sessions from automation (cron/heartbeat). Automation MUST fail closed — never prompt, never timeout-allow.

**Files:**
- Modify: `lib/policy.js` (evaluateToolCall signature, automation branch)
- Modify: `index.js` (context detection, force deny for automation timeout)
- Modify: `openclaw.plugin.json` (remove `allow` from approvalTimeoutBehavior enum)
- Test: `test/policy.test.mjs`

- [ ] **Step 1: Write failing tests for context model**

Add to `test/policy.test.mjs`:

```js
test("automation context: blocks with preapproval:missing when no grant exists", () => {
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
  // No jobId → not valid automation → falls through to interactive
  assert.equal(result.outcome, "approval");
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test`
Expected: New tests fail because current code already handles some of these (verify which fail)

- [ ] **Step 3: Implement context model changes**

In `lib/policy.js`, the `isAutomation` check at line 115 already exists. Verify it works for bash/exec, read/write/edit, and webfetch branches. The key change: ensure `approvalTimeoutBehavior` is always `"deny"` when `isAutomation` is true.

In `index.js`, add override in the approval branch:

```js
// Inside the approval block (line 60-71), before returning requireApproval:
const effectiveTimeoutBehavior = context.isAutomation ? "deny" : policy.approvalTimeoutBehavior;
```

Use `effectiveTimeoutBehavior` instead of `policy.approvalTimeoutBehavior` in the return.

In `openclaw.plugin.json`, remove `"allow"` from the `approvalTimeoutBehavior` enum — only `"deny"` remains. Keep the field for backward compat but it only accepts `"deny"`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add lib/policy.js index.js openclaw.plugin.json test/policy.test.mjs
git commit -m "feat: execution context model — automation always fails closed"
```

---

### Task 2: Fix Relative Path Resolution Against Workspace Root

`isTrustedWorkspaceRelativePath()` currently trusts by syntax (no `..`). Fix it to resolve against the actual workspace root and verify containment.

**Files:**
- Modify: `lib/policy.js` (replace `isTrustedWorkspaceRelativePath`, update `evaluateToolCall`)
- Test: `test/policy.test.mjs`

- [ ] **Step 1: Write failing tests for safe resolution**

```js
test("relative path resolves against workspace root and verifies containment", () => {
  const result = evaluateToolCall(
    { toolName: "read", params: { path: "notes/meeting.md" } },
    policy
  );
  assert.equal(result.outcome, "allow");
  assert.equal(result.reasons[0], "read_allow:trusted_workspace");
  // Subject must be absolute and inside a trusted workspace prefix
  assert.ok(path.isAbsolute(result.subject));
});

test("relative path that resolves outside workspace requires approval", () => {
  // If CWD is /home/openclaw, "notes/meeting.md" resolves to /home/openclaw/notes/meeting.md
  // which is NOT inside any trusted workspace prefix
  // This test depends on CWD — use a policy with a prefix that won't match CWD
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

test("relative path with .. that escapes workspace requires approval", () => {
  const result = evaluateToolCall(
    { toolName: "read", params: { path: "../../etc/passwd" } },
    policy
  );
  // Should NOT be allowed — resolves outside workspace
  assert.equal(result.outcome, "approval");
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test`
Expected: First test may pass (existing behavior), second and third should reveal the bug

- [ ] **Step 3: Implement safe resolution**

Replace `isTrustedWorkspaceRelativePath()` with resolution-based check. Remove the separate relative-path branch in `evaluateToolCall` — instead, always resolve to absolute and use `workspaceTrusted()`:

In `lib/policy.js`, remove `isTrustedWorkspaceRelativePath()` function entirely.

In `evaluateToolCall`, for read/write/edit, the subject is already normalized via `normalizePolicyPath()` which calls `path.resolve()` for relative paths. So `subject` is always absolute. The fix is to remove the separate `isTrustedWorkspaceRelativePath` branch (lines 146-148) and let the existing `workspaceTrusted(subject, ...)` check handle it:

```js
// Remove lines 146-148 (the isTrustedWorkspaceRelativePath branch)
// The workspaceTrusted check on line 142-145 already handles resolved absolute paths
```

After this change, relative paths like `notes/meeting.md` resolve to `path.resolve("notes/meeting.md")` = `{CWD}/notes/meeting.md`. If CWD is inside a trusted workspace, it's allowed. If not, it requires approval. This is the correct behavior.

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test`
Expected: All tests pass. Some existing tests for `trusted_workspace_relative` reason will need updating to `trusted_workspace` since the branch is unified.

- [ ] **Step 5: Update existing tests that reference `trusted_workspace_relative`**

Tests at lines 54-64 reference `read_allow:trusted_workspace_relative`. Update them to expect `read_allow:trusted_workspace` if the resolved path falls inside a trusted prefix, or `approval` if it doesn't.

- [ ] **Step 6: Run tests again**

Run: `node --test`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add lib/policy.js test/policy.test.mjs
git commit -m "fix: resolve relative paths against workspace root before trusting"
```

---

### Task 3: Durable Grant Engine

Upgrade `preapprovals.js` to support: approve, revoke, expiry, grant scoping by jobId+agentId+toolName+subjectPattern. Grants persist across restarts. New grants can be added post-hoc and read by subsequent executions.

**Files:**
- Modify: `lib/preapprovals.js` (approve, revoke, list, expiry check)
- Modify: `lib/policy.js` (use enhanced grant matching)
- Test: `test/preapprovals.test.mjs`

- [ ] **Step 1: Write failing tests for grant lifecycle**

```js
test("approveGrant transitions pending grant to approved", () => {
  let data = addPendingGrant(
    { jobId: "j1", agentId: "a1", toolName: "read", subjectPattern: ".*\\.md$" },
    { version: 1, grants: [] }
  );
  const grantId = data.grants[0].id;
  data = approveGrant(grantId, data);
  assert.equal(data.grants[0].status, "approved");
  assert.ok(data.grants[0].approvedAt);
});

test("revokeGrant transitions approved grant to revoked", () => {
  let data = addPendingGrant(
    { jobId: "j1", agentId: "a1", toolName: "read", subjectPattern: ".*" },
    { version: 1, grants: [] }
  );
  data.grants[0].status = "approved";
  data.grants[0].approvedAt = new Date().toISOString();
  const grantId = data.grants[0].id;
  data = revokeGrant(grantId, data, "policy_upgrade");
  assert.equal(data.grants[0].status, "revoked");
  assert.equal(data.grants[0].revokedReason, "policy_upgrade");
});

test("findMatchingGrant ignores expired grants", () => {
  const expired = new Date(Date.now() - 86400000).toISOString();
  const data = {
    version: 1,
    grants: [{
      id: "1", jobId: "j", agentId: "a", toolName: "read",
      subjectPattern: ".*", status: "approved",
      approvedAt: expired, expiresAt: expired,
      createdAt: expired
    }]
  };
  assert.equal(
    findMatchingGrant({ jobId: "j", agentId: "a", toolName: "read", subject: "foo" }, data),
    null
  );
});

test("findMatchingGrant returns non-expired approved grant", () => {
  const future = new Date(Date.now() + 86400000).toISOString();
  const data = {
    version: 1,
    grants: [{
      id: "1", jobId: "j", agentId: "a", toolName: "read",
      subjectPattern: ".*", status: "approved",
      approvedAt: new Date().toISOString(), expiresAt: future,
      createdAt: new Date().toISOString()
    }]
  };
  assert.ok(findMatchingGrant({ jobId: "j", agentId: "a", toolName: "read", subject: "foo" }, data));
});

test("findMatchingGrant returns permanent grant (no expiresAt)", () => {
  const data = {
    version: 1,
    grants: [{
      id: "1", jobId: "j", agentId: "a", toolName: "read",
      subjectPattern: ".*", status: "approved",
      approvedAt: new Date().toISOString(),
      createdAt: new Date().toISOString()
    }]
  };
  assert.ok(findMatchingGrant({ jobId: "j", agentId: "a", toolName: "read", subject: "foo" }, data));
});

test("listGrants filters by status", () => {
  const data = {
    version: 1,
    grants: [
      { id: "1", status: "approved", jobId: "j1" },
      { id: "2", status: "pending", jobId: "j1" },
      { id: "3", status: "revoked", jobId: "j1" }
    ]
  };
  assert.equal(listGrants(data, { status: "approved" }).length, 1);
  assert.equal(listGrants(data, { status: "pending" }).length, 1);
  assert.equal(listGrants(data).length, 3);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test`
Expected: Fail — `approveGrant`, `revokeGrant`, `listGrants` don't exist yet

- [ ] **Step 3: Implement grant lifecycle functions**

In `lib/preapprovals.js`, add:

```js
export function approveGrant(grantId, data) {
  const grants = (data?.grants || []).map((g) =>
    g.id === grantId ? { ...g, status: "approved", approvedAt: new Date().toISOString() } : g
  );
  return { ...data, grants };
}

export function revokeGrant(grantId, data, reason = "manual") {
  const grants = (data?.grants || []).map((g) =>
    g.id === grantId ? { ...g, status: "revoked", revokedAt: new Date().toISOString(), revokedReason: reason } : g
  );
  return { ...data, grants };
}

export function listGrants(data, filter = {}) {
  let grants = data?.grants || [];
  if (filter.status) grants = grants.filter((g) => g.status === filter.status);
  if (filter.jobId) grants = grants.filter((g) => g.jobId === filter.jobId);
  if (filter.agentId) grants = grants.filter((g) => g.agentId === filter.agentId);
  return grants;
}
```

Update `findMatchingGrant` to check expiry:

```js
export function findMatchingGrant({ jobId, agentId, toolName, subject }, data) {
  return (data?.grants || []).find((grant) => {
    if (grant.status !== "approved") return false;
    if (grant.expiresAt && new Date(grant.expiresAt) < new Date()) return false;
    return grant.jobId === jobId
      && grant.agentId === agentId
      && grant.toolName === toolName
      && new RegExp(grant.subjectPattern).test(subject);
  }) || null;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add lib/preapprovals.js test/preapprovals.test.mjs
git commit -m "feat: durable grant engine with approve, revoke, expiry, list"
```

---

### Task 4: Session-Scoped Approval Dedup for Live Sessions

For interactive sessions, track approved tool+subject pairs in memory so repeated identical prompts within the same session are auto-allowed.

**Files:**
- Modify: `index.js` (session approval cache, dedup logic)
- Test: `test/policy.test.mjs` (integration-level dedup tests)

- [ ] **Step 1: Write failing tests for session dedup**

```js
test("session approval cache deduplicates repeated approvals", () => {
  // This tests the SessionApprovalCache class directly
  const cache = new SessionApprovalCache();
  cache.record("session-1", "read", "/home/openclaw/.openclaw/openclaw.json");
  assert.ok(cache.has("session-1", "read", "/home/openclaw/.openclaw/openclaw.json"));
  assert.ok(!cache.has("session-1", "write", "/home/openclaw/.openclaw/openclaw.json"));
  assert.ok(!cache.has("session-2", "read", "/home/openclaw/.openclaw/openclaw.json"));
});

test("session approval cache clear removes session entries", () => {
  const cache = new SessionApprovalCache();
  cache.record("session-1", "read", "/tmp/file.txt");
  cache.clear("session-1");
  assert.ok(!cache.has("session-1", "read", "/tmp/file.txt"));
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test`
Expected: Fail — `SessionApprovalCache` doesn't exist

- [ ] **Step 3: Implement SessionApprovalCache**

In `lib/policy.js`, add:

```js
export class SessionApprovalCache {
  constructor() {
    this._cache = new Map();
  }

  _key(sessionId, toolName, subject) {
    return `${sessionId}:${toolName}:${subject}`;
  }

  has(sessionId, toolName, subject) {
    return this._cache.has(this._key(sessionId, toolName, subject));
  }

  record(sessionId, toolName, subject) {
    this._cache.set(this._key(sessionId, toolName, subject), Date.now());
  }

  clear(sessionId) {
    for (const key of this._cache.keys()) {
      if (key.startsWith(`${sessionId}:`)) this._cache.delete(key);
    }
  }
}
```

In `index.js`, create a module-level cache instance and use it:

```js
const sessionCache = new SessionApprovalCache();

// In before_tool_call, after decision is "approval" and mode is "approval":
if (sessionCache.has(ctx.sessionId, event.toolName, decision.subject)) {
  logSafe(policy, buildAuditRecord({ phase: "before_tool_call", classification: "session_dedup", decision: "allow", reasons: ["session_approval_cached"], severity: "info", subject: decision.subject, ...scope }), api.logger);
  return; // allow — already approved this session
}

// In onResolution callback, if approved:
onResolution: (resolution) => {
  if (resolution === "approved" || resolution === "allow") {
    sessionCache.record(ctx.sessionId, event.toolName, decision.subject);
  }
  logSafe(policy, buildAuditRecord({ ... }), api.logger);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add lib/policy.js index.js test/policy.test.mjs
git commit -m "feat: session-scoped approval dedup for interactive sessions"
```

---

### Task 5: Enhanced Audit Schema

Add grant ID, approver identity, job identity, policy version hash, and subject fingerprint to audit records.

**Files:**
- Modify: `lib/policy.js` (buildAuditRecord, add policyHash helper)
- Modify: `index.js` (pass enhanced fields to audit)
- Test: `test/policy.test.mjs`

- [ ] **Step 1: Write failing tests for enhanced audit**

```js
test("buildAuditRecord includes all required fields", () => {
  const record = buildAuditRecord({
    phase: "before_tool_call",
    toolName: "read",
    subject: "/tmp/file.txt",
    decision: "allow",
    grantId: "grant-123",
    jobId: "cron-456",
    agentId: "comercial",
    policyHash: "sha256:abc123"
  });
  assert.equal(record.pluginId, "security-watch");
  assert.equal(record.grantId, "grant-123");
  assert.equal(record.jobId, "cron-456");
  assert.equal(record.policyHash, "sha256:abc123");
  assert.ok(record.timestamp);
});

test("computePolicyHash returns stable hash for same policy", () => {
  const hash1 = computePolicyHash(policy);
  const hash2 = computePolicyHash(policy);
  assert.equal(hash1, hash2);
  assert.match(hash1, /^sha256:[a-f0-9]+$/);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test`
Expected: Fail — `computePolicyHash` doesn't exist

- [ ] **Step 3: Implement enhanced audit**

In `lib/policy.js`:

```js
import crypto from "node:crypto";

export function computePolicyHash(policy) {
  const content = JSON.stringify({
    critical: policy.critical,
    approval: policy.approval,
    readAllow: policy.readAllow,
    trustedWorkspacePrefixes: policy.trustedWorkspacePrefixes,
    trustedDomains: policy.trustedDomains
  });
  return `sha256:${crypto.createHash("sha256").update(content).digest("hex").slice(0, 16)}`;
}
```

In `index.js`, pass `policyHash`, `grantId`, `jobId`, `agentId` to all `buildAuditRecord` calls.

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add lib/policy.js index.js test/policy.test.mjs
git commit -m "feat: enhanced audit schema with grant/job/policy tracking"
```

---

### Task 6: Integration Verification

Run full test suite, verify all behaviors work together.

- [ ] **Step 1: Run full test suite**

Run: `node --test`
Expected: All tests pass (should be 40+ tests at this point)

- [ ] **Step 2: Manual smoke check of key scenarios**

Verify these scenarios produce correct outcomes:
1. Automation + no grant → block
2. Automation + approved grant → allow
3. Automation + expired grant → block
4. Interactive + first approval → prompt
5. Interactive + repeated same tool+subject → dedup (allow)
6. Relative path inside workspace → allow
7. Relative path outside workspace → approval
8. Timeout behavior always deny for automation

- [ ] **Step 3: Final commit if any fixes needed**

```bash
git add -A
git commit -m "test: integration verification and fixes"
```
