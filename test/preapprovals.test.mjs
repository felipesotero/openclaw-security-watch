import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { addPendingGrant, findMatchingGrant, loadPreapprovals, savePreapprovals, approveGrant, revokeGrant, listGrants, createBootstrapGrants } from "../lib/preapprovals.js";

test("loadPreapprovals returns default for missing file", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-watch-preapprovals-"));
  const filePath = path.join(tempDir, "missing.json");
  assert.deepEqual(loadPreapprovals(filePath), { version: 1, grants: [] });
});

test("addPendingGrant appends pending grant metadata", () => {
  const data = addPendingGrant({ jobId: "job-1", agentId: "agent-1", toolName: "read", subjectPattern: "foo" }, { version: 1, grants: [] });
  assert.equal(data.grants.length, 1);
  assert.equal(data.grants[0].status, "pending");
  assert.ok(data.grants[0].id);
  assert.ok(data.grants[0].createdAt);
  assert.equal(data.grants[0].approvedAt, null);
});

test("findMatchingGrant returns null when nothing matches", () => {
  assert.equal(findMatchingGrant({ jobId: "j", agentId: "a", toolName: "read", subject: "x" }, { version: 1, grants: [] }), null);
});

test("findMatchingGrant returns approved matching grant", () => {
  const data = { version: 1, grants: [{ id: "1", jobId: "j", agentId: "a", toolName: "read", subjectPattern: "foo.*", createdAt: new Date().toISOString(), approvedAt: new Date().toISOString(), status: "approved" }] };
  assert.equal(findMatchingGrant({ jobId: "j", agentId: "a", toolName: "read", subject: "foobar" }, data)?.id, "1");
});

test("findMatchingGrant ignores non-approved grants", () => {
  const data = { version: 1, grants: [{ id: "1", jobId: "j", agentId: "a", toolName: "read", subjectPattern: "foo.*", createdAt: new Date().toISOString(), approvedAt: null, status: "pending" }] };
  assert.equal(findMatchingGrant({ jobId: "j", agentId: "a", toolName: "read", subject: "foobar" }, data), null);
});

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

test("approveGrant does not modify other grants", () => {
  let data = addPendingGrant({ jobId: "j1", agentId: "a1", toolName: "read", subjectPattern: "a" }, { version: 1, grants: [] });
  data = addPendingGrant({ jobId: "j2", agentId: "a2", toolName: "write", subjectPattern: "b" }, data);
  const firstId = data.grants[0].id;
  data = approveGrant(firstId, data);
  assert.equal(data.grants[0].status, "approved");
  assert.equal(data.grants[1].status, "pending");
});

test("revokeGrant transitions approved grant to revoked with reason", () => {
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
  assert.ok(data.grants[0].revokedAt);
});

test("revokeGrant with default reason", () => {
  let data = addPendingGrant(
    { jobId: "j1", agentId: "a1", toolName: "bash", subjectPattern: ".*" },
    { version: 1, grants: [] }
  );
  data.grants[0].status = "approved";
  data.grants[0].approvedAt = new Date().toISOString();
  data = revokeGrant(data.grants[0].id, data);
  assert.equal(data.grants[0].revokedReason, "manual");
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
  const match = findMatchingGrant({ jobId: "j", agentId: "a", toolName: "read", subject: "foo" }, data);
  assert.ok(match);
  assert.equal(match.id, "1");
});

test("findMatchingGrant returns permanent grant without expiresAt", () => {
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

test("findMatchingGrant ignores revoked grants", () => {
  const data = {
    version: 1,
    grants: [{
      id: "1", jobId: "j", agentId: "a", toolName: "read",
      subjectPattern: ".*", status: "revoked",
      approvedAt: new Date().toISOString(),
      revokedAt: new Date().toISOString(),
      revokedReason: "manual",
      createdAt: new Date().toISOString()
    }]
  };
  assert.equal(findMatchingGrant({ jobId: "j", agentId: "a", toolName: "read", subject: "foo" }, data), null);
});

test("listGrants filters by status", () => {
  const data = {
    version: 1,
    grants: [
      { id: "1", status: "approved", jobId: "j1", agentId: "a1", toolName: "read" },
      { id: "2", status: "pending", jobId: "j1", agentId: "a1", toolName: "write" },
      { id: "3", status: "revoked", jobId: "j1", agentId: "a1", toolName: "bash" }
    ]
  };
  assert.equal(listGrants(data, { status: "approved" }).length, 1);
  assert.equal(listGrants(data, { status: "pending" }).length, 1);
  assert.equal(listGrants(data).length, 3);
});

test("listGrants filters by jobId", () => {
  const data = {
    version: 1,
    grants: [
      { id: "1", status: "approved", jobId: "j1", agentId: "a1", toolName: "read" },
      { id: "2", status: "approved", jobId: "j2", agentId: "a1", toolName: "read" }
    ]
  };
  assert.equal(listGrants(data, { jobId: "j1" }).length, 1);
});

test("createBootstrapGrants builds deterministic grant descriptors", () => {
  const grants = createBootstrapGrants({
    jobId: "cron-1",
    agentId: "agent-1",
    paths: ["/var/lib/openclaw/state", "/etc/openclaw/config/"] ,
    writes: ["/var/lib/openclaw/output/"],
    edits: ["/etc/openclaw/config.yaml"],
    commands: ["/usr/bin/systemctl restart openclaw-gateway.service"],
    urls: ["https://example.com/webhook"]
  });

  assert.equal(grants.length, 6);
  assert.deepEqual(grants.map((g) => g.toolName), ["read", "read", "write", "edit", "bash", "webfetch"]);
  assert.deepEqual(grants.map((g) => g.jobId), ["cron-1", "cron-1", "cron-1", "cron-1", "cron-1", "cron-1"]);
  assert.deepEqual(grants.map((g) => g.agentId), ["agent-1", "agent-1", "agent-1", "agent-1", "agent-1", "agent-1"]);
  assert.equal(grants[0].subjectPattern, "^/var/lib/openclaw/state$");
  assert.equal(grants[1].subjectPattern, "^/etc/openclaw/config(?:/.*)?$");
  assert.equal(grants[2].subjectPattern, "^/var/lib/openclaw/output(?:/.*)?$");
  assert.equal(grants[3].subjectPattern, "^/etc/openclaw/config\\.yaml$");
  assert.equal(grants[4].subjectPattern, "^/usr/bin/systemctl restart openclaw-gateway\\.service$");
  assert.equal(grants[5].subjectPattern, "^https://example\\.com/webhook$");
});

test("createBootstrapGrants expands home-relative path subjects", () => {
  const home = os.homedir();
  const grants = createBootstrapGrants({
    jobId: "cron-2",
    agentId: "agent-2",
    paths: ["~/.openclaw/state/"],
    writes: ["~/.openclaw/output"],
    edits: ["~/.openclaw/config.json"]
  });

  assert.equal(grants.length, 3);
  assert.equal(grants[0].subjectPattern, `^${home}/\\.openclaw/state(?:/.*)?$`);
  assert.equal(grants[1].subjectPattern, `^${home}/\\.openclaw/output$`);
  assert.equal(grants[2].subjectPattern, `^${home}/\\.openclaw/config\\.json$`);
});

test("createBootstrapGrants returns empty array for empty input", () => {
  assert.deepEqual(createBootstrapGrants({ jobId: "j", agentId: "a" }), []);
});

test("savePreapprovals writes and loadPreapprovals reads back", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-grant-"));
  const storePath = path.join(tempDir, "grants.json");
  const data = addPendingGrant({ jobId: "j1", agentId: "a1", toolName: "read", subjectPattern: ".*" }, { version: 1, grants: [] });
  savePreapprovals(storePath, data);
  const loaded = loadPreapprovals(storePath);
  assert.equal(loaded.grants.length, 1);
  assert.equal(loaded.grants[0].jobId, "j1");
});
