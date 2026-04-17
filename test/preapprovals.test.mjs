import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { addPendingGrant, findMatchingGrant, loadPreapprovals } from "../lib/preapprovals.js";

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
