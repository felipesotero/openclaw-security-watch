import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { canonicalizePath } from "./paths.js";

const DEFAULT_STORE = { version: 1, grants: [] };

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function subjectPatternForPath(value) {
  const pathValue = canonicalizePath(String(value));
  if (pathValue.endsWith("/")) {
    const base = pathValue.replace(/\/+$/, "");
    return `^${escapeRegExp(base)}(?:/.*)?$`;
  }
  return `^${escapeRegExp(pathValue)}$`;
}

function subjectPatternForExact(value) {
  return `^${escapeRegExp(value)}$`;
}

export function loadPreapprovals(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return structuredClone(DEFAULT_STORE);
    throw error;
  }
}

export function savePreapprovals(filePath, data) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`, "utf8");
  fs.renameSync(tmp, filePath);
}

export function findMatchingGrant({ jobId, agentId, toolName, subject }, data) {
  return (data?.grants || []).find((grant) => {
    if (grant.status !== "approved") return false;
    if (grant.expiresAt && new Date(grant.expiresAt) < new Date()) return false;
    return grant.jobId === jobId && grant.agentId === agentId && grant.toolName === toolName && new RegExp(grant.subjectPattern).test(subject);
  }) || null;
}

export function addPendingGrant({ jobId, agentId, toolName, subjectPattern }, data) {
  const grant = { id: crypto.randomUUID(), jobId, agentId, toolName, subjectPattern, createdAt: new Date().toISOString(), approvedAt: null, status: "pending" };
  return { ...(data || DEFAULT_STORE), grants: [...(data?.grants || []), grant] };
}

export function createBootstrapGrants({ jobId, agentId, paths = [], writes = [], edits = [], commands = [], urls = [] }) {
  const createdAt = new Date().toISOString();
  return [
    ...paths.map((subject) => ({
      id: crypto.randomUUID(),
      jobId,
      agentId,
      toolName: "read",
      subjectPattern: subjectPatternForPath(subject),
      createdAt,
      approvedAt: createdAt,
      status: "approved",
    })),
    ...writes.map((subject) => ({
      id: crypto.randomUUID(),
      jobId,
      agentId,
      toolName: "write",
      subjectPattern: subjectPatternForPath(subject),
      createdAt,
      approvedAt: createdAt,
      status: "approved",
    })),
    ...edits.map((subject) => ({
      id: crypto.randomUUID(),
      jobId,
      agentId,
      toolName: "edit",
      subjectPattern: subjectPatternForPath(subject),
      createdAt,
      approvedAt: createdAt,
      status: "approved",
    })),
    ...commands.map((subject) => ({
      id: crypto.randomUUID(),
      jobId,
      agentId,
      toolName: "bash",
      subjectPattern: subjectPatternForExact(subject),
      createdAt,
      approvedAt: createdAt,
      status: "approved",
    })),
    ...urls.map((subject) => ({
      id: crypto.randomUUID(),
      jobId,
      agentId,
      toolName: "webfetch",
      subjectPattern: subjectPatternForExact(subject),
      createdAt,
      approvedAt: createdAt,
      status: "approved",
    })),
  ];
}

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
