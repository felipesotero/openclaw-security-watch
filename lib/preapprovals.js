import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const DEFAULT_STORE = { version: 1, grants: [] };

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
  return (data?.grants || []).find((grant) => grant.status === "approved" && grant.jobId === jobId && grant.agentId === agentId && grant.toolName === toolName && new RegExp(grant.subjectPattern).test(subject)) || null;
}

export function addPendingGrant({ jobId, agentId, toolName, subjectPattern }, data) {
  const grant = { id: crypto.randomUUID(), jobId, agentId, toolName, subjectPattern, createdAt: new Date().toISOString(), approvedAt: null, status: "pending" };
  return { ...(data || DEFAULT_STORE), grants: [...(data?.grants || []), grant] };
}
