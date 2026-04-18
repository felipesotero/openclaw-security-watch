import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadPreapprovals, findMatchingGrant } from "./preapprovals.js";
import { expandHome } from "./util.js";

export { expandHome };

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_POLICY_PATH = path.join(__dirname, "..", "assets", "default-policy.json");

export function normalizePolicyPath(rawPath, opts = {}) {
  const expanded = expandHome(safeString(rawPath));
  if (!expanded) return expanded;

  let normalized = path.normalize(expanded);
  if (!path.isAbsolute(normalized)) {
    if (opts.baseDir && typeof opts.baseDir === "string") {
      normalized = path.resolve(opts.baseDir, normalized);
    } else {
      return normalized;
    }
  }

  try {
    return fs.realpathSync.native(normalized);
  } catch {
    return normalized;
  }
}

export function loadJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

export function loadPolicy(pluginConfig = {}) {
  const policyPath = expandHome(pluginConfig.policyPath || DEFAULT_POLICY_PATH);
  const base = loadJson(policyPath);
  return {
    ...base,
    logPath: expandHome(pluginConfig.logPath || base.logPath || "~/.openclaw/logs/security-watch-events.jsonl"),
    trustedWorkspacePrefixes: (base.trustedWorkspacePrefixes || []).map((prefix) => normalizePolicyPath(prefix)),
    mode: pluginConfig.mode || "approval",
    approvalTimeoutMs: Number(pluginConfig.approvalTimeoutMs || 600000),
    approvalTimeoutBehavior: pluginConfig.approvalTimeoutBehavior || "deny",
    blockOnValidatorFailure: pluginConfig.blockOnValidatorFailure !== false,
    preapprovals: pluginConfig.preapprovals || { storePath: "~/.openclaw/security-watch-preapprovals.json" }
  };
}

export function appendJsonl(logPath, record) {
  const resolved = expandHome(logPath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  fs.appendFileSync(resolved, `${JSON.stringify(record)}\n`, "utf8");
}

export function safeString(value) {
  if (typeof value === "string") return value;
  if (value == null) return "";
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export function extractSubject(toolName, params) {
  if (toolName === "bash" || toolName === "exec") return safeString(params.command || params.cmd || params.argv || "");
  if (toolName === "read" || toolName === "write" || toolName === "edit") return safeString(params.filePath || params.path || params.target || "");
  if (toolName === "webfetch") return safeString(params.url || params.uri || "");
  return safeString(params);
}

export function matchPatterns(value, patterns = []) {
  const subject = safeString(value);
  return patterns.filter((pattern) => new RegExp(pattern, "i").test(subject));
}

export function domainTrusted(urlString, trustedDomains = []) {
  try {
    const host = new URL(urlString).hostname.toLowerCase();
    return trustedDomains.some((domain) => host === domain || host.endsWith(`.${domain}`));
  } catch {
    return false;
  }
}

export function workspaceTrusted(filePath, prefixes = [], opts = {}) {
  const normalized = normalizePolicyPath(filePath, opts);
  return prefixes.some((prefix) => normalized === prefix || normalized.startsWith(`${prefix}${path.sep}`));
}

export function extractJobId(ctx = {}) {
  return ctx.jobId ?? ctx.cronJobId ?? null;
}

export function readPathAllowed(filePath, patterns = [], opts = {}) {
  const normalized = normalizePolicyPath(filePath, opts);
  return matchPatterns(normalized, patterns).length > 0;
}

export function evaluateToolCall({ toolName, params }, policy, context = {}) {
  const rawSubject = extractSubject(toolName, params);
  const workspaceDir = context.workspaceDir;
  const subject = toolName === "read" || toolName === "write" || toolName === "edit"
    ? normalizePolicyPath(rawSubject, { baseDir: workspaceDir })
    : rawSubject;
  const eventBase = {
    toolName,
    subject,
    timestamp: new Date().toISOString()
  };
  const isAutomation = context.isAutomation === true && extractJobId(context);
  const approvedPreapproval = () => {
    if (!policy.preapprovals) return null;
    return findMatchingGrant({ jobId: context.jobId, agentId: context.agentId, toolName, subject }, loadPreapprovals(expandHome(policy.preapprovals.storePath)));
  };

  if (!policy.critical?.toolNames?.includes(toolName)) {
    return { outcome: "allow", severity: "info", reasons: ["tool_not_scoped"], ...eventBase };
  }

  if (toolName === "bash" || toolName === "exec") {
    const criticalHits = matchPatterns(subject, policy.critical.commandPatterns);
    if (criticalHits.length > 0) return { outcome: "block", severity: "critical", reasons: criticalHits.map((p) => `critical_command:${p}`), ...eventBase };
    const approvalHits = matchPatterns(subject, policy.approval.commandPatterns);
    if (approvalHits.length > 0) {
      if (isAutomation && policy.preapprovals) {
        const grant = approvedPreapproval();
        if (grant) return { outcome: "allow", severity: "info", reasons: ["preapproval:granted"], ...eventBase };
        return { outcome: "block", severity: "critical", reasons: ["preapproval:missing_or_drifted"], ...eventBase };
      }
      return { outcome: "approval", severity: "warning", reasons: approvalHits.map((p) => `approval_command:${p}`), ...eventBase };
    }
  }

  if (toolName === "read" || toolName === "write" || toolName === "edit") {
    const criticalHits = matchPatterns(subject, policy.critical.pathPatterns);
    if (criticalHits.length > 0) return { outcome: "block", severity: "critical", reasons: criticalHits.map((p) => `critical_path:${p}`), ...eventBase };
    const isTrustedWorkspace = workspaceTrusted(subject, policy.trustedWorkspacePrefixes, { baseDir: workspaceDir });
    if (toolName === "read" && isTrustedWorkspace) {
      return { outcome: "allow", severity: "info", reasons: ["read_allow:trusted_workspace"], ...eventBase };
    }
    if (toolName === "read" && readPathAllowed(subject, policy.readAllow?.pathPatterns, { baseDir: workspaceDir })) {
      return { outcome: "allow", severity: "info", reasons: ["read_allow:trusted_external_doc"], ...eventBase };
    }
    const approvalHits = matchPatterns(subject, policy.approval.pathPatterns);
    if (approvalHits.length > 0 || !isTrustedWorkspace) {
      const reasons = approvalHits.map((p) => `approval_path:${p}`);
      if (!isTrustedWorkspace) reasons.push("approval_path:outside_trusted_workspace");
      if (isAutomation && policy.preapprovals) {
        const grant = approvedPreapproval();
        if (grant) return { outcome: "allow", severity: "info", reasons: ["preapproval:granted"], ...eventBase };
        return { outcome: "block", severity: "critical", reasons: ["preapproval:missing_or_drifted"], ...eventBase };
      }
      return { outcome: "approval", severity: "warning", reasons, ...eventBase };
    }
  }

  if (toolName === "webfetch") {
    const criticalHits = matchPatterns(subject, policy.critical.urlPatterns);
    if (criticalHits.length > 0) return { outcome: "block", severity: "critical", reasons: criticalHits.map((p) => `critical_url:${p}`), ...eventBase };
    const approvalHits = matchPatterns(subject, policy.approval.urlPatterns);
    if (approvalHits.length > 0 && !domainTrusted(subject, policy.trustedDomains)) {
      if (isAutomation && policy.preapprovals) {
        const grant = approvedPreapproval();
        if (grant) return { outcome: "allow", severity: "info", reasons: ["preapproval:granted"], ...eventBase };
        return { outcome: "block", severity: "critical", reasons: ["preapproval:missing_or_drifted"], ...eventBase };
      }
      return { outcome: "approval", severity: "warning", reasons: [...approvalHits.map((p) => `approval_url:${p}`), "approval_url:untrusted_domain"], ...eventBase };
    }
  }

  return { outcome: "allow", severity: "info", reasons: [], ...eventBase };
}

export function isAutomationContext(ctx) {
  if (!ctx) return false;
  if (extractJobId(ctx)) return true;
  const key = String(ctx.sessionKey || "");
  return /:(cron|heartbeat):/i.test(key);
}

export function summarizeDecision(policy, decision) {
  const reasons = decision.reasons.join(", ") || "no matching rule";
  if (decision.outcome === "block") return `Blocked by Security Watch: ${reasons}`;
  if (decision.outcome === "approval") {
    const label = ["read", "write", "edit"].includes(decision.toolName) ? "Path" : "Target";
    return `Approval required by Security Watch: ${reasons}\nTool: ${decision.toolName}\n${label}: ${decision.subject}`;
  }
  return `Allowed by Security Watch: ${reasons}`;
}

export function buildAuditRecord(fields) {
  return {
    timestamp: new Date().toISOString(),
    pluginId: "security-watch",
    ...fields
  };
}

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

export class SessionApprovalCache {
  constructor() {
    this._cache = new Map();
    this._pending = new Map();
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
    for (const key of this._pending.keys()) {
      if (key.startsWith(`${sessionId}:`)) this._pending.delete(key);
    }
  }

  _pendingKey(sessionId, toolName, subject) {
    return this._key(sessionId, toolName, subject);
  }

  hasPendingNotification({ sessionKey, toolName, subject }) {
    return this._pending.has(this._pendingKey(sessionKey, toolName, subject));
  }

  markPendingNotification({ sessionKey, toolName, subject }) {
    this._pending.set(this._pendingKey(sessionKey, toolName, subject), Date.now());
  }

  clearPendingNotification({ sessionKey, toolName, subject }) {
    this._pending.delete(this._pendingKey(sessionKey, toolName, subject));
  }
}
