import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_POLICY_PATH = path.join(__dirname, "..", "assets", "default-policy.json");

export function expandHome(rawPath) {
  if (!rawPath) return rawPath;
  return rawPath.startsWith("~/") ? path.join(os.homedir(), rawPath.slice(2)) : rawPath;
}

export function normalizePolicyPath(rawPath) {
  const expanded = expandHome(safeString(rawPath));
  if (!expanded) return expanded;

  const normalized = path.normalize(expanded);
  if (!path.isAbsolute(normalized)) return normalized;

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
    approvalTimeoutMs: Number(pluginConfig.approvalTimeoutMs || 120000),
    approvalTimeoutBehavior: pluginConfig.approvalTimeoutBehavior || "deny",
    blockOnValidatorFailure: pluginConfig.blockOnValidatorFailure !== false
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

export function workspaceTrusted(filePath, prefixes = []) {
  const normalized = normalizePolicyPath(filePath);
  return prefixes.some((prefix) => normalized.startsWith(prefix));
}

export function readPathAllowed(filePath, patterns = []) {
  const normalized = normalizePolicyPath(filePath);
  return matchPatterns(normalized, patterns).length > 0;
}

export function evaluateToolCall({ toolName, params }, policy) {
  const rawSubject = extractSubject(toolName, params);
  const subject = toolName === "read" || toolName === "write" || toolName === "edit"
    ? normalizePolicyPath(rawSubject)
    : rawSubject;
  const eventBase = {
    toolName,
    subject,
    timestamp: new Date().toISOString()
  };

  if (!policy.critical?.toolNames?.includes(toolName)) {
    return { outcome: "allow", severity: "info", reasons: ["tool_not_scoped"], ...eventBase };
  }

  if (toolName === "bash" || toolName === "exec") {
    const criticalHits = matchPatterns(subject, policy.critical.commandPatterns);
    if (criticalHits.length > 0) return { outcome: "block", severity: "critical", reasons: criticalHits.map((p) => `critical_command:${p}`), ...eventBase };
    const approvalHits = matchPatterns(subject, policy.approval.commandPatterns);
    if (approvalHits.length > 0) return { outcome: "approval", severity: "warning", reasons: approvalHits.map((p) => `approval_command:${p}`), ...eventBase };
  }

  if (toolName === "read" || toolName === "write" || toolName === "edit") {
    const criticalHits = matchPatterns(subject, policy.critical.pathPatterns);
    if (criticalHits.length > 0) return { outcome: "block", severity: "critical", reasons: criticalHits.map((p) => `critical_path:${p}`), ...eventBase };
    if (toolName === "read" && readPathAllowed(subject, policy.readAllow?.pathPatterns)) {
      return { outcome: "allow", severity: "info", reasons: ["read_allow:trusted_external_doc"], ...eventBase };
    }
    const approvalHits = matchPatterns(subject, policy.approval.pathPatterns);
    if (approvalHits.length > 0 || !workspaceTrusted(subject, policy.trustedWorkspacePrefixes)) {
      const reasons = approvalHits.map((p) => `approval_path:${p}`);
      if (!workspaceTrusted(subject, policy.trustedWorkspacePrefixes)) reasons.push("approval_path:outside_trusted_workspace");
      return { outcome: "approval", severity: "warning", reasons, ...eventBase };
    }
  }

  if (toolName === "webfetch") {
    const criticalHits = matchPatterns(subject, policy.critical.urlPatterns);
    if (criticalHits.length > 0) return { outcome: "block", severity: "critical", reasons: criticalHits.map((p) => `critical_url:${p}`), ...eventBase };
    const approvalHits = matchPatterns(subject, policy.approval.urlPatterns);
    if (approvalHits.length > 0 && !domainTrusted(subject, policy.trustedDomains)) {
      return { outcome: "approval", severity: "warning", reasons: [...approvalHits.map((p) => `approval_url:${p}`), "approval_url:untrusted_domain"], ...eventBase };
    }
  }

  return { outcome: "allow", severity: "info", reasons: [], ...eventBase };
}

export function summarizeDecision(policy, decision) {
  const reasons = decision.reasons.join(", ") || "no matching rule";
  if (decision.outcome === "block") return `Blocked by Security Watch: ${reasons}`;
  if (decision.outcome === "approval") return `Approval required by Security Watch: ${reasons}`;
  return `Allowed by Security Watch: ${reasons}`;
}

export function buildAuditRecord(fields) {
  return {
    timestamp: new Date().toISOString(),
    pluginId: "security-watch",
    ...fields
  };
}
