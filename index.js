import { createRequire } from "node:module";
let definePluginEntry = (entry) => entry;
try {
  const _require = createRequire(import.meta.url);
  const sdk = _require("openclaw/plugin-sdk/plugin-entry");
  if (sdk?.definePluginEntry) definePluginEntry = sdk.definePluginEntry;
} catch {}
import {
  appendJsonl,
  buildAuditRecord,
  evaluateToolCall,
  computePolicyHash,
  isAutomationContext,
  extractJobId,
  loadPolicy,
  SessionApprovalCache,
  summarizeDecision
} from "./lib/policy.js";
import { loadChannelPriority, findHumanChannel } from "./lib/channels.js";
import { buildMessage, cliStrategy, notifyCommandStrategy, runNotifier } from "./lib/notifier.js";
import { resolveSessionWorkspaceDir } from "./lib/workspace.js";
import { attemptAutomationNotification } from "./lib/notify-pipeline.js";

function logSafe(policy, record, logger) {
  try {
    appendJsonl(policy.logPath, record);
  } catch (error) {
    logger?.warn?.(`security-watch log write failed: ${String(error)}`);
  }
}

export default definePluginEntry({
  id: "security-watch",
  name: "Security Watch",
  description: "Fail-closed before_tool_call guardrails for sensitive tools with audit logs and approvals",
  register(api, deps = {}) {
    const sessionCache = new SessionApprovalCache();
    const notifierRun = deps.notifierRun || runNotifier;
    const evaluate = deps.evaluateToolCall || evaluateToolCall;
    const load = deps.loadPolicy || loadPolicy;
    const attemptNotify = deps.attemptAutomationNotification || attemptAutomationNotification;

    api.on("before_tool_call", async (event, ctx) => {
      const policy = load(api.pluginConfig ?? {});
      const pHash = computePolicyHash(policy);
      let workspaceDir = null;
      try {
        workspaceDir = resolveSessionWorkspaceDir({ ctx, sessionKey: ctx.sessionKey, agentId: ctx.agentId, config: api.config });
      } catch (error) {
        workspaceDir = null;
        api.logger?.warn?.(String(error));
      }
      const isAutomation = isAutomationContext(ctx);
      const context = {
        jobId: extractJobId(ctx),
        agentId: ctx.agentId,
        isAutomation,
        workspaceDir
      };
      const scope = {
        agentId: ctx.agentId,
        sessionId: ctx.sessionId,
        sessionKey: ctx.sessionKey,
        runId: ctx.runId,
        toolCallId: ctx.toolCallId,
        toolName: event.toolName
      };

      try {
        const decision = evaluate(event, policy, context);
        const notifyChannel = null;
        let resolvedChannel = null;
        if (decision.outcome === "approval" && isAutomation) {
          try {
            const priority = loadChannelPriority({ pluginConfig: api.pluginConfig || {}, storePath: "~/.openclaw/security-watch-channels.json" });
            resolvedChannel = findHumanChannel({ agentId: ctx.agentId, config: api.config || {}, priority });
          } catch (error) {
            api.logger?.warn?.(String(error));
          }
        }
        logSafe(policy, buildAuditRecord({ phase: "before_tool_call", classification: decision.outcome === "allow" ? "no_match" : "threat_detected", decision: decision.outcome, reasons: decision.reasons, severity: decision.severity, subject: decision.subject, policyHash: pHash, jobId: context.jobId || null, agentId: context.agentId || null, workspaceDir, notificationRequested: decision.outcome === "approval" && isAutomation && Boolean(resolvedChannel), notifyChannel: resolvedChannel ? { kind: resolvedChannel.kind, id: resolvedChannel.id } : null, ...scope }), api.logger);

        if (policy.mode === "monitor") return;

        if (decision.outcome === "block") {
          return {
            block: true,
            blockReason: summarizeDecision(policy, decision)
          };
        }

        if (decision.outcome === "approval") {
          if (policy.mode === "strict") {
            return {
              block: true,
              blockReason: summarizeDecision(policy, decision)
            };
          }

          if (sessionCache.has(ctx.sessionId, event.toolName, decision.subject)) {
            return;
          }

          const requireApproval = {
            title: `Security Watch approval for ${event.toolName}`,
            description: summarizeDecision(policy, decision),
            severity: decision.severity,
            timeoutMs: policy.approvalTimeoutMs,
            timeoutBehavior: isAutomation ? "deny" : policy.approvalTimeoutBehavior,
            onResolution: (resolution) => {
              if (resolution === "approved" || resolution === "allow") {
                sessionCache.record(ctx.sessionId, event.toolName, decision.subject);
              }
              logSafe(policy, buildAuditRecord({ phase: "approval_resolution", resolution, reasons: decision.reasons, severity: decision.severity, subject: decision.subject, policyHash: pHash, jobId: context.jobId || null, agentId: context.agentId || null, grantId: null, workspaceDir, notifyChannel: null, notifySent: false, notifyStrategy: null, notifyError: null, ...scope }), api.logger);
            }
          }

          if (isAutomation) {
            const notifyPromise = Promise.resolve().then(() => attemptNotify({ decision, ctx, policy, pluginConfig: api.pluginConfig || {}, config: api.config || {}, agentId: ctx.agentId, sessionKey: ctx.sessionKey, workspaceDir, sessionCache, appendAudit: (record) => logSafe(policy, buildAuditRecord({ phase: record.audit_event, ...record, ...scope, policyHash: pHash, workspaceDir, decision: decision.outcome, reasons: decision.reasons, severity: decision.severity, subject: decision.subject }), api.logger), warn: api.logger?.warn?.bind(api.logger), notifierRun }));
            void notifyPromise.catch((error) => api.logger?.warn?.(String(error)));
            if (resolvedChannel) requireApproval.description += `\nNotified ${resolvedChannel.kind} for approval`;
          }

          return {
            requireApproval: {
              ...requireApproval
            }
          };
        }
      } catch (error) {
        logSafe(policy, buildAuditRecord({ phase: "before_tool_call", classification: "validator_failure", decision: policy.blockOnValidatorFailure ? "block" : "allow", reasons: [String(error)], severity: "critical", subject: "", policyHash: pHash, jobId: context.jobId || null, agentId: context.agentId || null, grantId: null, workspaceDir: null, notifyChannel: null, notifySent: false, notifyStrategy: null, notifyError: String(error), ...scope }), api.logger);
        if (policy.blockOnValidatorFailure) {
          return {
            block: true,
            blockReason: "Security Watch validator failure"
          };
        }
      }
    });

    api.on("after_tool_call", async (event, ctx) => {
      const policy = load(api.pluginConfig ?? {});
      const pHash = computePolicyHash(policy);
      logSafe(policy, buildAuditRecord({ phase: "after_tool_call", toolName: event.toolName, toolCallId: event.toolCallId, runId: event.runId, agentId: ctx.agentId, sessionId: ctx.sessionId, sessionKey: ctx.sessionKey, durationMs: event.durationMs, error: event.error || null, policyHash: pHash, jobId: ctx.jobId || null, grantId: null }), api.logger);
    });
  }
});
