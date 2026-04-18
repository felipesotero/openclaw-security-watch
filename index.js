let definePluginEntry = (entry) => entry;
try {
  ({ definePluginEntry } = await import("openclaw/plugin-sdk/plugin-entry"));
} catch {}
import {
  appendJsonl,
  buildAuditRecord,
  evaluateToolCall,
  computePolicyHash,
  isAutomationContext,
  loadPolicy,
  SessionApprovalCache,
  summarizeDecision
} from "./lib/policy.js";
import { loadChannelPriority, findHumanChannel } from "./lib/channels.js";
import { buildMessage, cliStrategy, notifyCommandStrategy, runNotifier } from "./lib/notifier.js";
import { resolveSessionWorkspaceDir } from "./lib/workspace.js";

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

    api.on("before_tool_call", async (event, ctx) => {
      const policy = load(api.pluginConfig ?? {});
      const pHash = computePolicyHash(policy);
      const workspaceDir = resolveSessionWorkspaceDir({ sessionKey: ctx.sessionKey, agentId: ctx.agentId, config: api.config });
      const isAutomation = isAutomationContext(ctx);
      const context = {
        jobId: ctx.jobId || ctx.runId,
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
        logSafe(policy, buildAuditRecord({ phase: "before_tool_call", classification: decision.outcome === "allow" ? "no_match" : "threat_detected", decision: decision.outcome, reasons: decision.reasons, severity: decision.severity, subject: decision.subject, policyHash: pHash, jobId: context.jobId || null, agentId: context.agentId || null, grantId: null, workspaceDir, notifyChannel: null, notifySent: false, notifyStrategy: null, notifyError: null, ...scope }), api.logger);

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
            logSafe(policy, buildAuditRecord({
              phase: "before_tool_call",
              classification: "session_dedup",
              decision: "allow",
              reasons: ["session_approval_cached"],
              severity: "info",
              subject: decision.subject,
              policyHash: pHash,
              jobId: context.jobId || null,
              agentId: context.agentId || null,
              grantId: null,
              ...scope
            }), api.logger);
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
          };

          if (isAutomation) {
            const priority = loadChannelPriority({ pluginConfig: api.pluginConfig || {}, storePath: "~/.openclaw/security-watch-channels.json" });
            const channel = findHumanChannel({ agentId: ctx.agentId, config: api.config || {}, priority });
            if (channel) {
              const message = buildMessage({ agentId: ctx.agentId, sessionKey: ctx.sessionKey, toolName: event.toolName, subject: decision.subject, reasons: decision.reasons });
              const strategies = [cliStrategy({ timeoutMs: 5000 })];
              if (api.pluginConfig?.notifyCommand) strategies.push(notifyCommandStrategy({ template: api.pluginConfig.notifyCommand, timeoutMs: 5000 }));
              const notifyPayload = { channel, message, agentId: ctx.agentId, sessionKey: ctx.sessionKey, subject: decision.subject };
              const notifyPromise = notifierRun(strategies, notifyPayload);
              logSafe(policy, buildAuditRecord({ phase: "before_tool_call", classification: "threat_detected", decision: decision.outcome, reasons: decision.reasons, severity: decision.severity, subject: decision.subject, policyHash: pHash, jobId: context.jobId || null, agentId: context.agentId || null, grantId: null, workspaceDir, notifyChannel: channel.kind, notifySent: true, notifyStrategy: strategies[0]?.name || "cli", notifyError: null, ...scope }), api.logger);
              notifyPromise.then((notifyResult) => {
                logSafe(policy, buildAuditRecord({ phase: "notification_resolution", decision: decision.outcome, reasons: decision.reasons, severity: decision.severity, subject: decision.subject, policyHash: pHash, jobId: context.jobId || null, agentId: context.agentId || null, grantId: null, workspaceDir, notifyChannel: channel.kind, notifySent: Boolean(notifyResult?.ok), notifyStrategy: notifyResult?.strategy || strategies[0]?.name || "cli", notifyError: notifyResult?.ok ? null : String(notifyResult?.error || "notify_failed"), ...scope }), api.logger);
              }).catch((error) => {
                logSafe(policy, buildAuditRecord({ phase: "notification_resolution", decision: decision.outcome, reasons: decision.reasons, severity: decision.severity, subject: decision.subject, policyHash: pHash, jobId: context.jobId || null, agentId: context.agentId || null, grantId: null, workspaceDir, notifyChannel: channel.kind, notifySent: false, notifyStrategy: strategies[0]?.name || "cli", notifyError: String(error), ...scope }), api.logger);
              });
              requireApproval.description += `\nNotified ${channel.kind} for approval`;
            } else {
              logSafe(policy, buildAuditRecord({ phase: "before_tool_call", classification: "threat_detected", decision: decision.outcome, reasons: decision.reasons, severity: decision.severity, subject: decision.subject, policyHash: pHash, jobId: context.jobId || null, agentId: context.agentId || null, grantId: null, workspaceDir, notifyChannel: null, notifySent: false, notifyStrategy: null, notifyError: "no_human_channel", ...scope }), api.logger);
            }
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
