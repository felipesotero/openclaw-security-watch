import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import {
  appendJsonl,
  buildAuditRecord,
  evaluateToolCall,
  loadPolicy,
  summarizeDecision
} from "./lib/policy.js";

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
  register(api) {
    api.on("before_tool_call", async (event, ctx) => {
      const policy = loadPolicy(api.pluginConfig ?? {});
      const context = {
        jobId: ctx.jobId || ctx.runId,
        agentId: ctx.agentId,
        isAutomation: Boolean(ctx.jobId || ctx.cronJobId)
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
        const decision = evaluateToolCall(event, policy, context);
        logSafe(policy, buildAuditRecord({ phase: "before_tool_call", classification: decision.outcome === "allow" ? "no_match" : "threat_detected", decision: decision.outcome, reasons: decision.reasons, severity: decision.severity, subject: decision.subject, ...scope }), api.logger);

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

          return {
            requireApproval: {
              title: `Security Watch approval for ${event.toolName}`,
              description: summarizeDecision(policy, decision),
              severity: decision.severity,
              timeoutMs: policy.approvalTimeoutMs,
              timeoutBehavior: policy.approvalTimeoutBehavior,
              onResolution: (resolution) => {
                logSafe(policy, buildAuditRecord({ phase: "approval_resolution", resolution, reasons: decision.reasons, severity: decision.severity, subject: decision.subject, ...scope }), api.logger);
              }
            }
          };
        }
      } catch (error) {
        logSafe(policy, buildAuditRecord({ phase: "before_tool_call", classification: "validator_failure", decision: policy.blockOnValidatorFailure ? "block" : "allow", reasons: [String(error)], severity: "critical", subject: "", ...scope }), api.logger);
        if (policy.blockOnValidatorFailure) {
          return {
            block: true,
            blockReason: "Security Watch validator failure"
          };
        }
      }
    });

    api.on("after_tool_call", async (event, ctx) => {
      const policy = loadPolicy(api.pluginConfig ?? {});
      logSafe(policy, buildAuditRecord({ phase: "after_tool_call", toolName: event.toolName, toolCallId: event.toolCallId, runId: event.runId, agentId: ctx.agentId, sessionId: ctx.sessionId, sessionKey: ctx.sessionKey, durationMs: event.durationMs, error: event.error || null }), api.logger);
    });
  }
});
