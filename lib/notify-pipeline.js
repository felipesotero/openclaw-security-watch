import { buildMessage, cliStrategy, notifyCommandStrategy, runNotifier } from "./notifier.js";
import { findHumanChannel, loadChannelPriority } from "./channels.js";

export async function attemptAutomationNotification({
  decision,
  ctx,
  policy,
  pluginConfig,
  config,
  agentId,
  sessionKey,
  workspaceDir,
  sessionCache,
  appendAudit,
  warn,
  notifierRun = runNotifier,
}) {
  const resultBase = { dispatched: false, channel: null, strategy: null, error: null };
  if (!decision || decision.outcome !== "approval") return resultBase;

  if (sessionCache?.hasPendingNotification?.({ sessionKey, toolName: decision.toolName, subject: decision.subject })) {
    return { ...resultBase, error: null };
  }

  let channel = null;
  try {
    const priority = loadChannelPriority({ pluginConfig: pluginConfig || {}, storePath: "~/.openclaw/security-watch-channels.json" });
    channel = findHumanChannel({ agentId, config: config || {}, priority });
  } catch (error) {
    warn?.("channel discovery failed", error);
  }

  if (!channel) {
    appendAudit?.({
      audit_event: "notification_resolution",
      notifySent: false,
      notifyStrategy: null,
      notifyError: "no_human_channel",
      attempted: [],
      agentId,
      sessionKey,
      toolCallId: ctx?.toolCallId ?? null,
      jobId: ctx?.jobId ?? ctx?.cronJobId ?? null,
    });
    return { ...resultBase, error: "no_human_channel" };
  }

  const message = buildMessage({ agentId, sessionKey, toolName: decision.toolName, subject: decision.subject, reasons: decision.reasons });
  const strategies = [cliStrategy({ timeoutMs: 5000 })];
  if (pluginConfig?.notifyCommand) strategies.push(notifyCommandStrategy({ template: pluginConfig.notifyCommand, timeoutMs: 5000 }));

  sessionCache?.markPendingNotification?.({ sessionKey, toolName: decision.toolName, subject: decision.subject });
  let notifyResult;
  try {
    notifyResult = await notifierRun(strategies, { channel, message, agentId, sessionKey, subject: decision.subject });
  } catch (error) {
    notifyResult = { ok: false, error: String(error), attempted: strategies.map((s) => ({ name: s.name, error: String(error) })) };
  } finally {
    sessionCache?.clearPendingNotification?.({ sessionKey, toolName: decision.toolName, subject: decision.subject });
  }

  appendAudit?.({
    audit_event: "notification_resolution",
    notifySent: Boolean(notifyResult?.ok),
    notifyStrategy: notifyResult?.strategy ?? null,
    notifyError: notifyResult?.ok ? null : String(notifyResult?.error ?? "notify_failed"),
    attempted: notifyResult?.attempted ?? [],
    agentId,
    sessionKey,
    toolCallId: ctx?.toolCallId ?? null,
    jobId: ctx?.jobId ?? ctx?.cronJobId ?? null,
  });

  return { dispatched: true, channel, strategy: notifyResult?.strategy ?? null, error: notifyResult?.ok ? null : notifyResult?.error ?? "notify_failed" };
}
