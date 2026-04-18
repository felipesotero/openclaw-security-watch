import { spawn } from "node:child_process";

function truncate(text, max = 200) {
  const value = String(text || "");
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function waitForChild(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    let finished = false;
    const timer = timeoutMs > 0 ? setTimeout(() => {
      if (finished) return;
      finished = true;
      try { child.kill?.("SIGKILL"); } catch {}
      reject(new Error(`Notifier timed out after ${timeoutMs}ms`));
    }, timeoutMs) : null;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
    };

    child.on("error", (error) => {
      if (finished) return;
      finished = true;
      cleanup();
      reject(error);
    });

    child.on("exit", (code, signal) => {
      if (finished) return;
      finished = true;
      cleanup();
      resolve({ code, signal });
    });
  });
}

export function buildMessage({ agentId, sessionKey, toolName, subject, reasons = [], gatewayHint = "Abra o OpenClaw gateway para aprovar." }) {
  const parts = [
    `Agente: ${agentId}`,
    `Sessão: ${sessionKey}`,
    `Ferramenta: ${toolName}`,
    `Assunto: ${subject}`,
    reasons.length ? `Motivos: ${reasons.join("; ")}` : null,
    `Dica: ${gatewayHint}`,
  ].filter(Boolean);
  return parts.join("\n");
}

export function cliStrategy({ execImpl = spawn, timeoutMs = 30000 } = {}) {
  return async function notify(payload = {}) {
    const { channel, agentId, message } = payload;
    if (!channel?.kind) throw new Error("cliStrategy requires channel.kind");
    const args = [channel.kind, "send", "--agent", String(agentId ?? "")];
    if (channel.target) args.push("--to", String(channel.target));
    args.push("--text", String(message ?? ""));
    const child = execImpl("openclaw", args, { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr?.on?.("data", (chunk) => { stderr += chunk; });
    const result = await waitForChild(child, timeoutMs);
    if (result.code === 0) return { ok: true, strategy: "cli" };
    throw new Error(`cli strategy failed (code ${result.code}${result.signal ? `, signal ${result.signal}` : ""}): ${truncate(stderr)}`);
  };
}

export function notifyCommandStrategy({ template, execImpl = spawn, timeoutMs = 30000 } = {}) {
  if (!template) throw new Error("notifyCommandStrategy requires template");
  return async function notify(payload = {}) {
    const text = String(payload.message ?? payload.text ?? "");
    const rendered = template
      .replaceAll("{agent}", String(payload.agentId ?? ""))
      .replaceAll("{channel}", String(payload.channel?.kind ?? ""))
      .replaceAll("{text}", text)
      .replaceAll("{sessionKey}", String(payload.sessionKey ?? ""))
      .replaceAll("{subject}", String(payload.subject ?? ""));
    const child = execImpl("sh", ["-c", rendered], { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr?.on?.("data", (chunk) => { stderr += chunk; });
    const result = await waitForChild(child, timeoutMs);
    if (result.code === 0) return { ok: true, strategy: "notifyCommand" };
    throw new Error(`notifyCommand strategy failed (code ${result.code}${result.signal ? `, signal ${result.signal}` : ""}): ${truncate(stderr)}`);
  };
}

export async function runNotifier(strategies, payload) {
  let lastError = null;
  for (const strategy of strategies || []) {
    try {
      const result = await strategy(payload);
      if (result?.ok) return result;
      lastError = result?.error ? new Error(String(result.error)) : lastError;
    } catch (error) {
      lastError = error;
    }
  }
  return { ok: false, error: lastError };
}
