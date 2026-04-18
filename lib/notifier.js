import { spawn } from "node:child_process";

function truncate(text, max = 200) {
  const value = String(text || "");
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function truncateError(error, max = 500) {
  return truncate(error instanceof Error ? error.message || error.stack || String(error) : String(error ?? ""), max);
}

function redactSubject(subject, toolName) {
  let value = String(subject ?? "");
  if (!value) return value;

  try {
    const url = new URL(value);
    url.search = "";
    value = url.toString();
  } catch {}

  value = value.replace(/(?:authorization|bearer|token|api[_-]?key|password|secret|credential)\s*[:=]\s*\S+/gi, (match) => {
    const idx = match.search(/[:=]/);
    return `${match.slice(0, idx + 1)} [REDACTED]`;
  });

  value = value.replace(/[A-Fa-f0-9]{32,}/g, "[REDACTED]");
  value = value.replace(/\b(?=[A-Za-z0-9+/]{32,}={0,2}\b)(?=.*[0-9+/])[A-Za-z0-9+/]{32,}={0,2}\b/g, "[REDACTED]");

  if (/(\/secrets\/|\.env\b|id_rsa\b|credentials\b|keystore\b)/i.test(value)) {
    value = "[redacted-sensitive-path]";
  }

  if (toolName === "bash" || toolName === "exec") {
    value = value.replace(/\s+(--password|--token|--header|-H)\b.*$/i, "");
  }

  return truncate(value, 200);
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
  const redactedSubject = redactSubject(subject, toolName);
  const parts = [
    `Agente: ${agentId}`,
    `Sessão: ${sessionKey}`,
    `Ferramenta: ${toolName}`,
    `Assunto: ${redactedSubject}`,
    reasons.length ? `Motivos: ${reasons.join("; ")}` : null,
    `Dica: ${gatewayHint}`,
  ].filter(Boolean);
  return parts.join("\n");
}

export function cliStrategy({ execImpl = spawn, timeoutMs = 30000 } = {}) {
  return async function run(payload = {}) {
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
  const placeholders = {
    agent: (payload) => String(payload.agentId ?? ""),
    channel: (payload) => String(payload.channel?.kind ?? ""),
    text: (payload) => String(payload.message ?? payload.text ?? ""),
    sessionKey: (payload) => String(payload.sessionKey ?? ""),
    subject: (payload) => String(payload.subject ?? ""),
    kind: (payload) => String(payload.kind ?? payload.channel?.kind ?? ""),
    target: (payload) => String(payload.channel?.target ?? payload.target ?? ""),
  };
  const replaceOnce = (input, payload) => String(input).replace(/\{(agent|channel|text|sessionKey|subject|kind|target)\}/g, (_, key) => placeholders[key](payload));
  return async function run(payload = {}) {
    if (Array.isArray(template)) {
      const argv = template.map((item) => replaceOnce(item, payload));
      if (!argv.length || !argv[0]) throw new Error("notifyCommandStrategy requires a non-empty argv template");
      const child = execImpl(argv[0], argv.slice(1), { stdio: ["ignore", "ignore", "pipe"] });
      let stderr = "";
      child.stderr?.on?.("data", (chunk) => { stderr += chunk; });
      const result = await waitForChild(child, timeoutMs);
      if (result.code === 0) return { ok: true, strategy: "notifyCommand" };
      throw new Error(`notifyCommand strategy failed (code ${result.code}${result.signal ? `, signal ${result.signal}` : ""}): ${truncate(stderr)}`);
    }
    if (typeof template === "string" && /\s/.test(template)) {
      throw new Error("notifyCommandStrategy requires argv-array template; string templates with spaces are not supported");
    }
    const command = replaceOnce(template, payload);
    const child = execImpl(command, [], { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr?.on?.("data", (chunk) => { stderr += chunk; });
    const result = await waitForChild(child, timeoutMs);
    if (result.code === 0) return { ok: true, strategy: "notifyCommand" };
    throw new Error(`notifyCommand strategy failed (code ${result.code}${result.signal ? `, signal ${result.signal}` : ""}): ${truncate(stderr)}`);
  };
}

export async function runNotifier(strategies, payload) {
  const attempted = [];
  for (const strategy of strategies || []) {
    try {
      const result = await strategy.run(payload);
      if (result?.ok) return result;
    } catch (error) {
      attempted.push({ name: strategy.name, error: truncateError(error) });
    }
  }
  return { ok: false, error: attempted.at(-1)?.error ?? "No notifier strategies succeeded", attempted };
}

export { redactSubject };
