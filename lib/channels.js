import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { warn } from "./util.js";

export const HUMAN_KINDS = ["slack", "whatsapp", "telegram", "discord", "googlechat", "msteams", "signal", "imessage", "irc"];

function expandStorePath(storePath) {
  if (typeof storePath !== "string" || !storePath) return storePath;
  if (storePath === "~") return os.homedir();
  if (storePath.startsWith("~/")) return path.join(os.homedir(), storePath.slice(2));
  return storePath;
}

function normalizePriority(priority) {
  const input = Array.isArray(priority)
    ? priority.map((kind) => typeof kind === "string" ? kind.toLowerCase() : kind).filter((kind) => HUMAN_KINDS.includes(kind))
    : [];
  const seen = new Set(input);
  return [...input, ...HUMAN_KINDS.filter((kind) => !seen.has(kind))];
}

function readFilePriority(storePath) {
  const resolved = expandStorePath(storePath);
  if (typeof resolved !== "string" || !resolved) return null;
  try {
    const stat = fs.statSync(resolved);
    if (stat.size > 64 * 1024) {
      warn("priority file too large; using default");
      return null;
    }
    const raw = fs.readFileSync(resolved, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed?.priority) ? parsed.priority : null;
  } catch {
    return null;
  }
}

export function loadChannelPriority({ pluginConfig, storePath }) {
  const pluginPriority = Array.isArray(pluginConfig?.channelPriority) ? pluginConfig.channelPriority : null;
  const filePriority = pluginPriority ? null : readFilePriority(storePath);
  return normalizePriority(pluginPriority ?? filePriority ?? HUMAN_KINDS);
}

export function findHumanChannel({ agentId, config, priority }) {
  const list = Array.isArray(config?.agents?.list) ? config.agents.list : null;
  if (!list) return null;
  const agent = list.find((a) => a?.id === agentId);
  const bindings = Array.isArray(agent?.channels) ? agent.channels : Array.isArray(agent?.bindings) ? agent.bindings : [];
  const enabledBindings = bindings.filter((binding) => {
    const kind = typeof binding?.kind === "string" ? binding.kind.toLowerCase() : "";
    const disabled = binding?.enabled === false || binding?.enabled === "false";
    return binding && !disabled && HUMAN_KINDS.includes(kind) && typeof binding.id === "string" && binding.id;
  });
  for (const kind of Array.isArray(priority) ? priority : HUMAN_KINDS) {
    const normalized = typeof kind === "string" ? kind.toLowerCase() : kind;
    const hit = enabledBindings.find((binding) => (typeof binding.kind === "string" ? binding.kind.toLowerCase() : "") === normalized);
    if (hit) {
      const channelConfig = config?.channels?.[normalized]?.[hit.id] ?? {};
      return { kind: normalized, id: hit.id, target: hit.target ?? channelConfig.target ?? channelConfig.handle ?? null };
    }
  }
  return null;
}
