import { expandHome } from "./util.js";

function resolveContextAgentId({ agentId, sessionKey } = {}) {
  if (typeof agentId === "string" && agentId.trim()) return agentId;
  const match = String(sessionKey || "").match(/^agent:([^:]+):/i);
  return match?.[1] || null;
}

export function resolveSessionWorkspaceDir({ ctx, sessionKey, agentId, config } = {}) {
  try {
    if (typeof ctx?.workspaceDir === "string" && ctx.workspaceDir) return expandHome(ctx.workspaceDir);

    const effectiveAgentId = resolveContextAgentId({ agentId, sessionKey });
    const list = Array.isArray(config?.agents?.list) ? config.agents.list : null;
    const agent = list?.find((entry) => entry?.id === effectiveAgentId);

    if (agent && Object.prototype.hasOwnProperty.call(agent, "workspace")) {
      if (typeof agent.workspace === "string" && agent.workspace) return expandHome(agent.workspace);
      if (agent.workspace === null) return null;
    }
    if (typeof config?.agents?.defaults?.workspace === "string" && config.agents.defaults.workspace) {
      return expandHome(config.agents.defaults.workspace);
    }
  } catch {
    return null;
  }
  return null;
}
