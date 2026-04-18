import { expandHome } from "./util.js";

export function resolveSessionWorkspaceDir({ ctx, sessionKey, agentId, config } = {}) {
  void sessionKey;
  try {
    if (typeof ctx?.workspaceDir === "string" && ctx.workspaceDir) return expandHome(ctx.workspaceDir);
    const list = Array.isArray(config?.agents?.list) ? config.agents.list : null;
    const agent = list?.find((entry) => entry?.id === agentId);
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
