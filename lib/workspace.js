import { expandHome } from "./policy.js";

export function resolveSessionWorkspaceDir({ sessionKey, agentId, config } = {}) {
  void sessionKey;
  const agent = config?.agents?.list?.find((entry) => entry?.id === agentId);
  if (typeof agent?.workspace === "string" && agent.workspace) {
    return expandHome(agent.workspace);
  }
  if (typeof config?.agents?.defaults?.workspace === "string" && config.agents.defaults.workspace) {
    return expandHome(config.agents.defaults.workspace);
  }
  return null;
}
