# security-watch: workspace-relative path resolution + automation approval notifications

**Date:** 2026-04-18
**Status:** Draft for review

## Goal

Fix the path-resolution bug in `security-watch` so relative `read/write/edit` paths resolve against the real agent workspace (not `process.cwd()`), and add a non-blocking side-channel notification that asks a human to approve when automation (cron/heartbeat) runs into an `approval` outcome. Interactive sessions keep current behavior.

## Scope

In scope:
- Resolve relative paths against each session's agent workspace.
- Detect automation runs from `ctx` heuristics.
- Discover a human-operable channel for the agent via plugin config.
- Dispatch a best-effort notification for automation approvals.
- Raise default approval timeout to 10 minutes.
- Config file for channel priority.
- Audit + tests.

Out of scope:
- Auto-approving based on channel reply.
- Retrying notifications.
- UI for channel preferences.
- Integrating with a future `api.messages.send` if/when SDK adds one.

## Non-goals

- The plugin does not become an approval router. Gateway remains the source of truth for approval decisions.
- No change to `requireApproval` contract with the gateway.

## Background

`normalizePolicyPath` currently does `path.resolve(relativePath)` with no base, so relative paths resolve against the gateway `process.cwd()` (`/home/openclaw`), causing `approval_path:outside_trusted_workspace` for legitimate workspace files. Cron/heartbeat runs also cannot self-approve, so they hang on `approval`.

## Design

### 1. Workspace-aware path normalization

- New signature: `normalizePolicyPath(rawPath, { baseDir } = {})`.
- Behavior:
  - If `rawPath` is absolute → `realpathSync.native` if possible, else normalized path.
  - If `rawPath` is relative AND `baseDir` is a non-empty string → `path.resolve(baseDir, rawPath)` then realpath-if-exists.
  - If `rawPath` is relative AND `baseDir` is not available → return the raw normalized form without resolving against cwd. Downstream trust checks will then reject it as untrusted.
- `workspaceTrusted` and `readPathAllowed` accept `baseDir` via the decision context and forward it to `normalizePolicyPath`.
- `evaluateToolCall(event, policy, context)` gains `context.workspaceDir`.

This replaces the current silent `path.resolve(relative)` that used `process.cwd()`.

### 2. Workspace discovery in the plugin

- In `before_tool_call`, derive `workspaceDir` by:
  1. Prefer `ctx.workspaceDir` if ever provided.
  2. Else call the SDK resolver `resolveRunWorkspaceDir({ sessionKey, agentId, config })`.
  3. Else fall back to `resolveAgentWorkspaceDir(config, agentId)`.
  4. If none resolve, leave `workspaceDir` undefined and follow the conservative rule in §1.

The plugin imports these via `api.runtime` or from the published SDK module paths. If not exposed, a small local helper replicates their core lookup using `api.config.agents.list[].workspace` and `agents.defaults.workspace`.

### 3. Automation detection

`context.isAutomation` is true when any of:
- `ctx.jobId || ctx.cronJobId` is set (legacy/future-proof).
- `ctx.sessionKey` matches `:cron:` or `:heartbeat:` segments.

Otherwise false.

### 4. Channel discovery

- Plugin reads `api.config` to find channels bound to `ctx.agentId` through:
  - `agents.list[].channels[]` or `agents.list[].bindings[]`, if present.
  - `channels.*.bindings` / `routes` pointing at the agent.
- Supported kinds considered human-operable: `slack`, `whatsapp`, `telegram`, `discord`, `imessage`, `signal`, `googlechat`, `msteams`, `irc`.
- Only channels marked `enabled` (or without an explicit `enabled: false`) are considered.

### 5. Channel priority

Priority is resolved in this order, first valid source wins:

1. `api.pluginConfig.channelPriority` (comes from `openclaw.json` → `plugins.security-watch.channelPriority`), expected as an array of channel kinds.
2. `~/.openclaw/security-watch-channels.json`, shape:
   ```json
   {
     "priority": ["slack", "whatsapp", "telegram", "discord", "googlechat", "msteams", "signal", "imessage", "irc"]
   }
   ```
3. Embedded default order: `slack → whatsapp → telegram → discord → googlechat → msteams → signal → imessage → irc`.

Rules:
- Unknown kinds in the array are ignored.
- Missing kinds fall through to defaults appended at the end.
- Malformed config → log and use next source.

### 6. Notification dispatch

For each `approval` decision where `isAutomation === true`:

1. Pick the highest-priority available human-operable channel for the agent.
2. Build a concise message containing: agent id, session key, tool name, normalized subject, reason(s), and a hint to approve via OpenClaw gateway.
3. Dispatch via an injectable `notifier(strategies, { channel, message })` port, trying strategies in order until one succeeds:
   - **(a) Built-in CLI:** shell out to `openclaw <channelKind> send …` (or the current equivalent per channel kind). No user configuration required. Short timeout (default 5s) with stderr captured.
   - **(b) User `notifyCommand`:** optional string in `openclaw.json` → `plugins.security-watch.notifyCommand` with placeholders `{agent}`, `{channel}`, `{text}`, `{sessionKey}`, `{subject}`. Used only if present and if (a) fails or is unavailable. The user only needs to set this if they want to customize; they do not need to implement a new script.
4. If all strategies fail, set `notifyError` on audit and leave approval flow unchanged.
5. Record `notifyChannel`, `notifySent`, `notifyStrategy`, `notifyError` on the audit entry.

### 7. Approval UX

- `requireApproval` fields unchanged.
- `description` is extended with a single trailing line only when a notification was dispatched: `Notified <channel> at <ISO timestamp>`.
- New default `approvalTimeoutMs = 600000` (10 min). `approvalTimeoutBehavior` for automation stays `deny` (fail-closed).

### 8. Audit schema

- New fields on `buildAuditRecord`:
  - `workspaceDir` (string | null)
  - `notifyChannel` (string | null)
  - `notifySent` (boolean | null)
  - `notifyStrategy` (string | null) — `"cli"` or `"notifyCommand"`
  - `notifyError` (string | null)
- Existing fields unchanged.

### 9. Interactive vs automation behavior

| Case | `isAutomation` | Notification | Timeout behavior |
|---|---|---|---|
| Interactive chat, main session | false | none | `deny` (current default) |
| Cron/heartbeat | true | dispatched if channel exists | `deny` (fail closed) |

### 10. Error handling

- Workspace resolver throws → log, treat `workspaceDir` as undefined, keep existing relative-path rule (conservative rejection).
- Channel config reader throws → log, skip notification, proceed with normal approval flow.
- Notifier throws or times out → log, set `notifyError`, proceed with normal approval flow.
- No case where notification failure blocks or affects the approval decision.

## Files expected to change

- `lib/policy.js`: `normalizePolicyPath`, `workspaceTrusted`, `readPathAllowed`, `evaluateToolCall`, `computePolicyHash` (no new fields in hash), new default timeout.
- `lib/workspace.js` (new): `resolveSessionWorkspaceDir({ sessionKey, agentId, config })`.
- `lib/channels.js` (new): `loadChannelPriority({ storePath })`, `findHumanChannel({ agentId, config, priority })`.
- `lib/notifier.js` (new): default `cliNotifier({ channel, message, timeoutMs })`.
- `index.js`: wire workspace, automation detection, notifier, audit fields.
- `assets/default-policy.json`: raise default `approvalTimeoutMs` to 600000.
- `openclaw.plugin.json`: update default `approvalTimeoutMs` to 600000; keep `approvalTimeoutBehavior: "deny"`.
- `test/policy.test.mjs`: update and add tests.
- `test/workspace.test.mjs` (new): workspace resolver tests.
- `test/channels.test.mjs` (new): channel priority and discovery tests.

## Testing

- Unit (no real CLI, no real FS writes beyond tmp):
  - relative path + baseDir → resolves to baseDir
  - relative path without baseDir → not resolved against cwd; considered outside trusted workspace
  - absolute path → unchanged
  - `sessionKey` containing `:cron:` or `:heartbeat:` → `isAutomation=true`
  - chat/main session key → `isAutomation=false`
  - channel discovery returns correct channel based on config + priority file
  - priority file missing → defaults
  - priority file malformed → defaults + error logged
  - notifier called once per approval for automation
  - notifier not called for interactive approval
  - notifier failure → audit has `notifyError`, decision unchanged
  - timeout default is 600000
- All new code paths have corresponding tests. Existing `policy.test.mjs` adjusted for new signature.

## Rollout

1. New branch from `main`.
2. Implement with TDD per writing-plans output.
3. PR to main, full test suite green.
4. User merges.
5. Sync live extension, restart gateway.
6. Observe next comercial cron run and direct CLI session.

## Risks

- Workspace resolver availability across SDK versions. Mitigated by local fallback.
- Channel send CLI surface may vary. Mitigated by best-effort dispatch and graceful degradation.
- User-facing config file drift. Mitigated by tolerant parsing + defaults.
