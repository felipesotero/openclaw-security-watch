# Implementation Plan: workspace-relative paths + automation notifications

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make `security-watch` resolve relative `read/write/edit` paths against the agent workspace (not `process.cwd()`); raise approval timeout to 10 min; for automation (cron/heartbeat), dispatch a best-effort notification to a human-operable channel for the agent; make channel priority configurable.

**Architecture:** Node.js ESM plugin for OpenClaw. New focused modules (`workspace.js`, `channels.js`, `notifier.js`) imported by `index.js`; `policy.js` gains baseDir-aware normalization. All outbound side effects are injectable for tests.

**Tech Stack:** Node 20+, `node:test`, ESM modules, OpenClaw plugin SDK.

**Spec:** `docs/superpowers/specs/2026-04-18-workspace-relative-paths-and-automation-notifications-design.md`

---

## File structure

- Modify: `lib/policy.js` — baseDir-aware `normalizePolicyPath`, `workspaceTrusted`, `readPathAllowed`, `evaluateToolCall(context)` with `workspaceDir`; raise default timeout.
- Create: `lib/workspace.js` — `resolveSessionWorkspaceDir({ sessionKey, agentId, config })`.
- Create: `lib/channels.js` — `loadChannelPriority({ pluginConfig, storePath })`, `findHumanChannel({ agentId, config, priority })`.
- Create: `lib/notifier.js` — `buildMessage(ctx)`, `cliNotifier`, `notifyCommandNotifier`, composite `runNotifier`.
- Modify: `index.js` — wire workspace, automation detection, notifier, audit fields.
- Modify: `assets/default-policy.json` — default `approvalTimeoutMs=600000`.
- Modify: `openclaw.plugin.json` — default `approvalTimeoutMs=600000`; `channelPriority` and `notifyCommand` config slots documented.
- Modify: `test/policy.test.mjs` — update signature usages, add tests.
- Create: `test/workspace.test.mjs` — resolver tests.
- Create: `test/channels.test.mjs` — priority and discovery tests.
- Create: `test/notifier.test.mjs` — notifier strategy tests.

## Independent tasks (can run in parallel)

- Task 1: workspace-aware path resolution (depends on nothing)
- Task 2: approval timeout bumped to 10 min (depends on nothing)
- Task 3: automation detection by sessionKey (depends on nothing)
- Task 4: channel priority + discovery (depends on nothing)
- Task 5: notifier strategies (depends on Task 4 for tests injecting priority)
- Task 6: integrate everything into `index.js` (depends on 1-5)

---

### Task 1: baseDir-aware path normalization

**Files:**
- Modify: `lib/policy.js:17-29` (`normalizePolicyPath`), `:87-95` (`workspaceTrusted`, `readPathAllowed`), `:97-169` (`evaluateToolCall`)
- Test: `test/policy.test.mjs`

- [ ] **Step 1: Write failing tests**

```js
// in test/policy.test.mjs
test("relative path with baseDir resolves against baseDir", () => {
  const p = normalizePolicyPath("work/drafts/x.md", { baseDir: "/tmp/ws" });
  assert.strictEqual(p, "/tmp/ws/work/drafts/x.md");
});

test("relative path without baseDir does not use cwd", () => {
  const p = normalizePolicyPath("work/drafts/x.md");
  assert.ok(!p.startsWith(process.cwd()));
});

test("absolute path unaffected by baseDir", () => {
  const p = normalizePolicyPath("/etc/hosts", { baseDir: "/tmp/ws" });
  assert.strictEqual(p, "/etc/hosts");
});

test("evaluateToolCall allows workspace-relative read when baseDir trusted", () => {
  const decision = evaluateToolCall(
    { toolName: "read", params: { path: "work/drafts/a.md" } },
    policyWithTrustedPrefix("/tmp/ws"),
    { workspaceDir: "/tmp/ws" }
  );
  assert.strictEqual(decision.outcome, "allow");
});

test("evaluateToolCall requires approval for relative path when no baseDir", () => {
  const decision = evaluateToolCall(
    { toolName: "read", params: { path: "work/drafts/a.md" } },
    policyWithTrustedPrefix("/tmp/ws"),
    {}
  );
  assert.strictEqual(decision.outcome, "approval");
});
```

- [ ] **Step 2: Run tests; verify they fail**

Run: `node --test test/policy.test.mjs`
Expected: failures in the new cases.

- [ ] **Step 3: Implement**

Change `normalizePolicyPath(rawPath, opts = {})`:

```js
export function normalizePolicyPath(rawPath, opts = {}) {
  const expanded = expandHome(safeString(rawPath));
  if (!expanded) return expanded;

  let normalized = path.normalize(expanded);
  if (!path.isAbsolute(normalized)) {
    if (opts.baseDir && typeof opts.baseDir === "string") {
      normalized = path.resolve(opts.baseDir, normalized);
    } else {
      // Do not resolve against process.cwd(); keep as-is so trust check rejects it.
      return normalized;
    }
  }

  try {
    return fs.realpathSync.native(normalized);
  } catch {
    return normalized;
  }
}
```

Update `workspaceTrusted(filePath, prefixes, { baseDir })` and `readPathAllowed(filePath, patterns, { baseDir })` to forward `baseDir`.

In `evaluateToolCall({ toolName, params }, policy, context = {})`:
- Read `context.workspaceDir`.
- When normalizing `subject` for read/write/edit, pass `{ baseDir: context.workspaceDir }` to `normalizePolicyPath` and to the trust/allow helpers.

- [ ] **Step 4: Run tests; verify pass**

Run: `node --test`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add lib/policy.js test/policy.test.mjs
git commit -m "feat(policy): baseDir-aware path normalization"
```

---

### Task 2: raise default approval timeout to 10 min

**Files:**
- Modify: `lib/policy.js:43` (`approvalTimeoutMs`)
- Modify: `openclaw.plugin.json` default
- Test: `test/policy.test.mjs`

- [ ] **Step 1: Write failing test**

```js
test("default approvalTimeoutMs is 600000", () => {
  const policy = loadPolicy({});
  assert.strictEqual(policy.approvalTimeoutMs, 600000);
});
```

- [ ] **Step 2: Run test; verify fail**

Run: `node --test test/policy.test.mjs`

- [ ] **Step 3: Implement**

`lib/policy.js`:
```js
approvalTimeoutMs: Number(pluginConfig.approvalTimeoutMs || 600000),
```

`openclaw.plugin.json`: update default where `approvalTimeoutMs` appears.

- [ ] **Step 4: Run; verify pass**

- [ ] **Step 5: Commit**

```bash
git add lib/policy.js openclaw.plugin.json test/policy.test.mjs
git commit -m "feat: raise default approval timeout to 10 min"
```

---

### Task 3: automation detection from sessionKey

**Files:**
- Modify: `index.js` (automation flag building)
- Test: `test/policy.test.mjs` or new `test/automation.test.mjs`

- [ ] **Step 1: Write failing tests**

```js
import { isAutomationContext } from "../lib/policy.js";

test("cron sessionKey is automation", () => {
  assert.strictEqual(isAutomationContext({ sessionKey: "agent:x:cron:abc" }), true);
});
test("heartbeat sessionKey is automation", () => {
  assert.strictEqual(isAutomationContext({ sessionKey: "agent:x:heartbeat:abc" }), true);
});
test("main sessionKey is not automation", () => {
  assert.strictEqual(isAutomationContext({ sessionKey: "agent:x:main" }), false);
});
test("legacy jobId still marks automation", () => {
  assert.strictEqual(isAutomationContext({ sessionKey: "agent:x:main", jobId: "j" }), true);
});
```

- [ ] **Step 2: Run test; verify fail**

- [ ] **Step 3: Implement**

In `lib/policy.js` export:
```js
export function isAutomationContext(ctx) {
  if (!ctx) return false;
  if (ctx.jobId || ctx.cronJobId) return true;
  const key = String(ctx.sessionKey || "");
  return /:(cron|heartbeat):/i.test(key);
}
```

In `index.js`, replace current automation calculation with `isAutomationContext(ctx)`.

- [ ] **Step 4: Run; verify pass**

- [ ] **Step 5: Commit**

```bash
git add lib/policy.js index.js test/policy.test.mjs
git commit -m "feat: detect cron/heartbeat automation via sessionKey"
```

---

### Task 4: channel priority + discovery

**Files:**
- Create: `lib/channels.js`
- Create: `test/channels.test.mjs`

- [ ] **Step 1: Write failing tests**

```js
import { loadChannelPriority, findHumanChannel } from "../lib/channels.js";

test("pluginConfig.channelPriority wins over file and default", () => {
  const pri = loadChannelPriority({
    pluginConfig: { channelPriority: ["telegram", "slack"] },
    storePath: "/nonexistent.json"
  });
  assert.deepStrictEqual(pri.slice(0, 2), ["telegram", "slack"]);
});

test("falls back to default when both missing", () => {
  const pri = loadChannelPriority({ pluginConfig: {}, storePath: "/nonexistent.json" });
  assert.strictEqual(pri[0], "slack");
});

test("picks highest-priority human channel bound to agent", () => {
  const config = {
    agents: { list: [{ id: "comercial", channels: [{ kind: "slack", id: "slack-comercial", enabled: true }] }] },
    channels: { slack: { "slack-comercial": { enabled: true, target: "#sales" } } }
  };
  const hit = findHumanChannel({ agentId: "comercial", config, priority: ["slack"] });
  assert.strictEqual(hit.kind, "slack");
});

test("returns null when no channel bound to agent", () => {
  const hit = findHumanChannel({ agentId: "x", config: { agents: { list: [] } }, priority: ["slack"] });
  assert.strictEqual(hit, null);
});
```

- [ ] **Step 2: Run; verify fail**

- [ ] **Step 3: Implement `lib/channels.js`**

```js
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const HUMAN_KINDS = ["slack","whatsapp","telegram","discord","googlechat","msteams","signal","imessage","irc"];
const DEFAULT_PRIORITY = HUMAN_KINDS;

function expandHome(p) {
  return p?.startsWith("~/") ? path.join(os.homedir(), p.slice(2)) : p;
}

export function loadChannelPriority({ pluginConfig = {}, storePath } = {}) {
  const fromPlugin = Array.isArray(pluginConfig.channelPriority) ? pluginConfig.channelPriority : null;
  let fromFile = null;
  try {
    if (storePath) {
      const resolved = expandHome(storePath);
      if (fs.existsSync(resolved)) {
        const parsed = JSON.parse(fs.readFileSync(resolved, "utf8"));
        if (Array.isArray(parsed?.priority)) fromFile = parsed.priority;
      }
    }
  } catch { /* ignore */ }
  const chosen = (fromPlugin || fromFile || []).filter(k => HUMAN_KINDS.includes(k));
  const tail = DEFAULT_PRIORITY.filter(k => !chosen.includes(k));
  return [...chosen, ...tail];
}

export function findHumanChannel({ agentId, config = {}, priority = DEFAULT_PRIORITY } = {}) {
  if (!agentId) return null;
  const agent = (config.agents?.list || []).find(a => a.id === agentId);
  if (!agent) return null;
  const bindings = agent.channels || agent.bindings || [];
  for (const kind of priority) {
    const match = bindings.find(b => (b.kind === kind) && b.enabled !== false);
    if (match) return { kind, id: match.id || match.accountId || null, target: match.target || null };
  }
  return null;
}
```

- [ ] **Step 4: Run; verify pass**

- [ ] **Step 5: Commit**

```bash
git add lib/channels.js test/channels.test.mjs
git commit -m "feat(channels): priority resolution and human-channel discovery"
```

---

### Task 5: notifier strategies

**Files:**
- Create: `lib/notifier.js`
- Create: `test/notifier.test.mjs`

- [ ] **Step 1: Write failing tests**

```js
import { buildMessage, runNotifier } from "../lib/notifier.js";

test("buildMessage includes agent/tool/subject/reason", () => {
  const msg = buildMessage({ agentId: "comercial", sessionKey: "agent:comercial:cron:x", toolName: "write", subject: "/ws/x.md", reasons: ["approval_path:outside"] });
  assert.match(msg, /comercial/);
  assert.match(msg, /write/);
  assert.match(msg, /\/ws\/x.md/);
});

test("runNotifier uses first strategy that succeeds", async () => {
  const s1 = async () => { throw new Error("fail"); };
  const s2 = async () => ({ ok: true, strategy: "mock" });
  const res = await runNotifier([s1, s2], { channel: { kind: "slack" }, message: "hi" });
  assert.strictEqual(res.ok, true);
  assert.strictEqual(res.strategy, "mock");
});

test("runNotifier returns last error when all fail", async () => {
  const s1 = async () => { throw new Error("a"); };
  const s2 = async () => { throw new Error("b"); };
  const res = await runNotifier([s1, s2], { channel: { kind: "slack" }, message: "hi" });
  assert.strictEqual(res.ok, false);
  assert.match(res.error, /b/);
});
```

- [ ] **Step 2: Run; verify fail**

- [ ] **Step 3: Implement `lib/notifier.js`**

```js
import { spawn } from "node:child_process";

export function buildMessage({ agentId, sessionKey, toolName, subject, reasons = [], gatewayHint = "Abra o OpenClaw gateway para aprovar." }) {
  const parts = [
    `[security-watch] ${agentId || "?"} precisa de aprovação`,
    `Tool: ${toolName}`,
    `Alvo: ${subject}`,
    `Sessão: ${sessionKey}`,
    `Motivos: ${reasons.join(", ")}`,
    gatewayHint
  ];
  return parts.join("\n");
}

export function cliStrategy({ execImpl = spawn, timeoutMs = 5000 } = {}) {
  return async ({ channel, message, agentId }) => {
    if (!channel?.kind) throw new Error("no_channel");
    const args = [channel.kind, "send", "--agent", agentId || "", "--text", message];
    if (channel.target) args.push("--to", channel.target);
    return await runSubprocess("openclaw", args, { timeoutMs, execImpl });
  };
}

export function notifyCommandStrategy({ template, execImpl = spawn, timeoutMs = 5000 } = {}) {
  return async ({ channel, message, agentId, sessionKey, subject }) => {
    if (!template) throw new Error("no_notify_command");
    const cmd = String(template)
      .replace(/\{agent\}/g, agentId || "")
      .replace(/\{channel\}/g, channel?.kind || "")
      .replace(/\{text\}/g, message)
      .replace(/\{sessionKey\}/g, sessionKey || "")
      .replace(/\{subject\}/g, subject || "");
    return await runSubprocess("sh", ["-c", cmd], { timeoutMs, execImpl });
  };
}

async function runSubprocess(cmd, args, { timeoutMs, execImpl }) {
  return new Promise((resolve, reject) => {
    const child = execImpl(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    const to = setTimeout(() => { try { child.kill("SIGKILL"); } catch {} reject(new Error("notifier_timeout")); }, timeoutMs);
    child.stderr?.on("data", (d) => { stderr += String(d); });
    child.on("error", (e) => { clearTimeout(to); reject(e); });
    child.on("exit", (code) => {
      clearTimeout(to);
      if (code === 0) resolve({ ok: true, strategy: cmd === "openclaw" ? "cli" : "notifyCommand" });
      else reject(new Error(`exit_${code}:${stderr.slice(0, 200)}`));
    });
  });
}

export async function runNotifier(strategies, payload) {
  let lastError = null;
  for (const strat of strategies) {
    try {
      const res = await strat(payload);
      if (res?.ok) return res;
    } catch (e) {
      lastError = e;
    }
  }
  return { ok: false, error: String(lastError || "no_strategy") };
}
```

- [ ] **Step 4: Run; verify pass**

- [ ] **Step 5: Commit**

```bash
git add lib/notifier.js test/notifier.test.mjs
git commit -m "feat(notifier): cli + notifyCommand strategies with composite runner"
```

---

### Task 6: wire everything into index.js

**Files:**
- Modify: `index.js`
- Test: `test/policy.test.mjs` or integration in test for automation path

- [ ] **Step 1: Write failing integration-style test**

```js
test("automation approval triggers notifier and records audit", async () => {
  // craft a fake api.config and pluginConfig with a channel; inject notifier
  // assert that for an approval outcome with isAutomation true, notifier is called
  //   and audit contains notifyChannel + notifySent
});
```

- [ ] **Step 2: Run; verify fail**

- [ ] **Step 3: Implement**

In `index.js`:
- Import `resolveSessionWorkspaceDir`, `loadChannelPriority`, `findHumanChannel`, `cliStrategy`, `notifyCommandStrategy`, `runNotifier`, `buildMessage`, `isAutomationContext`.
- For each `before_tool_call`:
  - Compute `workspaceDir` via resolver.
  - Compute `isAutomation`.
  - Evaluate with `{ ...ctxFields, workspaceDir, isAutomation }`.
  - If outcome `approval` AND `isAutomation`:
    - Build message, pick channel, run notifier with strategies `[cliStrategy, notifyCommandStrategy({ template })]`.
    - Set `notifyChannel`, `notifySent`, `notifyStrategy`, `notifyError` on audit.
    - Append “Notified …” line to description when `ok`.

- [ ] **Step 4: Run full tests; verify pass**

Run: `node --test`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add index.js test/policy.test.mjs
git commit -m "feat: integrate workspace resolver + automation notifier"
```

---

### Task 7: open PR

- [ ] Push branch
- [ ] Open PR to `main` with summary linking the spec
- [ ] Request review

```bash
git push -u origin feat/workspace-paths-and-notifications
gh pr create --title "feat: workspace-relative paths + automation notifications" --body "$(cat <<'EOF'
## Summary
- Resolve relative read/write/edit paths against the agent workspace (fixes cron/CLI approval hangs)
- Raise default approval timeout to 10 min
- Detect cron/heartbeat automation from sessionKey
- Discover human-operable channel for agent via configurable priority (openclaw.json > file > default)
- Dispatch best-effort notification with built-in CLI + optional notifyCommand
- Enhanced audit with workspaceDir and notify fields

Spec: docs/superpowers/specs/2026-04-18-workspace-relative-paths-and-automation-notifications-design.md
EOF
)"
```

---

## Self-review checklist

- Task 1 covers relative-with-baseDir, relative-without-baseDir, absolute
- Task 2 covers new default timeout
- Task 3 covers sessionKey heuristic and legacy jobId
- Task 4 covers config precedence and agent binding selection
- Task 5 covers message shape + strategy ordering
- Task 6 wires all together and adds audit fields
