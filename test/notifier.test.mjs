import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { buildMessage, cliStrategy, notifyCommandStrategy, runNotifier } from "../lib/notifier.js";

function makeChild({ code = 0, stderrText = "" } = {}) {
  const child = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = () => { child.killed = true; };
  queueMicrotask(() => {
    if (stderrText) child.stderr.emit("data", stderrText);
    child.emit("exit", code, null);
  });
  return child;
}

test("buildMessage includes agent tool subject reasons and hint", () => {
  const msg = buildMessage({ agentId: "agent-1", sessionKey: "sess-9", toolName: "write", subject: "/tmp/a.md", reasons: ["fora do horário"] });
  assert.match(msg, /Agente: agent-1/);
  assert.match(msg, /Sessão: sess-9/);
  assert.match(msg, /Ferramenta: write/);
  assert.match(msg, /Assunto: \/tmp\/a\.md/);
  assert.match(msg, /Motivos: fora do horário/);
  assert.match(msg, /Abra o OpenClaw gateway para aprovar\./);
});

test("runNotifier uses first success", async () => {
  const result = await runNotifier([
    async () => ({ ok: false, error: new Error("nope") }),
    async () => ({ ok: true, strategy: "cli" }),
  ], {});
  assert.deepEqual(result, { ok: true, strategy: "cli" });
});

test("runNotifier returns last error on all-fail", async () => {
  const result = await runNotifier([
    async () => { throw new Error("first"); },
    async () => { throw new Error("last"); },
  ], {});
  assert.equal(result.ok, false);
  assert.equal(result.error.message, "last");
});

test("cliStrategy throws when no channel", async () => {
  const notify = cliStrategy({ execImpl: () => makeChild() });
  await assert.rejects(() => notify({ agentId: "a" }), /channel\.kind/);
});

test("notifyCommandStrategy throws when no template", () => {
  assert.throws(() => notifyCommandStrategy({}), /requires template/);
});

test("notifyCommandStrategy substitutes placeholders correctly", async () => {
  const calls = [];
  const notify = notifyCommandStrategy({
    template: "agent={agent} channel={channel} text={text} session={sessionKey} subject={subject}",
    execImpl: (cmd, args) => {
      calls.push({ cmd, args });
      return makeChild();
    },
  });
  await notify({ agentId: "agent-7", channel: { kind: "slack" }, message: "olá mundo", sessionKey: "s-1", subject: "/tmp/a.md" });
  assert.equal(calls[0].cmd, "sh");
  assert.deepEqual(calls[0].args, ["-c", "agent=agent-7 channel=slack text=olá mundo session=s-1 subject=/tmp/a.md"]);
});
