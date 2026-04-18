import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { HUMAN_KINDS, findHumanChannel, loadChannelPriority } from "../lib/channels.js";

test("pluginConfig priority wins over file and default", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-channels-"));
  const storePath = path.join(tempDir, "priority.json");
  fs.writeFileSync(storePath, JSON.stringify({ priority: ["discord", "telegram"] }));
  const pri = loadChannelPriority({ pluginConfig: { channelPriority: ["telegram", "slack"] }, storePath });
  assert.deepEqual(pri.slice(0, 2), ["telegram", "slack"]);
});

test("file wins over default", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-channels-"));
  const storePath = path.join(tempDir, "priority.json");
  fs.writeFileSync(storePath, JSON.stringify({ priority: ["discord", "telegram"] }));
  const pri = loadChannelPriority({ pluginConfig: {}, storePath });
  assert.deepEqual(pri.slice(0, 2), ["discord", "telegram"]);
});

test("malformed file falls back cleanly", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-channels-"));
  const storePath = path.join(tempDir, "priority.json");
  fs.writeFileSync(storePath, "{ not json");
  const pri = loadChannelPriority({ pluginConfig: {}, storePath });
  assert.equal(pri[0], "slack");
});

test("default used when nothing configured", () => {
  const pri = loadChannelPriority({ pluginConfig: {}, storePath: "/nonexistent/channel-priority.json" });
  assert.deepEqual(pri, HUMAN_KINDS);
});

test("findHumanChannel returns correct channel for agent with slack binding", () => {
  const config = {
    agents: { list: [{ id: "agent-1", channels: [{ kind: "slack", id: "slack-1", enabled: true }] }] },
    channels: { slack: { "slack-1": { target: "#sales" } } }
  };
  const hit = findHumanChannel({ agentId: "agent-1", config, priority: ["slack"] });
  assert.deepEqual(hit, { kind: "slack", id: "slack-1", target: "#sales" });
});

test("returns null when no bindings", () => {
  const config = { agents: { list: [{ id: "agent-1", channels: [] }] } };
  assert.equal(findHumanChannel({ agentId: "agent-1", config, priority: ["slack"] }), null);
});

test("respects enabled:false", () => {
  const config = { agents: { list: [{ id: "agent-1", channels: [{ kind: "slack", id: "slack-1", enabled: false }] }] } };
  assert.equal(findHumanChannel({ agentId: "agent-1", config, priority: ["slack"] }), null);
});

test("strips unknown kinds in priority input", () => {
  const pri = loadChannelPriority({ pluginConfig: { channelPriority: ["pagerduty", "telegram", "fax"] }, storePath: "/nonexistent/channel-priority.json" });
  assert.deepEqual(pri.slice(0, 3), ["telegram", "slack", "whatsapp"]);
  assert.ok(!pri.includes("pagerduty"));
  assert.ok(!pri.includes("fax"));
});
