import test from "node:test";
import assert from "node:assert/strict";
import { resolveSessionWorkspaceDir } from "../lib/workspace.js";

test("prefers ctx.workspaceDir over agent and default config workspace", () => {
  assert.equal(resolveSessionWorkspaceDir({ ctx: { workspaceDir: "/ctx" }, agentId: "a", config: { agents: { list: [{ id: "a", workspace: "/agent" }], defaults: { workspace: "/default" } } } }), "/ctx");
});

test("uses agent workspace when present and non-null", () => {
  assert.equal(resolveSessionWorkspaceDir({ agentId: "a", config: { agents: { list: [{ id: "a", workspace: "/agent" }] } } }), "/agent");
});

test("falls back to agents.defaults.workspace when agent workspace key is absent", () => {
  assert.equal(resolveSessionWorkspaceDir({ agentId: "a", config: { agents: { list: [{ id: "a" }], defaults: { workspace: "/default" } } } }), "/default");
});

test("does NOT fall back to defaults when agent workspace is explicitly null", () => {
  assert.equal(resolveSessionWorkspaceDir({ agentId: "a", config: { agents: { list: [{ id: "a", workspace: null }], defaults: { workspace: "/default" } } } }), null);
});

test("returns null for missing config without throwing", () => {
  assert.equal(resolveSessionWorkspaceDir({ agentId: "a" }), null);
});

test("returns null for malformed agents.list (not an array) without throwing", () => {
  assert.equal(resolveSessionWorkspaceDir({ agentId: "a", config: { agents: { list: {} } } }), null);
});

test("returns null for missing agentId in list and no defaults", () => {
  assert.equal(resolveSessionWorkspaceDir({ agentId: "missing", config: { agents: { list: [{ id: "a" }] } } }), null);
});

test("expands home (~) in resolved workspace path", () => {
  assert.ok(resolveSessionWorkspaceDir({ agentId: "a", config: { agents: { list: [{ id: "a", workspace: "~/.ws" }] } } }).endsWith("/.ws"));
});

test("expands home in agents.defaults.workspace", () => {
  assert.ok(resolveSessionWorkspaceDir({ agentId: "a", config: { agents: { list: [{ id: "a" }], defaults: { workspace: "~/.ws" } } } }).endsWith("/.ws"));
});

test("expands home in ctx.workspaceDir", () => {
  assert.ok(resolveSessionWorkspaceDir({ ctx: { workspaceDir: "~/.ctx" } }).endsWith("/.ctx"));
});

test("returns null when ctx.workspaceDir is empty string", () => {
  assert.equal(resolveSessionWorkspaceDir({ ctx: { workspaceDir: "" } }), null);
});

test("returns null when agent.workspace is empty string", () => {
  assert.equal(resolveSessionWorkspaceDir({ agentId: "a", config: { agents: { list: [{ id: "a", workspace: "" }] } } }), null);
});
