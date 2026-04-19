import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { mock } from "node:test";
import { canonicalizePath, isInsideDirectory, nearestExistingAncestorRealpath, workspaceTrusted } from "../lib/paths.js";

const baseDir = "/tmp/security-watch-workspace";

test("canonicalizePath with baseDir resolves correctly", () => {
  assert.equal(canonicalizePath("work/drafts/x.md", { baseDir }), "/tmp/security-watch-workspace/work/drafts/x.md");
});

test("canonicalizePath without baseDir keeps relative", () => {
  assert.equal(canonicalizePath("work/drafts/x.md"), "work/drafts/x.md");
});

test("canonicalizePath with absolute path ignores baseDir", () => {
  assert.equal(canonicalizePath("/etc/hosts", { baseDir }), "/etc/hosts");
});

test("canonicalizePath with home expands", () => {
  assert.equal(canonicalizePath("~/.config"), path.join(os.homedir(), ".config"));
});

test("canonicalizePath empty-ish returns empty string", () => {
  assert.equal(canonicalizePath(""), "");
  assert.equal(canonicalizePath(null), "");
  assert.equal(canonicalizePath(undefined), "");
});

test("canonicalizePath normalizes dot segments", () => {
  assert.equal(canonicalizePath("a/../b.txt"), "b.txt");
});

test("isInsideDirectory exact match returns true", () => {
  assert.equal(isInsideDirectory("/a/b", "/a/b"), true);
});

test("isInsideDirectory nested path returns true", () => {
  assert.equal(isInsideDirectory("/a/b/c", "/a/b"), true);
});

test("isInsideDirectory rejects sibling prefix collision", () => {
  assert.equal(isInsideDirectory("/a/b-evil/c", "/a/b"), false);
});

test("isInsideDirectory rejects parent traversal", () => {
  assert.equal(isInsideDirectory("/a/c", "/a/b"), false);
});

test("isInsideDirectory with nullish returns false", () => {
  assert.equal(isInsideDirectory(null, "/a/b"), false);
  assert.equal(isInsideDirectory("/a/b", ""), false);
});

test("workspaceTrusted delegates correctly", () => {
  assert.equal(workspaceTrusted("work/drafts/x.md", ["/tmp/security-watch-workspace"], { baseDir }), true);
});

test("workspaceTrusted rejects sibling prefix collision", () => {
  assert.equal(workspaceTrusted("/a/b-evil/c", ["/a/b"]), false);
});

test("nearestExistingAncestorRealpath returns existing parent", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "security-watch-paths-"));
  const file = path.join(dir, "missing", "file.txt");
  const parent = nearestExistingAncestorRealpath(file);
  assert.equal(parent, fs.realpathSync.native(dir));
});

test("nearestExistingAncestorRealpath returns null for impossible path", () => {
  try {
    mock.method(fs, "existsSync", () => false);
    mock.method(fs.realpathSync, "native", () => { throw new Error("nope"); });
    assert.equal(nearestExistingAncestorRealpath("/does/not/matter"), null);
  } finally {
    mock.restoreAll();
  }
});
