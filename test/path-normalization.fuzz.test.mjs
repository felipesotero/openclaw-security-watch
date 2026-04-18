import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { normalizePolicyPath, workspaceTrusted } from "../lib/policy.js";

test("workspace prefix fuzz never trusts siblings", () => {
  for (let i = 0; i < 75; i++) {
    const prefix = `/a/b/workspace${i}`;
    const sibling = `${prefix}-evil/secret-${i}.txt`;
    assert.equal(workspaceTrusted(sibling, [prefix]), false);
  }
});

test("normalizePolicyPath with baseDir cannot escape resolved base", () => {
  const baseDir = "/tmp/ws";
  for (let i = 0; i < 75; i++) {
    const input = `nested/${i}/./file.txt`;
    const normalized = normalizePolicyPath(input, { baseDir });
    assert.ok(normalized === baseDir || normalized.startsWith(baseDir + path.sep));
  }
});

test("normalizePolicyPath without baseDir keeps relative paths relative", () => {
  for (let i = 0; i < 75; i++) {
    const input = `./dir/${i}/../file.txt`;
    const normalized = normalizePolicyPath(input);
    assert.equal(path.isAbsolute(normalized), false);
  }
});
