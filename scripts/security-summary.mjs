#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function expandHome(rawPath) {
  return rawPath.startsWith("~/") ? path.join(os.homedir(), rawPath.slice(2)) : rawPath;
}

const logPath = expandHome(process.argv[2] || "~/.openclaw/logs/security-watch-events.jsonl");
const windowMinutes = Number(process.argv[3] || "60");
const cutoff = Date.now() - windowMinutes * 60 * 1000;

if (!fs.existsSync(logPath)) {
  console.log(JSON.stringify({ logPath, total: 0, decisions: {}, message: "log not found" }));
  process.exit(0);
}

const records = fs
  .readFileSync(logPath, "utf8")
  .split("\n")
  .filter(Boolean)
  .map((line) => JSON.parse(line))
  .filter((entry) => Date.parse(entry.timestamp) >= cutoff);

const byDecision = {};
const byPhase = {};
for (const record of records) {
  if (record.decision) byDecision[record.decision] = (byDecision[record.decision] || 0) + 1;
  if (record.phase) byPhase[record.phase] = (byPhase[record.phase] || 0) + 1;
}

console.log(JSON.stringify({ logPath, windowMinutes, total: records.length, byDecision, byPhase, important: records.filter((r) => r.decision === "block" || r.classification === "validator_failure").slice(-10) }, null, 2));
