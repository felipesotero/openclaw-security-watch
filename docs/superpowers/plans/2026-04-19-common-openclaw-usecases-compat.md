# Common OpenClaw Use Cases Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce breakage for common OpenClaw workflows by broadening safe in-workspace file operations and shipping pragmatic cron preapproval bootstrap defaults.

**Architecture:** Keep PR #5 security model intact, but move common day-to-day agent outputs into explicit allow/preapproval paths. Implement this as policy-level and small helper changes rather than another semantic rewrite of automation approvals. Add tests that model common OpenClaw flows: drafts, attachments, memory, docs, and recurring cron jobs.

**Tech Stack:** Node.js ESM, node:test, JSON policy files, OpenClaw plugin hooks.

---

### Task 1: Define compatibility policy targets

**Files:**
- Modify: `assets/default-policy.json`
- Test: `test/policy.test.mjs`

- [ ] **Step 1: Add failing tests for common safe workspace writes**
- [ ] **Step 2: Verify they fail under current policy**
- [ ] **Step 3: Update default policy / policy evaluation to allow safe workspace output paths**
- [ ] **Step 4: Re-run targeted tests**

### Task 2: Expand safe read paths for common OpenClaw workflows

**Files:**
- Modify: `assets/default-policy.json`
- Test: `test/policy.test.mjs`

- [ ] **Step 1: Add failing tests for common repo/docs/config reads**
- [ ] **Step 2: Verify they fail under current policy**
- [ ] **Step 3: Expand read allowlist conservatively**
- [ ] **Step 4: Re-run targeted tests**

### Task 3: Bootstrap cron preapprovals for standard agents

**Files:**
- Modify: `lib/preapprovals.js`
- Modify: `test/preapprovals.test.mjs`
- Optional: `docs/superpowers/specs/` or README if behavior needs operator docs

- [ ] **Step 1: Add failing tests for bootstraping grants for known jobs**
- [ ] **Step 2: Implement helper(s) to create simple job-bound grants**
- [ ] **Step 3: Re-run targeted tests**

### Task 4: Verify common use-case coverage

**Files:**
- Modify: `test/policy.test.mjs`
- Modify: `test/index.integration.test.mjs`

- [ ] **Step 1: Add integration scenarios covering comercial/posreuniao/financeiro-style flows**
- [ ] **Step 2: Run full test suite**
- [ ] **Step 3: Review for regressions vs PR #5 hardening**

### Task 5: Ship branch and PR

**Files:**
- Modify: git branch only

- [ ] **Step 1: Review diff and summarize behavior change**
- [ ] **Step 2: Commit with focused message**
- [ ] **Step 3: Push branch and open PR to main**
