# openclaw-security-watch

Fail-closed `before_tool_call` security plugin for OpenClaw `2026.4.9+`, plus a small operator skill.

## What it uses from official OpenClaw docs/code

- `before_tool_call` hook
- `PluginHookBeforeToolCallResult.block`
- `PluginHookBeforeToolCallResult.requireApproval`
- local plugin manifest `openclaw.plugin.json`
- `definePluginEntry(...)`

Validated against the installed OpenClaw `2026.4.9` SDK/docs in this environment.

## Install locally

```bash
/home/openclaw/.local/bin/openclaw plugins install /path/to/openclaw-security-watch --force
/home/openclaw/.local/bin/openclaw plugins enable security-watch
```

## Default behavior

- destructive shell / secret reads / localhost-metadata fetches → block
- medium-risk operations → approval in `approval` mode
- validator failure → block by default

## Companion skill

The `skill/SKILL.md` file provides operator commands to inspect the JSONL audit log and test the plugin.
