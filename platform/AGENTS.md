# Repository instructions

- This repository is a protocol reverse-engineering tool with a general Agent /
  MCP / Skill / tool / LLM layer. Do not reintroduce penetration-testing domain
  features (tasks, asset graph, vulnerability management, traffic MITM, intercept,
  notification, ScopeSentry sync, pentest reporter/retester agents/tools).
- Keep the protocol main agent and phase sub-agents (`protocol`, `protocol_p1`…
  `protocol_p6`) and their tools working.
- `data/`, `config.json`, `jwt.key`, `platform.exe`, `web/node_modules`,
  `web/.next`, `web/out`, `server/webui/dist` are local-only. Never stage or
  commit them.
- `doc/` and `docs/` are local documentation and must not be committed.
- Keep public release notes in `CHANGELOG.md`.
- Protocol results are evidence-graded (`traffic > live > static > inferred`).
  Inferred conclusions must never be presented as confirmed.
- P5 probes default to read-only. Write/reset/destructive operations require
  explicit authorization and before/after device-state snapshots.