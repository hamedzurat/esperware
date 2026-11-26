# agentic

Pi workspace template for esperware runs.

`just run <binary>` starts the container, then `scaffold.sh` creates `.runs/<id>/`:

```
.runs/<id>/
  pi            launcher (sources agentic/.env, renders configs, starts Pi)
  export-html   dumps every session to html/
  run.json      port, MCP urls, state dir, container name
  agent/        PI_CODING_AGENT_DIR: SYSTEM.md (edit freely) + rendered models/mcp/settings
  template/     copy of agentic/template configs, re-rendered on every ./pi start
  work/         Pi's cwd, empty
  sessions/     Pi session JSONL (full trace)
```

```sh
cd .runs/<id> && ./pi                         # interactive
./pi -p "Improve readability of this binary"  # one shot
./pi --thinking low                           # off | low | medium | xhigh (default)
./pi --mode json "task" > events.jsonl        # JSONL events
./export-html [dark|light]                    # sessions -> html/*.html (default dark)
```

- Model endpoint, model id and `rw`/`ro` MCP access live in `agentic/.env` (see `.env.example`).
- The Ghidra state dir stays outside `.runs/` (`just run` rejects dot-prefixed state paths). `run.json` records it.
- Pi's built-in MCP client connects to `/mcp/rw` or `/mcp/ro`; tools are exposed directly to the model.
- `dev/stub-mcp.ts` is a fake MCP server for testing without a container: `bun agentic/dev/stub-mcp.ts 8799`.
