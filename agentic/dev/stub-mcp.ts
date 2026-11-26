// Fake esperware MCP server for testing the Pi workspace without a container.
//   bun agentic/dev/stub-mcp.ts [port]
// Serves /mcp/rw and /mcp/ro (streamable HTTP, JSON responses) and prints a ready.json line.
const port = Number(process.argv[2] ?? 8799);
const base = `http://127.0.0.1:${port}`;

const tools = {
  rw: [
    { name: "ping_binary", description: "Return the stub binary name.", inputSchema: { type: "object", properties: {} } },
    { name: "apply_edits", description: "Stub edit.", inputSchema: { type: "object", properties: { note: { type: "string" } } } },
  ],
  ro: [{ name: "ping_binary", description: "Return the stub binary name.", inputSchema: { type: "object", properties: {} } }],
};

Bun.serve({
  port,
  async fetch(req) {
    const path = new URL(req.url).pathname;
    const role = path === "/mcp/rw" ? "rw" : path === "/mcp/ro" ? "ro" : null;
    if (!role) return new Response("not found", { status: 404 });
    if (req.method !== "POST") return new Response("method not allowed", { status: 405 });
    const msg: any = await req.json();
    console.error(role, msg.method, JSON.stringify(msg.params ?? {}).slice(0, 120));
    if (msg.id === undefined) return new Response(null, { status: 202 });
    let result: unknown = {};
    if (msg.method === "initialize")
      result = { protocolVersion: msg.params?.protocolVersion ?? "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "stub-esperware", version: "0" } };
    else if (msg.method === "tools/list") result = { tools: tools[role] };
    else if (msg.method === "tools/call") result = { content: [{ type: "text", text: "stub-binary.elf (version 0)" }] };
    return Response.json({ jsonrpc: "2.0", id: msg.id, result });
  },
});

console.log(JSON.stringify({
  status: "ready", launch_id: "stub", binary_name: "stub.stripped.elf", binary_sha256: "0".repeat(64),
  current_version: 0, mcp_rw_url: `${base}/mcp/rw`, mcp_ro_url: `${base}/mcp/ro`, api_url: `${base}/api/v1`,
}));
