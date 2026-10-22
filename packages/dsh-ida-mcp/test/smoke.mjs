// End-to-end smoke test: connect the official MCP SDK (the exact stack
// @deepseek-ai/dsh-mcp-client uses) to the ida-pro-mcp broker through the
// same launcher the DSH plugin spawns. No IDA GUI instance is required —
// the broker registers its tool catalog even with zero connected IDBs.
//
// Usage:
//   node test/smoke.mjs
//   IDA_MCP_PYTHON=/path/to/python node test/smoke.mjs
//
// The interpreter is resolved exactly like the shipped cordis.patch.yml:
// $IDA_MCP_PYTHON, else `python` from PATH. It must have ida-pro-mcp installed.
//
// Exit code 0 = broker reachable and tools listed; anything else = failure.
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

function resolveSdkRoot() {
  const candidates = [
    // Local install (preferred when developing this package).
    path.join(__dirname, "..", "node_modules", "@modelcontextprotocol", "sdk"),
    // The DSH installation provides the SDK; reuse it so this test works
    // without a separate install.
    path.join(process.env.DSH_HOME || path.join(os.homedir(), ".dsh"), "profiles", "node_modules", "@modelcontextprotocol", "sdk"),
  ];
  for (const candidate of candidates) {
    try {
      // Package exists if its exports entry resolves; the SDK ships ESM under dist/esm.
      require.resolve(path.join(candidate, "dist", "esm", "client", "index.js"));
      return candidate;
    } catch {
      // keep looking
    }
  }
  throw new Error(
    "cannot resolve @modelcontextprotocol/sdk — run `npm install` here, or make sure DSH is installed under ~/.dsh",
  );
}

const sdkRoot = resolveSdkRoot();
const { Client } = await import(pathToFileURL(path.join(sdkRoot, "dist", "esm", "client", "index.js")));
const { StdioClientTransport } = await import(
  pathToFileURL(path.join(sdkRoot, "dist", "esm", "client", "stdio.js")),
);

// Resolve the interpreter the same way the shipped cordis.patch.yml does:
// $IDA_MCP_PYTHON, else `python` from PATH.
const python = process.env.IDA_MCP_PYTHON || (process.platform === "win32" ? "python" : "python3");

const transport = new StdioClientTransport({
  command: python,
  args: ["-m", "ida_pro_mcp.launcher"],
});

const client = new Client({ name: "dsh-ida-mcp-smoke", version: "0.1.0" }, { capabilities: {} });

try {
  await client.connect(transport);
  const { tools } = await client.listTools();
  console.log(`OK: broker reachable, ${tools.length} tools listed`);
  for (const tool of tools) {
    console.log(`  - ${tool.name}${tool.description ? `: ${tool.description.split("\n")[0]}` : ""}`);
  }
  if (tools.length === 0) {
    console.error("FAIL: broker returned an empty tool list");
    process.exitCode = 1;
  }
} catch (error) {
  console.error(`FAIL: ${error}`);
  process.exitCode = 1;
} finally {
  try {
    await client.close();
  } catch {
    // teardown noise is fine
  }
}
