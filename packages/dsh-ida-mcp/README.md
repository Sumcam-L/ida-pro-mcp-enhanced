# dsh-ida-mcp

Bridge the [IDA Pro MCP](https://github.com/Sumcam-L/ida-pro-mcp-enhanced) broker
into [DeepSeek Harness](https://deepseek-harness.github.io/deepseek-harness/), exposing
~66 IDA tools as native `mcp__ida__*` tools: decompile, cross-references, rename,
disassembly, and more.

## Why a broker

Most IDA MCP setups spawn one broker per client, so opening a second AI tool fights
over the port and over the same IDB. This plugin reuses the ida-pro-mcp broker:

```
DSH (mcp__ida__* tools)
   |  @deepseek-ai/dsh-mcp-client (stdio)
   v
ida_pro_mcp_enhanced.launcher --> Broker (127.0.0.1:13337)
                                     |  SSE routing
                                     v
                    IDA GUI instances (ida_mcp.py plugin, one per IDB)
```

The broker starts on demand and is shared by every MCP client (DSH, Cursor,
Claude Desktop, ...). It keeps running as long as any IDA instance is attached,
even if all MCP clients disconnect -- so reconnecting a client never kicks your
IDA sessions offline.

## Install

### 1. Python side (broker + stdio server + IDA plugin)

The package is not on PyPI: the name `ida-pro-mcp` there belongs to upstream
mrexodia (1.4.0, no broker). Install from the GitHub release instead:

```bash
pip install https://github.com/Sumcam-L/ida-pro-mcp-enhanced/releases/latest/download/ida_pro_mcp_enhanced-2.0.2-py3-none-any.whl
ida-mcp-setup
```

### 2. This plugin

```bash
dsh plugin install dsh-ida-mcp
```

Then open a database in IDA and fully restart DSH.

## Requirements

| Requirement | Notes |
| --- | --- |
| Python 3.11+ | Must be on PATH and be the interpreter IDA uses |
| `ida-pro-mcp-enhanced` | Installed via the wheel above |
| IDA plugin | `ida-mcp-setup` installs it; restart IDA afterwards |
| IDA Pro | 8.3+ (IDA Free has no plugin API) |

## Configuration

The plugin runs `python -m ida_pro_mcp_enhanced.launcher` using `python` from PATH.
If IDA uses a specific interpreter (common with 32-bit IDA), point it explicitly:

```bash
set IDA_MCP_PYTHON=D:\Program Files\Python\Python311-32\python.exe
```

Other tunables are documented in the
[ida-pro-mcp-enhanced README](https://github.com/Sumcam-L/ida-pro-mcp-enhanced#环境变量).

## Usage

Just ask in a DSH session:

- "which IDA instances are connected" -> `mcp__ida__instance_list`
- "decompile main" -> `mcp__ida__decompile`
- "who calls this function" -> `mcp__ida__xrefs_to`

## Troubleshooting

**Tool list is empty**
IDA is not running, or the plugin has not connected. Open IDA, load a database,
then press `Ctrl+Alt+M` to reconnect manually.

**`No module named ida_pro_mcp_enhanced`**
The `python` on PATH does not have the package, or IDA uses a different
interpreter than PATH. Set `IDA_MCP_PYTHON`.

**Calls fail with 'not connected' while IDA is open**
The plugin failed to load. Check IDA's Output window for a `[MCP]` error, usually
caused by not running `ida-mcp-setup`.

## License

MIT. Upstream: [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) and its
enhancement [ida-pro-mcp-enhancement](https://github.com/QiuChenly/ida-pro-mcp-enhancement).
