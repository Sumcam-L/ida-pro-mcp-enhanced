# dsh-ida-mcp

把 opencode 里那套 IDA Pro MCP（`ida-pro-mcp` broker + IDA GUI 插件 `ida_mcp.py`）
桥接进 DeepSeek Harness 的插件。复用 DSH 内置的
[`@deepseek-ai/dsh-mcp-client`](https://deepseek-harness.github.io/deepseek-harness/)，
broker 的启动/停止、多客户端共享、IDA 实例注册全部沿用现有的
`ida_mcp_launcher.py` —— 不新增任何 Python 代码。

## 原理

```
DSH (mcp__ida__* tools)
   │  @deepseek-ai/dsh-mcp-client (stdio)
   ▼
ida_mcp_launcher.py ──启动/共享──► Broker (http://127.0.0.1:13337)
                                      │  SSE 路由
                                      ▼
                        IDA GUI 实例 (ida_mcp.py 插件, 每个一个 IDB)
```

- 工具以 `mcp__ida__<工具名>` 形式注册进 `ctx.tools`（如 `mcp__ida__decompile`、
  `mcp__ida__xrefs_to`、`mcp__ida__instance_list`、`mcp__ida__survey_binary` 等约 60+ 个，
  unsafe 工具已由 broker 过滤）。
- 与 opencode 共享同一个 broker 和同一批 IDA 实例：任一端连上时 broker 自动拉起，
  最后一个客户端退出后自动停止。
- IDA 工具调用超时默认 180 秒（分析/反编译可能较慢）。

## 前置条件

- 已安装 `ida_pro_mcp`（Python 包）与 IDA GUI 插件 `ida_mcp.py`（本机路径见下）。
- IDA 实例不需要预先打开；但调用具体工具前，需要先打开对应二进制（IDA 会自动连上 broker）。

## 安装（到 dsh web profile）

```bash
# 1. 在 profile 的 package.json 增加依赖与 bundle：
#    dependencies:  "dsh-ida-mcp": "link:E:/WorkSpace/Tools/dsh-ida-mcp"
#    dsh.profile.bundles 追加: "dsh-ida-mcp"
# 2. 安装并重启：
dsh plugin --profile web install
# 重启 web（dsb web / 重启服务）后，模型即可看到 mcp__ida__* 工具
```

路径可用环境变量覆盖（不设置则用默认值）：

| 变量 | 默认值 |
|---|---|
| `IDA_MCP_PYTHON` | `D:\Program Files\Python\Python311-32\python.exe` |
| `IDA_MCP_LAUNCHER` | `C:\Users\Sumcam\.config\opencode\scripts\ida_mcp_launcher.py` |

## 验证

```bash
# 端到端冒烟：走与 DSH 完全相同的 SDK 栈连接 launcher，列出工具目录
node test/smoke.mjs
```

web 启动日志应出现 `mcp-client(ida)` 的连接与工具同步记录；会话中让模型调用
`mcp__ida__instance_list` 可看到当前连接的 IDA 实例。

## 使用示例

1. 在 IDA 中打开目标二进制（如 `GameCore_XP2_FinalRelease.dll`），插件自动连 broker。
2. 在 DSH 会话中让模型：
   - `mcp__ida__instance_list` 查看实例
   - `mcp__ida__survey_binary` 总览
   - `mcp__ida__decompile` 反编译 `main` / 指定函数
   - `mcp__ida__xrefs_to` / `mcp__ida__list_funcs` 等常规逆向操作

## License

MIT
