# dsh-ida-mcp

把 [ida-pro-mcp](https://github.com/Sumcam-L/ida-pro-mcp-enhanced) 的 IDA Pro
broker 桥接进 [DeepSeek Harness](https://deepseek-harness.github.io/deepseek-harness/)：
把约 66 个 IDA 工具注册成原生的 `mcp__ida__*` 工具，模型可以直接反编译、查交叉引用、
改名、看反汇编。

## 它解决什么

IDA 的 MCP 生态里通常是「一个客户端一个 broker」，多开几个 AI 工具就会抢端口、
抢同一个 IDB。本项目复用 ida-pro-mcp 的 broker 架构：

```
DSH (mcp__ida__* tools)
   │  @deepseek-ai/dsh-mcp-client (stdio)
   ▼
ida_pro_mcp_enhanced.launcher ──启动/共享──► Broker (127.0.0.1:13337)
                                        │  SSE 路由
                                        ▼
                        IDA GUI 实例 (ida_mcp.py 插件，每个带一个 IDB)
```

broker 按需拉起，最后一个客户端退出后自动停止。**多个 MCP 客户端（DSH、Cursor、
Claude Desktop…）共用同一个 broker 和同一批 IDA 实例**，不会互相抢。

## 安装

```bash
# 1. 装 Python 侧（broker + stdio server + IDA 插件）
pip install ida-pro-mcp-enhanced
ida-mcp-setup

# 2. 装本插件
dsh plugin install dsh-ida-mcp
```

然后在 IDA 里打开一个数据库，**完全重启** DSH。

## 前置条件

| 条件 | 说明 |
| --- | --- |
| Python 3.11+ | 需要在 PATH 上，**且要和 IDA 用的是同一个解释器** |
| `ida-pro-mcp` | `pip install ida-pro-mcp-enhanced` |
| IDA 插件 | `ida-mcp-setup` 安装，重启 IDA 生效 |
| IDA Pro | 8.3+（不支持 IDA Free，它没有插件 API） |

## 配置

插件默认用 PATH 上的 `python`。如果你的 IDA 用的是特定解释器（常见于 32 位 IDA），
设置环境变量：

```bash
set IDA_MCP_PYTHON=D:\Program Files\Python\Python311-32\python.exe
```

其他可调项见 [ida-pro-mcp 文档](https://github.com/Sumcam-L/ida-pro-mcp-enhanced#环境变量)。

## 用法示例

在 DSH 会话里直接说：

- 「看看现在连着哪些 IDA 实例」 → `mcp__ida__instance_list`
- 「反编译 main」 → `mcp__ida__decompile`
- 「谁调用了这个函数」 → `mcp__ida__xrefs_to`
- 「把所有 xxx 开头的函数找出来」 → `mcp__ida__list_funcs`

## 常见问题

**工具列表是空的**
IDA 没开，或插件没连上 broker。打开 IDA → 加载数据库 → 按 `Ctrl+Alt+M` 手动重连。

**调用报 `No module named ida_pro_mcp_enhanced`**
PATH 上的 `python` 没装包，或者 IDA 用的解释器和 PATH 上的不是同一个。用
`IDA_MCP_PYTHON` 明确指定。

**调用报 `not connected` 但 IDA 开着**
插件加载失败。看 IDA 的 Output 窗口有没有 `[MCP]` 开头的报错，通常是没跑 `ida-mcp-setup`。

## License

MIT。归属于 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 与其增强版
[ida-pro-mcp-enhancement](https://github.com/QiuChenly/ida-pro-mcp-enhancement)。
