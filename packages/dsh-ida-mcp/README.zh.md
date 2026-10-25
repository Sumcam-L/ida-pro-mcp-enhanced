# dsh-ida-mcp

把 [IDA Pro MCP](https://github.com/Sumcam-L/ida-pro-mcp-enhanced) 的 broker 桥接进
[DeepSeek Harness](https://deepseek-harness.github.io/deepseek-harness/)，把约 66 个
IDA 工具注册成原生的 `mcp__ida__*` 工具：反编译、交叉引用、改名、反汇编等。

## 为什么需要 broker

多数 IDA MCP 方案是「一个客户端一个 broker」，多开几个 AI 工具就会抢端口、抢同一个 IDB。
本插件复用 ida-pro-mcp 的 broker 架构：

```
DSH (mcp__ida__* 工具)
   |  @deepseek-ai/dsh-mcp-client (stdio)
   v
ida_pro_mcp_enhanced.launcher --> Broker (127.0.0.1:13337)
                                   |  SSE 路由
                                   v
                  IDA GUI 实例（ida_mcp.py 插件，每个带一个 IDB）
```

broker 按需拉起，被所有 MCP 客户端（DSH、Cursor、Claude Desktop…）共享。
**只要还有 IDA 实例挂着，broker 就会一直运行**，即使所有 MCP 客户端都断开——
所以客户端重连不会把正在用的 IDA 实例踢下线。

## 安装

### 1. Python 侧（broker + stdio server + IDA 插件）

这个包**不在 PyPI 上**：`ida-pro-mcp` 那个名字属于上游 mrexodia（1.4.0，没有 broker）。
从 GitHub Release 安装：

```bash
pip install https://github.com/Sumcam-L/ida-pro-mcp-enhanced/releases/latest/download/ida_pro_mcp_enhanced-2.0.2-py3-none-any.whl
ida-mcp-setup
```

### 2. 本插件

```bash
dsh plugin install dsh-ida-mcp
```

然后在 IDA 里打开一个数据库，**完全重启** DSH。

## 前置条件

| 条件 | 说明 |
| --- | --- |
| Python 3.11+ | 需要在 PATH 上，**且要和 IDA 用的是同一个解释器** |
| `ida-pro-mcp-enhanced` | 用上面的 wheel 安装 |
| IDA 插件 | `ida-mcp-setup` 安装，之后重启 IDA |
| IDA Pro | 8.3+（IDA Free 没有插件 API） |

## 配置

插件用 PATH 上的 `python` 执行 `python -m ida_pro_mcp_enhanced.launcher`。
如果你的 IDA 用的是特定解释器（32 位 IDA 常见），显式指定：

```bash
set IDA_MCP_PYTHON=D:\Program Files\Python\Python311-32\python.exe
```

其他可调项见
[ida-pro-mcp-enhanced 的 README](https://github.com/Sumcam-L/ida-pro-mcp-enhanced#环境变量)。

## 用法

在 DSH 会话里直接说：

- 「看看连着哪些 IDA 实例」 -> `mcp__ida__instance_list`
- 「反编译 main」 -> `mcp__ida__decompile`
- 「谁调用了这个函数」 -> `mcp__ida__xrefs_to`

## 常见问题

**工具列表是空的**
IDA 没开，或插件没连上 broker。打开 IDA、加载数据库，然后按 `Ctrl+Alt+M` 手动重连。

**报 `No module named ida_pro_mcp_enhanced`**
PATH 上的 `python` 没装这个包，或者 IDA 用的解释器和 PATH 上的不是同一个。
设置 `IDA_MCP_PYTHON` 指定。

**IDA 开着但调用报 not connected**
插件加载失败。看 IDA 的 Output 窗口有没有 `[MCP]` 开头的报错，通常是没跑 `ida-mcp-setup`。

## License

MIT。上游：[ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 及其增强版
[ida-pro-mcp-enhancement](https://github.com/QiuChenly/ida-pro-mcp-enhancement)。
