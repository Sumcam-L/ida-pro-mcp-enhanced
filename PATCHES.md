# 本地修改记录（相对上游 ida-pro-mcp-enhancement）

上游基线：`https://github.com/QiuChenly/ida-pro-mcp-enhancement` (main, v2.0.0)

本仓库 = 上游 + 下列 5 处本地改动。这些改动原先散落在两处互不同步的副本里
（site-packages 与 IDA plugins 目录），现已合并进同一份源码。

---

## 1. `ida_pro_mcp/ida_mcp.py` — 重连时卸载 broker 包

**问题**：`broker/` 只在首次连接时 import，之后 Ctrl+Alt+M 重连不会卸载，
于是改了 `broker/*.py` 仍是旧代码在跑，排查时会误以为改动没生效。

**改动**：`unload_package("ida_mcp")` 之后补 `unload_package("broker")`。

---

## 2. `ida_pro_mcp/ida_mcp/api_core.py` — 重写 `search_text`

**问题**：原实现用 `ida_search.find_text()`，按行渲染 + 比较。实测在 16MB 的
`.text` 里搜未出现的 token 要 **235 秒**，搜 `GetProcAddress` 要 **70 秒**。
broker 侧 60 秒超时后请求被丢弃，但 IDA 主线程还在跑那个 C 扫描 → 整个 IDA 卡死。

**改动**：改为「逐块渲染 + 内存匹配」：

- `generate_disassembly()` 渲染约 3.5 µs/行；6 万函数 80 万行只要 ~4 秒（find_text 的 1/25~1/60）
- 匹配在整块文本上做一次 C 层 `find`/正则扫描，再二分定位到行
- 主循环带硬性时间预算（默认 15s / 上限 40s），到点停下并返回 partial 游标，
  绝不把 IDA 主线程霸占到超时之后

---

## 3. `ida_pro_mcp/broker/cache_handlers.py` — 补齐缓存层 filter/分页语义

**问题**：上游 `list_funcs / list_globals / entity_query / imports_query` 只收一个
`queries` 参数（`list[ListQuery] | ListQuery | str`），缓存层早期版本却去读
`name_pattern / pattern / limit / offset`，结果 **filter 与分页被整段丢弃**：
传 filter 返回全表前 200 条，传 offset/count 毫无反应。

**改动**：新增上游工具参数 → 缓存查询参数的翻译层（约 +412 行）：

- `_pattern_to_sql_regex()` 把上游 `utils.pattern_filter` 的三种语法翻译成 SQLite 正则：
  - `sub` → 子串、大小写不敏感（`re.escape` 保证元字符不被误解释）
  - `*sub*` / `a?b` → glob（fnmatch、大小写不敏感）
  - `/re/flags` → 正则（默认大小写敏感，带 `i` 才不敏感）
- `_LIST_QUERY_RE` 解析 `offset:count` 简写
- 新增 `imports_query` 到缓存工具集合

目标是与原生工具**结果一致**：缓存层只做加速，不该改变语义。

---

## 4. `ida_pro_mcp/ida_mcp/sync.py` — panic-patch 4 / 5

这是**最关键的一处**：前两版超时实现都有致命缺陷。

### panic-patch 4：去掉 `idc.batch()`

`idc.batch(0)` 会跑 IDA 事件循环。从 `execute_sync` **内部**调用它会重入主循环，
进而重入执行我们自己排队的 `execute_sync` 回调：工具函数体被挂起、wrapper 的
`finally` 永不执行、主线程再也回不到事件循环。batch 是 per-thread 状态，wrapper
在这里本来也没增加任何语义，直接不碰它。

### panic-patch 5：超时由等待线程担保，不再中断主线程

两版被删掉的错误设计：

1. **`sys.setprofile` 到点抛异常** —— 钩子在每次 Python 调用/返回时触发，
   *包括解释器正在构建 traceback 的时候*，于是 `PyTraceBack_Print_Indented`
   → hook → raise → 无限递归。全员 100% CPU，每个工具都在 60.00s 准时暴死。
2. **watchdog 线程 `PyThreadState_SetAsyncExc()`** —— 异常落在
   `idaapi.execute_sync()` 内的任意字节码处，直接穿透 IDA 的 C++ 栈帧。
   IDA 永不释放 MFF 所有权，数据库保持锁定，**之后所有 `@idasync` 永久阻塞**。
   一次慢反编译毒死整个会话。

**现行做法**：工具函数体完全不加包装，超时由**等待线程**执行
（`res_container.get(timeout=...)`）。超时后等待方 `abandoned.set()` 并抛
`_WatchdogTimeout`，**主线程继续把活干完**。回调若还没开始就检查 `abandoned`
直接返回，不去碰可能已被改到一半的数据库。

---

## 5. `ida_pro_mcp/ida_mcp/api_survey.py` — panic-patch 2

**问题**：`survey_binary` 是"整库扫描"。十万级函数的库上会在 IDA 主线程跑
几十分钟，且中途无法取消（超时/取消都依赖 Python 字节码边界，卡在 C 层时形同虚设）。

**改动**：

- 超过门槛（默认 50000 函数，`IDA_MCP_SURVEY_MAX_FUNCS` 可覆盖）直接拒答，
  返回 `_note` 引导调用方改用更窄的工具（`lookup_funcs` / `decompile` / `disasm` /
  `xrefs_to` / `get_bytes`）
- 计数循环只遍历前 `_MAX_FUNC_ITER` 个，不再全量遍历

---

## 打包相关的额外改动（本次整理新增）

| 文件 | 改动 | 原因 |
| --- | --- | --- |
| `ida_pro_mcp/launcher.py` | 从 opencode scripts 目录并入包内，去硬编码 | 原来散落在 `%USERPROFILE%\.config\opencode\scripts\`，pip 装包不会带上 |
| `ida_pro_mcp/setup_cli.py` | 新增 | 一键装插件 + 打印配置 |
| `ida_pro_mcp/server.py` | `serverInfo.version` 改为读包元数据 | 原写死 `1.0.0`，装了新版本仍报旧版本 |
| `ida_pro_mcp/installer.py` | 补上 `broker/` 的安装/卸载 | 上游死代码缺 broker，误用会导致缓存类工具 ImportError |
| `pyproject.toml` | 加 console scripts、显式 packages.find | 让 wheel 可作为独立发行版安装 |
---

## 6. launcher.py — broker 生命周期修复（v2.0.2）

**症状**：IDA 明明开着，用着用着突然连不上，过一会儿又自己好了。

**根因**：unregister_client() 里只判断 state[clients] 为空就杀掉 broker，
而 state[clients] **只记录 MCP 客户端（launcher）进程，完全不记录 IDA 实例**。

于是出现这条连锁反应：

    DSH 重载插件 / 工具调用超时重连 / DSH 重启
      -> launcher 进程退出
      -> clients 变空
      -> broker 被 SIGTERM
      -> 所有 IDA 的 SSE 长连接瞬间断开
      -> IDA 插件按 3s~30s 退避重连，这期间工具调用全部失败

日志实测：broker 启动 **222 次**、IDA 连接 484 次、断开 334 次 —— 不是偶发，是高频震荡。

**修复**：

- 新增 broker_instance_count()：向 broker /status 查询当前 IDA 实例数
  - unregister_client() 改为：**只要 broker 上还有 IDA 实例就不许关**，改为打上 orphaned_since 标记
  - 新增 reap_orphaned_broker()：每次 launcher 启动时清理「无客户端且无 IDA 实例且空闲超过 15 分钟」的孤儿 broker，避免端口被永久占用
  - register_client() 认领 broker 时清除孤儿标记

**效果**：MCP 客户端断开不再影响已连接的 IDA 实例，DSH 重连时直接复用现有 broker，不再有「断开→重连→重新注册」的空窗期。

**验证**：真实环境直接走 unregister_client，broker 进程存活、2 个 IDA 实例保持连接、orphaned_since 正确设置；恢复注册后标记清除。另有 13 项生命周期单测覆盖。

---

## 7. server.py — 剔除旧架构遗留的实例发现工具（v2.0.3）

**症状**：调用 list_instances 永远返回空数组，明明 IDA 开着好几个。

**根因**：list_instances / select_instance 是 mrexodia 原始「每个 IDA 插件各开一个 HTTP 端口」时代的产物。list_instances 内部调用 discover_instances() 去扫本机端口，select_instance 据此把后续调用代理到另一个实例。

当前是 broker 纯路由架构：IDA 插件不再监听任何端口，只作为 SSE 客户端挂在 broker 上。discover_instances() 扫不到东西，所以这两个工具永远返回空——但对外语义却是「列出所有 IDA 实例」，极易误导调用方。

**修复**：解析完 api 文件后，从 _IDA_TOOLS 中过滤掉 list_instances / select_instance。实例列表的正确来源是 broker 侧的 instance_list / instance_info。

**效果**：工具总数 66 -> 64，工具目录里不再有这两个陷阱。

**验证**：从源码加载确认两个工具已消失、instance_list 仍能返回 2 个实例；重启 broker 后实测 tools/list 为 64 个。

---

## 8. 批量接口的拼写校验（v2.0.4）

**症状**：`rename` 一直返回 `total: 0`，看不出哪里错。

**根因**：`rename` 的 `batch` 是逐个 `batch.get("func")` 取字段的，拼错键（写成 `functions` / `locals` 复数）不会报错，只会让 `summary.total` 变成 0。调用方看到 0 会以为是嵌套格式不对，然后反复试各种写法。

实测对照（GameCore，dry_run）：

| 传入 | 结果 |
| --- | --- |
| `{"batch": {"functions": [...]}}` | total: 0（静默） |
| `{"batch": {"locals": [...]}}` | total: 0（静默） |
| `{"batch": {}}` | total: 0（静默） |
| `{"batch": {"func": [...]}}` | total: 1 ✅ |

**修复**：`utils.reject_unknown_keys()` 在参数解析前校验键名，不合法就直接抛 `IDAError` 并回显合法键列表。接入 `rename` 与 `type_apply_batch` 两个批量接口。

合法键：

- `rename`：func / data / global / globals / local / stack / stop_on_error / dry_run / allow_overwrite（注意 local、func 都是单数）
- `type_apply_batch`：edits / stop_on_error

**验证**：8 项逻辑单测（正确键放行、拼错键报错、非 dict 报错、空 batch 放行）。
