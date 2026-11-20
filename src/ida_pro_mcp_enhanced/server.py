"""IDA Pro MCP Server

  --broker: 单端口 HTTP 服务器 (0.0.0.0)，同时提供 MCP 端点和 IDA 注册端点
            远程 Cursor --HTTP--> Broker <--HTTP+SSE-- IDA Plugin
  default:  本地 stdio 模式，通过 HTTP 转发到 Broker
"""

import argparse
import json
import os
import sys
import threading
from typing import BinaryIO, Optional


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

# 包名与模块名故意不同：
#   PyPI 包名  ida-pro-mcp-enhanced   （ida-pro-mcp 属于上游 mrexodia，发不上去）
#   模块名     ida_pro_mcp_enhanced   （与官方包区分，避免 pip 互相覆盖文件）
_PACKAGE_NAME = "ida-pro-mcp-enhanced"


def _package_version() -> str:
    """实际安装版本，而不是写死的常量。

    MCP 客户端会把 initialize 里的 serverInfo.version 显示出来；写死会导致
    "明明装了 2.0.1，却报 1.0.0"。
    """
    try:
        from importlib.metadata import version

        return version(_PACKAGE_NAME)
    except Exception:  # PackageNotFoundError, or running from a source tree
        return "0.0.0+source"


if __name__ == "__main__" or __package__ is None:
    sys.path.insert(0, os.path.dirname(SCRIPT_DIR))
    from ida_pro_mcp_enhanced.broker.manager import (
        get_broker_client,
        register_broker_tools,
        setup_dispatch_proxy,
    )
    from ida_pro_mcp_enhanced.install import (
        install_ida_plugin,
        install_mcp_servers,
        print_mcp_config,
    )
    from ida_pro_mcp_enhanced.tool_registry import (
        ToolDef,
        parse_all_api_files,
        tool_to_mcp_schema,
    )
else:
    from .broker.manager import (
        get_broker_client,
        register_broker_tools,
        setup_dispatch_proxy,
    )
    from .install import install_ida_plugin, install_mcp_servers, print_mcp_config
    from .tool_registry import ToolDef, parse_all_api_files, tool_to_mcp_schema


sys.path.insert(0, os.path.join(SCRIPT_DIR, "ida_mcp"))
from zeromcp import McpServer

sys.path.pop(0)


_stdio_stdout: Optional[BinaryIO] = None
_stdio_lock = threading.Lock()


def send_notification(method: str, params: Optional[dict] = None):
    """Send an MCP notification to the stdio client."""
    if _stdio_stdout is None:
        return

    notification = {"jsonrpc": "2.0", "method": method}
    if params:
        notification["params"] = params

    try:
        with _stdio_lock:
            _stdio_stdout.write(json.dumps(notification).encode("utf-8") + b"\n")
            _stdio_stdout.flush()
    except Exception as e:
        print(f"[MCP] 发送通知失败: {e}", file=sys.stderr)


mcp = McpServer("ida-pro-mcp", version=_package_version())
dispatch_original = mcp.registry.dispatch

# Register broker-local instance management tools.
register_broker_tools(mcp)


_IDA_API_DIR = os.path.join(SCRIPT_DIR, "ida_mcp")
_IDA_TOOLS, _IDA_RESOURCES = parse_all_api_files(_IDA_API_DIR)

# ---------------------------------------------------------------------------
# 剔除旧架构遗留的实例发现工具
#
# list_instances / select_instance 是 mrexodia 原始「每个 IDA 插件各开一个
# HTTP 端口」时代的产物：list_instances 内部调用 discover_instances() 去扫
# 本机端口，select_instance 据此把后续调用代理到另一个实例。
#
# 现在是 broker 纯路由架构：IDA 插件不再监听任何端口，只作为 SSE 客户端挂在
# broker 上。discover_instances() 扫不到东西，所以这两个工具**永远返回空数组**，
# 而它们对外表现的语义却是「列出所有 IDA 实例」，极易误导调用方。
#
# 实例列表的真实来源是 broker 侧的 instance_list / instance_info
# （见 register_broker_tools），保留这两个只会让工具目录多两个陷阱。
# ---------------------------------------------------------------------------
_LEGACY_INSTANCE_TOOLS = {"list_instances", "select_instance"}
_IDA_TOOLS = [t for t in _IDA_TOOLS if t.name not in _LEGACY_INSTANCE_TOOLS]

_IDA_TOOL_SCHEMAS = {t.name: tool_to_mcp_schema(t) for t in _IDA_TOOLS}

UNSAFE_TOOLS = {t.name for t in _IDA_TOOLS if t.is_unsafe}
IDA_TOOLS: set[str] = set()
_UNSAFE_ENABLED = False


def _create_ida_tool_wrapper(tool_def: ToolDef):
    """Create a lightweight local wrapper so tools/list exposes IDA tool schemas."""
    from typing import Annotated, Any as AnyType

    def wrapper(**kwargs):
        pass

    wrapper.__name__ = tool_def.name
    wrapper.__doc__ = tool_def.description

    annotations = {}
    for param in tool_def.params:
        annotations[param.name] = Annotated[AnyType, param.description]
    annotations["return"] = AnyType
    wrapper.__annotations__ = annotations

    return wrapper


UNSAFE_GROUP_WILDCARD = "all"


def _unsafe_group_enabled(tool_def, enabled_groups: set[str]) -> bool:
    """这个 unsafe 工具是否被点名的类别放行。

    非 unsafe 工具永远放行；unsafe 工具只有在它的类别（或 "all"）被显式
    启用时才放行。类别缺失（旧式裸 @unsafe 且 AST 没解析出类别）按 
    "write" 处理，保持与历史行为一致。
    """
    if not tool_def.is_unsafe:
        return True
    if UNSAFE_GROUP_WILDCARD in enabled_groups:
        return True
    group = tool_def.unsafe_group or "write"
    return group in enabled_groups


def _register_ida_tools(enable_unsafe: bool = False, unsafe_groups: set[str] | None = None):
    """Register all IDA-side tools as broker-routed MCP tool placeholders.

    ``unsafe_groups`` 允许只开放某一类危险工具（例如只要 python 执行，
    不必把 22 个调试器工具一起放出来）。传 ``enable_unsafe=True`` 等价于
    开启全部类别。
    """
    global IDA_TOOLS, _UNSAFE_ENABLED
    _UNSAFE_ENABLED = enable_unsafe

    groups = set(unsafe_groups or ())
    # 只有"裸 --unsafe"（开了但没有点名类别）才是全开；
    # `--unsafe python` 必须只开 python，否则分组就形同虚设。
    if enable_unsafe and not groups:
        groups.add(UNSAFE_GROUP_WILDCARD)

    registered_count = 0
    skipped_unsafe = 0
    skipped_by_group: dict[str, int] = {}

    for tool_def in _IDA_TOOLS:
        if not _unsafe_group_enabled(tool_def, groups):
            skipped_unsafe += 1
            group = tool_def.unsafe_group or "write"
            skipped_by_group[group] = skipped_by_group.get(group, 0) + 1
            continue

        IDA_TOOLS.add(tool_def.name)
        mcp.tools.methods[tool_def.name] = _create_ida_tool_wrapper(tool_def)
        registered_count += 1

    if skipped_unsafe > 0:
        detail = ", ".join(f"{k}:{v}" for k, v in sorted(skipped_by_group.items()))
        print(
            f"[MCP] 注册了 {registered_count} 个 IDA 工具 "
            f"(跳过 {skipped_unsafe} 个 unsafe 工具；{detail}；"
            f"用 --unsafe <类别> 开放)",
            file=sys.stderr,
        )
    else:
        print(f"[MCP] 注册了 {registered_count} 个 IDA 工具", file=sys.stderr)


def _register_ida_resources():
    """Register IDA resources locally so tools/list/resources/list stay complete."""
    for res_def in _IDA_RESOURCES:

        def make_wrapper(uri):
            def wrapper(**kwargs):
                pass

            wrapper.__name__ = res_def.name
            wrapper.__doc__ = res_def.description
            setattr(wrapper, "__resource_uri__", uri)
            return wrapper

        mcp.resources.methods[res_def.name] = make_wrapper(res_def.uri)

    print(f"[MCP] 注册了 {len(_IDA_RESOURCES)} 个 IDA 资源", file=sys.stderr)


setup_dispatch_proxy(mcp, dispatch_original, IDA_TOOLS, _IDA_TOOL_SCHEMAS)


def main():
    global _stdio_stdout

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--install", action="store_true", help="安装 IDA 插件和 MCP 客户端配置")
    parser.add_argument("--uninstall", action="store_true", help="卸载 IDA 插件和 MCP 客户端配置")
    parser.add_argument("--allow-ida-free", action="store_true", help="允许安装到 IDA Free")
    parser.add_argument("--config", action="store_true", help="打印 MCP 配置")
    parser.add_argument(
        "--unsafe",
        nargs="*",
        default=None,
        metavar="GROUP",
        help=(
            "启用不安全工具。不带值 = 全部开放；也可只点名类别："
            "debugger（dbg_*）、python（py_eval/py_exec_file）、"
            "write（idb_save/diff_before_after）。"
            "例：--unsafe python"
        ),
    )
    parser.add_argument("--port", type=int, default=13337, help="HTTP 服务器端口（Broker 模式）")
    parser.add_argument(
        "--broker",
        action="store_true",
        help="启动 Broker HTTP 服务器（0.0.0.0），同时提供 MCP 和 IDA 注册端点；省略则使用 stdio",
    )
    parser.add_argument(
        "--broker-url",
        type=str,
        default="http://127.0.0.1:13337",
        help="MCP 模式连接 Broker 的 URL",
    )
    args = parser.parse_args()

    raw_unsafe = getattr(args, "unsafe", None)
    # --unsafe        -> []      （裸用，全开）
    # --unsafe python -> ["python"]
    unsafe_groups = set(raw_unsafe or ())
    _register_ida_tools(
        enable_unsafe=raw_unsafe is not None,
        unsafe_groups=unsafe_groups,
    )
    _register_ida_resources()

    if args.install:
        install_ida_plugin(allow_ida_free=args.allow_ida_free)
        install_mcp_servers()
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True)
        install_mcp_servers(uninstall=True)
        return

    if args.config:
        print_mcp_config()
        return

    if args.broker:
        from http.server import ThreadingHTTPServer
        from .broker.combined import CombinedRequestHandler

        get_broker_client(f"http://127.0.0.1:{args.port}")
        mcp.cors_allowed_origins = ["*"]

        server = ThreadingHTTPServer(("0.0.0.0", args.port), CombinedRequestHandler, bind_and_activate=False)
        server.allow_reuse_address = True
        setattr(server, "mcp_server", mcp)
        server.server_bind()
        server.server_activate()
        mcp._http_server = server
        mcp._running = True

        print(f"[MCP] Broker 已启动: http://0.0.0.0:{args.port}/mcp", file=sys.stderr)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
            mcp._running = False
        return

    get_broker_client(args.broker_url)

    try:
        _stdio_stdout = sys.stdout.buffer
        mcp.stdio()
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        print("[MCP] 正在退出...", file=sys.stderr)
        _stdio_stdout = None
        os._exit(0)


if __name__ == "__main__":
    main()
