"""一键安装：装 IDA 插件 + 打印各 MCP 客户端配置。

用法:
    ida-mcp-setup                # 安装插件并打印 config
    ida-mcp-setup --check        # 只检查当前安装状态
    ida-mcp-setup --uninstall    # 卸载 IDA 插件

设计取舍：客户端配置只"打印"不"自动写"。自动改别人的配置文件风险太高
（Claude Desktop / Cursor / VS Code 的格式各不相同，写坏了很难排查），
所以这里给出可直接粘贴的片段。
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .install import generate_mcp_config, install_ida_plugin


def _ida_user_dir() -> str:
    if sys.platform == "win32":
        return os.path.join(os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro")
    return os.path.join(os.path.expanduser("~"), ".idapro")


def installed_plugin_paths() -> dict[str, str]:
    folder = os.path.join(_ida_user_dir(), "plugins")
    return {
        "loader": os.path.join(folder, "ida_mcp.py"),
        "package": os.path.join(folder, "ida_mcp"),
        "broker": os.path.join(folder, "broker"),
    }


def plugin_status() -> dict[str, bool]:
    return {name: os.path.lexists(path) for name, path in installed_plugin_paths().items()}


def launcher_config() -> dict:
    """推荐给 MCP 客户端的配置：走 launcher，按需拉起共享 broker。

    注意不能用 generate_mcp_config()：那条路径直接起 server.py，每个客户端
    各拉一个 broker，多客户端之间无法共享 IDA 实例。
    """
    return {
        "command": sys.executable,
        "args": ["-m", "ida_pro_mcp.launcher"],
    }


def _print_status() -> bool:
    status = plugin_status()
    paths = installed_plugin_paths()
    ok = True
    print("IDA plugin:")
    for name, present in status.items():
        mark = "OK  " if present else "MISS"
        if not present:
            ok = False
        print(f"  [{mark}] {name:8} {paths[name]}")
    print()
    print(f"Python : {sys.executable}")
    print(f"Package: {os.path.dirname(os.path.abspath(__file__))}")
    return ok


def _print_configs() -> None:
    entry = launcher_config()
    print("Stdio launcher config (recommended for most clients):")
    print(
        json.dumps(
            {"mcpServers": {"ida-pro-mcp": entry}},
            indent=2,
            ensure_ascii=False,
        )
    )
    print()
    print("Direct server config (one broker per client; no sharing):")
    print(
        json.dumps(
            {"mcpServers": {"ida-pro-mcp": generate_mcp_config()}},
            indent=2,
            ensure_ascii=False,
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ida-mcp-setup",
        description="Install the IDA Pro MCP plugin and print MCP client config.",
    )
    parser.add_argument(
        "--uninstall", action="store_true", help="remove the IDA plugin"
    )
    parser.add_argument(
        "--check", action="store_true", help="only report install status"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="suppress progress output"
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="allow installing into IDA Free (plugins are unsupported there)",
    )
    args = parser.parse_args(argv)

    if args.check:
        return 0 if _print_status() else 1

    install_ida_plugin(
        uninstall=args.uninstall,
        quiet=args.quiet,
        allow_ida_free=args.allow_ida_free,
    )

    if args.uninstall:
        print()
        print("IDA plugin removed. Restart IDA.")
        return 0

    print()
    _print_status()
    print()
    _print_configs()
    print()
    print("Next: restart IDA, open a database, then connect your MCP client.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
