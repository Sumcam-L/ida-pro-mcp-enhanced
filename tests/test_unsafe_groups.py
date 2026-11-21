"""Unsafe tool categorization: groups, gating, and CLI/env plumbing.

Every @unsafe tool used to be all-or-nothing: the broker either exposed
all 26 (22 debugger tools + py_eval/py_exec_file + idb_save +
diff_before_after) or none at all. Wanting only "run a Python script"
therefore meant also handing the model debugger control, which is a much
bigger blast radius than the thing actually asked for.

@unsafe now carries a category: debugger / python / write. The CLI accepts
--unsafe <group>..., the launcher translates IDA_MCP_UNSAFE for MCP
clients that can only pass environment variables.
"""

import pathlib
import sys
import unittest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

import http.server  # noqa: E402,F401  (must precede the path insert effects)

from ida_pro_mcp_enhanced.tool_registry import parse_all_api_files  # noqa: E402
from ida_pro_mcp_enhanced import launcher  # noqa: E402
from ida_pro_mcp_enhanced.server import (  # noqa: E402
    UNSAFE_GROUP_WILDCARD,
    _IDA_TOOLS,
    _unsafe_group_enabled,
)


_API_DIR = _ROOT / "src" / "ida_pro_mcp_enhanced" / "ida_mcp"


def _by_name(name):
    for tool in _IDA_TOOLS:
        if tool.name == name:
            return tool
    raise AssertionError(f"{name} not found in _IDA_TOOLS")


class UnsafeGroupTaggingTests(unittest.TestCase):
    """Every unsafe tool must carry a category the CLI can name."""

    def test_registry_parses_groups(self):
        tools, _ = parse_all_api_files(str(_API_DIR))
        unsafe = {t.name: t.unsafe_group for t in tools if t.is_unsafe}
        self.assertEqual(unsafe.get("py_eval"), "python")
        self.assertEqual(unsafe.get("py_exec_file"), "python")
        self.assertEqual(unsafe.get("idb_save"), "write")
        self.assertEqual(unsafe.get("diff_before_after"), "write")
        self.assertEqual(unsafe.get("dbg_start"), "debugger")

    def test_no_unsafe_tool_is_untagged(self):
        tools, _ = parse_all_api_files(str(_API_DIR))
        untagged = [t.name for t in tools if t.is_unsafe and not t.unsafe_group]
        self.assertEqual(untagged, [], f"unsafe tools without a group: {untagged}")

    def test_safe_tools_have_no_group(self):
        tools, _ = parse_all_api_files(str(_API_DIR))
        grouped = [t.name for t in tools if not t.is_unsafe and t.unsafe_group]
        self.assertEqual(grouped, [])

    def test_all_dbg_tools_are_debugger_group(self):
        tools, _ = parse_all_api_files(str(_API_DIR))
        wrong = [
            t.name
            for t in tools
            if t.name.startswith("dbg_") and t.unsafe_group != "debugger"
        ]
        self.assertEqual(wrong, [])


class UnsafeGroupGatingTests(unittest.TestCase):
    """_unsafe_group_enabled decides what the broker exposes."""

    def test_safe_tool_always_enabled(self):
        self.assertTrue(_unsafe_group_enabled(_by_name("decompile"), set()))

    def test_python_group_only_opens_python_tools(self):
        g = {"python"}
        self.assertTrue(_unsafe_group_enabled(_by_name("py_eval"), g))
        self.assertTrue(_unsafe_group_enabled(_by_name("py_exec_file"), g))
        self.assertFalse(_unsafe_group_enabled(_by_name("idb_save"), g))
        self.assertFalse(_unsafe_group_enabled(_by_name("dbg_start"), g))

    def test_write_group_only_opens_write_tools(self):
        g = {"write"}
        self.assertTrue(_unsafe_group_enabled(_by_name("idb_save"), g))
        self.assertFalse(_unsafe_group_enabled(_by_name("py_eval"), g))

    def test_debugger_group_only_opens_debugger_tools(self):
        g = {"debugger"}
        self.assertTrue(_unsafe_group_enabled(_by_name("dbg_start"), g))
        self.assertFalse(_unsafe_group_enabled(_by_name("py_eval"), g))

    def test_empty_groups_disable_all_unsafe(self):
        for name in ("py_eval", "idb_save", "dbg_start"):
            self.assertFalse(_unsafe_group_enabled(_by_name(name), set()))
        self.assertTrue(_unsafe_group_enabled(_by_name("decompile"), set()))

    def test_wildcard_enables_everything(self):
        g = {UNSAFE_GROUP_WILDCARD}
        for name in ("py_eval", "idb_save", "dbg_start", "decompile"):
            self.assertTrue(_unsafe_group_enabled(_by_name(name), g))

    def test_multiple_groups_union(self):
        g = {"python", "write"}
        self.assertTrue(_unsafe_group_enabled(_by_name("py_eval"), g))
        self.assertTrue(_unsafe_group_enabled(_by_name("idb_save"), g))
        self.assertFalse(_unsafe_group_enabled(_by_name("dbg_start"), g))


class UnsafeEnvTranslationTests(unittest.TestCase):
    """MCP clients can only pass env vars, so IDA_MCP_UNSAFE must translate."""

    def setUp(self):
        self._saved = __import__("os").environ.get("IDA_MCP_UNSAFE")
        self._cfg = launcher.LauncherConfig()

    def tearDown(self):
        import os
        if self._saved is None:
            os.environ.pop("IDA_MCP_UNSAFE", None)
        else:
            os.environ["IDA_MCP_UNSAFE"] = self._saved

    def _args(self, value):
        import os
        if value is None:
            os.environ.pop("IDA_MCP_UNSAFE", None)
        else:
            os.environ["IDA_MCP_UNSAFE"] = value
        return self._cfg.unsafe_args

    def test_unset_opens_nothing(self):
        self.assertEqual(self._args(None), [])

    def test_empty_string_opens_nothing(self):
        self.assertEqual(self._args(""), [])

    def test_all_opens_everything(self):
        self.assertEqual(self._args("all"), ["--unsafe"])

    def test_all_is_case_insensitive(self):
        self.assertEqual(self._args("ALL"), ["--unsafe"])

    def test_single_group(self):
        self.assertEqual(self._args("python"), ["--unsafe", "python"])

    def test_multiple_groups(self):
        self.assertEqual(self._args("python,write"), ["--unsafe", "python", "write"])

    def test_whitespace_is_tolerated(self):
        self.assertEqual(self._args(" python , write "), ["--unsafe", "python", "write"])

    def test_broker_command_gets_the_flag(self):
        import os
        os.environ["IDA_MCP_UNSAFE"] = "python"
        cmd = self._cfg.broker_command
        self.assertIn("--unsafe", cmd)
        self.assertIn("python", cmd)

    def test_broker_command_clean_by_default(self):
        import os
        os.environ.pop("IDA_MCP_UNSAFE", None)
        self.assertNotIn("--unsafe", self._cfg.broker_command)


class StdioCommandForwardingTests(unittest.TestCase):
    """The stdio server keeps its own tool table, so it needs the flag too.

    The broker can happily expose py_eval while a client still sees 63 tools,
    because tools/list is answered by the stdio server's own registry. That
    mismatch is invisible unless something compares the two.
    """

    def setUp(self):
        import os
        self._saved = os.environ.get("IDA_MCP_UNSAFE")
        self._cfg = launcher.LauncherConfig()

    def tearDown(self):
        import os
        if self._saved is None:
            os.environ.pop("IDA_MCP_UNSAFE", None)
        else:
            os.environ["IDA_MCP_UNSAFE"] = self._saved

    def test_stdio_command_forwards_groups(self):
        import os
        os.environ["IDA_MCP_UNSAFE"] = "python"
        cmd = self._cfg.stdio_command
        self.assertIn("--unsafe", cmd)
        self.assertIn("python", cmd)

    def test_stdio_command_clean_by_default(self):
        import os
        os.environ.pop("IDA_MCP_UNSAFE", None)
        self.assertNotIn("--unsafe", self._cfg.stdio_command)

    def test_stdio_and_broker_agree_on_groups(self):
        import os
        for raw in ("", "all", "python", "python,write"):
            os.environ["IDA_MCP_UNSAFE"] = raw
            self.assertEqual(
                self._cfg.unsafe_args,
                [a for a in self._cfg.stdio_command if a == "--unsafe" or a in ("all", "python", "write", "debugger")],
                f"mismatch for IDA_MCP_UNSAFE={raw!r}",
            )


class NoSavePolicyTests(unittest.TestCase):
    """The no-save rule must be visible where the model actually reads it.

A tool-level gate cannot enforce this: py_eval is a full interpreter with
ida_loader, ctypes and subprocess in reach, so "idb_save is not listed"
protects nothing. The only durable guard is telling the model, in the two
places it reads (the tool description and the repo rules), that saving is
forbidden. These tests keep that text from being edited away.
    """

    @staticmethod
    def _descriptions():
        tools, _ = parse_all_api_files(str(_API_DIR))
        return {t.name: t.description for t in tools}

    def test_py_eval_forbids_saving(self):
        desc = self._descriptions()["py_eval"]
        self.assertIn("NEVER save", desc)
        self.assertIn("save_database", desc)

    def test_py_exec_file_forbids_saving(self):
        desc = self._descriptions()["py_exec_file"]
        self.assertIn("NEVER save", desc)

    def test_idb_save_documents_the_hazard(self):
        desc = self._descriptions()["idb_save"]
        self.assertIn("Unsafe", desc)

    def test_repo_rules_carry_the_ban(self):
        rules = (_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
        self.assertIn("数据库写盘：绝对禁止", rules)
        self.assertIn("save_database", rules)

    def test_global_rules_carry_the_ban(self):
        import os
        import pathlib
        p = pathlib.Path(os.path.expanduser("~")) / ".dsh" / "AGENTS.md"
        if not p.is_file():
            self.skipTest("no global AGENTS.md on this machine")
        rules = p.read_text(encoding="utf-8")
        self.assertIn("绝对不要保存数据库", rules)



if __name__ == "__main__":
    unittest.main()
