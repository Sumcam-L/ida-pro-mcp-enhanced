"""Truncation middleware invariants. Regression guards for #361 and e802b32.

Truncated structuredContent must still validate against the tool's
outputSchema, and truncation metadata must live under `_meta`, not
merged into structuredContent.
"""

import json
import sys
import pathlib
import unittest
from typing import TypedDict

from jsonschema import Draft202012Validator

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _mcp_spec_support import (
    CALL_TOOL_RESULT_SCHEMA,
    McpHttpTestServer,
    McpServer,
    assert_schema,
    call_rpc,
    load_ida_rpc_module,
)


class _Item(TypedDict):
    name: str
    value: int


class _ListResult(TypedDict):
    items: list[_Item]
    count: int


def _fresh_truncated_server() -> McpServer:
    """McpServer with the production truncation middleware (rpc.py) applied."""
    rpc = load_ida_rpc_module()
    srv = rpc.McpServer("truncation-test")
    original = srv.registry.methods["tools/call"]

    def patched(name, arguments=None, _meta=None):
        # Exercise the shipped function, not a copy of it: a hand-written
        # duplicate here would keep passing after rpc.limit_response_size
        # regressed.
        return rpc.limit_response_size(original(name, arguments, _meta))

    srv.registry.methods["tools/call"] = patched
    return srv


class TruncationInvariantTests(unittest.TestCase):
    def _call_large_list_tool(self, srv):
        @srv.tool
        def big_list() -> _ListResult:
            """Returns a huge list; forces truncation."""
            return {
                "items": [{"name": f"n{i}", "value": i} for i in range(5000)],
                "count": 5000,
            }

        tools = call_rpc(srv, "tools/list")["tools"]
        tool = next(t for t in tools if t["name"] == "big_list")
        result = call_rpc(srv, "tools/call", name="big_list", arguments={})
        return tool, result

    def test_truncation_actually_triggers_on_large_output(self):
        srv = _fresh_truncated_server()
        _, result = self._call_large_list_tool(srv)
        self.assertIn("_meta", result)
        self.assertIn("ida_mcp", result["_meta"])

    def test_truncated_structuredContent_matches_outputSchema(self):
        srv = _fresh_truncated_server()
        tool, result = self._call_large_list_tool(srv)
        Draft202012Validator(tool["outputSchema"]).validate(result["structuredContent"])

    def test_truncated_response_envelope_is_valid_call_tool_result(self):
        srv = _fresh_truncated_server()
        _, result = self._call_large_list_tool(srv)
        assert_schema(result, CALL_TOOL_RESULT_SCHEMA)

    def test_truncation_metadata_not_inside_structuredContent(self):
        # Regression for #361: underscore-prefixed fields must not leak.
        srv = _fresh_truncated_server()
        _, result = self._call_large_list_tool(srv)
        leaked = [k for k in result["structuredContent"] if k.startswith("_")]
        self.assertFalse(leaked, f"leaked keys: {leaked}")

    def test_truncated_items_do_not_contain_sentinel_dict(self):
        # Regression for e802b32: no {"_truncated": ...} appended to lists.
        srv = _fresh_truncated_server()
        _, result = self._call_large_list_tool(srv)
        for item in result["structuredContent"].get("items", []):
            with self.subTest(item=item):
                self.assertEqual(set(item.keys()), {"name", "value"})

    def test_download_url_is_valid_looking_url(self):
        srv = _fresh_truncated_server()
        _, result = self._call_large_list_tool(srv)
        meta = result["_meta"]["ida_mcp"]
        self.assertTrue(meta["output_truncated"])
        self.assertTrue(meta["download_url"].startswith("http://"))
        self.assertIn("/output/", meta["download_url"])

    def test_content_text_blocks_are_valid(self):
        srv = _fresh_truncated_server()
        _, result = self._call_large_list_tool(srv)
        self.assertGreaterEqual(len(result["content"]), 1)
        for block in result["content"]:
            with self.subTest(block=block):
                self.assertEqual(block["type"], "text")
                self.assertIsInstance(block["text"], str)


class DownloadUrlDerivationOverHttpTests(unittest.TestCase):
    def test_download_url_uses_forwarded_public_base(self):
        srv = _fresh_truncated_server()

        @srv.tool
        def big_list() -> _ListResult:
            """Returns a huge list; forces truncation."""
            return {
                "items": [{"name": f"n{i}", "value": i} for i in range(5000)],
                "count": 5000,
            }

        with McpHttpTestServer(srv) as harness:
            status, _, response = harness.post_jsonrpc(
                "tools/call",
                {"name": "big_list", "arguments": {}},
                extra_headers={
                    "Forwarded": 'for=127.0.0.1;proto=https;host="mcp.example.com"',
                },
            )

        self.assertEqual(status, 200)
        meta = response["result"]["_meta"]["ida_mcp"]
        self.assertTrue(meta["download_url"].startswith("https://mcp.example.com/output/"))

    def test_download_url_uses_forwarded_prefix(self):
        srv = _fresh_truncated_server()

        @srv.tool
        def big_list() -> _ListResult:
            """Returns a huge list; forces truncation."""
            return {
                "items": [{"name": f"n{i}", "value": i} for i in range(5000)],
                "count": 5000,
            }

        with McpHttpTestServer(srv) as harness:
            status, _, response = harness.post_jsonrpc(
                "tools/call",
                {"name": "big_list", "arguments": {}},
                extra_headers={
                    "X-Forwarded-Proto": "https",
                    "X-Forwarded-Host": "mcp.example.com",
                    "X-Forwarded-Prefix": "/ida/proxy/",
                },
            )

        self.assertEqual(status, 200)
        meta = response["result"]["_meta"]["ida_mcp"]
        self.assertTrue(
            meta["download_url"].startswith(
                "https://mcp.example.com/ida/proxy/output/"
            )
        )


class NonTruncatedOutputsUnchangedTests(unittest.TestCase):
    def test_small_output_has_no_truncation_metadata(self):
        srv = _fresh_truncated_server()

        @srv.tool
        def small() -> _ListResult:
            """small list."""
            return {"items": [{"name": "n", "value": 1}], "count": 1}

        result = call_rpc(srv, "tools/call", name="small", arguments={})
        self.assertNotIn("ida_mcp", result.get("_meta") or {})

    def test_small_output_structuredContent_is_exact(self):
        srv = _fresh_truncated_server()

        @srv.tool
        def small() -> _ListResult:
            """small list."""
            return {"items": [{"name": "n", "value": 1}], "count": 1}

        result = call_rpc(srv, "tools/call", name="small", arguments={})
        self.assertEqual(
            result["structuredContent"],
            {"items": [{"name": "n", "value": 1}], "count": 1},
        )


class TruncationOverDeeplyNestedDataTests(unittest.TestCase):
    def test_nested_dict_output_still_schema_valid(self):
        class Deep(TypedDict):
            label: str
            value: str

        class Outer(TypedDict):
            levels: dict[str, Deep]

        srv = _fresh_truncated_server()

        @srv.tool
        def deep() -> Outer:
            """deep nested."""
            return {
                "levels": {f"k{i}": {"label": f"l{i}", "value": "v" * 200} for i in range(200)}
            }

        tools = call_rpc(srv, "tools/list")["tools"]
        tool = next(t for t in tools if t["name"] == "deep")
        result = call_rpc(srv, "tools/call", name="deep", arguments={})
        Draft202012Validator(tool["outputSchema"]).validate(result["structuredContent"])


class TruncationKeepsDataInsteadOfDroppingItTests(unittest.TestCase):
    """The preview must keep what fits, not cut every list to 10 items.

    Regression for the reported xrefs_to behaviour: the same target returned
    100 / 100 / 10 xrefs depending only on how many addresses were passed in
    one call. The old preview capped every list at a fixed 10 items.
    So an oversized reply was indistinguishable from a target that
    really has 10 xrefs.
    """

    @staticmethod
    def _xref_payload(count: int) -> list[dict]:
        return [
            {
                "addr": hex(0x140001460 + i * 0x10),
                "xrefs": [{"addr": hex(0x140F98D28 + i), "type": "data", "fn": None}],
                "more": False,
            }
            for i in range(count)
        ]

    def test_oversized_list_keeps_far_more_than_ten(self):
        rpc = load_ida_rpc_module()
        payload = self._xref_payload(900)
        self.assertGreater(len(json.dumps(payload)), rpc.OUTPUT_LIMIT_MAX_CHARS)

        preview = rpc._truncate_value(payload)
        self.assertGreater(len(preview), 10)
        self.assertLessEqual(rpc._json_size(preview), rpc.OUTPUT_LIMIT_MAX_CHARS)

    def test_preview_keeps_a_prefix_in_original_order(self):
        rpc = load_ida_rpc_module()
        payload = self._xref_payload(350)
        preview = rpc._truncate_value(payload)
        self.assertEqual(preview[0], payload[0])
        self.assertEqual(preview, payload[: len(preview)])

    def test_budget_is_stable_across_repeated_calls(self):
        rpc = load_ida_rpc_module()
        payload = self._xref_payload(400)
        sizes = {len(rpc._truncate_value(payload)) for _ in range(3)}
        self.assertEqual(len(sizes), 1, f"preview length varied: {sizes}")

    def test_dict_scalars_are_preserved(self):
        """Truncation must not hide how much was cut.

        A response carries its own totals (total, more flags); losing them
        would make a capped reply look complete.
        """
        rpc = load_ida_rpc_module()
        payload = {"target": "0x1", "data": self._xref_payload(600), "total": 600}
        preview = rpc._truncate_value(payload)
        self.assertEqual(preview["total"], 600)
        self.assertEqual(preview["target"], "0x1")
        self.assertGreater(len(preview["data"]), 10)

    def test_deep_nesting_does_not_drop_siblings(self):
        rpc = load_ida_rpc_module()
        payload = [[{"x": i, "s": "y" * 50} for i in range(400)] for _ in range(6)]
        preview = rpc._truncate_value(payload)
        self.assertEqual(len(preview), 6, "outer list must survive")
        self.assertLessEqual(rpc._json_size(preview), rpc.OUTPUT_LIMIT_MAX_CHARS)



class LimitSemanticsTests(unittest.TestCase):
    """limit <= 0 must mean the documented default, not the maximum.

    xrefs_to used to turn limit=0 into 1000 while its docstring promised a
    default of 100, so asking for the default silently returned ten times
    more rows. Combined with output truncation that produced the observed
    100 / 100 / 10 reply sizes for what looked like the same query.
    """

    def test_xrefs_to_non_positive_limit_uses_default(self):
        import pathlib
        import sys

        pkg = pathlib.Path(__file__).resolve().parents[1] / "src"
        sys.path.insert(0, str(pkg))
        source = (
            pkg / "ida_pro_mcp_enhanced" / "ida_mcp" / "api_analysis.py"
        ).read_text(encoding="utf-8")

        start = source.index("def xrefs_to(")
        end = source.index(chr(10) + "def ", start + 10)
        body = source[start:end]

        self.assertIn("limit = 100", body)
        self.assertNotIn("limit <= 0 or limit > 1000", body)

if __name__ == "__main__":
    unittest.main()
