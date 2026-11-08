"""Broker cache layer: response envelope and argument handling.

The broker/cache_handlers.py path intercepts cache tools *before* the MCP
registry dispatch, so it never gets the framework parameter validation or
its response normalization. Both had bugs that only showed up in production:

  * _wrap_ok called dict(payload) on every payload. entity_query pages have
    five keys, so dict() raised "dictionary update sequence element #0 has
    length 5; 2 is required" on every entity_query call. list_funcs pages
    have exactly two keys, so dict() happened to succeed and silently
    produced {"data": "next_offset"} instead. Neither was caught by a test
    because the broker layer had none.

  * entity_query only accepted kind/regex/segment inside the nested queries
    object. A flat name_pattern + limit call could never reach the globals,
    strings or imports tables, and passing kind at the top level was
    rejected as an unknown parameter.
"""

import pathlib
import sys
import unittest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from ida_pro_mcp_enhanced.broker import cache_handlers as H  # noqa: E402


class WrapOkEnvelopeTests(unittest.TestCase):
    """_wrap_ok must always produce a valid CallToolResult.

    MCP requires structuredContent to be a JSON object, so list payloads
    have to be wrapped. The wrapper must never iterate a dict as if it were
    a sequence of pairs.
    """

    def _structured(self, payload):
        out = H._wrap_ok(1, payload)
        self.assertNotIn("error", out, out.get("error"))
        return out["result"]["structuredContent"]

    def test_entity_query_five_key_pages(self):
        """Regression: 5-key pages used to raise ValueError.

        entity_query returns {kind, data, next_offset, total, error} per
        page. dict() on a one-element list of that shape tried to unpack
        five keys into a pair.
        """
        payload = [
            {"kind": "functions", "data": [], "next_offset": None, "total": 0, "error": None}
        ]
        structured = self._structured(payload)
        self.assertIsInstance(structured, dict)
        self.assertEqual(structured["result"], payload)

    def test_entity_query_pages_keep_every_key(self):
        payload = [
            {"kind": "globals", "data": [{"addr": "0x1"}], "next_offset": 3, "total": 9, "error": None}
        ]
        structured = self._structured(payload)
        page = structured["result"][0]
        self.assertEqual(page["next_offset"], 3)
        self.assertEqual(page["total"], 9)
        self.assertIsNone(page["error"])

    def test_two_key_pages_are_not_mangled(self):
        """Regression: 2-key pages produced {"data": "next_offset"}.

        list_funcs pages happen to have exactly two keys, so dict() accepted
        them and returned the second key name as the value.
        """
        payload = [{"data": [{"addr": "0x1"}], "next_offset": 2}]
        structured = self._structured(payload)
        self.assertEqual(structured["result"], payload)
        self.assertNotEqual(structured, {"data": "next_offset"})

    def test_multiple_pages_preserve_order(self):
        payload = [{"data": [], "next_offset": 1}, {"data": [], "next_offset": None}]
        structured = self._structured(payload)
        self.assertEqual(structured["result"], payload)

    def test_dict_payload_is_not_wrapped(self):
        payload = {"items": [], "total": 0, "offset": 0, "limit": 5}
        structured = self._structured(payload)
        self.assertEqual(structured, payload)
        self.assertNotIn("result", structured)

    def test_empty_list_payload(self):
        self.assertEqual(self._structured([]), {"result": []})


class EntityQueryFlatArgumentTests(unittest.TestCase):
    """Flat arguments must reach every entity kind, not just functions."""

    ARGS = {
        "instance_id": "x",
        "name_pattern": "??_7*Foo*",
        "limit": 10,
    }

    def test_flat_kind_is_accepted(self):
        self.assertIn("kind", H._CACHE_TOOL_ARGS["entity_query"])

    def test_flat_kind_reaches_the_query(self):
        queries = H._queries_from_args(dict(self.ARGS, kind="globals"))
        self.assertEqual(queries[0]["kind"], "globals")

    def test_flat_pattern_and_limit_still_apply(self):
        queries = H._queries_from_args(dict(self.ARGS, kind="globals"))
        self.assertEqual(queries[0]["filter"], "??_7*Foo*")
        self.assertEqual(queries[0]["count"], 10)

    def test_nested_query_wins_over_flat_kind(self):
        queries = H._queries_from_args(
            {"kind": "functions", "queries": [{"kind": "globals", "filter": "x"}]}
        )
        self.assertEqual(queries[0]["kind"], "globals")

    def test_flat_regex_and_segment_are_accepted(self):
        queries = H._queries_from_args(
            {"name_pattern": "x", "regex": "^a", "segment": ".text"}
        )
        self.assertEqual(queries[0]["regex"], "^a")
        self.assertEqual(queries[0]["segment"], ".text")

    def test_include_xrefs_is_not_forced_into_the_query(self):
        queries = H._queries_from_args({"name_pattern": "x"})
        self.assertNotIn("include_xrefs", queries[0])

    def test_other_tools_still_reject_kind(self):
        self.assertNotIn("kind", H._CACHE_TOOL_ARGS["list_funcs"])


if __name__ == "__main__":
    unittest.main()
