"""Every emitted tool inputSchema must stay inside the model-visible subset.

The harness that projects MCP tool schemas into the SDK the model programs
against supports only: type / oneOf / properties / required /
additionalProperties / items / enum / const (plus title/description/default/
examples). It does not support anyOf. A single anyOf anywhere in a tool's
inputSchema makes the WHOLE parameter object render as `unknown`, leaving the
model to guess every argument name -- which is exactly how calls like
`search_structs(filter=..., limit=...)` or `type_inspect(name=...)` happen.

These tests pin the emission to that subset so a future union re-introduces
neither anyOf nor an unsupported keyword.
"""

import http.server  # Preload stdlib http before adding the local ida_mcp path.
import json
import os
import pathlib
import sys
import unittest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from ida_pro_mcp_enhanced.tool_registry import (  # noqa: E402
    parse_all_api_files,
    tool_to_mcp_schema,
)

CONSTRAINT_KEYWORDS = {
    "type",
    "oneOf",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
}
ANNOTATION_KEYWORDS = {"description", "title", "default", "examples"}
ONE_OF_SIBLING_KEYWORDS = [
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
]
SCHEMA_TYPES = {
    "object",
    "array",
    "string",
    "number",
    "integer",
    "boolean",
    "null",
}


def find_violations(node, path="schema"):
    """Return the harness-subset violations for one schema tree."""
    out = []
    if not isinstance(node, dict):
        return [f"{path} must be a schema object"]

    for key in node:
        if key in CONSTRAINT_KEYWORDS or key in ANNOTATION_KEYWORDS:
            continue
        out.append(f"{path}.{key} is not a supported keyword")

    has_type = "type" in node
    has_one_of = "oneOf" in node
    if has_type and has_one_of:
        return out + [f"{path} cannot declare both type and oneOf"]

    if not has_type and not has_one_of:
        for key in ONE_OF_SIBLING_KEYWORDS:
            if key in node:
                out.append(f"{path}.{key} requires type or oneOf")
        return out

    if has_one_of:
        for key in ONE_OF_SIBLING_KEYWORDS:
            if key in node:
                out.append(f"{path}.{key} is not supported beside oneOf")
        branches = node["oneOf"]
        if not isinstance(branches, list) or len(branches) < 2:
            out.append(f"{path}.oneOf must be an array of at least two schemas")
        else:
            for index, branch in enumerate(branches):
                out.extend(find_violations(branch, f"{path}.oneOf[{index}]"))
        return out

    schema_type = node["type"]
    if schema_type not in SCHEMA_TYPES:
        return out + [f"{path}.type must be one of {sorted(SCHEMA_TYPES)}"]

    for key, allowed in (
        ("properties", {"object"}),
        ("required", {"object"}),
        ("additionalProperties", {"object"}),
        ("items", {"array"}),
        ("enum", {"string", "number", "integer", "boolean", "null"}),
        ("const", {"string", "number", "integer", "boolean", "null"}),
    ):
        if key in node and schema_type not in allowed:
            out.append(f'{path}.{key} is not supported on type "{schema_type}"')

    if schema_type == "object":
        properties = node.get("properties")
        if properties is not None:
            if not isinstance(properties, dict):
                out.append(f"{path}.properties must be an object of schemas")
            else:
                for name, sub in properties.items():
                    out.extend(find_violations(sub, f"{path}.properties.{name}"))
        required = node.get("required")
        if required is not None:
            if not isinstance(required, list) or any(
                not isinstance(entry, str) for entry in required
            ):
                out.append(f"{path}.required must be an array of strings")
            elif isinstance(properties, dict):
                for name in required:
                    if name not in properties:
                        out.append(f'{path}.required names "{name}" not in properties')
        if "additionalProperties" in node and not isinstance(
            node["additionalProperties"], bool
        ):
            out.append(f"{path}.additionalProperties must be a boolean")
    elif schema_type == "array" and "items" in node:
        out.extend(find_violations(node["items"], f"{path}.items"))

    return out


def _all_tool_schemas():
    api_dir = _ROOT / "src" / "ida_pro_mcp_enhanced" / "ida_mcp"
    tools, _resources = parse_all_api_files(str(api_dir))
    return {tool.name: tool_to_mcp_schema(tool) for tool in tools}


class EmittedSchemaSubsetTests(unittest.TestCase):
    """The schemas the broker advertises must be renderable by the harness."""

    @classmethod
    def setUpClass(cls):
        cls.schemas = _all_tool_schemas()

    def test_tool_schemas_were_found(self):
        self.assertGreater(len(self.schemas), 50)

    def test_no_schema_uses_any_of(self):
        offenders = [
            name
            for name, schema in self.schemas.items()
            if "anyOf" in json.dumps(schema)
        ]
        self.assertEqual(
            offenders,
            [],
            "anyOf is outside the harness subset and degrades the entire "
            "parameter object to 'unknown'; use oneOf",
        )

    def test_every_schema_stays_in_supported_subset(self):
        failures = []
        for name, schema in self.schemas.items():
            violations = find_violations(schema["inputSchema"])
            if violations:
                failures.append(f"{name}: " + "; ".join(violations[:5]))
        self.assertEqual(failures, [], "\n".join(failures))

    def test_union_parameters_expose_their_typed_branch(self):
        """A list[T] | T parameter must still describe T's fields."""
        for name, param in (
            ("type_inspect", "queries"),
            ("set_type", "edits"),
            ("entity_query", "queries"),
            ("declare_type", "decls"),
        ):
            prop = self.schemas[name]["inputSchema"]["properties"][param]
            blob = json.dumps(prop)
            self.assertNotIn("anyOf", blob, f"{name}.{param}")
            self.assertTrue(
                "oneOf" in blob or "type" in prop,
                f"{name}.{param} lost its type information",
            )

    def test_typed_dict_fields_survive_into_the_union(self):
        """The concrete field names of the TypedDict must be present."""
        prop = self.schemas["type_inspect"]["inputSchema"]["properties"]["queries"]
        blob = json.dumps(prop)
        for field in ("name", "include_members", "max_members"):
            self.assertIn(field, blob, f"type_inspect.queries lost field {field!r}")

    def test_placeholder_flag_is_advertised(self):
        """type_inspect must document is_placeholder so callers can spot shells."""
        blob = json.dumps(self.schemas["type_inspect"])
        self.assertIn("is_placeholder", blob)


if __name__ == "__main__":
    unittest.main()
