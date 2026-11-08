import json
import os
from typing import Any, Optional
from .zeromcp import (
    McpRpcRegistry,
    McpServer,
    McpToolError,
    McpHttpRequestHandler,
    get_current_request_external_base_url,
)

MCP_UNSAFE: set[str] = set()
MCP_EXTENSIONS: dict[str, set[str]] = {}  # group -> set of function names
MCP_SERVER = McpServer("ida-pro-mcp", extensions=MCP_EXTENSIONS)

# ============================================================================
# Output Size Limiting
# ============================================================================

OUTPUT_LIMIT_MAX_CHARS = 50000
# The preview has to fit the transport cap together with the envelope, so it
# gets a smaller share than the raw limit.
OUTPUT_LIMIT_PREVIEW_BUDGET = 40000
OUTPUT_CACHE_MAX_SIZE = 100
_output_cache: dict[str, Any] = {}
_download_base_url: str = os.environ.get("IDA_MCP_URL", "http://127.0.0.1:13337")


def set_download_base_url(url: str) -> None:
    global _download_base_url
    _download_base_url = url.rstrip("/")


def get_download_base_url() -> str:
    return get_current_request_external_base_url() or _download_base_url


def get_current_transport_session_id() -> str | None:
    return MCP_SERVER.get_current_transport_session_id()


def _generate_output_id() -> str:
    import uuid

    return str(uuid.uuid4())


OUTPUT_LIMIT_PREVIEW_STR_LEN = 1000
# Never shred a record below this: a list entry that cannot hold a normal
# object is worse than dropping the entry outright.
OUTPUT_LIMIT_MIN_ITEM_BUDGET = 256
# Beyond this nesting level the per-key split stops measuring and just divides
# the remaining budget evenly. Measuring a deep tree costs a full serialize.
OUTPUT_LIMIT_SPLIT_DEPTH = 4


def _json_size(value: Any) -> int:
    """Serialized size in characters; unserializable counts as very large."""
    try:
        return len(json.dumps(value, separators=(",", ":"), default=str))
    except (TypeError, ValueError):
        return OUTPUT_LIMIT_MAX_CHARS * 10


def _clip_string(text: str, budget: int) -> str:
    """Trim one string so it fits `budget` characters."""
    limit = min(OUTPUT_LIMIT_PREVIEW_STR_LEN, max(0, budget))
    if len(text) <= limit:
        return text
    # The trailing marker is plain text, so it cannot violate a schema.
    marker = f"... [{len(text)} chars total]"
    keep = max(0, limit - len(marker))
    return text[:keep] + marker


def _minimal_like(value: Any) -> Any:
    """An empty value of the same shape, used when no budget is left."""
    if isinstance(value, list):
        return []
    if isinstance(value, dict):
        return {}
    if isinstance(value, str):
        return ""
    return value


def _truncate_list(items: list, budget: int, depth: int) -> list:
    """Keep as many leading items as the budget allows."""
    if not items:
        return []
    out: list = []
    used = 2  # "[" + "]"
    total_items = len(items)
    for index, item in enumerate(items):
        remaining = budget - used
        if remaining <= 8:
            break
        # Fair share of what is left, with a floor so ordinary records are not
        # shredded just because the list is long.
        fair_share = remaining // max(1, total_items - index)
        per_item = max(OUTPUT_LIMIT_MIN_ITEM_BUDGET, fair_share)
        shrunk = _truncate_budget(item, min(per_item, remaining), depth + 1)
        cost = _json_size(shrunk) + 1  # + separator
        if used + cost > budget:
            # One retry with exactly the space that is left, then give up.
            shrunk = _truncate_budget(item, remaining - 1, depth + 1)
            cost = _json_size(shrunk) + 1
            if used + cost > budget:
                break
        out.append(shrunk)
        used += cost
    return out


def _truncate_dict(mapping: dict, budget: int, depth: int) -> dict:
    """Shrink each value proportionally. Keys are never dropped."""
    if not mapping:
        return {}
    if depth >= OUTPUT_LIMIT_SPLIT_DEPTH:
        share = max(OUTPUT_LIMIT_MIN_ITEM_BUDGET, budget // max(1, len(mapping)))
        return {k: _truncate_budget(v, share, depth + 1) for k, v in mapping.items()}

    raw = {k: _json_size(v) for k, v in mapping.items()}
    total = sum(raw.values()) or 1
    out: dict = {}
    used = 2  # "{" + "}"
    for key, value in mapping.items():
        remaining = budget - used
        if remaining <= 8:
            out[key] = _minimal_like(value)
            used += _json_size(out[key]) + len(str(key)) + 4
            continue
        share = int(remaining * raw[key] / total)
        share = min(remaining, max(OUTPUT_LIMIT_MIN_ITEM_BUDGET, share))
        out[key] = _truncate_budget(value, share, depth + 1)
        used += _json_size(out[key]) + len(str(key)) + 4
    return out


def _truncate_budget(value: Any, budget: int, depth: int = 0) -> Any:
    """Shrink value to roughly `budget` characters, preserving its shape."""
    if isinstance(value, str):
        return _clip_string(value, budget)
    if isinstance(value, list):
        return _truncate_list(value, max(0, budget), depth)
    if isinstance(value, dict):
        return _truncate_dict(value, max(0, budget), depth)
    return value


def _truncate_value(value: Any, depth: int = 0) -> Any:
    """Shrink a tool payload to the preview budget, keeping as much as fits.

    The old implementation capped every list at a fixed 10 items. That turned
    an oversized xrefs_to reply into 10 of its 350 results, indistinguishable
    from a target that really only has 10 xrefs. Budgeting by size instead
    keeps hundreds and only touches what genuinely does not fit.
    """
    return _truncate_budget(value, OUTPUT_LIMIT_PREVIEW_BUDGET, depth)


def _build_download_meta(output_id: str, total_chars: int, preview_chars: int = 0) -> dict:
    download_url = f"{get_download_base_url()}/output/{output_id}.json"
    return {
        "output_truncated": True,
        "total_chars": total_chars,
        "preview_chars": preview_chars,
        "output_id": output_id,
        "download_url": download_url,
        "download_hint": (
            f"Output truncated to fit the transport limit "
            f"({preview_chars}/{total_chars} chars). Full result: "
            f"curl -o .ida-mcp/{output_id}.json {download_url}"
        ),
    }


def get_cached_output(output_id: str) -> Optional[Any]:
    return _output_cache.get(output_id)


def _cache_output(output_id: str, data: Any) -> None:
    if len(_output_cache) >= OUTPUT_CACHE_MAX_SIZE:
        oldest_key = next(iter(_output_cache))
        del _output_cache[oldest_key]
    _output_cache[output_id] = data


def limit_response_size(response: dict) -> dict:
    """Shrink one tools/call response that exceeds the transport cap.

    Returns the response untouched when it is small enough or carries an
    error. Kept as a standalone function so tests exercise the production
    code path instead of re-implementing it.
    """
    if response.get("isError"):
        return response

    structured = response.get("structuredContent")
    if structured is None:
        return response

    serialized = json.dumps(structured, default=str)
    if len(serialized) <= OUTPUT_LIMIT_MAX_CHARS:
        return response

    output_id = _generate_output_id()
    _cache_output(output_id, structured)

    preview = _truncate_value(structured)
    preview_chars = _json_size(preview)
    # Second pass for the rare case where the shape-preserving budget still
    # overshoots: a dict split cannot predict how the re-serialized child grows.
    if preview_chars > OUTPUT_LIMIT_MAX_CHARS:
        preview = _truncate_budget(
            preview,
            max(OUTPUT_LIMIT_MIN_ITEM_BUDGET, OUTPUT_LIMIT_MAX_CHARS // 2),
        )
        preview_chars = _json_size(preview)

    download_meta = _build_download_meta(output_id, len(serialized), preview_chars)

    content = [{
        "type": "text",
        "text": json.dumps(preview, separators=(",", ":"), default=str),
    }, {
        "type": "text",
        "text": download_meta["download_hint"],
    }]

    return {
        "structuredContent": preview,
        "content": content,
        "isError": False,
        "_meta": {"ida_mcp": download_meta},
    }


def _install_tools_call_patch() -> None:
    original = MCP_SERVER.registry.methods["tools/call"]

    def patched(
        name: str, arguments: Optional[dict] = None, _meta: Optional[dict] = None
    ) -> dict:
        return limit_response_size(original(name, arguments, _meta))

    MCP_SERVER.registry.methods["tools/call"] = patched


# Install the output limiting patch
_install_tools_call_patch()


# ============================================================================
# Decorators
# ============================================================================


def tool(func):
    return MCP_SERVER.tool(func)


def resource(uri):
    return MCP_SERVER.resource(uri)


def unsafe(func):
    MCP_UNSAFE.add(func.__name__)
    return func


def ext(group: str):
    """Mark a tool as belonging to an extension group.

    Tools in extension groups are hidden by default. Enable via ?ext=group query param.
    Example: @ext("dbg") marks debugger tools that require ?ext=dbg to be visible.
    """

    def decorator(func):
        if group not in MCP_EXTENSIONS:
            MCP_EXTENSIONS[group] = set()
        MCP_EXTENSIONS[group].add(func.__name__)
        return func

    return decorator


__all__ = [
    "McpRpcRegistry",
    "McpServer",
    "McpToolError",
    "McpHttpRequestHandler",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "MCP_EXTENSIONS",
    "tool",
    "unsafe",
    "ext",
    "resource",
    "get_cached_output",
    "set_download_base_url",
    "get_download_base_url",
    "get_current_transport_session_id",
]
