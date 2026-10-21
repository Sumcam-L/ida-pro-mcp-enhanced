"""IDA 插件进程的"客户端 MCP 接管层"

当 Broker 把 `tools/call` 请求转发到 IDA 后，这一层在 ida_mcp 正常
`MCP_SERVER.registry.dispatch` 之前做拦截：

- 如果目标工具在 `CACHE_TOOL_NAMES` 集合里，改由本模块直接读本地
  `.mcp.sqlite` 缓存并构造响应 (完全不占用 IDA 主线程)。
- 未就绪 / 数据库缺失时直接返回 JSON-RPC error，不 fallback。

所有签名都是严格类型化的，返回 `JsonRpcResponse`。
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping, cast

from . import sqlite_cache as _cache
from . import sqlite_query as _query
from .cache_types import (
    CacheStatusArgs,
    CacheStatusResult,
    EntityKind,
    EntityQueryArgs,
    EntityQueryResult,
    FindRegexArgs,
    FindRegexResult,
    ImportsArgs,
    JsonRpcError,
    JsonRpcId,
    JsonRpcRequest,
    JsonRpcResponse,
    ListFuncsArgs,
    ListFuncsResult,
    ListGlobalsArgs,
    ListGlobalsResult,
    ListImportsResult,
    McpTextContent,
    McpToolCallResult,
    RefreshCacheArgs,
    RefreshCacheResult,
)


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

CACHE_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "find_regex",
        "entity_query",
        "list_funcs",
        "list_globals",
        "imports",
        "imports_query",
        "refresh_cache",
        "cache_status",
    }
)

# 上游 utils.parse_list_query 的 "offset:count" 简写。
_LIST_QUERY_RE = re.compile(r"^\s*(-?\d+)\s*:\s*(-?\d+)\s*$")

_VALID_ENTITY_KINDS: frozenset[str] = frozenset(
    {"strings", "functions", "globals", "imports"}
)


# ---------------------------------------------------------------------------
# JSON-RPC 封装
# ---------------------------------------------------------------------------


def _wrap_ok(req_id: JsonRpcId, payload: Mapping[str, Any]) -> JsonRpcResponse:
    text_content: McpTextContent = {
        "type": "text",
        "text": json.dumps(payload, ensure_ascii=False, default=str),
    }
    result: McpToolCallResult = {"content": [text_content], "isError": False}
    return {"jsonrpc": "2.0", "result": result, "id": req_id}


def _wrap_err(req_id: JsonRpcId, code: int, message: str) -> JsonRpcResponse:
    err: JsonRpcError = {"code": code, "message": message}
    return {"jsonrpc": "2.0", "error": err, "id": req_id}


# ---------------------------------------------------------------------------
# 参数解析工具
# ---------------------------------------------------------------------------


def _get_args(req: JsonRpcRequest) -> dict[str, Any]:
    params = req.get("params")
    if not isinstance(params, dict):
        return {}
    args = params.get("arguments")
    return args if isinstance(args, dict) else {}


def _get_tool_name(req: JsonRpcRequest) -> str:
    params = req.get("params")
    if not isinstance(params, dict):
        return ""
    name = params.get("name", "")
    return name if isinstance(name, str) else ""


def _opt_str(args: Mapping[str, Any], key: str) -> str | None:
    v = args.get(key)
    return v if isinstance(v, str) and v else None


def _int_or(args: Mapping[str, Any], key: str, default: int) -> int:
    v = args.get(key, default)
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _bool_or(args: Mapping[str, Any], key: str, default: bool) -> bool:
    v = args.get(key, default)
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        return v.lower() in {"1", "true", "yes", "y", "on"}
    return default


# ---------------------------------------------------------------------------
# 各工具 handler (强类型)
# ---------------------------------------------------------------------------


def _do_find_regex(args: FindRegexArgs, db_path: str) -> FindRegexResult:
    return _query.find_regex(
        db_path,
        pattern=args["pattern"],
        limit=_int_or(args, "limit", 100),
        offset=_int_or(args, "offset", 0),
        include_xrefs=_bool_or(args, "include_xrefs", True),
    )


def _do_entity_query(args: EntityQueryArgs, db_path: str) -> EntityQueryResult:
    return _query.entity_query(
        db_path,
        kind=args["kind"],
        name_pattern=_opt_str(args, "name_pattern"),
        segment=_opt_str(args, "segment"),
        limit=_int_or(args, "limit", 200),
        offset=_int_or(args, "offset", 0),
        include_xrefs=_bool_or(args, "include_xrefs", True),
    )


def _do_list_funcs(args: ListFuncsArgs, db_path: str) -> ListFuncsResult:
    return _query.list_funcs(
        db_path,
        name_pattern=_opt_str(args, "name_pattern"),
        limit=_int_or(args, "limit", 200),
        offset=_int_or(args, "offset", 0),
        include_xrefs=_bool_or(args, "include_xrefs", False),
    )


def _do_list_globals(args: ListGlobalsArgs, db_path: str) -> ListGlobalsResult:
    return _query.list_globals(
        db_path,
        name_pattern=_opt_str(args, "name_pattern"),
        limit=_int_or(args, "limit", 200),
        offset=_int_or(args, "offset", 0),
    )


def _do_imports(args: ImportsArgs, db_path: str) -> ListImportsResult:
    return _query.list_imports(
        db_path,
        name_pattern=_opt_str(args, "name_pattern"),
        module_pattern=_opt_str(args, "module_pattern"),
        limit=_int_or(args, "limit", 500),
        offset=_int_or(args, "offset", 0),
    )


def _do_refresh_cache(_args: RefreshCacheArgs, idb_path: str) -> RefreshCacheResult:
    triggered = _cache.request_refresh(idb_path) if idb_path else False
    return {"triggered": bool(triggered), "idb_path": idb_path}


def _do_cache_status(_args: CacheStatusArgs, db_path: str) -> CacheStatusResult:
    return _query.cache_status(db_path)


# ---------------------------------------------------------------------------
# 上游工具参数 -> 缓存查询参数
#
# 上游的 list_funcs / list_globals / entity_query / imports_query 只收一个
# queries 参数（list[ListQuery] | ListQuery | str），缓存层早期版本却去读
# name_pattern / pattern / limit / offset，结果 filter 与分页被整段丢弃：
# 传 filter 会返回全表前 200 条，传 offset/count 也没反应。
#
# 下面的解析把上游语义翻译成 SQLite 查询。匹配规则与 utils.pattern_filter 对齐：
#   "sub"         -> 子串、大小写不敏感
#   "*sub*"/"a?b" -> glob（fnmatch，大小写不敏感）
#   "/re/flags"   -> 正则（flags 支持 i/m/s，默认大小写敏感）
# ---------------------------------------------------------------------------


def _pattern_to_sql_regex(pattern: str) -> str | None:
    """把上游 filter 语法翻译成 Python re 表达式（交给 REGEXP 运算符）。

    与 utils.pattern_filter 的语义保持一致：
      * 子串 / glob：大小写不敏感（上游对两者都做 .lower() 比较）；
      * /re/flags：默认大小写敏感，只有带 i 才不敏感。
    SQLite 的 REGEXP 只吃正则，所以都要先转成正则；子串用 re.escape
    保证元字符不被误解释。
    """
    if not pattern:
        return None
    # 与 utils.pattern_filter 完全一致：正则必须形如 /body/ 或 /body/flags，
    # 结尾的斜杠不能省。写成 "/^g_[A-Z]"（漏了结尾斜杠）在上游会被当作
    # 普通子串，这里同样按子串处理，保证缓存层与原生工具结果一致。
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last = pattern.rfind("/")
        body = pattern[1:last]
        flag_str = pattern[last + 1:]
        prefix = ""
        if flag_str:
            inline = "".join(ch for ch in "ims" if ch in flag_str)
            if inline:
                prefix = "(?" + inline + ")"
        return prefix + body
    if "*" in pattern or "?" in pattern or "[" in pattern:
        return _glob_to_regex(pattern)
    return _case_insensitive(re.escape(pattern))


def _glob_to_regex(pattern: str) -> str:
    """glob -> 正则，语义与 fnmatch.fnmatch(..., 忽略大小写) 一致。

    刻意不用 fnmatch.translate()：它生成的 "(?>.*?X)"（原子组 + 惰性量词）
    在 Python re 里会退化成逐字节回溯。实测 43773 个函数名上，
    fnmatch.translate("*Create*") 需要 4125 ms，而下面的写法 39 ms（100 倍）。
    """
    out: list[str] = []
    index = 0
    size = len(pattern)
    while index < size:
        ch = pattern[index]
        index += 1
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif ch == "[":
            end = index
            if end < size and pattern[end] in "!^":
                end += 1
            if end < size and pattern[end] == "]":
                end += 1
            while end < size and pattern[end] != "]":
                end += 1
            if end >= size:
                out.append(re.escape("["))
                continue
            body = pattern[index:end]
            index = end + 1
            if body[:1] in ("!", "^"):
                body = "^" + body[1:]
            out.append("[" + body.replace("\\", "\\\\") + "]")
        else:
            out.append(re.escape(ch))
    return "(?i:(?s:\A" + "".join(out) + "\Z))"


def _case_insensitive(regex: str) -> str:
    """把整条正则包进大小写不敏感的分组。

    不能简单前置 "(?i)"：有些模式本身以 \A/^ 锚点开头，内联 flag 落在锚点
    之前会改变语义。用 (?i:...) 整体包裹最稳。
    """
    if regex.startswith("(?i)"):
        return regex
    return "(?i:" + regex + ")"


def _parse_list_query_string(text: str) -> dict[str, Any]:
    """与 utils.parse_list_query 对齐：'0:50' 是分页，其余当 filter。"""
    match = _LIST_QUERY_RE.match(text)
    if match:
        return {"offset": int(match.group(1)), "count": int(match.group(2)), "filter": ""}
    return {"offset": 0, "count": 50, "filter": text.strip()}


def _queries_from_args(args: Mapping[str, Any]) -> list[dict[str, Any]]:
    """把上游 queries 参数归一成 [dict]，并兼容缓存层的旧扁平参数名。"""
    raw = args.get("queries")
    queries: list[dict[str, Any]] = []

    def add(obj: Any) -> None:
        if isinstance(obj, dict):
            queries.append(dict(obj))
        elif isinstance(obj, str):
            queries.append(_parse_list_query_string(obj))

    if isinstance(raw, dict):
        add(raw)
    elif isinstance(raw, list):
        if not raw:
            queries.append({})
        for item in raw:
            add(item)
    elif isinstance(raw, str):
        add(raw)
    if not queries:
        # 完全没有 queries：回落到旧的扁平参数（name_pattern/limit/offset）。
        queries.append({})

    for query in queries:
        if not query.get("filter") and isinstance(args.get("name_pattern"), str):
            query["filter"] = args["name_pattern"]
        if query.get("offset") is None and "offset" in args:
            query["offset"] = _int_or(args, "offset", 0)
        if query.get("count") is None:
            for key in ("count", "limit"):
                if key in args:
                    query["count"] = _int_or(args, key, 0)
                    break
    return queries


def _norm_filter(value: Any) -> str | None:
    text = value.strip() if isinstance(value, str) else ""
    if not text or text == "*":
        return None
    return text


# ---------------------------------------------------------------------------
# 上游返回外形（与 ida_mcp/api_core.py 的原生工具对齐）
#
# list_funcs   -> list[Page[Function]]     [{data:[...], next_offset}]
# list_globals -> list[Page[Global]]       [{data:[...], next_offset}]
# entity_query -> list[EntityQueryPage]    [{kind, data, next_offset, total, error}]
# imports      -> Page[Import]             {data:[...], next_offset}
# imports_query-> list[Page[Import]]       [{data:[...], next_offset}]
# ---------------------------------------------------------------------------


# SQLite 侧的 LIMIT：0 在这里表示"取 0 条"（SQL 语义），而缓存查询层的
# limit 只能表达上限。count==0 表示"取全部"，只能用一个足够大的数来取。
_FETCH_ALL = 1_000_000


def _fetch_limit(count: int, offset: int) -> int:
    """把上游 count 语义（0=全部）翻译成 SQL LIMIT 值。"""
    if count == 0:
        return _FETCH_ALL
    return max(0, offset + count)


def _page(
    items: list[dict[str, Any]],
    offset: int,
    count: int,
    total: int | None = None,
) -> dict[str, Any]:
    """与 utils.paginate 对齐：count==0 表示取全部。

    注意 items 可能已经被 SQL 的 LIMIT 截断到 offset+count 条，这时不能拿
    len(items) 判断是否还有下一页，必须用真实 total（查询层返回的匹配总数）。
    """
    size = total if total is not None else len(items)
    if count == 0:
        count = size
    next_offset = offset + count
    if next_offset >= size:
        next_offset = None
    return {"data": items[offset:offset + count], "next_offset": next_offset}


def _function_rows(result: _query.ListFuncsResult, with_kind: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in result["items"]:
        row: dict[str, Any] = {
            "addr": item["addr"],
            "name": item["name"],
            "size": hex(int(item["size"])),
            "segment": item["segment"],
            "has_type": bool(item["has_type"]),
        }
        if with_kind:
            row["kind"] = "function"
        rows.append(row)
    return rows


def _global_rows(result: _query.ListGlobalsResult, with_kind: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in result["items"]:
        row: dict[str, Any] = {
            "addr": item["addr"],
            "name": item["name"],
            "size": int(item["size"]),
            "segment": item["segment"],
        }
        if with_kind:
            row["kind"] = "global"
        rows.append(row)
    return rows


def _string_rows(result: _query.EntityQueryResult, with_kind: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in result["items"]:
        text = item.get("text", "")
        row: dict[str, Any] = {
            "addr": item.get("addr", ""),
            "text": text,
            "length": int(item.get("length", len(text))),
            "segment": item.get("segment", ""),
        }
        if "xrefs" in item:
            row["xrefs"] = item["xrefs"]
        if with_kind:
            row["kind"] = "string"
        rows.append(row)
    return rows


def _import_rows(
    result: _query.ListImportsResult, with_kind: bool, imported_name: bool
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in result["items"]:
        row: dict[str, Any] = {
            "addr": item["addr"],
            "imported_name" if imported_name else "name": item["name"],
            "module": item["module"],
        }
        if with_kind:
            row["kind"] = "import"
        rows.append(row)
    return rows


def _do_list_funcs_pages(
    queries: list[dict[str, Any]], db_path: str
) -> list[dict[str, Any]]:
    pages: list[dict[str, Any]] = []
    for query in queries:
        offset = max(0, _int_or(query, "offset", 0))
        count = _int_or(query, "count", 50)
        args: ListFuncsArgs = {
            "instance_id": "",
            "limit": _fetch_limit(count, offset),
        }
        pattern = _norm_filter(query.get("filter"))
        regex = _pattern_to_sql_regex(pattern) if pattern else None
        if regex:
            args["name_pattern"] = regex
        result = _do_list_funcs(args, db_path)
        pages.append(_page(_function_rows(result, False), offset, count, result["total"]))
    return pages


def _do_list_globals_pages(
    queries: list[dict[str, Any]], db_path: str
) -> list[dict[str, Any]]:
    pages: list[dict[str, Any]] = []
    for query in queries:
        offset = max(0, _int_or(query, "offset", 0))
        count = _int_or(query, "count", 50)
        args: ListGlobalsArgs = {
            "instance_id": "",
            "limit": _fetch_limit(count, offset),
        }
        pattern = _norm_filter(query.get("filter"))
        regex = _pattern_to_sql_regex(pattern) if pattern else None
        if regex:
            args["name_pattern"] = regex
        result = _do_list_globals(args, db_path)
        pages.append(_page(_global_rows(result, False), offset, count, result["total"]))
    return pages


def _entity_rows(kind: EntityKind, result: _query.EntityQueryResult) -> list[dict[str, Any]]:
    if kind == "functions":
        return _function_rows(cast(_query.ListFuncsResult, result), True)
    if kind == "globals":
        return _global_rows(cast(_query.ListGlobalsResult, result), True)
    if kind == "strings":
        return _string_rows(result, True)
    return _import_rows(cast(_query.ListImportsResult, result), True, False)


def _do_entity_query_pages(
    queries: list[dict[str, Any]], db_path: str
) -> list[dict[str, Any]]:
    pages: list[dict[str, Any]] = []
    for query in queries:
        kind_raw = str(query.get("kind", "functions") or "functions").lower()
        offset = max(0, _int_or(query, "offset", 0))
        count = _int_or(query, "count", 100)

        if kind_raw not in _VALID_ENTITY_KINDS:
            pages.append(
                {
                    "kind": kind_raw,
                    "data": [],
                    "next_offset": None,
                    "total": 0,
                    "error": f"Unsupported kind: {kind_raw}",
                }
            )
            continue

        kind = cast(EntityKind, kind_raw)
        # 上游 entity_query 同时有 filter（glob/子串）和 regex 两个字段，
        # 语义是"先 filter 再 regex"（交集）。SQL 只能表达一个 REGEXP，所以
        # 用 filter 做 SQL 预筛，再把 regex 作为 Python 侧复核。
        pattern = _norm_filter(query.get("filter"))
        extra_regex = _norm_filter(query.get("regex"))
        sql_regex = _pattern_to_sql_regex(pattern) if pattern else None
        if not sql_regex and extra_regex:
            sql_regex = extra_regex

        args: EntityQueryArgs = {"instance_id": "", "kind": kind}
        if sql_regex:
            args["name_pattern"] = sql_regex
        segment = _opt_str(query, "segment")
        if segment:
            args["segment"] = segment
        # 需要 Python 复核时不能提前截断，否则分页会漏行。
        if pattern and extra_regex:
            args["limit"] = 0
        else:
            args["limit"] = _fetch_limit(count, offset)
        args["offset"] = 0
        result = _do_entity_query(args, db_path)
        rows = _entity_rows(kind, result)
        if pattern and extra_regex:
            try:
                compiled = re.compile(extra_regex)
            except re.error:
                rows = []
            else:
                key = "text" if kind == "strings" else "name"
                rows = [row for row in rows if compiled.search(str(row.get(key, "")))]
        page = _page(rows, offset, count, len(rows) if pattern and extra_regex else result["total"])
        pages.append(
            {
                "kind": kind,
                "data": page["data"],
                "next_offset": page["next_offset"],
                "total": result["total"],
                "error": None,
            }
        )
    return pages


def _imports_page_for_query(query: Mapping[str, Any], db_path: str) -> dict[str, Any]:
    offset = max(0, _int_or(query, "offset", 0))
    count = _int_or(query, "count", 0)
    args: ImportsArgs = {
        "instance_id": "",
        "limit": _fetch_limit(count, offset),
    }
    pattern = _norm_filter(query.get("filter"))
    regex = _pattern_to_sql_regex(pattern) if pattern else None
    if regex:
        args["name_pattern"] = regex
    module = _norm_filter(query.get("module"))
    module_regex = _pattern_to_sql_regex(module) if module else None
    if module_regex:
        args["module_pattern"] = module_regex
    result = _do_imports(args, db_path)
    return _page(_import_rows(result, False, True), offset, count, result["total"])


def _do_imports_query_pages(
    queries: list[dict[str, Any]], db_path: str
) -> list[dict[str, Any]]:
    return [_imports_page_for_query(query, db_path) for query in queries]

# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------


def handle_cache_tool_locally(req: JsonRpcRequest, idb_path: str) -> JsonRpcResponse:
    """在 IDA 插件进程内部，直接用 SQLite 响应缓存类工具。

    调用前请先用 `is_cache_tool()` / `CACHE_TOOL_NAMES` 判断。
    """
    req_id: JsonRpcId = req.get("id")
    tool_name = _get_tool_name(req)
    raw_args = _get_args(req)

    if not idb_path:
        return _wrap_err(
            req_id,
            -32000,
            "当前 IDA 实例未提供 idb_path，无法定位本地 SQLite 缓存。",
        )

    db_path = _query.get_cache_path_for_binary(idb_path)
    if not db_path:
        return _wrap_err(req_id, -32000, "无法根据 idb_path 推导缓存数据库路径。")

    try:
        if tool_name == "find_regex":
            pattern = raw_args.get("pattern") or raw_args.get("regex")
            if not isinstance(pattern, str) or not pattern:
                return _wrap_err(req_id, -32602, "find_regex 需要 pattern 参数 (str)。")
            fr_args: FindRegexArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
                "pattern": pattern,
            }
            if "limit" in raw_args:
                fr_args["limit"] = _int_or(raw_args, "limit", 100)
            if "offset" in raw_args:
                fr_args["offset"] = _int_or(raw_args, "offset", 0)
            if "include_xrefs" in raw_args:
                fr_args["include_xrefs"] = _bool_or(raw_args, "include_xrefs", True)
            return _wrap_ok(req_id, _do_find_regex(fr_args, db_path))

        if tool_name == "entity_query":
            queries = _queries_from_args(raw_args)
            return _wrap_ok(req_id, _do_entity_query_pages(queries, db_path))

        if tool_name == "list_funcs":
            queries = _queries_from_args(raw_args)
            return _wrap_ok(req_id, _do_list_funcs_pages(queries, db_path))

        if tool_name == "list_globals":
            queries = _queries_from_args(raw_args)
            return _wrap_ok(req_id, _do_list_globals_pages(queries, db_path))

        if tool_name == "imports":
            # 上游 imports 只收 offset/count；imports_query 收 queries。
            return _wrap_ok(req_id, _imports_page_for_query(dict(raw_args), db_path))

        if tool_name == "imports_query":
            queries = _queries_from_args(raw_args)
            return _wrap_ok(req_id, _do_imports_query_pages(queries, db_path))

        if tool_name == "refresh_cache":
            rc_args: RefreshCacheArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
            }
            return _wrap_ok(req_id, _do_refresh_cache(rc_args, idb_path))

        if tool_name == "cache_status":
            cs_args: CacheStatusArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
            }
            return _wrap_ok(req_id, _do_cache_status(cs_args, db_path))

    except _query.CacheNotReadyError as e:
        return _wrap_err(req_id, -32001, str(e))
    except Exception as e:  # noqa: BLE001
        return _wrap_err(req_id, -32603, f"SQLite 缓存查询失败: {e}")

    return _wrap_err(req_id, -32601, f"未知缓存工具: {tool_name!r}")


def is_cache_tool(req: JsonRpcRequest) -> bool:
    """请求是否命中缓存拦截名单。"""
    if req.get("method") != "tools/call":
        return False
    return _get_tool_name(req) in CACHE_TOOL_NAMES