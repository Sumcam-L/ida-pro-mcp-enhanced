"""Core API Functions - IDB metadata and basic queries"""

import bisect
import logging
import re
import time
from typing import Annotated, Any, NotRequired, TypedDict

import ida_auto
import ida_bytes
import idaapi
import ida_funcs
import ida_hexrays
import ida_lines
import ida_segment
import idautils
import ida_loader
import ida_nalt
import ida_typeinf
import idc

from .rpc import tool
from .sync import idasync
from .utils import (
    ConvertedNumber,
    EntityQuery,
    Function,
    FunctionQuery,
    Global,
    Import,
    ListQuery,
    NumberConversion,
    Page,
    ImportQuery,
    get_function,
    normalize_dict_list,
    normalize_list_input,
    parse_address,
    paginate,
    pattern_filter,
)


logger = logging.getLogger(__name__)


class ServerHealthResult(TypedDict):
    status: str
    uptime_sec: float
    idb_path: str | None
    module: str
    input_path: str
    imagebase: str
    auto_analysis_ready: bool | None
    hexrays_ready: bool
    strings_cache_ready: bool
    strings_cache_size: int


class ServerWarmupStep(TypedDict, total=False):
    step: str
    ok: bool
    ms: float
    error: str


class ServerWarmupResult(TypedDict):
    ok: bool
    steps: list[ServerWarmupStep]
    health: ServerHealthResult


class LookupFuncResult(TypedDict):
    query: str
    fn: Function | None
    error: str | None


class IntConvertResult(TypedDict):
    input: str
    result: ConvertedNumber | None
    error: str | None


class FunctionQueryRow(Function, total=False):
    has_type: bool
    size_int: int


class FunctionQueryPage(TypedDict, total=False):
    data: list[FunctionQueryRow]
    next_offset: int | None
    error: str | None


class EntityQueryPage(TypedDict, total=False):
    kind: str
    data: list[dict[str, Any]]
    next_offset: int | None
    total: int
    error: str | None


class ImportsQueryPage(TypedDict):
    data: list[Import]
    next_offset: int | None


class IdbSaveResult(TypedDict):
    ok: bool
    path: str | None
    error: NotRequired[str]


class FindRegexResult(TypedDict, total=False):
    n: int
    matches: list[dict[str, Any]]
    cursor: dict[str, Any]
    error: str | None


class SearchTextLine(TypedDict, total=False):
    kind: str  # "disasm" | "comment"
    text: str


class SearchTextHit(TypedDict, total=False):
    addr: str
    function: str
    segment: str
    matches: list[SearchTextLine]


class SearchTextResult(TypedDict, total=False):
    n: int
    hits: list[SearchTextHit]
    cursor: dict[str, Any]
    error: str
    # 0 命中且 pattern 明显是正则时的解释性提示（不改变匹配行为）。
    note: str


# Cached strings list: [(ea, text), ...]
_strings_cache: list[tuple[int, str]] | None = None
_server_started_at = time.time()


def _get_strings_cache() -> list[tuple[int, str]]:
    """Get cached strings, building cache on first access."""
    global _strings_cache
    if _strings_cache is None:
        _strings_cache = [(s.ea, str(s)) for s in idautils.Strings() if s is not None]
    return _strings_cache


def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache
    _strings_cache = None


def init_caches():
    """Build caches on plugin startup (called from Ctrl+M)."""
    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    logger.info("[MCP] Cached %d strings in %.0fms", len(strings), (t1 - t0) * 1000)


# ============================================================================
# Core API Functions
# ============================================================================


def _parse_func_query(query: str) -> int:
    """Fast path for common function query patterns. Returns ea or BADADDR."""
    q = query.strip()

    # 0x<hex> - direct address
    if q.startswith("0x") or q.startswith("0X"):
        try:
            return int(q, 16)
        except ValueError:
            pass

    # sub_<hex> - IDA auto-named function
    if q.startswith("sub_"):
        try:
            return int(q[4:], 16)
        except ValueError:
            pass

    return idaapi.BADADDR


def _coerce_sort_number(value, default: int = 0) -> int:
    """Parse decimal or prefixed string numbers used by generic entity rows."""
    if value in (None, ""):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def _collect_imports() -> list[Import]:
    """Collect all imports in the current database."""
    all_imports: list[Import] = []
    nimps = ida_nalt.get_import_module_qty()

    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"
            acc += [Import(addr=hex(ea), imported_name=symbol_name, module=module_name)]
            return True

        def imp_cb_w_context(ea, symbol_name, ordinal):
            return imp_cb(ea, symbol_name, ordinal, all_imports)

        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return all_imports


def _segment_name_for_ea(ea: int) -> str | None:
    seg = idaapi.getseg(ea)
    if not seg:
        return None
    try:
        return idaapi.get_segm_name(seg)
    except Exception:
        return None


def _primary_text_key(kind: str) -> str:
    if kind == "strings":
        return "text"
    return "name"


def _collect_entities(kind: str) -> list[dict]:
    if kind == "functions":
        rows: list[dict] = []
        for ea in idautils.Functions():
            fn = idaapi.get_func(ea)
            if not fn:
                continue
            size_int = fn.end_ea - fn.start_ea
            rows.append(
                {
                    "kind": "function",
                    "addr": hex(fn.start_ea),
                    "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                    "size": hex(size_int),
                    "size_int": size_int,
                    "segment": _segment_name_for_ea(fn.start_ea),
                    "has_type": bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)),
                }
            )
        return rows

    if kind == "globals":
        rows = []
        for ea, name in idautils.Names():
            if idaapi.get_func(ea) or name is None:
                continue
            rows.append(
                {
                    "kind": "global",
                    "addr": hex(ea),
                    "name": name,
                    "size": idc.get_item_size(ea),
                    "segment": _segment_name_for_ea(ea),
                }
            )
        return rows

    if kind == "imports":
        rows = []
        for imp in _collect_imports():
            rows.append(
                {
                    "kind": "import",
                    "addr": imp["addr"],
                    "name": imp["imported_name"],
                    "module": imp["module"],
                }
            )
        return rows

    if kind == "strings":
        rows = []
        for ea, text in _get_strings_cache():
            rows.append(
                {
                    "kind": "string",
                    "addr": hex(ea),
                    "text": text,
                    "length": len(text),
                    "segment": _segment_name_for_ea(ea),
                }
            )
        return rows

    if kind == "names":
        rows = []
        imports_by_ea = {int(imp["addr"], 16): imp for imp in _collect_imports()}
        for ea, name in idautils.Names():
            is_function = bool(idaapi.get_func(ea))
            is_import = ea in imports_by_ea
            rows.append(
                {
                    "kind": "name",
                    "addr": hex(ea),
                    "name": name,
                    "segment": _segment_name_for_ea(ea),
                    "is_function": is_function,
                    "is_import": is_import,
                }
            )
        return rows

    return []


def _apply_projection(items: list[dict], fields: list[str] | None) -> list[dict]:
    if not fields:
        return items
    normalized = [str(f).strip() for f in fields if str(f).strip()]
    if not normalized:
        return items
    keep = set(normalized)
    keep.add("kind")
    projected = []
    for item in items:
        projected.append({k: v for k, v in item.items() if k in keep})
    return projected


def _build_health_payload() -> dict:
    auto_is_ok = getattr(ida_auto, "auto_is_ok", None)
    auto_analysis_ready = bool(auto_is_ok()) if callable(auto_is_ok) else None

    hexrays_ready = False
    try:
        hexrays_ready = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        hexrays_ready = False

    idb_path = None
    try:
        idb_path = idc.get_idb_path()
    except Exception:
        idb_path = None

    return {
        "status": "ok",
        "uptime_sec": round(time.time() - _server_started_at, 3),
        "idb_path": idb_path,
        "module": ida_nalt.get_root_filename(),
        "input_path": ida_nalt.get_input_file_path(),
        "imagebase": hex(idaapi.get_imagebase()),
        "auto_analysis_ready": auto_analysis_ready,
        "hexrays_ready": hexrays_ready,
        "strings_cache_ready": _strings_cache is not None,
        "strings_cache_size": len(_strings_cache) if _strings_cache is not None else 0,
    }


@tool
@idasync
def server_health() -> ServerHealthResult:
    """Health/ready probe for MCP server and current IDB state."""
    return _build_health_payload()


@tool
@idasync
def server_warmup(
    wait_auto_analysis: Annotated[bool, "Wait for auto analysis queue"] = True,
    build_caches: Annotated[bool, "Build core caches (currently strings)"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays decompiler plugin"] = True,
) -> ServerWarmupResult:
    """Warm up IDA subsystems to reduce first-call latency and transient failures."""
    steps = []

    if wait_auto_analysis:
        t0 = time.perf_counter()
        ida_auto.auto_wait()
        steps.append(
            {
                "step": "auto_wait",
                "ok": True,
                "ms": round((time.perf_counter() - t0) * 1000, 2),
            }
        )

    if build_caches:
        t0 = time.perf_counter()
        init_caches()
        steps.append(
            {
                "step": "init_caches",
                "ok": True,
                "ms": round((time.perf_counter() - t0) * 1000, 2),
            }
        )

    if init_hexrays:
        t0 = time.perf_counter()
        ok = bool(ida_hexrays.init_hexrays_plugin())
        step = {
            "step": "init_hexrays",
            "ok": ok,
            "ms": round((time.perf_counter() - t0) * 1000, 2),
        }
        if not ok:
            step["error"] = "Hex-Rays unavailable"
        steps.append(step)

    return {
        "ok": all(bool(step.get("ok")) for step in steps),
        "steps": steps,
        "health": _build_health_payload(),
    }


@tool
@idasync
def lookup_funcs(
    queries: Annotated[
        list[str] | list[dict] | str,
        "函数地址或名称。支持: 字符串'0x401000'、逗号分隔'main, start'、数组['0x401000','main']、或对象数组[{'addr':'0x401000'}]。",
    ],
) -> list[LookupFuncResult]:
    """按地址或名称查找函数。输入: 地址(0x401000/sub_401000)或符号名(main,start)。输出: addr,name,size。支持批量。"""
    raw = normalize_list_input(queries) if isinstance(queries, (list, str)) else [queries]
    # 支持 [{"addr": "0x401000"}, ...] 格式，统一转为字符串列表
    queries = [
        (q.get("addr") or q.get("name") or str(q)) if isinstance(q, dict) else str(q)
        for q in raw
    ]

    # Treat empty/"*" as "all functions" - but add limit
    if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
        all_funcs = []
        for addr in idautils.Functions():
            all_funcs.append(get_function(addr))
            if len(all_funcs) >= 1000:
                break
        return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

    results = []
    for query in queries:
        try:
            # Fast path: 0x<ea> or sub_<ea>
            ea = _parse_func_query(query)

            # Slow path: name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    results.append({"query": query, "fn": func, "error": None})
                else:
                    results.append(
                        {"query": query, "fn": None, "error": "Not a function"}
                    )
            else:
                results.append({"query": query, "fn": None, "error": "Not found"})
        except Exception as e:
            results.append({"query": query, "fn": None, "error": str(e)})

    return results


@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion | str,
        "要转换的数: 字符串'0x41'/'255'、数组['0x41','255']、对象{'text':'0x1000','size':32}。输出 decimal/hex/ascii/binary。LLM 切勿自行做进制转换，请用此工具。",
    ],
) -> list[IntConvertResult]:
    """数值进制转换。输入任意格式数(0x/十进制)，输出 decimal/hex/ascii/binary。禁止 LLM 手算进制，必须调用此工具。"""
    inputs = normalize_dict_list(inputs, lambda s: {"text": s, "size": 64})

    results = []
    for item in inputs:
        text = item.get("text", "")
        size = item.get("size")

        try:
            value = int(text, 0)
        except ValueError:
            results.append(
                {"input": text, "result": None, "error": f"Invalid number: {text}"}
            )
            continue

        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        try:
            bytes_data = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            results.append(
                {
                    "input": text,
                    "result": None,
                    "error": f"Number {text} is too big for {size} bytes",
                }
            )
            continue

        ascii_str = ""
        for byte in bytes_data.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str = None
                break

        results.append(
            {
                "input": text,
                "result": ConvertedNumber(
                    decimal=str(value),
                    hexadecimal=hex(value),
                    bytes=bytes_data.hex(" "),
                    ascii=ascii_str,
                    binary=bin(value),
                ),
                "error": None,
            }
        )

    return results


@tool
@idasync
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "查询: glob过滤'main'、分页简写'0:50'(表示从第0个起取50个，非地址范围)、对象{filter,offset,count}。",
    ],
) -> list[Page[Function]]:
    """列出函数。支持 glob 过滤、分页。'0:50'=offset:count（列表索引，非地址）。"""
    try:
        from .utils import parse_list_query
        queries = normalize_dict_list(queries, parse_list_query)
    except Exception:
        queries = normalize_dict_list(queries)
    all_functions = [get_function(addr) for addr in idautils.Functions()]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_functions, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def func_query(
    queries: Annotated[
        list[FunctionQuery] | FunctionQuery,
        "Richer function query (size/type/name filters + pagination)",
    ],
) -> list[FunctionQueryPage]:
    """Query functions with richer filtering than list_funcs."""
    queries = normalize_dict_list(queries)

    all_functions: list[dict] = []
    for addr in idautils.Functions():
        fn = idaapi.get_func(addr)
        if not fn:
            continue
        size_int = fn.end_ea - fn.start_ea
        fn_name = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
        has_type = ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)
        all_functions.append(
            {
                "addr": hex(fn.start_ea),
                "name": fn_name,
                "size": hex(size_int),
                "size_int": size_int,
                "has_type": has_type,
            }
        )

    def apply_name_regex(items: list[dict], expr: str) -> list[dict]:
        if not expr:
            return items
        try:
            compiled = re.compile(expr)
        except re.error:
            return []
        return [item for item in items if compiled.search(item["name"])]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 50)
        sort_by = query.get("sort_by", "addr")
        descending = bool(query.get("descending", False))
        if sort_by not in ("addr", "name", "size"):
            sort_by = "addr"

        filtered = all_functions
        name_filter = query.get("filter", "")
        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "name")

        name_regex = query.get("name_regex", "")
        if name_regex:
            filtered = apply_name_regex(filtered, name_regex)

        min_size = query.get("min_size")
        if min_size is not None:
            filtered = [f for f in filtered if f["size_int"] >= int(min_size)]

        max_size = query.get("max_size")
        if max_size is not None:
            filtered = [f for f in filtered if f["size_int"] <= int(max_size)]

        if "has_type" in query:
            require_type = bool(query.get("has_type"))
            filtered = [f for f in filtered if bool(f["has_type"]) is require_type]

        if sort_by == "name":
            filtered.sort(key=lambda f: f["name"].lower(), reverse=descending)
        elif sort_by == "size":
            filtered.sort(key=lambda f: f["size_int"], reverse=descending)
        else:
            filtered.sort(key=lambda f: int(f["addr"], 16), reverse=descending)

        page = paginate(filtered, offset, count)
        page["data"] = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]
        results.append(page)

    return results


@tool
@idasync
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "查询: glob'g_'、分页'0:20'(offset:count 列表索引，非地址)、对象{filter,offset,count}。",
    ],
) -> list[Page[Global]]:
    """列出全局变量。支持 glob 过滤、分页。'0:20'=offset:count（列表索引，非地址）。"""
    try:
        from .utils import parse_list_query
        queries = normalize_dict_list(queries, parse_list_query)
    except Exception:
        queries = normalize_dict_list(queries)
    all_globals: list[Global] = []
    for addr, name in idautils.Names():
        if not idaapi.get_func(addr) and name is not None:
            all_globals.append(Global(addr=hex(addr), name=name))

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_globals, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def entity_query(
    queries: Annotated[
        list[EntityQuery] | EntityQuery,
        "Generic entity query with filtering, projection, and pagination",
    ],
) -> list[EntityQueryPage]:
    """Query IDB entities with typed filters, projection, and pagination."""
    queries = normalize_dict_list(queries)
    results: list[dict] = []

    for query in queries:
        kind = str(query.get("kind", "functions") or "functions").lower()
        if kind not in {"functions", "globals", "imports", "strings", "names"}:
            results.append(
                {
                    "kind": kind,
                    "data": [],
                    "next_offset": None,
                    "total": 0,
                    "error": f"Unsupported kind: {kind}",
                }
            )
            continue

        rows = _collect_entities(kind)
        primary_key = _primary_text_key(kind)
        filter_pattern = str(query.get("filter", "") or "")
        if filter_pattern:
            rows = pattern_filter(rows, filter_pattern, primary_key)

        regex = str(query.get("regex", "") or "")
        if regex:
            try:
                compiled = re.compile(regex)
                rows = [row for row in rows if compiled.search(str(row.get(primary_key, "")))]
            except re.error:
                rows = []

        segment_filter = str(query.get("segment", "") or "")
        if segment_filter and kind in {"functions", "globals", "strings", "names"}:
            rows = pattern_filter(rows, segment_filter, "segment")

        module_filter = str(query.get("module", "") or "")
        if module_filter and kind == "imports":
            rows = pattern_filter(rows, module_filter, "module")

        min_addr = query.get("min_addr")
        if min_addr not in (None, ""):
            try:
                min_ea = parse_address(min_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) >= min_ea]
            except Exception:
                rows = []

        max_addr = query.get("max_addr")
        if max_addr not in (None, ""):
            try:
                max_ea = parse_address(max_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) <= max_ea]
            except Exception:
                rows = []

        sort_by = str(query.get("sort_by", "addr") or "addr")
        descending = bool(query.get("descending", False))
        if sort_by == "addr":
            rows.sort(key=lambda row: int(str(row.get("addr", "0x0")), 16), reverse=descending)
        elif sort_by in {"size", "length"}:
            rows.sort(
                key=lambda row: row.get("size_int", _coerce_sort_number(row.get(sort_by, 0))),
                reverse=descending,
            )
        else:
            rows.sort(key=lambda row: str(row.get(sort_by, "")).lower(), reverse=descending)

        offset = int(query.get("offset", 0) or 0)
        count = int(query.get("count", 100) or 100)
        page = paginate(rows, offset, count)
        data = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]

        fields_raw = query.get("fields")
        fields = None
        if fields_raw is not None:
            if isinstance(fields_raw, str):
                fields = normalize_list_input(fields_raw)
            elif isinstance(fields_raw, list):
                fields = [str(f) for f in fields_raw]
            else:
                fields = [str(fields_raw)]
        data = _apply_projection(data, fields)

        results.append(
            {
                "kind": kind,
                "data": data,
                "next_offset": page["next_offset"],
                "total": len(rows),
                "error": None,
            }
        )

    return results


@tool
@idasync
def imports(
    offset: Annotated[int, "起始索引，从 0 开始"],
    count: Annotated[int, "返回数量，0 表示全部"],
) -> Page[Import]:
    """列出导入表。返回 addr, imported_name, module。用于查动态链接/API 调用。"""
    return paginate(_collect_imports(), offset, count)


@tool
@idasync
def imports_query(
    queries: Annotated[
        list[ImportQuery] | ImportQuery,
        "Import query with import/module filters and pagination",
    ],
) -> list[ImportsQueryPage]:
    """Query imports with richer filtering than imports(offset,count)."""
    queries = normalize_dict_list(queries)
    all_imports = _collect_imports()
    results = []

    for query in queries:
        filtered = all_imports
        name_filter = query.get("filter", "")
        module_filter = query.get("module", "")

        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "imported_name")
        if module_filter:
            filtered = pattern_filter(filtered, module_filter, "module")

        results.append(
            paginate(filtered, query.get("offset", 0), query.get("count", 100))
        )

    return results


@tool
@idasync
def idb_save(
    path: Annotated[str, "Optional destination path (default: current IDB path)"] = "",
) -> IdbSaveResult:
    """Save active IDB to disk, optionally to a provided path."""
    try:
        save_path = path.strip() if path else ""
        if not save_path:
            save_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not save_path:
            return {"ok": False, "path": None, "error": "Could not resolve IDB path"}

        ok = bool(ida_loader.save_database(save_path, 0))
        result: dict = {"ok": ok, "path": save_path}
        if not ok:
            result["error"] = "save_database returned false"
        return result
    except Exception as e:
        return {"ok": False, "path": path or None, "error": str(e)}


@tool
@idasync
def find_regex(
    pattern: Annotated[str, "正则表达式，在 IDA 识别的字符串中搜索。例: 'error|fail'、'password'"],
    limit: Annotated[int, "Max matches (default: 30, max: 500)"] = 30,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> FindRegexResult:
    """在二进制字符串中按正则搜索。返回 addr,string。不区分大小写。用于找硬编码字符串。"""
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    matches = []
    regex = re.compile(pattern, re.IGNORECASE)
    strings = _get_strings_cache()

    skipped = 0
    more = False
    for ea, text in strings:
        if regex.search(text):
            if skipped < offset:
                skipped += 1
                continue
            if len(matches) >= limit:
                more = True
                break
            matches.append({"addr": hex(ea), "string": text})

    return {
        "n": len(matches),
        "matches": matches,
        "cursor": {"next": offset + limit} if more else {"done": True},
    }


# ============================================================================
# search_text - rendered-listing search
#
# 历史实现用 ida_search.find_text() 做"IDA 原生文本搜索"。实测这条路径极慢：
# 它按行渲染 + 比较，在 16MB 的 .text 里找未出现的 token 要 235 秒，找
# "GetProcAddress" 要 70 秒。broker 侧 60 秒超时后请求被丢弃，而 IDA 主线程
# 还在继续跑那个 C 扫描，于是整个 IDA 卡死。
#
# 现在的实现改成"逐块渲染 + 内存匹配"：
#   * generate_disassembly() 渲染一个函数约 3.5 us/行，全库 6 万函数 80 万行
#     只要 ~4 秒（find_text 的 1/25 ~ 1/60）。
#   * 匹配在整块文本上做一次 C 层 find/正则扫描，再二分定位到行。
#   * 主循环带硬性时间预算，到点就停下并返回 partial 游标，绝不会把 IDA
#     主线程霸占到超时之后。
# ============================================================================

# 单个函数最多渲染这么多行；超过时 IDA 会返回 ".ERROR ..." 行，需要降级切片。
_SEARCH_MAX_ITEM_LINES = 4000
# 按段切片渲染时的粒度。
_SEARCH_SEGMENT_CHUNK_LINES = 4000
# 默认/最大时间预算（秒）。必须明显小于 MCP 侧 60s 的 tool-call 超时，
# 否则又会重演"客户端超时了、IDA 还在搜"。
_SEARCH_DEFAULT_BUDGET_SEC = 15.0
_SEARCH_MAX_BUDGET_SEC = 40.0
# 命中行里地址前缀的解析（行形如 ".text:0000000140001470  call ..."）。
_LISTING_ADDR_RE = re.compile(r"^[^\n:]{0,64}:([0-9A-Fa-f]{4,16})\b")

# 仅收录"强正则信号"：| \ ^ $ 以及 .* / .+ 这类组合。
# 不把裸 . * ( ) [ ] 算进来 —— 符号名里本来就常带它们（Foo.Bar、operator()），
# 那样会在正常的字面量搜索未命中时刷出无意义的提示。
_REGEX_HINT_TOKENS = ("|", "\\", "^", "$", ".*", ".+", "(?", "[A-Z", "[a-z", "[0-9")


def _regex_literal_hint(pattern: str) -> str | None:
    """pattern 看着像正则、却被当字面量搜且 0 命中时，返回一句提示。

    典型误用是传 "A|B" 求 OR，但忘了 regex=true：于是整串（含竖线）被当成
    一个有 8 个字符的字面量，必然搜不到。调用方拿到 0 条后会误判
    "A 和 B 都不存在"，这是假阴性，比慢查询危险得多。
    """
    strong = [t for t in _REGEX_HINT_TOKENS if t in pattern]
    if not strong:
        return None
    shown = ", ".join(repr(t) for t in strong)
    return (
        f"no literal match, and pattern contains regex markers ({shown}). "
        f"It was searched as the plain string {pattern!r}, NOT as a regex. "
        f"If you meant a regex (e.g. OR groups), retry with regex=true or pass "
        f"the alternatives separately. A 0 here does NOT prove the symbol is absent."
    )


def _render_listing(ea: int, max_lines: int) -> list[str] | None:
    """Render up to max_lines listing lines starting at ea (colour tags stripped).

    Returns None when IDA refuses to render at that address.
    """
    try:
        result = ida_lines.generate_disassembly(ea, max_lines, False, True)
    except Exception:
        return None
    if not isinstance(result, tuple):
        return None
    # Bindings vary: (n, lineno, lines) or (lines, lineno).
    for item in result:
        if isinstance(item, (list, tuple)) and item and isinstance(item[0], str):
            return list(item)
    return None


def _listing_line_ea(tagged_line: str) -> int | None:
    match = _LISTING_ADDR_RE.match(tagged_line)
    if not match:
        return None
    try:
        return int(match.group(1), 16)
    except ValueError:
        return None


def _listing_line_is_comment(tagged_line: str) -> bool:
    """True when the line carries no disassembly text before its ';' comment.

    Colour tags are deliberately not used: IDA paints operands that mention
    names with SCOLOR_REGCMT too, and auto-generated "DATA XREF" continuation
    lines carry no comment colour at all, so a colour test misclassifies ~13%
    of the lines in a real database.
    """
    match = _LISTING_ADDR_RE.match(tagged_line)
    body = tagged_line[match.end():] if match else tagged_line
    if "\x01" in body:
        body = ida_lines.tag_remove(body)
    semi = body.find(";")
    if semi < 0:
        return False
    return not body[:semi].strip()


def _listing_line_text(tagged_line: str) -> str:
    if "\x01" in tagged_line:
        return ida_lines.tag_remove(tagged_line) or tagged_line
    return tagged_line


def _exec_segments() -> list[tuple[int, int]]:
    """Return [(start, end)] for executable segments in address order."""
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        if not (seg.perm & idaapi.SEGPERM_EXEC):
            continue
        ranges.append((seg.start_ea, seg.end_ea))
    return ranges


def _all_segments() -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg:
            ranges.append((seg.start_ea, seg.end_ea))
    return ranges


def _exec_function_starts() -> list[int]:
    """Function entry addresses inside executable segments, ascending."""
    starts: list[int] = []
    for func_ea in idautils.Functions():
        seg = idaapi.getseg(func_ea)
        if seg is not None and (seg.perm & idaapi.SEGPERM_EXEC):
            starts.append(func_ea)
    starts.sort()
    return starts


def _listing_chunks(start_ea: int, code_only: bool):
    """Yield (chunk_start_ea, rendered lines) in ascending address order.

    code_only=True renders one function per chunk: dense, covers exactly the
    disassembly, and every rendered line belongs to the function. Oversized
    functions (where IDA returns a ".ERROR ..." line) are sliced by item.

    code_only=False walks whole segments in slices. The slice is only re-anchored
    when IDA stops making progress, because generate_disassembly() renders from
    an arbitrary address much less efficiently than from an item head.
    """
    if code_only:
        starts = _exec_function_starts()
        if not starts:
            return
        # Re-enter the function that *contains* start_ea, not the next one:
        # a page cursor points mid-function, and skipping it would silently
        # drop every later hit inside that function. Lines before start_ea are
        # filtered out by min_ea in _scan_rendered_block().
        func = idaapi.get_func(start_ea)
        anchor = func.start_ea if func is not None else start_ea
        index = bisect.bisect_left(starts, anchor)
        while index < len(starts):
            func_ea = starts[index]
            index += 1
            lines = _render_listing(func_ea, _SEARCH_MAX_ITEM_LINES)
            if not lines:
                continue
            if not any(line.startswith(".ERROR") for line in lines):
                yield func_ea, lines
                continue
            func = idaapi.get_func(func_ea)
            limit_ea = func.end_ea if func is not None else None
            if limit_ea is None:
                continue
            cursor = func_ea
            while cursor < limit_ea:
                chunk = _render_listing(cursor, _SEARCH_SEGMENT_CHUNK_LINES)
                if not chunk:
                    break
                yield cursor, chunk
                last_ea = _last_line_ea(chunk)
                if last_ea is None:
                    break
                nxt = ida_bytes.next_head(last_ea, limit_ea)
                if nxt == idaapi.BADADDR or nxt <= cursor:
                    break
                cursor = nxt
        return

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg is None:
            continue
        cursor = max(seg.start_ea, start_ea)
        if cursor >= seg.end_ea:
            continue
        while cursor < seg.end_ea:
            chunk = _render_listing(cursor, _SEARCH_SEGMENT_CHUNK_LINES)
            if not chunk:
                break
            yield cursor, chunk
            last_ea = _last_line_ea(chunk)
            if last_ea is None:
                break
            if last_ea > cursor:
                # Made progress: keep rendering from here, IDA handles it fine.
                cursor = last_ea
                continue
            nxt = ida_bytes.next_head(cursor, seg.end_ea)
            if nxt == idaapi.BADADDR or nxt <= cursor:
                break
            cursor = nxt


def _last_line_ea(lines: list[str]) -> int | None:
    best: int | None = None
    for line in lines:
        ea = _listing_line_ea(line)
        if ea is not None and (best is None or ea > best):
            best = ea
    return best


def _matching_line_indexes(
    lines: list[str],
    needle: str | None,
    rx: "re.Pattern[str] | None",
    case_sensitive: bool,
    max_results: int = 0,
) -> list[int]:
    """Indexes of the lines that match, ascending. One C-level scan per block.

    Matching is per line: after a hit the scan resumes at the start of the next
    line, so a multi-hit line is reported once and a regex never straddles two
    listing lines.
    """
    if not lines:
        return []
    offsets = [0]
    total = 0
    for line in lines:
        total += len(line)
        offsets.append(total)
    blob = "".join(lines)
    line_count = len(lines)

    found: list[int] = []
    if rx is not None:
        pos = 0
        while True:
            match = rx.search(blob, pos)
            if not match:
                break
            index = bisect.bisect_right(offsets, match.start()) - 1
            if not (0 <= index < line_count):
                pos = match.start() + 1
                continue
            found.append(index)
            pos = offsets[index + 1]
            if pos <= match.start():
                pos = match.start() + 1
            if max_results and len(found) >= max_results:
                break
        return found

    assert needle is not None
    haystack = blob if case_sensitive else blob.lower()
    if len(haystack) != len(blob):
        # Exotic case folding changed the length; fall back to per-line matching.
        for i, line in enumerate(lines):
            hay = line if case_sensitive else line.lower()
            if needle in hay:
                found.append(i)
                if max_results and len(found) >= max_results:
                    break
        return found

    pos = 0
    while True:
        hit = haystack.find(needle, pos)
        if hit < 0:
            break
        index = bisect.bisect_right(offsets, hit) - 1
        if 0 <= index < line_count:
            found.append(index)
            pos = offsets[index + 1]
            if max_results and len(found) >= max_results:
                break
        else:
            pos = hit + 1
    return found


def _scan_rendered_block(
    lines: list[str],
    min_ea: int,
    want_disasm: bool,
    want_comments: bool,
    needle: str | None,
    rx: "re.Pattern[str] | None",
    case_sensitive: bool,
    max_results: int = 0,
) -> list[tuple[int, list[SearchTextLine]]]:
    """Match one rendered block; returns [(ea, matching lines)] ascending."""
    indexes = _matching_line_indexes(lines, needle, rx, case_sensitive, max_results)
    if not indexes:
        return []

    grouped: dict[int, list[SearchTextLine]] = {}
    for index in indexes:
        tagged = lines[index]
        ea = _listing_line_ea(tagged)
        if ea is None or ea < min_ea:
            continue
        is_comment = _listing_line_is_comment(tagged)
        kind = "comment" if is_comment else "disasm"
        if kind == "disasm" and not want_disasm:
            continue
        if kind == "comment" and not want_comments:
            continue
        grouped.setdefault(ea, []).append({"kind": kind, "text": _listing_line_text(tagged)})

    return sorted(grouped.items())


@tool
@idasync
def search_text(
    pattern: Annotated[
        str,
        "要搜的文本。默认按字面量子串匹配（不区分大小写）。"
        "想用 | 表示 OR、或用分组/字符类/锚点，必须同时传 regex=true；"
        "否则 'A|B' 会连同竖线一起被当成一个普通字符串去搜，几乎必然 0 命中。",
    ],
    limit: Annotated[int, "Max hits per page (default: 30, max: 500)"] = 30,
    start: Annotated[str, "Cursor: address to resume from (hex or symbol). Empty = first segment."] = "",
    regex: Annotated[
        bool,
        "把 pattern 当 Python 正则处理。"
        "要搜 OR（A|B）、分组（(?:x)）、字符类（[A-Z]）、锚点（^x）时必须置 true。",
    ] = False,
    case_sensitive: Annotated[bool, "Case-sensitive match (default: false)"] = False,
    include: Annotated[str, "'disasm' | 'comments' | 'all' (default: all)"] = "all",
    code_only: Annotated[bool, "Restrict search to executable segments (default: true)"] = True,
    time_budget_sec: Annotated[float, "Hard wall-clock budget in seconds (default 15, max 40)"] = 0.0,
) -> SearchTextResult:
    """Search the rendered listing for text or a regex.

    PATTERN SEMANTICS - read this before concluding a symbol is absent:

      regex=False (default)  literal substring. "Foo|Bar" looks for the eight
                             characters F,o,o,|,B,a,r in that order - it does
                             NOT mean "Foo OR Bar". A hit count of 0 here says
                             nothing about whether Foo or Bar exist.
      regex=True             Python re syntax. Use it for OR, groups, classes
                             and anchors:    "TerrainElement|AssetCooker"

    A zero result whose pattern contains | ( ) [ ] \ ^ $ or .* is almost always
    a forgotten regex=true, not a missing symbol. When that happens this tool
    returns a "note" field saying so - retry with regex=true before drawing any
    conclusion. For OR searches, regex=true is cheaper than several literal
    scans anyway.

    Renders the listing block by block (function by function for code) and
    matches in memory instead of using ida_search.find_text(), which is orders
    of magnitude slower and can lock the IDA main thread for minutes.

    The call always returns within time_budget_sec. If the scan did not finish,
    cursor carries {"next": "<addr>", "partial": True}; pass that address back
    as start to continue. cursor.done means the address space was exhausted.
    Hits are ordered by address and never repeat across pages.
    """
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    include = (include or "all").lower()
    if include not in ("disasm", "comments", "all"):
        return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid include: {include!r}"}

    want_disasm = include in ("disasm", "all")
    want_comments = include in ("comments", "all")

    budget = time_budget_sec if time_budget_sec and time_budget_sec > 0 else _SEARCH_DEFAULT_BUDGET_SEC
    budget = min(float(budget), _SEARCH_MAX_BUDGET_SEC)

    needle: str | None = None
    rx: "re.Pattern[str] | None" = None
    if regex:
        try:
            rx = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
        except re.error as exc:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid regex: {exc}"}
    else:
        if not pattern:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": "pattern must not be empty"}
        needle = pattern if case_sensitive else pattern.lower()

    segments = _exec_segments() if code_only else _all_segments()
    if not segments:
        return {"n": 0, "hits": [], "cursor": {"done": True}, "stats": {"reason": "no segments"}}

    if start:
        try:
            cursor_ea = parse_address(start)
        except Exception as exc:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid start: {exc}"}
        min_ea = cursor_ea
    else:
        cursor_ea = segments[0][0]
        min_ea = 0

    started = time.perf_counter()
    deadline = started + budget

    hits: list[SearchTextHit] = []
    scanned_blocks = 0
    scanned_lines = 0
    resume_ea: int | None = None
    partial = False
    exhausted = True

    for chunk_start, lines in _listing_chunks(cursor_ea, code_only):
        if scanned_blocks and time.perf_counter() >= deadline:
            partial = True
            exhausted = False
            resume_ea = chunk_start
            break
        scanned_blocks += 1
        scanned_lines += len(lines)
        for ea, matches in _scan_rendered_block(
            lines,
            min_ea,
            want_disasm,
            want_comments,
            needle,
            rx,
            case_sensitive,
            limit - len(hits),
        ):
            entry: SearchTextHit = {"addr": hex(ea), "matches": matches}
            func = idaapi.get_func(ea)
            if func is not None:
                fname = ida_funcs.get_func_name(func.start_ea)
                if fname:
                    entry["function"] = fname
            seg = idaapi.getseg(ea)
            if seg is not None:
                sname = ida_segment.get_segm_name(seg)
                if sname:
                    entry["segment"] = sname
            hits.append(entry)
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            last_ea = int(hits[-1]["addr"], 16)
            item_size = idaapi.get_item_size(last_ea)
            resume_ea = last_ea + (item_size if item_size > 0 else 1)
            exhausted = False
            break

    elapsed = time.perf_counter() - started
    cursor: dict[str, Any]
    if partial:
        cursor = {"next": hex(resume_ea if resume_ea is not None else cursor_ea), "partial": True}
    elif not exhausted and resume_ea is not None:
        cursor = {"next": hex(resume_ea)}
    else:
        cursor = {"done": True}

    stats: dict[str, Any] = {
        "blocks": scanned_blocks,
        "lines": scanned_lines,
        "elapsed_ms": round(elapsed * 1000.0, 1),
        "budget_ms": round(budget * 1000.0, 1),
    }
    if partial:
        stats["partial"] = True
        stats["hint"] = "time budget reached; call again with start=cursor.next to continue"

    result: SearchTextResult = {
        "n": len(hits),
        "hits": hits,
        "cursor": cursor,
        "stats": stats,
    }
    # 字面量搜索 0 命中、但 pattern 明显是正则意图时补一句解释。
    # 只加提示，不自动改成正则 —— 匹配语义保持不变，避免"搜 a|b 字面量"被误伤。
    if not hits and needle is not None:
        hint = _regex_literal_hint(pattern)
        if hint:
            result["note"] = hint
    return result