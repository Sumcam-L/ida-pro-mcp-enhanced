import logging
import queue
import functools
import os
import threading
import idaapi
from .rpc import McpToolError
from .zeromcp.jsonrpc import RequestCancelledError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""

    pass


class _WatchdogTimeout(IDASyncError):
    """The waiting thread gave up before the IDA main thread finished.

    Raised in the *calling* thread, never injected into the main thread.
    """


class _WatchdogCancelled(CancelledError):
    """The request was cancelled while waiting for the IDA main thread."""


logger = logging.getLogger(__name__)
_TOOL_TIMEOUT_ENV = "IDA_MCP_TOOL_TIMEOUT_SEC"
_DEFAULT_TOOL_TIMEOUT_SEC = 60.0


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        return float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC


call_stack = queue.LifoQueue()

# Thread-local: while a synchronized tool body is running, holds the batch
# value that was in effect *before* the sync wrapper bumped it to 1. Tools
# decorated with @keep_batch read this via get_pre_call_batch() so they can
# restore the caller's original state — not assume a hard-coded default.
_sync_state = threading.local()

def get_pre_call_batch() -> int | None:
    """Return the pre-call batch state, or None if not inside a sync body.

    Only meaningful inside a @idasync function body — outside of that the
    sync wrapper isn't tracking anything. Tools using @keep_batch should
    read this and pass it to whatever asynchronous restorer they install,
    so the original batch state is preserved across the deferred work.
    """
    return getattr(_sync_state, "pre_call_batch", None)


def _sync_wrapper(ff, keep_batch=False, wait_timeout=None):
    """Schedule ff on the IDA main thread via execute_sync and return its result.

    wait_timeout: if set, stop waiting after that many seconds and raise
        _WatchdogTimeout. The main thread is deliberately left alone.
    """

    res_container = queue.Queue()
    # Set when the caller gives up. execute_sync() has no way to cancel an
    # already-queued callback, so a callback that has not started yet must
    # notice this and return without touching the database.
    abandoned = threading.Event()

    def runned():
        # The caller already gave up. Touch nothing: the tool may have modified
        # the database before stalling, and running its tail now would only
        # compound the damage.
        if abandoned.is_set():
            return

        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = f"Call stack is not empty while calling the function {ff.__name__} from {last_func_name}"
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        # --- [panic-patch 4] no idc.batch() in the wrapper --------------------
        # idc.batch(0) runs IDA's event loop (process_ui / UI events). Calling
        # it from *inside* execute_sync re-enters the main loop, which then
        # runs our own queued execute_sync callbacks re-entrantly: the tool
        # body suspends, the wrapper's finally/cleanup never runs, and the
        # main thread never returns to the event loop.
        #
        # Batch mode is per-thread state in IDA and the wrapper adds nothing
        # here, so simply stop touching it. Tools that genuinely need batch
        # mode manage it themselves (see keep_batch() / get_pre_call_batch()).
        prev_pre_call = getattr(_sync_state, "pre_call_batch", None)
        _sync_state.pre_call_batch = 0
        try:
            res_container.put(ff())
        except BaseException as x:
            # BaseException, not Exception: anything that escapes the tool body
            # must still reach the waiting caller, otherwise it waits out the
            # full timeout for a result that will never arrive.
            res_container.put(x)
        finally:
            # [panic-patch 4] no idc.batch(old_batch) here either - see above.
            _sync_state.pre_call_batch = prev_pre_call
            call_stack.get()

    idaapi.execute_sync(runned, idaapi.MFF_WRITE)

    if wait_timeout is None:
        res = res_container.get()
    else:
        try:
            res = res_container.get(timeout=wait_timeout)
        except queue.Empty:
            # [panic-patch 5] Give up waiting, but do NOT interrupt the main
            # thread. Interrupting it unwinds through IDA's C++ frames and
            # leaves the database locked for the rest of the session.
            abandoned.set()
            raise _WatchdogTimeout(
                f"Tool did not complete within {wait_timeout:.2f}s; the IDA "
                f"main thread was left running it to completion"
            )

    if isinstance(res, BaseException):
        raise res
    return res


def _normalize_timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def sync_wrapper(
    ff, timeout_override: float | None = None, keep_batch: bool = False
):
    """Run ff on the IDA main thread, bounding how long the caller waits.

    timeout_override: seconds to wait for ff. 0/None means wait forever.
    keep_batch: kept for decorator compatibility; batch mode is no longer
        toggled by this wrapper (see the note in _sync_wrapper).
    """
    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()

    # [panic-patch 5] The tool body runs completely unwrapped, and the timeout
    # is enforced by the *waiting* thread.
    #
    # Two earlier designs were removed, both fatally wrong:
    #
    # 1. sys.setprofile(profilefunc) raising on the deadline. The hook fires on
    #    every Python call/return, including while the interpreter is building
    #    a traceback, so raising there re-entered PyTraceBack_Print_Indented
    #    -> hook -> raise -> forever. 100% CPU, every tool died at 60.00s.
    #
    # 2. A watchdog thread calling PyThreadState_SetAsyncExc() on the main
    #    thread at the deadline. The exception lands at an arbitrary bytecode
    #    inside idaapi.execute_sync() and unwinds straight through IDA's C++
    #    frames. IDA never releases its MFF (main-function-file) ownership, the
    #    database stays locked, and EVERY later @idasync call blocks forever.
    #    One slow decompile poisoned the whole session.
    #
    # A tool that overruns now returns an error to its caller while the main
    # thread is left alone to finish whatever it was doing.
    return _sync_wrapper(
        ff,
        keep_batch=keep_batch,
        wait_timeout=timeout if timeout and timeout > 0 else None,
    )


def idasync(f):
    """Run the function on the IDA main thread in write mode.

    This is the unified decorator for all IDA synchronization.
    Previously there were separate @idaread and @idawrite decorators,
    but since read-only operations in IDA might actually require write
    access (e.g., decompilation), we now use a single decorator.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        keep_batch = bool(getattr(f, "__ida_mcp_keep_batch__", False))
        return sync_wrapper(ff, timeout_override, keep_batch=keep_batch)

    return wrapper


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds).

    IMPORTANT: Must be applied BEFORE @idasync (i.e., listed AFTER it)
    so the attribute exists when it captures the function in closure.

    Correct order:
        @tool
        @idasync
        @tool_timeout(90.0)  # innermost
        def my_func(...):
    """

    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func

    return decorator


def keep_batch(func):
    """Decorator to skip the sync wrapper's post-call batch-mode restore.

    Apply when the tool schedules asynchronous work that runs on the IDA
    main thread *after* execute_sync exits (e.g. start_process, which
    triggers the "matching executable names" dialog later). The decorated
    function MUST arrange batch-mode restoration itself, typically via a
    DBG_Hooks callback that fires once the asynchronous work has completed,
    so batch mode is not left on indefinitely.

    Same ordering rule as tool_timeout: place AFTER @idasync (innermost).

        @tool
        @idasync
        @keep_batch
        def my_func(...):
    """

    setattr(func, "__ida_mcp_keep_batch__", True)
    return func


def is_window_active():
    """Returns whether IDA is currently active."""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)

    if using_pyside6:
        from PySide6 import QtWidgets
    else:
        from PyQt5 import QtWidgets

    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    return app.activeWindow() is not None
