import ctypes
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

if sys.platform == "win32":
    import msvcrt
else:  # pragma: no cover - the launcher targets Windows, but stay importable.
    msvcrt = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# 默认值与可移植性
#
# 这里刻意不写死任何绝对路径：此前 launcher 把 python.exe 和 opencode 的
# state/log 目录写死在常量里，换一台机器就得改代码。现在的规则：
#
#   python 解释器  IDA_MCP_PYTHON   -> 否则用运行本模块的解释器(sys.executable)
#   broker 地址    IDA_MCP_BROKER_URL -> 否则 http://127.0.0.1:13337
#   state/日志目录 IDA_MCP_STATE_DIR / IDA_MCP_LOG_DIR
#                  -> 否则沿用 opencode 的目录(若存在)，以便与 opencode 共享
#                     同一个 broker；都不存在则落到用户目录下的 .ida-pro-mcp
#
# 共享 state 目录是"多客户端共用一个 broker"的关键：DSH、opencode、其他
# MCP 客户端读同一份 ida-mcp-launcher.json，谁先来谁拉起 broker，最后一个
# 退出的负责关掉它。
# ---------------------------------------------------------------------------

DEFAULT_BROKER_URL = "http://127.0.0.1:13337"


def _default_state_dir() -> Path:
    override = os.environ.get("IDA_MCP_STATE_DIR")
    if override:
        return Path(override)
    # 优先复用 opencode 的 state 目录，保持与 opencode 共用 broker。
    for candidate in _opencode_state_candidates():
        if candidate.is_dir():
            return candidate
    return _user_data_dir() / "state"


def _default_log_dir() -> Path:
    override = os.environ.get("IDA_MCP_LOG_DIR")
    if override:
        return Path(override)
    for candidate in _opencode_log_candidates():
        if candidate.is_dir():
            return candidate
    return _user_data_dir() / "logs"


def _user_data_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return Path(base) / "ida-pro-mcp"
    return Path(os.path.expanduser("~")) / ".ida-pro-mcp"


def _opencode_state_candidates() -> list[Path]:
    home = Path(os.path.expanduser("~"))
    return [home / ".config" / "opencode" / "state"]


def _opencode_log_candidates() -> list[Path]:
    home = Path(os.path.expanduser("~"))
    return [home / ".config" / "opencode" / "logs"]


def _resolve_python_exe() -> str:
    """解释器优先级：IDA_MCP_PYTHON > 当前解释器。

    用 sys.executable 而不是写死路径，包被 pip 装到哪个环境就用哪个环境。
    """
    override = os.environ.get("IDA_MCP_PYTHON")
    if override:
        return override
    return sys.executable or "python"


PYTHON_EXE = _resolve_python_exe()

# 子进程创建标志：Windows 上隐藏控制台窗口，其他平台为 0。
_WIN_CREATE_FLAGS = (
    (subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)
    if sys.platform == "win32"
    else 0
)
# 让 stderr 也能落到日志文件（Windows 用 CREATE_NO_WINDOW 即可，无需额外处理）。
_NO_WINDOW_FLAG = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


@dataclass(frozen=True)
class LauncherConfig:
    state_dir: Path = field(default_factory=_default_state_dir)
    log_dir: Path = field(default_factory=_default_log_dir)
    broker_url: str = field(
        default_factory=lambda: os.environ.get("IDA_MCP_BROKER_URL") or DEFAULT_BROKER_URL
    )
    broker_start_timeout: float = 15.0
    # 宿主关闭 stdin 之后，留给 stdio server 自行收尾的时间
    eof_grace_seconds: float = 2.0

    @property
    def broker_port(self) -> int:
        """从 broker_url 推导端口，保证两处永远一致。"""
        parsed = urlparse(self.broker_url)
        return parsed.port or 13337

    @property
    def state_path(self) -> Path:
        return self.state_dir / "ida-mcp-launcher.json"

    @property
    def lock_path(self) -> Path:
        return self.state_dir / "ida-mcp-launcher.lock"

    @property
    def broker_log_path(self) -> Path:
        return self.log_dir / "ida-mcp-broker.log"

    @property
    def broker_command(self) -> list[str]:
        return [
            PYTHON_EXE,
            "-m",
            "ida_pro_mcp_enhanced.server",
            "--broker",
            "--port",
            str(self.broker_port),
        ]

    @property
    def stdio_command(self) -> list[str]:
        return [
            PYTHON_EXE,
            "-m",
            "ida_pro_mcp_enhanced.server",
            "--broker-url",
            self.broker_url,
        ]


def default_state() -> dict:
    return {
        "broker": {"pid": None, "token": None, "owned": False},
        "clients": [],
    }


@contextmanager
def state_lock(config: LauncherConfig):
    """对 state 文件加独占锁，串行化"读-改-写"。"""
    config.state_dir.mkdir(parents=True, exist_ok=True)
    with config.lock_path.open("a+b") as lock_file:
        lock_file.seek(0, os.SEEK_END)
        if lock_file.tell() == 0:
            lock_file.write(b"0")
            lock_file.flush()
        lock_file.seek(0)
        _acquire_lock(lock_file)
        try:
            yield
        finally:
            _release_lock(lock_file)


def _acquire_lock(lock_file) -> None:
    if msvcrt is None:  # pragma: no cover - Windows is the supported target.
        import fcntl

        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        return
    while True:
        try:
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            return
        except OSError:
            time.sleep(0.05)


def _release_lock(lock_file) -> None:
    if msvcrt is None:  # pragma: no cover
        import fcntl

        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        return
    lock_file.seek(0)
    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)


def read_state(config: LauncherConfig) -> dict:
    try:
        state = json.loads(config.state_path.read_text(encoding="utf-8"))
        if not isinstance(state.get("broker"), dict) or not isinstance(state.get("clients"), list):
            raise ValueError("invalid state shape")
        return state
    except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError):
        return default_state()


def write_state(config: LauncherConfig, state: dict) -> None:
    config.state_dir.mkdir(parents=True, exist_ok=True)
    temporary_path = config.state_path.with_suffix(".tmp")
    temporary_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.replace(temporary_path, config.state_path)


def get_process_token(pid: int) -> Optional[str]:
    """返回能唯一定位该进程实例的令牌（Windows 用创建时间）。

    令牌用来区分"同一个 pid 被复用"，避免把新进程误认成旧 broker。
    """
    if sys.platform != "win32":
        return _posix_process_token(pid)
    process_query_limited_information = 0x1000
    handle = ctypes.windll.kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return None
    try:
        creation = ctypes.c_ulonglong()
        exit_time = ctypes.c_ulonglong()
        kernel = ctypes.c_ulonglong()
        user = ctypes.c_ulonglong()
        if not ctypes.windll.kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            return None
        return str(creation.value)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _posix_process_token(pid: int) -> Optional[str]:
    """非 Windows 平台：用进程创建时刻（/proc/<pid>/stat 的 starttime）。"""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    # starttime 是第 22 个字段；comm 里可能有空格，先按右括号定位。
    try:
        after_comm = stat.rsplit(")", 1)[1].split()
        return after_comm[19]
    except (IndexError, ValueError):
        return None


def process_matches(pid: Optional[int], token: Optional[str]) -> bool:
    return bool(pid and token and get_process_token(pid) == token)


def prune_dead_clients(state: dict) -> None:
    state["clients"] = [
        client
        for client in state.get("clients", [])
        if process_matches(client.get("pid"), client.get("token"))
    ]


def broker_is_healthy(config: LauncherConfig, timeout: float = 0.5) -> bool:
    try:
        with urllib.request.urlopen(f"{config.broker_url}/status", timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
            return response.status == 200 and isinstance(payload.get("instances"), list)
    except (OSError, urllib.error.URLError, json.JSONDecodeError, AttributeError):
        return False


def wait_for_broker(config: LauncherConfig) -> bool:
    deadline = time.monotonic() + config.broker_start_timeout
    while time.monotonic() < deadline:
        if broker_is_healthy(config):
            return True
        time.sleep(0.1)
    return False


def start_broker(config: LauncherConfig) -> subprocess.Popen:
    config.log_dir.mkdir(parents=True, exist_ok=True)
    with config.broker_log_path.open("ab", buffering=0) as log_file:
        return subprocess.Popen(
            config.broker_command,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=log_file,
            creationflags=_WIN_CREATE_FLAGS,
            close_fds=True,
        )


def terminate_owned_broker(broker: dict) -> bool:
    pid = broker.get("pid")
    token = broker.get("token")
    if not broker.get("owned") or not process_matches(pid, token):
        return False
    try:
        os.kill(pid, signal.SIGTERM)
        return True
    except OSError:
        return False


def register_client(config: LauncherConfig, client_pid: int) -> None:
    client_token = get_process_token(client_pid)
    if client_token is None:
        raise RuntimeError(f"Unable to identify launcher process {client_pid}")

    with state_lock(config):
        state = read_state(config)
        prune_dead_clients(state)
        broker = state.get("broker", default_state()["broker"])

        if broker_is_healthy(config):
            if not process_matches(broker.get("pid"), broker.get("token")):
                broker = {"pid": None, "token": None, "owned": False}
        else:
            if broker.get("owned"):
                terminate_owned_broker(broker)
            process = start_broker(config)
            if not wait_for_broker(config):
                try:
                    process.terminate()
                except OSError:
                    pass
                raise RuntimeError(
                    f"IDA MCP Broker did not become ready; see {config.broker_log_path}"
                )
            broker_token = get_process_token(process.pid)
            if broker_token is None:
                process.terminate()
                raise RuntimeError("Unable to identify the started IDA MCP Broker")
            broker = {"pid": process.pid, "token": broker_token, "owned": True}

        state["broker"] = broker
        state["clients"] = [
            client for client in state["clients"] if client.get("pid") != client_pid
        ]
        state["clients"].append({"pid": client_pid, "token": client_token})
        write_state(config, state)


def unregister_client(config: LauncherConfig, client_pid: int) -> None:
    with state_lock(config):
        state = read_state(config)
        state["clients"] = [
            client for client in state.get("clients", []) if client.get("pid") != client_pid
        ]
        prune_dead_clients(state)
        if not state["clients"]:
            terminate_owned_broker(state.get("broker", {}))
            state["broker"] = {"pid": None, "token": None, "owned": False}
        write_state(config, state)


# ---------------------------------------------------------------------------
# stdio 通道隔离
#
# 旧实现直接让 ida_pro_mcp_enhanced.server 继承本进程(launcher)的 stdin/stdout/stderr。
# 那些句柄其实是宿主(Node)那头的管道：宿主 kill 掉 launcher 之后，stdin/stdout
# 仍然被孙进程握着，宿主那侧的可读流永远等不到 EOF，"任务收尾"就被拖过 10 秒
# 宽限期(desktop update: graceful deadline exceeded)。
#
# 现在的做法：
#   1. launcher 独占宿主管道，server 只拿到 launcher 建的私有管道，由 launcher
#      在两侧搬运字节 —— 孙进程再也不会继承宿主句柄；
#   2. 把 server 放进 KILL_ON_JOB_CLOSE 的 Job Object，launcher 一旦被硬杀，
#      内核会连带结束 server，不留孤儿；
#   3. 宿主关闭 stdin(EOF) 后给 server 一个短暂收尾窗口，然后主动清理进程树。
# ---------------------------------------------------------------------------


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def create_kill_on_close_job() -> Optional[int]:
    try:
        kernel32 = ctypes.windll.kernel32
    except AttributeError:
        return None
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None
    job_object_limit_kill_on_job_close = 0x2000
    job_object_extended_limit_information = 9
    information = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    information.BasicLimitInformation.LimitFlags = job_object_limit_kill_on_job_close
    ok = kernel32.SetInformationJobObject(
        job,
        job_object_extended_limit_information,
        ctypes.byref(information),
        ctypes.sizeof(information),
    )
    if not ok:
        kernel32.CloseHandle(job)
        return None
    return job


def bind_child_to_job(job: Optional[int], pid: int) -> None:
    if not job:
        return
    process_set_quota = 0x0100
    process_terminate = 0x0001
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(process_set_quota | process_terminate, False, pid)
    if not handle:
        return
    try:
        # 宿主可能已经把这个子进程放进自己的 Job；失败就退回到仅靠管道隔离。
        kernel32.AssignProcessToJobObject(job, handle)
    finally:
        kernel32.CloseHandle(handle)


def terminate_process_tree(pid: int) -> None:
    """强制结束进程及其子进程。"""
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_NO_WINDOW_FLAG,
                check=False,
            )
        else:  # pragma: no cover
            os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _read_available(stream, size: int = 65536) -> bytes:
    """Return whatever bytes are currently available instead of blocking.

    ``BufferedReader.read(n)`` blocks until ``n`` bytes are read or EOF; on a
    stdio pipe that never happens for short JSON-RPC lines, so the relay would
    stall and the host's ``initialize`` message would never reach the server.
    ``read1`` performs at most one raw read and returns immediately.
    """
    read1 = getattr(stream, "read1", None)
    if callable(read1):
        return read1(size)
    return stream.read(size)


def run_stdio_mcp(
    config: LauncherConfig,
    popen: Callable[..., subprocess.Popen] = subprocess.Popen,
) -> int:
    job = create_kill_on_close_job()
    child = popen(
        config.stdio_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        close_fds=True,
        creationflags=_NO_WINDOW_FLAG,
    )
    bind_child_to_job(job, child.pid)

    input_closed = threading.Event()

    def pump_input() -> None:
        try:
            while True:
                chunk = _read_available(sys.stdin.buffer)
                if not chunk:
                    break
                child.stdin.write(chunk)
                child.stdin.flush()
        except (OSError, ValueError):
            pass
        finally:
            try:
                child.stdin.close()
            except (OSError, ValueError):
                pass
            input_closed.set()

    def pump_output(source, sink) -> None:
        try:
            while True:
                chunk = _read_available(source)
                if not chunk:
                    break
                sink.write(chunk)
                sink.flush()
        except (OSError, ValueError):
            pass

    threads = [
        threading.Thread(target=pump_input, name="stdin->server", daemon=True),
        threading.Thread(target=pump_output, args=(child.stdout, sys.stdout.buffer), name="server->stdout", daemon=True),
        threading.Thread(target=pump_output, args=(child.stderr, sys.stderr.buffer), name="server->stderr", daemon=True),
    ]
    for thread in threads:
        thread.start()

    try:
        while child.poll() is None:
            if input_closed.is_set():
                deadline = time.monotonic() + config.eof_grace_seconds
                while child.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                if child.poll() is None:
                    terminate_process_tree(child.pid)
            time.sleep(0.05)
        return child.wait()
    except KeyboardInterrupt:
        terminate_process_tree(child.pid)
        return child.wait()


_CLI_DESCRIPTION = """IDA Pro MCP stdio launcher.

按需拉起共享 broker，注册本客户端，并在宿主断开后清理进程树。
默认行为就是作为 stdio MCP 服务器运行：供 DSH / opencode / 其他 MCP
客户端直接 spawn。

子命令：
  (无)     以 stdio MCP 服务器模式运行（客户端默认调用这条路）
  status   打印 broker 与已注册客户端的状态
  stop     停掉本机拥有的 broker
"""


def _cli_status(config: LauncherConfig) -> int:
    healthy = broker_is_healthy(config)
    state = read_state(config)
    broker = state.get("broker", {})
    print(f"broker_url : {config.broker_url}")
    print(f"healthy    : {healthy}")
    print(f"pid        : {broker.get('pid')}  (owned={broker.get('owned')})")
    live = [
        client
        for client in state.get("clients", [])
        if process_matches(client.get("pid"), client.get("token"))
    ]
    print(f"clients    : {len(live)}")
    for client in live:
        print(f"  - pid {client.get('pid')}")
    print(f"state_dir  : {config.state_dir}")
    print(f"log_dir    : {config.log_dir}")
    return 0


def _cli_stop(config: LauncherConfig) -> int:
    with state_lock(config):
        state = read_state(config)
        broker = state.get("broker", {})
        stopped = terminate_owned_broker(broker)
        state["broker"] = {"pid": None, "token": None, "owned": False}
        write_state(config, state)
    print("broker stopped" if stopped else "no owned broker to stop")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    config = LauncherConfig()

    if args and args[0] in {"-h", "--help", "help"}:
        print(_CLI_DESCRIPTION)
        return 0
    if args and args[0] == "status":
        return _cli_status(config)
    if args and args[0] == "stop":
        return _cli_stop(config)

    client_pid = os.getpid()
    registered = False
    try:
        register_client(config, client_pid)
        registered = True
        return run_stdio_mcp(config)
    except Exception as error:
        print(f"[IDA MCP launcher] {error}", file=sys.stderr, flush=True)
        return 1
    finally:
        if registered:
            unregister_client(config, client_pid)


if __name__ == "__main__":
    raise SystemExit(main())
