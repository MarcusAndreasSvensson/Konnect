#!/usr/bin/env python3
"""Explicit macOS workbench launch; stdlib only, never called by the broker.

python3 -B launch_workbench.py --policy /absolute/policy.json
python3 -B launch_workbench.py --self-test

Uses scoped_mcp.py's EXACT Policy keys. Directories/design/private API-enabled
prefs must already exist; declared external config/runtime files must be absent.
Any previous launch evidence refuses startup: no automatic restart, removal of
locks, kill, launch retry, or socket guess. Parent reconciliation is required.
Runtime is published only after pinned-engine initialize + read-only sole-board
readiness polling, within one shared 60-second launch budget.
Published runtime has exactly six keys: ready, pid, executable, board, socket,
ownership_identity [lstart_string, socket_dev, socket_ino, editor_dev, editor_ino].
Restart Zed's scoped server after changing runtime; it pins runtime/config bytes.
Checks are not an OS sandbox or an atomic defense against another same-uid actor.
"""

import argparse
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
import scoped_mcp as broker

NATIVE = Path("/Applications/KiCad/KiCad.app/Contents/Applications/pcbnew.app/Contents/MacOS/pcbnew")
CLI = Path("/Applications/KiCad/KiCad.app/Contents/MacOS/kicad-cli")
MANAGER = Path("/Applications/KiCad/KiCad.app/Contents/MacOS/kicad")
Denied = broker.Denied


def require(condition, reason):
    if not condition:
        raise Denied(reason)


def canonical(value, label, existing=True):
    path = broker.absolute(str(value), label)
    require(not path.is_symlink() and path.resolve(strict=existing) == path,
            label + " must be canonical, without symlinks")
    return path


class LaunchPolicy:
    """Broker's static policy checks, with unpublished launch outputs kept absent."""

    def __init__(self, filename):
        self.filename = canonical(filename, "policy")
        self.policy_bytes = broker.regular_bytes(self.filename, 65536)
        self.raw = broker.strict_json(self.policy_bytes)
        broker.exact_keys(self.raw, broker.POLICY_PATHS | {"binary_sha256", "writes_enabled"}, "Policy")
        require(type(self.raw["writes_enabled"]) is bool, "writes_enabled must be explicit boolean")
        self.paths = {}
        for key in broker.POLICY_PATHS:
            path = canonical(self.raw[key], key, key not in {"backend_config", "runtime_file"})
            self.paths[key] = path
            setattr(self, key, path)
        require(self.board.parent == self.workspace_root and self.board.suffix == ".kicad_pcb",
                "board must be directly in workspace_root")
        require(self.schematic == self.board.with_suffix(".kicad_sch") and
                self.project == self.board.with_suffix(".kicad_pro"), "designs must be same-stem siblings")
        require(self.library_root != self.workspace_root and self.library_root.is_relative_to(self.workspace_root),
                "library_root must be strictly project-local")
        self.preimages = {"board": self.board, "schematic": self.schematic, "project": self.project,
                          "fp-lib-table": self.workspace_root / "fp-lib-table",
                          "sym-lib-table": self.workspace_root / "sym-lib-table"}
        protected = list(self.preimages.values()) + [self.filename, self.binary, self.backend_config, self.runtime_file]
        require(len(set(protected)) == len(protected), "input/control roles must be distinct")
        for key in ("binary", "backend_config", "runtime_file"):
            require(not self.paths[key].is_relative_to(self.workspace_root), key + " must be external to workspace")
        for role in broker.ROLE_DIRS:
            root = self.paths[role]
            require(not self.workspace_root.is_relative_to(root) and
                    not any(path.is_relative_to(root) for path in protected), "role contains protected input: " + role)
            require(not any(root.is_relative_to(self.paths[other]) for other in broker.ROLE_DIRS - {role}),
                    "overlapping role directories: " + role)
        for path in (self.filename.parent, self.backend_config.parent, self.runtime_file.parent):
            broker.Policy.check_directory(path)
        for executable in (self.binary, NATIVE, CLI, MANAGER):
            canonical(executable, "executable")
            broker.regular_bytes(executable)
            require(os.access(executable, os.X_OK), "executable access denied: " + str(executable))
        before = broker.signature(self.binary.stat())
        require(broker.sha(broker.regular_bytes(self.binary)) == self.raw["binary_sha256"],
                "pinned engine SHA256 mismatch")
        require(before == broker.signature(self.binary.stat()), "engine changed during hash check")
        self.binary_signature = before
        self.native_signature = broker.signature(NATIVE.stat())
        self.config_bytes = self.runtime_bytes = None
        self.check()

    def check(self):
        require(broker.regular_bytes(self.filename, 65536) == self.policy_bytes, "policy changed")
        for role in broker.ROLE_DIRS | {"workspace_root"}:
            broker.Policy.check_directory(self.paths[role])
        for key, path in self.paths.items():
            canonical(path, key, key not in {"backend_config", "runtime_file"})
        for name, path in self.preimages.items():
            canonical(path, name, name in {"board", "schematic", "project"})
            if os.path.lexists(path):
                broker.regular_bytes(path)
        require(broker.signature(self.binary.stat()) == self.binary_signature and
                broker.signature(NATIVE.stat()) == self.native_signature, "pinned executable changed")
        for path, expected in ((self.backend_config, self.config_bytes), (self.runtime_file, self.runtime_bytes)):
            if expected is None:
                require(not os.path.lexists(path), "prior config/runtime exists; inspect, never overwrite: " + str(path))
            else:
                require(broker.regular_bytes(path, 65536) == expected, "launch output changed: " + str(path))
        prefs = canonical(self.prefs_dir / "10.0" / "kicad_common.json", "private API prefs")
        broker.Policy.check_directory(prefs.parent)
        settings = broker.strict_json(broker.regular_bytes(prefs, 65536))
        require(isinstance(settings, dict) and isinstance(settings.get("api"), dict) and
                settings["api"].get("enable_server") is True, "private KiCad API must already be enabled")
        thirdparty = self.documents_dir / "KiCad/10.0/3rdparty"
        canonical(thirdparty, "private third-party directory", existing=False)
        for path in (thirdparty.parent.parent, thirdparty.parent, thirdparty):
            if os.path.lexists(path):
                broker.Policy.check_directory(path)


def left(deadline):
    remaining = deadline - time.monotonic()
    require(remaining > 0, "60-second launch/readiness budget exhausted; inspect retained evidence")
    return remaining


def probe(argv, deadline):
    result = subprocess.run(argv, capture_output=True, text=True, check=False,
                            timeout=min(5, left(deadline)), env={"PATH": broker.PATH_ENV, "LC_ALL": "C"})
    require(result.returncode == 0 and not result.stderr.strip(), "OS ownership probe failed: " + argv[0])
    return result.stdout


def before_spawn(policy, deadline):
    policy.check()
    for path in policy.workspace_root.glob("*.lck"):
        raise Denied("editor lock exists (including stale/dangling locks); parent must reconcile: " + str(path))
    processes = probe(["/bin/ps", "-ww", "-axo", "pid=,command="], deadline)
    require(not any(str(policy.board) in row for row in processes.splitlines()),
            "a process already names the scoped board; no second launch")


def new_stream(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_APPEND, 0o600)
    return os.fdopen(fd, "wb")


def candidates(output, pid):
    """Select names reported by lsof, NEVER derive api-PID names."""
    result, owner, kind = set(), None, None
    for line in output.splitlines():
        if line.startswith("p"):
            owner, kind = int(line[1:]), None
        elif line.startswith("f"):
            kind = None
        elif line.startswith("t"):
            kind = line[1:]
        elif line.startswith("n/") and owner == pid and kind == "unix":
            path = Path(line[1:])
            if path.parent.name == "kicad" and path.name.endswith(".sock"):
                result.add(path)
    return result


class Owned(broker.Ownership):
    def __init__(self, policy, deadline):
        super().__init__(policy, establish_identity=True)
        self.deadline = deadline

    def probe(self, argv):
        return probe(argv, self.deadline)


class ReadinessBackend(broker.Backend):
    """Reuse bounded broker RPCs; shutdown is EOF-only, never a signal/kill."""

    def __init__(self, policy, deadline):
        self.deadline = deadline
        super().__init__(policy)

    def rpc(self, method, params, timeout=20):
        return super().rpc(method, params, timeout=min(timeout, left(self.deadline)))

    def notify(self, method):
        self.send({"jsonrpc": "2.0", "method": method}, self.deadline)

    def close(self):
        self.selector.close()
        process = getattr(self, "process", None)
        stopped = True
        if process is not None:
            if process.stdin:
                process.stdin.close()
            try:
                process.wait(timeout=max(0, min(2, self.deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                stopped = False
            if process.stdout:
                process.stdout.close()
        self.log.close()
        return stopped


def configure(policy, socket):
    config = {"kicad_cli": str(CLI), "kicad_binary": str(MANAGER),
              "project_dir": str(policy.workspace_root), "ipc_address": "ipc://" + str(socket),
              "transport": "stdio", "eager_toolsets": True, "log_level": "warn"}
    broker.exact_keys(config, broker.CONFIG_KEYS, "Backend config")
    policy.config_bytes = broker.encoded(config)
    broker.write_new(policy.backend_config, policy.config_bytes)
    broker.fsync_dir(policy.backend_config.parent)


def open_project_ready(policy, reply):
    """Fail closed on anything except the pinned backend's known startup states."""
    broker.exact_keys(reply, {"result"}, "open_project reply")
    result = broker.rpc_result(reply, "open_project")
    broker.exact_keys(result, {"isError", "content"}, "open_project result")
    content = result["content"]
    require(result["isError"] is False and type(content) is list and len(content) == 1,
            "malformed/error open_project result; no retry")
    broker.exact_keys(content[0], {"type", "text"}, "open_project content")
    require(content[0]["type"] == "text" and type(content[0]["text"]) is str,
            "open_project must return one JSON text block")
    body = broker.strict_json(content[0]["text"])
    identity = {"requested_path": str(policy.board), "requested_board": str(policy.board),
                "ipc_address": policy.endpoint}
    broker.exact_keys(body, set(identity) | {"ipc_available", "kicad_ui_running", "ipc_failure",
                      "open_board_count", "open_boards", "open_boards_error", "requested_open",
                      "requested_check_error", "message"}, "open_project body")
    require(all(type(body[key]) is str and body[key] == value for key, value in identity.items()),
            "open_project request/endpoint identity mismatch; no retry")
    connected, boards = body["ipc_available"], body["open_boards"]
    require(type(connected) is bool and body["kicad_ui_running"] is connected and
            type(body["message"]) is str and type(boards) is list and
            all(type(board) is str for board in boards) and type(body["open_board_count"]) is int and
            body["open_board_count"] == len(boards), "malformed open_project observation; no retry")
    require(len(boards) <= 1 and all(board == str(policy.board) for board in boards),
            "different/ambiguous open PCB document; no retry")

    # ApiStatusError::Display carries the status only in this exact string form.
    def transient(error):
        return (type(error) is str and error.startswith("KiCad IPC error: ") and
                error.endswith((" (AS_NOT_READY)", " (AS_BUSY)")))

    listing_error, check_error = body["open_boards_error"], body["requested_check_error"]
    if not connected:
        require(boards == [] and listing_error is None and check_error is None and
                body["requested_open"] is None, "inconsistent unavailable open_project observation")
        failure = body["ipc_failure"]
        broker.exact_keys(failure, {"kind", "message"}, "open_project ipc_failure")
        require(failure["kind"] == "request_failed" and transient(failure["message"]),
                "IPC failure is not explicit AS_NOT_READY/AS_BUSY; no retry")
        return False

    require(body["ipc_failure"] is None and type(body["requested_open"]) is bool,
            "inconsistent connected open_project observation")
    require(listing_error is None or (boards == [] and transient(listing_error)),
            "open PCB listing failed without explicit AS_NOT_READY/AS_BUSY; no retry")
    no_documents = (f"requested board '{policy.board}' is not open because "
                    "KiCad reports no PCB documents")  # BoardTargetError::NoOpenDocuments
    require((body["requested_open"] is True and check_error is None) or
            (body["requested_open"] is False and (transient(check_error) or check_error == no_documents)),
            "requested PCB check failed/has different-document evidence; no retry")
    if listing_error is None and check_error is None:
        # The two native document queries can straddle initial board readiness.
        return boards == [str(policy.board)]
    return False


def poll_ready(policy, backend, owner, deadline, record):
    attempt = 0
    while True:
        left(deadline)
        owner.verify()
        attempt += 1
        try:
            reply = backend.rpc("tools/call", {"name": "open_project", "arguments": {"path": str(policy.board)}},
                                timeout=min(20, left(deadline)))
            # Retain even a rejected reply, or one followed by ownership loss.
            record({"phase": "open_project", "attempt": attempt, "reply": reply})
        except broker.TransportFailure as error:
            record({"phase": "open_project_error", "attempt": attempt, "error": str(error)})
            raise
        finally:
            owner.verify()
        ready = open_project_ready(policy, reply)
        record({"phase": "open_project_check", "attempt": attempt, "ready": ready, "identity": owner.identity})
        if ready:
            return reply
        time.sleep(min(0.25, left(deadline)))


def prove_ready(policy, process, deadline, record):
    while True:
        left(deadline)
        require(process.poll() is None, "native editor exited; retained logs require inspection")
        sockets = probe(["/usr/sbin/lsof", "-nP", "-U", "-Fptn"], deadline)
        names = candidates(sockets, process.pid)
        require(len(names) <= 1, "multiple owned IPC candidates; no socket selected")
        if names:
            break
        time.sleep(min(0.25, left(deadline)))
    original = names.pop()
    # /tmp is macOS's documented system symlink; no other alias is adopted.
    checked = Path("/private/tmp").joinpath(*original.parts[2:]) if original.parts[:2] == ("/", "tmp") else original
    socket = canonical(checked, "lsof-owned socket")
    broker.Policy.check_directory(socket.parent)
    info = socket.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid() and
            broker.lsof_owners(sockets, socket, unix=True) == {process.pid}, "socket is not solely owned by launched PID")
    require(os.getpgid(process.pid) == process.pid, "native process is not detached in its own process group")
    policy.editor, policy.socket_original, policy.socket = NATIVE, original, socket
    policy.endpoint = "ipc://" + str(original)
    policy.runtime = {"ready": False, "pid": process.pid, "executable": str(NATIVE),
                      "board": str(policy.board), "socket": str(original), "ownership_identity": None}
    owner = Owned(policy, deadline)
    owner.verify()
    record({"phase": "owned_socket", "pid": process.pid, "socket": str(original), "identity": owner.identity})
    configure(policy, original)
    backend = ReadinessBackend(policy, deadline)
    record({"phase": "readiness_backend", "pid": backend.process.pid})
    try:
        initialization_reply = backend.rpc("initialize", {
            "protocolVersion": broker.PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "workbench-launch-readiness", "version": "1"}})
        record({"phase": "initialize", "reply": initialization_reply})
        initialization = broker.rpc_result(initialization_reply, "initialize")
        require(initialization.get("protocolVersion") == broker.PROTOCOL, "unexpected MCP protocol negotiation")
        backend.notify("notifications/initialized")
        reply = poll_ready(policy, backend, owner, deadline, record)
        record({"phase": "ready_proof", "initialize": initialization, "open_project": reply})
    finally:
        stopped = backend.close()
        record({"phase": "backend_eof", "pid": backend.process.pid, "stopped": stopped})
    require(stopped, "readiness backend did not stop on EOF; no kill/retry; inspect recorded PID")
    owner.verify()
    require(process.poll() is None and os.getpgid(process.pid) == process.pid, "native editor ownership lost")
    policy.runtime["ownership_identity"] = list(owner.identity)
    policy.runtime["ready"] = True
    return policy.runtime


def launch(filename):
    require(sys.platform == "darwin", "this launcher is macOS-only")
    deadline = time.monotonic() + 60
    policy = LaunchPolicy(filename)
    evidence = policy.logs_dir / "launch.jsonl"
    stdout_path, stderr_path = policy.logs_dir / "pcbnew.stdout.log", policy.logs_dir / "pcbnew.stderr.log"
    for path in (evidence, stdout_path, stderr_path):
        require(not os.path.lexists(path), "prior launch evidence exists; no blind relaunch: " + str(path))
    before_spawn(policy, deadline)
    journal = broker.Journal(policy)  # Hold exclusive broker mutation lock through publication.
    try:
        require(not journal.blocked, "pending/unknown broker mutation; parent reconciliation required")
        with new_stream(evidence) as events:
            def record(row):
                events.write(broker.encoded({"time_ns": time.time_ns(), **row}))
                events.flush()
                os.fsync(events.fileno())
                broker.fsync_dir(policy.logs_dir)

            record({"phase": "intent", "policy": str(policy.filename), "policy_sha256": broker.sha(policy.policy_bytes),
                    "binary_sha256": policy.raw["binary_sha256"], "argv": [str(NATIVE), str(policy.board)]})
            process = None
            try:
                before_spawn(policy, deadline)
                env = {"PATH": broker.PATH_ENV, "LANG": "en_US.UTF-8", "HOME": str(policy.home_dir),
                       "KICAD_CONFIG_HOME": str(policy.prefs_dir), "KICAD_DOCUMENTS_HOME": str(policy.documents_dir),
                       "KICAD10_3RD_PARTY": str(policy.documents_dir / "KiCad/10.0/3rdparty")}
                with new_stream(stdout_path) as stdout, new_stream(stderr_path) as stderr:
                    left(deadline)
                    process = subprocess.Popen([str(NATIVE), str(policy.board)], cwd=policy.workspace_root,
                                               env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                               start_new_session=True, umask=0o077)
                record({"phase": "spawned", "pid": process.pid})
                runtime = prove_ready(policy, process, deadline, record)
                broker.exact_keys(runtime, broker.RUNTIME_KEYS, "Runtime")
                identity = runtime["ownership_identity"]
                require(type(identity) is list and len(identity) == 5 and type(identity[0]) is str and identity[0] and
                        all(type(value) is int and value >= 0 for value in identity[1:]),
                        "runtime must pin the verified five-part ownership identity")
                require(runtime == {"ready": True, "pid": process.pid, "executable": str(NATIVE),
                                    "board": str(policy.board), "socket": policy.runtime["socket"],
                                    "ownership_identity": policy.runtime["ownership_identity"]}, "runtime identity mismatch")
                policy.check()
                left(deadline)
                policy.runtime_bytes = broker.encoded(runtime)
                broker.write_new(policy.runtime_file, policy.runtime_bytes)
                broker.fsync_dir(policy.runtime_file.parent)
                record({"phase": "published", "runtime_file": str(policy.runtime_file), "runtime": runtime,
                        "instruction": "Restart Zed scoped server: runtime/config are pinned"})
                return runtime
            except BaseException as error:
                record({"phase": "failed", "pid": process.pid if process is not None else None,
                        "error": str(error), "instruction": "No kill/relaunch/retry; inspect retained evidence and locks"})
                raise
    finally:
        journal.close()


def self_test():
    """Offline mocked guards, detachment and readiness; no processes/IPC started."""
    import tempfile
    from unittest import mock

    module = sys.modules[__name__]
    with tempfile.TemporaryDirectory(prefix="workbench-launch-test-") as directory:
        root = Path(directory).resolve()
        raw = {"writes_enabled": False}
        for key in broker.ROLE_DIRS | {"workspace_root"}:
            path = root / key
            if key == "library_root":
                path = root / "workspace_root/library"
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            raw[key] = str(path)
        for key, suffix in (("board", ".kicad_pcb"), ("schematic", ".kicad_sch"), ("project", ".kicad_pro")):
            path = root / ("workspace_root/design" + suffix)
            broker.write_new(path, b"fixture")
            raw[key] = str(path)
        for name in ("engine", "pcbnew", "kicad-cli", "kicad"):
            broker.write_new(root / name, b"mock executable")
            (root / name).chmod(0o700)
        raw.update(binary=str(root / "engine"), binary_sha256=broker.sha(b"mock executable"),
                   backend_config=str(root / "config.json"), runtime_file=str(root / "runtime.json"))
        prefs = root / "prefs_dir/10.0"
        prefs.mkdir(mode=0o700)
        broker.write_new(prefs / "kicad_common.json", broker.encoded({"api": {"enable_server": True}}))
        policy_file = root / "policy.json"
        broker.write_new(policy_file, broker.encoded(raw))
        fake_process = mock.Mock(pid=43210)
        fake_process.poll.return_value = None

        # Match handle_open_project + CallToolResult::json, including null
        # requested_open on failed Ping (NOT false) and isError:false.
        ready_body = {"ipc_available": True, "kicad_ui_running": True,
                      "requested_open": True, "open_board_count": 1, "open_boards": [raw["board"]],
                      "requested_path": raw["board"], "requested_board": raw["board"],
                      "ipc_address": "ipc:///tmp/kicad/api.sock", "ipc_failure": None,
                      "open_boards_error": None, "requested_check_error": None,
                      "message": "The requested board is open in KiCad."}
        not_ready_error = "KiCad IPC error: KiCad is not ready (AS_NOT_READY)"
        unavailable = {**ready_body, "ipc_available": False, "kicad_ui_running": False,
                       "requested_open": None, "open_board_count": 0, "open_boards": [],
                       "ipc_failure": {"kind": "request_failed", "message": not_ready_error},
                       "message": "The KiCad IPC request did not complete and may have reached the endpoint; a KiCad "
                                  "status in ipc_failure proves receipt, and KiCad may still be starting."}
        no_documents = {**ready_body, "requested_open": False, "open_board_count": 0, "open_boards": [],
                        "requested_check_error": f"requested board '{raw['board']}' is not open because KiCad reports no PCB documents",
                        "message": "KiCad IPC is available, but the requested board is not open."}
        busy = {**no_documents, "open_boards_error": "KiCad IPC error: KiCad is busy (AS_BUSY)",
                "requested_check_error": not_ready_error}

        def tool_reply(body):
            return {"result": {"isError": False, "content": [
                {"type": "text", "text": broker.encoded(body).decode().rstrip("\n")}]}}

        startup_transition = {**ready_body, "open_boards": [], "open_board_count": 0}
        observations = (unavailable, no_documents, busy, startup_transition, ready_body)
        synthetic_identity = ["Mon Oct 5 12:00:00 2026", 1, 2, 3, 4]
        backend, owner = mock.Mock(), mock.Mock(identity=synthetic_identity)
        backend.rpc.side_effect = [tool_reply(body) for body in observations]

        def ready(policy, process, deadline, record):
            configure(policy, Path("/tmp/kicad/api.sock"))
            policy.endpoint = ready_body["ipc_address"]
            policy.runtime = {"ready": False, "pid": process.pid, "executable": str(NATIVE),
                              "board": str(policy.board), "socket": "/tmp/kicad/api.sock", "ownership_identity": None}
            poll_ready(policy, backend, owner, deadline, record)
            policy.runtime["ownership_identity"] = list(owner.identity)
            policy.runtime["ready"] = True
            return policy.runtime

        with mock.patch.object(sys, "platform", "darwin"), \
             mock.patch.object(module, "NATIVE", root / "pcbnew"), \
             mock.patch.object(module, "CLI", root / "kicad-cli"), \
             mock.patch.object(module, "MANAGER", root / "kicad"), \
             mock.patch.object(module, "probe", return_value="") as os_probe, \
             mock.patch.object(module, "prove_ready", side_effect=ready), \
             mock.patch.object(time, "sleep") as sleep, \
             mock.patch.object(subprocess, "Popen", return_value=fake_process) as popen:
            blockers = [root / "runtime.json", root / "config.json", root / "logs_dir/launch.jsonl",
                        root / "workspace_root/~design.kicad_pcb.lck"]
            for blocker in blockers:
                broker.write_new(blocker, b"prior/live/stale evidence")
                try:
                    launch(policy_file)
                    raise AssertionError("spawn guard did not refuse")
                except Denied:
                    pass
                popen.assert_not_called()
                blocker.unlink()  # Fixture cleanup ONLY; launcher never removes locks/evidence.
            mutation = root / "logs_dir/mutations.jsonl"
            for rows in ([{"call": "x", "phase": "request"}],
                         [{"call": "x", "phase": "request"}, {"call": "x", "phase": "unknown"}]):
                broker.write_new(mutation, b"".join(broker.encoded(row) for row in rows))
                try:
                    launch(policy_file)
                    raise AssertionError("uncertain mutation guard did not refuse")
                except Denied:
                    pass
                popen.assert_not_called()
                mutation.unlink()
            os_probe.return_value = "123 " + str(root / "pcbnew") + " " + raw["board"]
            try:
                launch(policy_file)
                raise AssertionError("live-board process guard did not refuse")
            except Denied:
                pass
            popen.assert_not_called()
            os_probe.return_value = ""
            test_policy = mock.Mock(board=Path(raw["board"]), endpoint=ready_body["ipc_address"])
            with mock.patch.object(broker.Ownership, "__init__", return_value=None) as bootstrap:
                Owned(test_policy, time.monotonic() + 60)
                bootstrap.assert_called_once_with(test_policy, establish_identity=True)
            assert open_project_ready(test_policy, tool_reply(startup_transition)) is False
            assert open_project_ready(test_policy, tool_reply(ready_body)) is True
            wrong_board = str(root / "workspace_root/other.kicad_pcb")
            wrong_document = {**ready_body, "open_boards": [wrong_board], "requested_open": False,
                              "requested_check_error": not_ready_error, "message": no_documents["message"]}
            wrong_check = {**ready_body, "requested_open": False, "message": no_documents["message"],
                           "requested_check_error": f"requested board '{raw['board']}' is not open in KiCad (open boards: {wrong_board})"}
            bad_failure = {**unavailable, "ipc_failure": {"kind": "request_failed", "message": "receive timed out"}}
            refused = [tool_reply(body) for body in (wrong_document, wrong_check, bad_failure,
                       {**ready_body, "open_board_count": True})]
            refused.append({"result": {"isError": False, "content": [{"type": "text", "text": "not JSON"}]}})
            for reply in refused:
                reader, ownership, rows = mock.Mock(), mock.Mock(identity=synthetic_identity), []
                reader.rpc.return_value = reply
                sleep.reset_mock()
                try:
                    poll_ready(test_policy, reader, ownership, time.monotonic() + 60, rows.append)
                    raise AssertionError("unsafe readiness reply was retried/accepted")
                except ValueError:  # Includes strict_json's JSONDecodeError and Denied.
                    pass
                reader.rpc.assert_called_once()
                assert ownership.verify.call_count == 2 and rows[0]["reply"] == reply
                sleep.assert_not_called()
            reader.rpc.side_effect = broker.TransportFailure("broken backend pipe")
            reader.rpc.reset_mock()
            try:
                poll_ready(test_policy, reader, ownership, time.monotonic() + 60, rows.append)
                raise AssertionError("transport failure was retried")
            except broker.TransportFailure:
                pass
            reader.rpc.assert_called_once()
            assert rows[-1]["phase"] == "open_project_error"
            sleep.assert_not_called()
            reader.rpc.reset_mock()
            reader.rpc.side_effect = None
            reader.rpc.return_value = tool_reply(ready_body)
            ownership.verify.side_effect = [None, Denied("ownership lost")]
            try:
                poll_ready(test_policy, reader, ownership, time.monotonic() + 60, rows.append)
                raise AssertionError("ownership loss accepted/retried")
            except Denied as error:
                assert "ownership lost" in str(error)
            reader.rpc.assert_called_once()
            assert rows[-1]["reply"] == tool_reply(ready_body)
            sleep.assert_not_called()

            runtime = launch(policy_file)
            popen.assert_called_once()
            assert backend.rpc.call_count == len(observations) and owner.verify.call_count == 2 * len(observations)
            for call in backend.rpc.call_args_list:
                args, kwargs = call
                assert args == ("tools/call", {"name": "open_project", "arguments": {"path": raw["board"]}})
                assert 0 < kwargs["timeout"] <= 20
            args, kwargs = popen.call_args
            assert args == ([str(root / "pcbnew"), raw["board"]],)
            assert kwargs["stdin"] == subprocess.DEVNULL and kwargs["start_new_session"] is True
            assert kwargs["stdout"] != subprocess.PIPE and kwargs["stderr"] != subprocess.PIPE
            assert kwargs["umask"] == 0o077 and kwargs["cwd"] == Path(raw["workspace_root"])
            assert set(kwargs["env"]) == {"PATH", "LANG", "HOME", "KICAD_CONFIG_HOME", "KICAD_DOCUMENTS_HOME", "KICAD10_3RD_PARTY"}
            assert set(runtime) == broker.RUNTIME_KEYS == {"ready", "pid", "executable", "board", "socket", "ownership_identity"}
            assert runtime["ready"] is True and runtime["ownership_identity"] == synthetic_identity
            assert runtime["ownership_identity"] is not owner.identity
            assert broker.strict_json((root / "runtime.json").read_bytes()) == runtime
            for path in (root / "runtime.json", root / "config.json", root / "logs_dir/launch.jsonl",
                         root / "logs_dir/pcbnew.stdout.log", root / "logs_dir/pcbnew.stderr.log"):
                assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert candidates("p43210\nf3\ntunix\nn/tmp/kicad/api.sock\n", 43210) == {Path("/tmp/kicad/api.sock")}
            rows = [broker.strict_json(line) for line in (root / "logs_dir/launch.jsonl").read_bytes().splitlines()]
            assert [row["reply"] for row in rows if row["phase"] == "open_project"] == [
                tool_reply(body) for body in observations]
            assert [row["ready"] for row in rows if row["phase"] == "open_project_check"] == [False, False, False, False, True]

            # Fixture cleanup only; simulate the shared deadline expiring while
            # waiting after a valid startup refusal. No publication/second spawn.
            for path in (root / "runtime.json", root / "config.json", root / "logs_dir/launch.jsonl",
                         root / "logs_dir/pcbnew.stdout.log", root / "logs_dir/pcbnew.stderr.log"):
                path.unlink()
            popen.reset_mock()
            backend.rpc.side_effect = None
            backend.rpc.return_value = tool_reply(unavailable)
            backend.rpc.reset_mock()
            with mock.patch.object(time, "monotonic", return_value=0) as clock, \
                 mock.patch.object(time, "sleep", side_effect=lambda seconds: setattr(clock, "return_value", 60)):
                try:
                    launch(policy_file)
                    raise AssertionError("expired readiness budget was published")
                except Denied as error:
                    assert "budget exhausted" in str(error)
            popen.assert_called_once()
            backend.rpc.assert_called_once()
            assert not (root / "runtime.json").exists()
            rows = [broker.strict_json(line) for line in (root / "logs_dir/launch.jsonl").read_bytes().splitlines()]
            assert rows[-1]["phase"] == "failed" and rows[-1]["pid"] == fake_process.pid
            assert any(row["phase"] == "open_project" and row["reply"] == tool_reply(unavailable) for row in rows)
            assert not any(row["phase"] == "published" for row in rows)
            try:
                launch(policy_file)
                raise AssertionError("failed-launch evidence allowed a second spawn")
            except Denied:
                pass
            popen.assert_called_once()
    print("PASS: mocked guards/detachment, ownership bootstrap + six-field runtime, startup readiness polling"
          " including empty-list/true transition, fail-closed replies and deadline exhaustion without"
          " publication/second spawn; no actual spawn/IPC")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        if args.policy is not None:
            parser.error("--self-test and --policy are mutually exclusive")
        self_test()
    else:
        if args.policy is None:
            parser.error("--policy is required; there is no arbitrary board argument")
        try:
            runtime = launch(args.policy)
            sys.stdout.buffer.write(broker.encoded(runtime))
            print("Restart Zed's scoped server before use; runtime/config are pinned.", file=sys.stderr)
        except (OSError, ValueError, broker.TransportFailure, subprocess.SubprocessError) as error:
            print("Workbench launch refused/failed: " + str(error) + "; inspect evidence, no blind retry", file=sys.stderr)
            raise SystemExit(1) from error


if __name__ == "__main__":
    main()
