#!/usr/bin/env python3
"""Default-deny, single-workspace stdio MCP bridge (Python 3.10+, stdlib only).

Usage: python3 -B scoped_mcp.py --policy /absolute/policy.json
       python3 -B scoped_mcp.py --self-test

The parent qualifies/releases Konnect, creates the directories/design, and owns
KiCad's launch and runtime lifecycle. This program NEVER launches KiCad. This is
an MCP authorization boundary, NOT an OS sandbox: the backend/CLI retain this
account's privileges, and installed library/model resources can still be read.
Filesystem/process checks cannot atomically freeze a GUI or defeat a malicious
same-user process. Do not concurrently change documents during a mutation.

Policy is a JSON object with EXACTLY these required fields (no defaults):
  binary:           absolute executable Konnect file
  binary_sha256:    its lowercase, 64-character SHA256
  backend_config:   absolute existing backend JSON configuration file
  workspace_root:   absolute existing directory; also backend project_dir
  board:            exact existing workspace_root/<stem>.kicad_pcb
  schematic:        exact existing workspace_root/<stem>.kicad_sch
  project:          exact existing workspace_root/<stem>.kicad_pro
  exports_root:     existing directory for NEW export files/directories only
  library_root:     existing project-local directory strictly below workspace_root
  home_dir:         existing private backend HOME
  prefs_dir:        existing private KICAD_CONFIG_HOME
  documents_dir:    existing private KICAD_DOCUMENTS_HOME
  runtime_file:     absolute existing immutable runtime JSON file, described below
  backups_dir:      existing directory for new per-call preimages/request manifests
  logs_dir:         existing directory for mutations.jsonl, backend stderr, CLI temps
  writes_enabled:   boolean, explicitly supplied AFTER the parent's gates
All paths are absolute. Roles must be distinct/non-overlapping; role directories
may be below the workspace, but cannot contain it or protected inputs. Designs
must be same-stem siblings. Files may not be symlinks/hardlinks; resolved roots
and all known inputs are rechecked. Directories must be owned by this uid and not
group/other writable. No directories are provisioned by the connector.

backend_config accepts only the repository's probe-config fields:
  kicad_cli, kicad_binary: existing absolute executable files (parent-qualified)
  project_dir: exactly workspace_root
  ipc_address: exactly "ipc://" + runtime.socket (no auto detection)
  transport: "stdio"; eager_toolsets: true; log_level: error/warn/info/debug/trace
All seven fields are required. Policy/configuration/runtime contents are pinned for the
session. The backend gets a minimal environment, fixed system PATH, the three
private directories, private third-party directory, and TMPDIR=logs_dir. No
inherited API socket/token, loader variables, or user configuration overrides.

runtime_file is EXACTLY {"ready": true, "pid": <positive integer>,
 "executable": "/absolute/native/pcbnew", "board": "<exact policy board>",
 "socket": "/absolute/owned/unix/socket", "ownership_identity": [<lstart string>,
 <socket device>, <socket inode>, <editor device>, <editor inode>]}.
All six fields are required. ownership_identity must be a nonempty bounded string
followed by four nonnegative JSON integers (not booleans); null is never admitted.
The parent must launch precisely [executable, board], using the canonical policy
board path. Ownership checks are macOS /bin/ps (uid, exact command, stable process
start) and /usr/sbin/lsof (executable text mapping, sole named Unix socket owner),
plus socket uid/inode. Persisted launch identity is checked from the FIRST probe,
including after broker restarts; only explicit launcher bootstrap can establish it
before runtime publication. /tmp's system symlink is resolved, but the configured
endpoint string is exact. Ownership loss is latched; even saved/offline queries
then fail closed. No backend respawn, socket reselection, automatic retry, or
mutation replay.

Schemas come from the pinned backend's eager tools/list, NOT invented schemas.
The reviewed property-name contract below is from konnect-core/src/tools:
 project.rs, pcb_board.rs, board_stackup.rs, pcb_components.rs, pcb_routing.rs,
 sch_components.rs, sch_export.rs, library.rs, verification.rs, manufacturing.rs;
 plus router/meta_tools.rs and editor_navigation.rs. Discovery and dispatch use
one tightened schema catalog; unknown methods/tools/keys (including nested
record keys) are denied. board/schematic/path/project_dir are const-bound.

Inspection: the old connector's 13 tools + query_traces/search_footprints/
get_board_2d_view. Sync dry-run is also available without writes. Apply requires
an explicit expected_plan_revision equal to the latest successful ready/noop
dry-run returned through THIS session. Echoing it is review acknowledgement,
not proof of human review; the backend also validates its current revision.
Any forwarded write invalidates that acknowledgement. With writes disabled,
sync is const dry_run=true and DRC is const sync_live_board=false, with report
output arguments removed. ERC without output is also analysis-only.

Writes: update_pcb_from_schematic, edit_schematic_component,
set_component_placements, move_component, route_trace, modify_trace,
delete_trace, add_via, add_zone, add_board_outline, save_project; run_drc with
sync_live_board or output; run_erc with output; export_gerber (includes drills),
export_3d (STEP ONLY), export_bom, export_position_file,
export_manufacturing_package. Corrections-file input is deliberately not exposed.
Exports need new destinations below exports_root: .json for DRC/ERC, .step/.stp
for STEP, .csv for BOM/CSV positions, .gbr for Gerber positions; directory outputs
must also be new. Relative output paths are relative to workspace_root.
Single-root schematics only: hierarchical sheets are refused because their files
are not named by this exact-file policy. Library creation/registration, global
library management, configuration, resources, toolset loading, GUI actions,
RunAction and Undo are DEFERRED/BLOCKED (not backend native-action aliases).

Every tool call checks ownership and preflights backend open_project against the
sole exact board. Every write, INCLUDING argless save, does so again immediately
before forwarding, after fsynced board/schematic/project/fp-lib-table/sym-lib-table
preimages (absent tables recorded), a new request manifest, and a fsynced journal
request. Preimages cover SAVED files, not unsaved live editor state. Schematic
file edits refuse both ~<filename>.lck and <filename>.lck, even dangling links.
The serialized journal is exclusively flocked. An outstanding request, transport
failure, uncertain backend classification, or unclassified mutation error blocks
further writes, including across restarts. Responses/classifications are passed
through unchanged and journaled. Parent reconciliation must archive/repair the
journal or supply a new logs directory; there is no MCP reset/restore facility.

Bounds: 16 MiB JSON-RPC frames, 64 MiB saved files/journal, 5s OS probes, 20s
preflight, 90s tool RPCs, 180s exports/render. Pipe writes ALSO have deadlines.
Cancellation notifications are validated but ignored (no in-flight interrupt).
A timeout cannot establish non-delivery; killing the owned backend is not rollback.
"""

import argparse
import copy
import fcntl
import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

MAX_FRAME = 16 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
PATH_ENV = "/usr/bin:/bin:/usr/sbin:/sbin"
PROTOCOL = "2025-06-18"

# Property names copied from the actual repository schemas, not tool prose.
READ_TOOLS = {
    "get_installation_info": "",
    "check_kicad_ui": "timeout_seconds",
    "get_editor_state": "",
    "open_project": "path",
    "get_board_info": "board",
    "get_layer_list": "board board_source",
    "get_board_stackup": "board expected",
    "get_board_extents": "board board_source",
    "get_component_list": "board",
    "get_component_pads": "board reference",
    "find_component": "board reference",
    "get_pad_position": "board reference pad_number",
    "get_nets_list": "board",
    "query_traces": "board net_name layer",
    "search_footprints": "query limit project_dir",
    "get_board_2d_view": "board width height",
}
WRITE_TOOLS = {
    "update_pcb_from_schematic": "schematic board dry_run expected_plan_revision",
    "edit_schematic_component": "schematic reference new_reference value footprint datasheet fields field_placements unit",
    "set_component_placements": "board placements",
    "move_component": "board reference x y",
    "route_trace": "board net_name layer x1 y1 x2 y2 width",
    "modify_trace": "board uuid net_name layer x1 y1 x2 y2 width",
    "delete_trace": "board uuid",
    "add_via": "board net_name x y drill pad_size",
    "add_zone": "board net_name layer points clearance min_width name priority pad_connection",
    "add_board_outline": "board x1 y1 x2 y2 corner_radius",
    "save_project": "",
}
EXPORT_TOOLS = {
    "run_drc": "board output sync_live_board refill_zones severity limit",
    "run_erc": "schematic output severity",
    "export_gerber": "board output_dir layers drill_file",
    "export_3d": "board output format include_unspecified",
    "export_bom": "schematic output format fields labels group_by exclude_dnp",
    "export_position_file": "board output format side units",
    "export_manufacturing_package": "board schematic output_dir fab_house include_assembly bom_fields bom_labels bom_group_by gerber_layers position_side position_units jlcpcb_cpl_corrections_path",
}
TOOL_KEYS = {name: set(keys.split()) for name, keys in
             {**READ_TOOLS, **WRITE_TOOLS, **EXPORT_TOOLS}.items()}
POLICY_PATHS = {
    "binary", "backend_config", "workspace_root", "board", "schematic", "project",
    "exports_root", "library_root", "home_dir", "prefs_dir", "documents_dir",
    "runtime_file", "backups_dir", "logs_dir",
}
ROLE_DIRS = {"exports_root", "library_root", "home_dir", "prefs_dir",
             "documents_dir", "backups_dir", "logs_dir"}
CONFIG_KEYS = {"kicad_cli", "kicad_binary", "project_dir", "ipc_address",
               "transport", "eager_toolsets", "log_level"}
RUNTIME_KEYS = {"ready", "pid", "executable", "board", "socket", "ownership_identity"}


class Denied(ValueError):
    pass


class TransportFailure(RuntimeError):
    pass


def encoded(value):
    return (json.dumps(value, allow_nan=False, separators=(",", ":")) + "\n").encode()


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Denied("Duplicate JSON key: " + key)
            result[key] = value
        return result

    def constant(value):
        raise Denied("Non-finite JSON constant: " + value)

    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def exact_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != keys:
        raise Denied(label + " must contain exactly: " + ", ".join(sorted(keys)))


def text(value, label):
    if not isinstance(value, str) or not value or len(value) > 16384 or any(ord(c) < 32 for c in value):
        raise Denied(label + " must be a nonempty bounded string without control characters")
    return value


def absolute(value, label):
    path = Path(text(value, label))
    if not path.is_absolute() or ".." in path.parts:
        raise Denied(label + " must be absolute without '..'")
    return path


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def regular_bytes(path, limit=MAX_FILE):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise Denied("Expected bounded, non-hardlinked regular file: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise Denied("Expected bounded, non-hardlinked regular file: " + str(path))
        data = stream.read(limit + 1)
        if len(data) > limit or signature(before) != signature(os.fstat(stream.fileno())):
            raise Denied("File changed during read or exceeds bound: " + str(path))
        return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class Policy:
    binary: Path
    backend_config: Path
    workspace_root: Path
    board: Path
    schematic: Path
    project: Path
    exports_root: Path
    library_root: Path
    home_dir: Path
    prefs_dir: Path
    documents_dir: Path
    runtime_file: Path
    backups_dir: Path
    logs_dir: Path

    def __init__(self, filename):
        self.filename = absolute(str(filename), "policy").resolve(strict=True)
        self.policy_bytes = regular_bytes(self.filename, 65536)
        raw = strict_json(self.policy_bytes)
        exact_keys(raw, POLICY_PATHS | {"binary_sha256", "writes_enabled"}, "Policy")
        if type(raw["writes_enabled"]) is not bool:
            raise Denied("writes_enabled must be a boolean")
        if not isinstance(raw["binary_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", raw["binary_sha256"]):
            raise Denied("binary_sha256 must be lowercase SHA256")
        self.writes_enabled = raw["writes_enabled"]
        self.paths = {}
        self.original_paths = {}
        for key in POLICY_PATHS:
            original = absolute(raw[key], key)
            if original.is_symlink():
                raise Denied("Policy role cannot be a symlink: " + key)
            self.original_paths[key] = original
            self.paths[key] = original.resolve(strict=True)
            setattr(self, key, self.paths[key])
        if self.board.parent != self.workspace_root or self.board.suffix != ".kicad_pcb":
            raise Denied("board must be an exact .kicad_pcb directly in workspace_root")
        if self.schematic != self.board.with_suffix(".kicad_sch") or self.project != self.board.with_suffix(".kicad_pro"):
            raise Denied("board, schematic and .kicad_pro must be same-stem workspace siblings")
        if self.library_root == self.workspace_root or not self.library_root.is_relative_to(self.workspace_root):
            raise Denied("library_root must be strictly project-local")
        self.preimages = {
            "board.kicad_pcb": self.board,
            "schematic.kicad_sch": self.schematic,
            "project.kicad_pro": self.project,
            "fp-lib-table": self.workspace_root / "fp-lib-table",
            "sym-lib-table": self.workspace_root / "sym-lib-table",
        }
        protected = list(self.preimages.values()) + [self.filename, self.binary, self.backend_config, self.runtime_file]
        for role in ROLE_DIRS:
            root = self.paths[role]
            if self.workspace_root.is_relative_to(root) or any(p.is_relative_to(root) for p in protected):
                raise Denied("Role directory contains protected input: " + role)
            for other in ROLE_DIRS - {role}:
                if root.is_relative_to(self.paths[other]):
                    raise Denied("Role directories must not overlap: " + role + "/" + other)
        control_files = [self.filename, self.binary, self.backend_config, self.runtime_file]
        if len(set(control_files + list(self.preimages.values()))) != len(control_files) + len(self.preimages):
            raise Denied("Input/control file roles must be distinct")
        for key in ("binary", "backend_config", "runtime_file"):
            if self.paths[key].is_relative_to(self.workspace_root):
                raise Denied(key + " must be outside the active workspace")
        for role in ROLE_DIRS | {"workspace_root"}:
            self.check_directory(self.paths[role])
        for path in (self.board, self.schematic, self.project):
            regular_bytes(path)
        before_binary = signature(self.binary.stat())
        if not os.access(self.binary, os.X_OK) or sha(regular_bytes(self.binary)) != raw["binary_sha256"]:
            raise Denied("Backend executable SHA256/access check failed")
        self.binary_signature = signature(self.binary.stat())
        if self.binary_signature != before_binary:
            raise Denied("Backend executable changed while checking its SHA256")
        self.config_bytes = regular_bytes(self.backend_config, 65536)
        self.runtime_bytes = regular_bytes(self.runtime_file, 65536)
        self.config = strict_json(self.config_bytes)
        self.runtime = strict_json(self.runtime_bytes)
        exact_keys(self.config, CONFIG_KEYS, "Backend config")
        exact_keys(self.runtime, RUNTIME_KEYS, "Runtime")
        if self.runtime["ready"] is not True or type(self.runtime["pid"]) is not int or self.runtime["pid"] <= 0:
            raise Denied("Runtime must be ready with a positive integer owned PID")
        identity = self.runtime["ownership_identity"]
        if (type(identity) is not list or len(identity) != 5 or type(identity[0]) is not str or
                any(type(value) is not int or value < 0 for value in identity[1:])):
            raise Denied("Runtime ownership_identity must be a five-item list: lstart string and four nonnegative integers")
        text(identity[0], "runtime.ownership_identity.lstart")
        if self.runtime["board"] != str(self.board):
            raise Denied("Runtime board must exactly match the policy")
        self.editor = absolute(self.runtime["executable"], "runtime.executable")
        if self.editor != self.editor.resolve(strict=True) or not os.access(self.editor, os.X_OK):
            raise Denied("Native executable must be canonical and executable")
        regular_bytes(self.editor)
        self.socket_original = absolute(self.runtime["socket"], "runtime.socket")
        if self.socket_original.is_symlink():
            raise Denied("Socket itself cannot be a symlink")
        self.socket = self.socket_original.resolve(strict=True)
        self.endpoint = "ipc://" + self.runtime["socket"]
        if self.config["ipc_address"] != self.endpoint or self.config["project_dir"] != str(self.workspace_root):
            raise Denied("Backend endpoint/project_dir must match the exact runtime/workspace")
        if self.config["transport"] != "stdio" or self.config["eager_toolsets"] is not True:
            raise Denied("Backend must use eager stdio only")
        if self.config["log_level"] not in {"error", "warn", "info", "debug", "trace"}:
            raise Denied("Invalid backend log_level")
        for key in ("kicad_cli", "kicad_binary"):
            path = absolute(self.config[key], key)
            if path != path.resolve(strict=True) or not os.access(path, os.X_OK):
                raise Denied(key + " must be a canonical executable")
            regular_bytes(path)
        self.check()

    @staticmethod
    def check_directory(path):
        if path.is_symlink() or path.resolve(strict=True) != path:
            raise Denied("Directory symlink/identity changed: " + str(path))
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise Denied("Expected owned, non-group/other-writable directory: " + str(path))

    def check(self):
        if regular_bytes(self.filename, 65536) != self.policy_bytes:
            raise Denied("Parent policy changed; this session cannot keep using stale authorization")
        for key, path in self.paths.items():
            if self.original_paths[key].is_symlink() or self.original_paths[key].resolve(strict=True) != path:
                raise Denied("Policy path identity changed: " + key)
        for role in ROLE_DIRS | {"workspace_root"}:
            self.check_directory(self.paths[role])
        if signature(self.binary.stat()) != self.binary_signature:
            raise Denied("Pinned backend executable changed; parent requalification required")
        if regular_bytes(self.backend_config, 65536) != self.config_bytes or regular_bytes(self.runtime_file, 65536) != self.runtime_bytes:
            raise Denied("Pinned backend config/runtime changed; no reconnect permitted")
        for name, path in self.preimages.items():
            if path.resolve(strict=False) != path or path.is_symlink():
                raise Denied("Design/library-table symlink refused: " + name)
            if name.endswith((".kicad_pcb", ".kicad_sch", ".kicad_pro")) or path.exists():
                info = path.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise Denied("Design/library table must be an unaliased regular file: " + name)

    def output(self, value, suffixes=None, directory=False):
        path = Path(text(value, "output"))
        if ".." in path.parts:
            raise Denied("Output traversal is forbidden")
        path = path if path.is_absolute() else self.workspace_root / path
        if path == self.exports_root or not path.is_relative_to(self.exports_root):
            raise Denied("Output must be strictly below exports_root")
        if path.resolve(strict=False) != path or path.is_symlink():
            raise Denied("Output symlinks/escape are forbidden")
        if os.path.lexists(path):
            raise Denied("Output must be NEW; existing destinations are never overwritten")
        if not directory:
            if suffixes is None:
                raise Denied("No reviewed output-file role for this tool")
            if path.suffix.lower() not in suffixes:
                raise Denied("Wrong export extension; expected " + "/".join(sorted(suffixes)))
        return str(path)

    def schematic_guard(self, editing=False):
        if editing:
            for name in ("~" + self.schematic.name + ".lck", self.schematic.name + ".lck"):
                if os.path.lexists(self.workspace_root / name):
                    raise Denied("Schematic editor lock exists; file edits are refused: " + name)
        source = regular_bytes(self.schematic).decode("utf-8")
        # Ignore quoted strings/comments, then reject unlisted hierarchical files.
        atoms = re.sub(r'"(?:\\.|[^"\\])*"|;[^\n]*', '""', source)
        if re.search(r"\(\s*sheet(?:\s|\))", atoms):
            raise Denied("Hierarchical schematic files are outside this exact-file policy")


def lsof_owners(output, target, unix=False):
    owners = set()
    pid, kind = None, None
    for line in output.splitlines():
        if line.startswith("p"):
            pid, kind = int(line[1:]), None
        elif line.startswith("f"):
            kind = None
        elif line.startswith("t"):
            kind = line[1:]
        elif line.startswith("n/") and (not unix or kind == "unix") and Path(line[1:]).resolve(strict=False) == target:
            owners.add(pid)
    return owners


class Ownership:
    """Verify pinned launch identity from the first probe; establishment is launcher-only."""

    def __init__(self, policy, establish_identity=False):
        self.policy = policy
        self.establish_identity = establish_identity is True
        self.identity = None
        self.invalid = False

    @staticmethod
    def probe(argv):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5, check=False,
                                env={"PATH": PATH_ENV, "LC_ALL": "C"})
        if result.returncode != 0 or result.stderr.strip():
            raise Denied("Ownership probe failed: " + argv[0])
        return result.stdout

    def verify(self):
        if self.invalid:
            raise Denied("Ownership was lost; this session cannot reconnect")
        try:
            p = self.policy
            p.check()
            if p.socket_original.is_symlink() or p.socket_original.resolve(strict=True) != p.socket:
                raise Denied("Runtime socket path changed")
            before = p.socket.stat()
            if not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.getuid():
                raise Denied("Runtime endpoint is not an owned Unix socket")
            pid = p.runtime["pid"]
            fields = self.probe(["/bin/ps", "-ww", "-p", str(pid), "-o", "uid=", "-o", "lstart=", "-o", "command="]).strip().split(None, 6)
            if len(fields) != 7 or fields[0] != str(os.getuid()) or fields[6] != str(p.editor) + " " + str(p.board):
                raise Denied("PID/uid/executable/board command ownership does not match")
            mappings = self.probe(["/usr/sbin/lsof", "-nP", "-a", "-p", str(pid), "-d", "txt", "-Fpn"])
            if lsof_owners(mappings, p.editor) != {pid}:
                raise Denied("PID does not map the exact owned native executable")
            sockets = self.probe(["/usr/sbin/lsof", "-nP", "-U", "-Fptn"])
            if lsof_owners(sockets, p.socket, unix=True) != {pid}:
                raise Denied("IPC socket is not solely owned by the exact runtime PID")
            after = p.socket.stat()
            if signature(before) != signature(after):
                raise Denied("Socket changed during ownership checks")
            identity = (" ".join(fields[1:6]), before.st_dev, before.st_ino,
                        p.editor.stat().st_dev, p.editor.stat().st_ino)
            expected = p.runtime["ownership_identity"]
            if expected is None:
                if not self.establish_identity:
                    raise Denied("Persisted ownership identity is required; bootstrap is launcher-only")
            elif identity != tuple(expected):
                raise Denied("Owned process/socket identity differs from pinned launch (possible PID/socket reuse)")
            if self.identity is not None and identity != self.identity:
                raise Denied("Owned process/socket identity changed (possible PID/socket reuse)")
            if expected is None:
                p.runtime["ownership_identity"] = list(identity)
            self.identity = identity
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            self.invalid = True
            raise Denied("Owned runtime unavailable: " + str(error)) from error


# Only the simple schema vocabulary actually used by this reviewed tool set.
SCHEMA_KEYS = {"type", "properties", "required", "additionalProperties", "items",
               "minItems", "maxItems", "minLength", "maxLength", "minimum", "maximum",
               "exclusiveMinimum", "exclusiveMaximum", "enum", "const", "description",
               "default", "title"}


def close_schema(schema):
    if not isinstance(schema, dict) or set(schema) - SCHEMA_KEYS:
        raise Denied("Unreviewed upstream schema vocabulary")
    if schema.get("type") == "object" or "properties" in schema:
        schema.setdefault("additionalProperties", False)
        for child in schema.get("properties", {}).values():
            close_schema(child)
        additional = schema["additionalProperties"]
        if isinstance(additional, dict):
            close_schema(additional)
    if "items" in schema:
        close_schema(schema["items"])


def validate(value, schema, label="arguments", depth=0):
    if depth > 32:
        raise Denied("Argument nesting exceeds bound")
    kind = schema.get("type")
    checks = {"object": lambda: isinstance(value, dict), "array": lambda: isinstance(value, list),
              "string": lambda: isinstance(value, str), "boolean": lambda: type(value) is bool,
              "integer": lambda: type(value) is int,
              "number": lambda: type(value) in (int, float) and math.isfinite(value)}
    try:
        valid_type = kind is None or (kind in checks and checks[kind]())
    except OverflowError:
        valid_type = False
    if not valid_type:
        raise Denied(label + " has the wrong type or is outside numeric bounds")
    if "const" in schema and (type(value) is not type(schema["const"]) or value != schema["const"]):
        raise Denied(label + " violates its scope const")
    if "enum" in schema and value not in schema["enum"]:
        raise Denied(label + " is not an allowed value")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        if set(schema.get("required", [])) - set(value):
            raise Denied(label + " is missing required keys")
        additional = schema.get("additionalProperties", False)
        for key, child in value.items():
            if key not in props and additional is False:
                raise Denied(label + " has an unknown key: " + key)
            child_schema = props.get(key, additional if isinstance(additional, dict) else {})
            validate(child, child_schema, label + "." + key, depth + 1)
    elif isinstance(value, list):
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 10000):
            raise Denied(label + " has an invalid item count")
        for index, child in enumerate(value):
            validate(child, schema.get("items", {}), label + "[" + str(index) + "]", depth + 1)
    elif isinstance(value, str):
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 16384) or "\0" in value:
            raise Denied(label + " has an invalid string length/NUL")
    elif type(value) in (int, float):
        try:
            finite = math.isfinite(value)
        except OverflowError:
            finite = False
        if not finite:
            raise Denied(label + " must be finite and within numeric bounds")
        for keyword, bad in (("minimum", lambda n: value < n), ("maximum", lambda n: value > n),
                             ("exclusiveMinimum", lambda n: value <= n), ("exclusiveMaximum", lambda n: value >= n)):
            if keyword in schema and bad(schema[keyword]):
                raise Denied(label + " violates " + keyword)


def effectful(name, args):
    if name == "update_pcb_from_schematic":
        return args.get("dry_run", True) is False
    if name == "run_drc":
        return args.get("sync_live_board", False) is True or "output" in args
    if name == "run_erc":
        return "output" in args
    return name in WRITE_TOOLS or name in EXPORT_TOOLS


def catalog(raw_tools, policy):
    tools = {}
    for raw in raw_tools:
        if not isinstance(raw, dict) or raw.get("name") not in TOOL_KEYS:
            continue
        name = raw["name"]
        if name in tools:
            raise Denied("Duplicate upstream tool: " + name)
        tool = copy.deepcopy(raw)
        schema = tool.get("inputSchema", {})
        if schema.get("type") != "object" or set(schema.get("properties", {})) != TOOL_KEYS[name]:
            raise Denied("Pinned backend schema keys differ from reviewed contract: " + name)
        close_schema(schema)
        props = schema["properties"]
        for key, path in (("board", policy.board), ("schematic", policy.schematic),
                          ("path", policy.board), ("project_dir", policy.workspace_root)):
            if key in props:
                props[key]["const"] = str(path)
        if name == "export_manufacturing_package":
            props.pop("jlcpcb_cpl_corrections_path")
        if name == "edit_schematic_component":
            props["fields"]["additionalProperties"] = {"type": "string"}
        if name == "export_3d":
            props["format"]["const"] = "step"
        if name == "check_kicad_ui":
            props["timeout_seconds"]["maximum"] = 30
        if not policy.writes_enabled:
            if name == "update_pcb_from_schematic":
                props["dry_run"]["const"] = True
                props.pop("expected_plan_revision")
            elif name in ("run_drc", "run_erc"):
                props.pop("output")
                if name == "run_drc":
                    props["sync_live_board"]["const"] = False
            elif name in WRITE_TOOLS or name in EXPORT_TOOLS:
                continue
        for key in ("output", "output_dir"):
            if key in props:
                props[key]["description"] = "NEW destination strictly below " + str(policy.exports_root) + "; never replace existing files or follow symlinks."
        read_only = name in READ_TOOLS or (not policy.writes_enabled and name in {"update_pcb_from_schematic", "run_drc", "run_erc"})
        tool["annotations"] = {"readOnlyHint": read_only, "destructiveHint": not read_only}
        tool["description"] = tool.get("description", "") + " Scoped connector: only policy-bound inputs; owned sole-board preflight required."
        tools[name] = tool
    expected = set(TOOL_KEYS) if policy.writes_enabled else set(READ_TOOLS) | {"update_pcb_from_schematic", "run_drc", "run_erc"}
    if set(tools) != expected:
        raise Denied("Required tools missing from eager pinned backend: " + ", ".join(sorted(expected - set(tools))))
    return tools


def tool_payload(reply):
    result = reply.get("result", {})
    if not isinstance(result, dict):
        return {}
    content = result.get("content", [])
    if not isinstance(content, list):
        return {}
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
            try:
                value = strict_json(block["text"])
            except ValueError:
                continue
            if isinstance(value, dict):
                return value
    return {}


SAFE_REFUSALS = {"invalid_argument", "file_not_found", "conflict", "ambiguous_target",
                 "wrong_document", "wrong_project", "wrong_sheet_instance", "stale_target",
                 "plan_blocked", "editor_unavailable", "unsupported_capability",
                 "unsafe_file_fallback", "ambiguous_open_board", "invalid_configuration",
                 "ipc_batch_recovered", "unknown_tool", "toolset_not_loaded"}


def uncertain(reply):
    if "error" in reply:
        return True
    result = reply.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("content"), list) or type(result.get("isError")) is not bool:
        return True
    if not any(isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str) and block["text"] for block in result["content"]):
        return True
    body = tool_payload(reply)
    error = body.get("error", {})
    outcome = body.get("outcome", {})
    if isinstance(outcome, dict) and outcome.get("status") == "uncertain":
        return True
    if isinstance(error, dict) and (error.get("board_state") == "unknown" or error.get("kind") in {"ipc_outcome_unknown", "mutation_outcome_uncertain", "readback_mismatch"}):
        return True
    return result["isError"] and (not isinstance(error, dict) or error.get("kind") not in SAFE_REFUSALS)


class Journal:
    def __init__(self, policy):
        self.policy = policy
        self.path = policy.logs_dir / "mutations.jsonl"
        policy.check()
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        self.stream = os.fdopen(fd, "a+b")
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                raise Denied("Unsafe mutation journal file")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if info.st_size > MAX_FILE:
                raise Denied("Journal exceeds bound; parent must archive it")
            self.stream.seek(0)
            pending, self.blocked = set(), False
            seen = set()
            for line in self.stream:
                row = strict_json(line)
                if not isinstance(row, dict) or not isinstance(row.get("call"), str):
                    raise Denied("Malformed mutation journal; parent reconciliation required")
                call, phase = row["call"], row.get("phase")
                if phase == "request" and call not in seen:
                    seen.add(call)
                    pending.add(call)
                elif phase in {"response", "not_forwarded"} and call in pending:
                    pending.remove(call)
                    self.blocked = self.blocked or row.get("blocked") is True
                elif phase == "unknown" and call in pending:
                    self.blocked = True
                else:
                    raise Denied("Inconsistent journal sequence; parent reconciliation required")
            self.blocked = self.blocked or bool(pending)
        except BaseException:
            self.stream.close()
            raise

    def append(self, row):
        self.policy.check()
        info = self.path.lstat()
        if signature(info) != signature(os.fstat(self.stream.fileno())) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Denied("Journal path was replaced/aliased")
        data = encoded(row)
        if self.stream.seek(0, os.SEEK_END) + len(data) > MAX_FILE:
            raise Denied("Journal capacity reached; no further writes")
        self.stream.write(data)
        self.stream.flush()
        os.fsync(self.stream.fileno())
        fsync_dir(self.policy.logs_dir)

    def prepare(self, request):
        if self.blocked:
            raise Denied("Unreconciled/uncertain prior mutation; inspect mutations.jsonl before any further writes")
        try:
            self.policy.check()
            directory = Path(tempfile.mkdtemp(prefix="call-", dir=self.policy.backups_dir))
            images = {}
            for name, path in self.policy.preimages.items():
                present = os.path.lexists(path)
                data = regular_bytes(path) if present else b""
                images[name] = {"path": str(path), "present": present,
                                "sha256": sha(data) if present else None,
                                "bytes": len(data) if present else None}
                if present:
                    write_new(directory / name, data)
            row = {"call": directory.name, "phase": "request", "time_ns": time.time_ns(),
                   "backup_dir": str(directory), "request": request, "preimages": images}
            write_new(directory / "request.json", encoded(row))
            fsync_dir(directory)
            fsync_dir(self.policy.backups_dir)
            self.append(row)  # Durable intent before ANY effectful backend request.
            return row
        except BaseException:
            self.blocked = True  # A partial journal write must not be followed by another request.
            raise

    def unchanged(self, row):
        self.policy.check()
        for image in row["preimages"].values():
            path = Path(image["path"])
            if os.path.lexists(path) != image["present"] or (image["present"] and sha(regular_bytes(path)) != image["sha256"]):
                raise Denied("Saved preimage changed before dispatch: " + str(path))

    def finish(self, row, phase, **fields):
        self.blocked = self.blocked or fields.get("blocked", False) or phase == "unknown"
        try:
            self.append({"call": row["call"], "phase": phase, "time_ns": time.time_ns(), **fields})
        except BaseException:
            self.blocked = True
            raise

    def close(self):
        self.stream.close()


class Backend:
    """One child, serialized RPCs, finite nonblocking reads AND writes; no restart."""
    def __init__(self, policy):
        self.dead = False
        self.sequence = 0
        self.buffer = b""
        self.selector = selectors.DefaultSelector()
        policy.check()
        log_path = policy.logs_dir / ("backend-" + uuid.uuid4().hex + ".log")
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.log = os.fdopen(fd, "wb")
        env = {"PATH": PATH_ENV, "LANG": "en_US.UTF-8", "HOME": str(policy.home_dir),
               "KICAD_CONFIG_HOME": str(policy.prefs_dir),
               "KICAD_DOCUMENTS_HOME": str(policy.documents_dir),
               "KICAD10_3RD_PARTY": str(policy.documents_dir / "KiCad/10.0/3rdparty"),
               "TMPDIR": str(policy.logs_dir) + os.sep}
        try:
            self.process = subprocess.Popen([str(policy.binary), "--config", str(policy.backend_config)],
                                            cwd=policy.workspace_root, env=env, stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=self.log, bufsize=0,
                                            start_new_session=True)
            if self.process.stdin is None or self.process.stdout is None:
                raise TransportFailure("Backend pipes were not created")
            self.stdin, self.stdout = self.process.stdin, self.process.stdout
            os.set_blocking(self.stdin.fileno(), False)
            os.set_blocking(self.stdout.fileno(), False)
            self.selector.register(self.stdout, selectors.EVENT_READ)
        except BaseException:
            if hasattr(self, "process"):
                self.close()
            else:
                self.selector.close()
                self.log.close()
            raise

    def send(self, message, deadline):
        data = encoded(message)
        if len(data) > MAX_FRAME:
            raise TransportFailure("Backend request exceeds frame bound")
        offset = 0
        with selectors.DefaultSelector() as writable:
            writable.register(self.stdin, selectors.EVENT_WRITE)
            while offset < len(data):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not writable.select(remaining):
                    raise TransportFailure("Backend pipe write deadline exceeded; delivery may be partial")
                try:
                    count = os.write(self.stdin.fileno(), data[offset:])
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise TransportFailure("Backend stdin closed")
                offset += count

    def notify(self, method):
        try:
            self.send({"jsonrpc": "2.0", "method": method}, time.monotonic() + 20)
        except (OSError, ValueError, TransportFailure) as error:
            self.dead = True
            raise TransportFailure(str(error)) from error

    def rpc(self, method, params, timeout: float = 90):
        if self.dead:
            raise TransportFailure("Backend failed; reconnect/replay is prohibited")
        self.sequence += 1
        expected = self.sequence
        deadline = time.monotonic() + timeout
        try:
            self.send({"jsonrpc": "2.0", "id": expected, "method": method, "params": params}, deadline)
            while True:
                while b"\n" in self.buffer:
                    if time.monotonic() >= deadline:
                        raise TransportFailure("Backend RPC processing deadline exceeded")
                    line, self.buffer = self.buffer.split(b"\n", 1)
                    message = strict_json(line)
                    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                        raise TransportFailure("Malformed backend JSON-RPC")
                    if "method" in message:
                        if "id" in message:
                            raise TransportFailure("Backend requested an unexposed client capability")
                        continue  # No upstream discovery/logging/progress notification leakage.
                    if type(message.get("id")) is not int or message["id"] != expected or (("result" in message) == ("error" in message)):
                        raise TransportFailure("Unexpected backend response identity/envelope")
                    return {key: message[key] for key in ("result", "error") if key in message}
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self.selector.select(remaining):
                    raise TransportFailure("Backend RPC deadline exceeded; inspect state, NEVER blindly retry")
                chunk = os.read(self.stdout.fileno(), 65536)
                if not chunk:
                    raise TransportFailure("Backend exited during RPC; inspect state before any retry")
                self.buffer += chunk
                if len(self.buffer) > MAX_FRAME:
                    raise TransportFailure("Backend frame exceeds bound")
        except (OSError, ValueError, TransportFailure, RecursionError) as error:
            self.dead = True
            raise TransportFailure(str(error)) from error

    def close(self):
        self.selector.close()
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            # Only our backend process group, NEVER the parent-owned KiCad PID.
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=2)
        if self.process.stdout is not None:
            self.process.stdout.close()
        self.log.close()


def rpc_result(reply, label):
    if "error" in reply or not isinstance(reply.get("result"), dict):
        raise Denied("Backend did not complete " + label + ": " + json.dumps(reply))
    return reply["result"]


class Scope:
    def __init__(self, policy, backend, ownership, journal, raw_tools, initialization):
        self.policy, self.backend, self.ownership, self.journal = policy, backend, ownership, journal
        self.tools = catalog(raw_tools, policy)
        self.reviewed_revision = None
        self.initialized = self.ready = False
        if initialization.get("protocolVersion") != PROTOCOL or not isinstance(initialization.get("serverInfo"), dict):
            raise Denied("Unreviewed backend initialization")
        self.initialization = copy.deepcopy(initialization)
        self.initialization["serverInfo"]["name"] = "kicad-scoped-workbench"
        self.initialization["capabilities"] = {"tools": {"listChanged": False}}
        self.initialization["instructions"] = (
            "Only this connector's listed tools/keys are authorized; no toolset loading, resources, "
            "configuration, library writes, GUI launch, RunAction or Undo. Not an OS sandbox. "
            "Every tool call requires the exact parent-owned sole board. Ownership loss fails closed, "
            "including offline queries. Writes require policy gates, preimages and a durable journal; "
            "never replay uncertain work. Sync apply must echo this session's latest reviewed plan revision. "
            "Exports use new destinations only; saved-file backups do not capture unsaved editor state. "
            "Workspace: " + str(policy.workspace_root) + "; writes_enabled=" + str(policy.writes_enabled).lower()
        )

    def arguments(self, name, args):
        if name not in self.tools or not isinstance(args, dict):
            raise Denied("Tool/arguments are unavailable through this scoped connector")
        schema = self.tools[name]["inputSchema"]
        if set(args) - set(schema["properties"]):
            raise Denied("Unexpected tool argument keys")
        args = copy.deepcopy(args)
        for key in ("board", "schematic", "path", "project_dir"):
            if key in schema["properties"]:
                bound = schema["properties"][key]["const"]
                if key in args and args[key] != bound:
                    raise Denied("Only the exact policy-bound " + key + " is permitted")
                args[key] = bound
        validate(args, schema)
        if name == "update_pcb_from_schematic" and args.get("dry_run", True) is False:
            revision = args.get("expected_plan_revision")
            if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision) or revision != self.reviewed_revision:
                raise Denied("Apply requires the exact latest successful reviewed dry-run revision from this session")
        if effectful(name, args) and not self.policy.writes_enabled:
            raise Denied("Policy has not enabled writes")
        # Zed may require optional string properties in its tool-call envelope.
        # Blank BOM column options mean defaults, not explicit empty CLI columns.
        columns = ("fields", "labels", "group_by") if name == "export_bom" else ("bom_fields", "bom_labels", "bom_group_by") if name == "export_manufacturing_package" else ()
        for key in columns:
            if key in args and not args[key].strip():
                args.pop(key)
        if "output_dir" in args:
            args["output_dir"] = self.policy.output(args["output_dir"], directory=True)
        if "output" in args:
            suffixes = {"run_drc": {".json"}, "run_erc": {".json"}, "export_bom": {".csv"},
                        "export_3d": {".step", ".stp"}, "export_position_file": {".csv"} if args.get("format", "csv") == "csv" else {".gbr"}}
            args["output"] = self.policy.output(args["output"], suffixes[name])
        if name == "export_manufacturing_package" and "fab_house" in args and args["fab_house"] not in {"jlcpcb", "pcbway", "oshpark", "generic"}:
            raise Denied("Unsupported manufacturing target")
        if name in {"run_drc", "run_erc"} and "severity" in args and args["severity"] not in {"error", "warning", "info"}:
            raise Denied("Unsupported severity")
        return args

    def authorize(self, message):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or set(message) - {"jsonrpc", "id", "method", "params"}:
            raise Denied("Expected one closed JSON-RPC 2.0 request; batches are forbidden")
        method = message.get("method")
        params = message.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            raise Denied("Invalid MCP method/parameters")
        if "id" not in message:
            if method == "notifications/initialized" and not params:
                return {**message, "params": {}}
            if method == "notifications/cancelled" and set(params) <= {"requestId", "reason"} and type(params.get("requestId")) in (int, str):
                if "reason" in params:
                    text(params["reason"], "cancellation reason")
                return message
            raise Denied("Notification is not allowed")
        if type(message["id"]) not in (int, str):
            raise Denied("Request id must be a string/integer, not boolean/null")
        if method in {"ping", "tools/list"}:
            if params:
                raise Denied("No parameters/cursors are allowed for " + method)
        elif method == "initialize":
            exact_keys(params, {"protocolVersion", "capabilities", "clientInfo"}, "Initialize params")
            text(params["protocolVersion"], "protocolVersion")
            if not isinstance(params["capabilities"], dict) or not isinstance(params["clientInfo"], dict):
                raise Denied("Invalid initialization identity/capabilities")
            info = params["clientInfo"]
            if set(info) - {"name", "version", "title"} or not {"name", "version"} <= set(info):
                raise Denied("Unexpected clientInfo keys")
            for key, value in info.items():
                text(value, "clientInfo." + key)
            # Client capabilities are not forwarded to the backend.
        elif method == "tools/call":
            if set(params) - {"name", "arguments", "_meta"} or not isinstance(params.get("name"), str):
                raise Denied("Invalid tool call params")
            meta = params.get("_meta", {})
            if not isinstance(meta, dict) or set(meta) - {"progressToken"} or ("progressToken" in meta and type(meta["progressToken"]) not in (int, str)):
                raise Denied("Unexpected tool metadata")
            params = {"name": params["name"], "arguments": self.arguments(params["name"], params.get("arguments", {}))}
        else:
            raise Denied("MCP method is not exposed")
        return {**message, "params": params}

    def preflight(self):
        self.ownership.verify()  # Before any IPC, including backend file-fallback queries.
        reply = self.backend.rpc("tools/call", {"name": "open_project", "arguments": {"path": str(self.policy.board)}}, timeout=20)
        self.ownership.verify()
        result, body = reply.get("result", {}), tool_payload(reply)
        expected = {"ipc_available": True, "kicad_ui_running": True,
                    "requested_open": True, "open_board_count": 1,
                    "open_boards": [str(self.policy.board)], "requested_path": str(self.policy.board),
                    "requested_board": str(self.policy.board), "ipc_address": self.policy.endpoint,
                    "ipc_failure": None, "open_boards_error": None, "requested_check_error": None}
        if not isinstance(result, dict) or result.get("isError") is not False or any(key not in body or body[key] != value or type(body[key]) is not type(value) for key, value in expected.items()):
            raise Denied("Backend preflight did not prove the sole exact owned board ready; nothing forwarded")
        return reply

    def call(self, message):
        params = message["params"]
        name, args = params["name"], params["arguments"]
        writes = effectful(name, args)
        if writes and self.journal.blocked:
            raise Denied("Prior mutation needs parent reconciliation; no further writes")
        ready_reply = self.preflight()
        if "schematic" in args:
            self.policy.schematic_guard(editing=name == "edit_schematic_component")
        if name == "open_project":
            return ready_reply
        row = None
        if writes:
            row = self.journal.prepare(message)
            try:
                self.preflight()  # Fresh sole-board check AFTER snapshots/journaling, even for argless save.
                self.arguments(name, args)  # Recheck new outputs and revision immediately before forwarding.
                if name == "edit_schematic_component":
                    self.policy.schematic_guard(editing=True)
                self.journal.unchanged(row)
                self.ownership.verify()
            except BaseException as error:
                self.journal.finish(row, "not_forwarded", reason=str(error), blocked=False)
                raise
            self.reviewed_revision = None  # Consume/invalidate review even if the backend refuses.
        timeout = 180 if name.startswith("export_") or name == "get_board_2d_view" else 90
        try:
            reply = self.backend.rpc("tools/call", params, timeout=timeout)
        except BaseException as error:
            if row:
                self.journal.finish(row, "unknown", reason=str(error), blocked=True)
            raise
        if row:
            self.journal.finish(row, "response", response=reply, blocked=uncertain(reply))
        if name == "update_pcb_from_schematic" and not writes:
            self.reviewed_revision = None
            body = tool_payload(reply)
            revision = body.get("plan_revision")
            if reply.get("result", {}).get("isError") is False and body.get("status") in {"ready", "noop"} and isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{64}", revision):
                self.reviewed_revision = revision
        return reply

    def handle(self, message):
        message = self.authorize(message)
        method = message["method"]
        if method == "notifications/initialized":
            if not self.initialized:
                raise Denied("Initialize first")
            self.ready = True
            return None
        if method == "notifications/cancelled":
            return None
        if method == "initialize":
            if self.initialized:
                raise Denied("This bridge cannot reinitialize/reconnect")
            self.initialized = True
            reply = {"result": self.initialization}
        elif method == "ping":
            reply = {"result": {}}
        else:
            if not self.ready:
                raise Denied("Initialize and send notifications/initialized first")
            if method == "tools/list":
                reply = {"result": {"tools": list(self.tools.values())}}
            else:
                reply = self.call(message)
        return {"jsonrpc": "2.0", "id": message["id"], **reply}


def serve(policy_file):
    policy = Policy(policy_file)
    backend = journal = None
    try:
        journal = Journal(policy)
        ownership = Ownership(policy)
        ownership.verify()
        backend = Backend(policy)
        initialization = rpc_result(backend.rpc("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                    "clientInfo": {"name": "kicad-scoped-workbench", "version": "1"}}, timeout=20), "initialize")
        backend.notify("notifications/initialized")
        listing = rpc_result(backend.rpc("tools/list", {}, timeout=20), "tools/list")
        if not isinstance(listing.get("tools"), list) or "nextCursor" in listing:
            raise Denied("Need one complete eager backend tool listing, no cursors")
        scope = Scope(policy, backend, ownership, journal, listing["tools"], initialization)
        while True:
            line = sys.stdin.buffer.readline(MAX_FRAME + 1)
            if not line:
                break
            message = None
            try:
                if len(line) > MAX_FRAME or not line.endswith(b"\n"):
                    raise TransportFailure("Client frame exceeds bound or lacks newline")
                message = strict_json(line)
                response = scope.handle(message)
                if response is not None:
                    sys.stdout.buffer.write(encoded(response))
                    sys.stdout.buffer.flush()
            except (OSError, ValueError, TransportFailure, RecursionError) as error:
                request_id = message.get("id") if isinstance(message, dict) and type(message.get("id")) in (int, str) else None
                if request_id is not None or not isinstance(message, dict) or "id" in message:
                    response = {"jsonrpc": "2.0", "id": request_id, "error": {
                        "code": -32002 if isinstance(error, TransportFailure) else -32602,
                        "message": str(error), "data": {"writes_blocked": journal.blocked,
                        "instruction": "No automatic retry. Inspect the owned runtime and mutation journal before retrying any write."}}}
                    sys.stdout.buffer.write(encoded(response))
                    sys.stdout.buffer.flush()
                else:
                    print("Rejected MCP notification: " + str(error), file=sys.stderr)
                if backend.dead or isinstance(error, TransportFailure):
                    break
    finally:
        if backend is not None:
            backend.close()
        if journal is not None:
            journal.close()


def self_test():
    """Pure authorization/guard tests: temp files/socket + mocks, NO subprocesses."""
    import socket
    import unittest
    from unittest import mock

    def call(name, arguments=None):
        return {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": {"name": name, "arguments": arguments if arguments is not None else {}}}

    def result(body, error=False):
        return {"result": {"content": [{"type": "text", "text": json.dumps(body)}], "isError": error}}

    # Small mock catalog using the reviewed schemas' keys/types. Production ALWAYS
    # uses the real pinned backend's schemas, never these test fixtures.
    def fixtures():
        numbers = {"x", "y", "x1", "y1", "x2", "y2", "width", "clearance", "min_width", "corner_radius", "drill", "pad_size"}
        integers = {"limit", "height", "timeout_seconds", "unit", "priority"}
        booleans = {"dry_run", "sync_live_board", "refill_zones", "drill_file", "include_unspecified", "exclude_dnp", "include_assembly"}
        tools = []
        for name, keys in TOOL_KEYS.items():
            props: dict[str, dict] = {key: {"type": "number" if key in numbers else "integer" if key in integers else "boolean" if key in booleans else "string"} for key in keys}
            required = []
            if name == "update_pcb_from_schematic":
                required = ["board", "schematic"]
            if name == "set_component_placements":
                props["placements"] = {"type": "array", "minItems": 1, "items": {"type": "object", "properties": {
                    "reference": {"type": "string"}, "x": {"type": "number"}, "y": {"type": "number"}, "rotation": {"type": "number"}}, "required": ["reference", "x", "y", "rotation"]}}
                required = ["board", "placements"]
            if name == "edit_schematic_component":
                props["fields"] = {"type": "object", "additionalProperties": True}
                props["field_placements"] = {"type": "object", "additionalProperties": {"type": "object", "properties": {
                    "x": {"type": "number"}, "y": {"type": "number"}, "rotation": {"type": "number"}, "hide": {"type": "boolean"}}}}
                required = ["schematic", "reference"]
            for key in ("layers", "gerber_layers"):
                if key in props:
                    props[key] = {"type": "array", "items": {"type": "string"}}
            if name == "add_zone":
                props["points"] = {"type": "array", "items": {"type": "object", "properties": {"x": {"type": "number"}, "y": {"type": "number"}}}}
            if name == "get_board_stackup":
                props["expected"] = {"type": "object", "properties": {"finish": {"type": "string"}}}
            tools.append({"name": name, "description": name, "inputSchema": {"type": "object", "properties": props, "required": required}})
        # Keep this source-faithful fixture independent of TOOL_KEYS so a drift in
        # the reviewed property contract fails the tests rather than mocking itself.
        extents = next(tool for tool in tools if tool["name"] == "get_board_extents")
        extents["inputSchema"] = {"type": "object", "properties": {
            "board": {"type": "string"},
            "board_source": {"type": "string", "enum": ["auto", "live", "saved"], "default": "auto"}},
            "required": ["board"]}
        tools.append({"name": "load_toolset", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}}})
        return tools

    class Tests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(prefix="s-")
            self.addCleanup(self.temp.cleanup)
            root = Path(self.temp.name).resolve()
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            raw = {"workspace_root": str(workspace), "writes_enabled": True}
            for key in ROLE_DIRS:
                path = workspace / "libraries" if key == "library_root" else root / key
                path.mkdir(mode=0o700)
                raw[key] = str(path)
            for key, suffix in (("board", ".kicad_pcb"), ("schematic", ".kicad_sch"), ("project", ".kicad_pro")):
                path = workspace / ("demo" + suffix)
                path.write_text("(kicad_sch)" if key == "schematic" else key + " preimage\n")
                raw[key] = str(path)
            (workspace / "fp-lib-table").write_text("(fp_lib_table)\n")
            binary = root / "konnect"
            binary.write_bytes(b"test executable, never executed\n")
            binary.chmod(0o700)
            editor = root / "pcbnew"
            editor.write_bytes(b"test native editor, never executed\n")
            editor.chmod(0o700)
            sock = socket.socket(socket.AF_UNIX)
            self.addCleanup(sock.close)
            sock.bind(str(root / "s"))
            raw["binary"], raw["binary_sha256"] = str(binary), sha(binary.read_bytes())
            runtime = root / "runtime.json"
            socket_info, editor_info = (root / "s").stat(), editor.stat()
            runtime.write_text(json.dumps({"ready": True, "pid": os.getpid(), "executable": str(editor),
                "board": raw["board"], "socket": str(root / "s"),
                "ownership_identity": ["Mon Oct 5 12:00:00 2026", socket_info.st_dev, socket_info.st_ino,
                                       editor_info.st_dev, editor_info.st_ino]}))
            config = root / "config.json"
            config.write_text(json.dumps({"kicad_cli": str(binary), "kicad_binary": str(editor),
                "project_dir": str(workspace), "ipc_address": "ipc://" + str(root / "s"),
                "transport": "stdio", "log_level": "warn", "eager_toolsets": True}))
            raw["runtime_file"], raw["backend_config"] = str(runtime), str(config)
            self.filename = root / "policy.json"
            self.filename.write_text(json.dumps(raw))
            self.raw = raw
            self.policy = Policy(self.filename)
            self.journal = Journal(self.policy)
            self.addCleanup(self.journal.close)
            self.owner = mock.Mock()
            self.backend = mock.Mock(dead=False)
            self.revision = "a" * 64
            self.forwarded = []

            def rpc(method, params, timeout=90):
                self.assertEqual(method, "tools/call")
                if params["name"] == "open_project":
                    return result({"ipc_available": True, "kicad_ui_running": True, "requested_open": True,
                        "open_board_count": 1, "open_boards": [str(self.policy.board)], "requested_path": str(self.policy.board),
                        "requested_board": str(self.policy.board), "ipc_address": self.policy.endpoint,
                        "ipc_failure": None, "open_boards_error": None, "requested_check_error": None})
                if effectful(params["name"], params["arguments"]):
                    rows = [strict_json(line) for line in self.journal.path.read_bytes().splitlines()]
                    self.assertEqual(rows[-1]["phase"], "request", "Intent must be durable before forwarding")
                    manifest = Path(rows[-1]["backup_dir"]) / "request.json"
                    self.assertTrue(manifest.is_file())
                    self.assertEqual((manifest.parent / "board.kicad_pcb").read_bytes(), self.policy.board.read_bytes())
                self.forwarded.append(params)
                if params["name"] == "update_pcb_from_schematic":
                    return result({"status": "ready", "plan_revision": self.revision})
                return result({"ok": True})

            self.backend.rpc.side_effect = rpc
            self.scope = Scope(self.policy, self.backend, self.owner, self.journal, fixtures(),
                               {"protocolVersion": PROTOCOL, "serverInfo": {"name": "konnect", "version": "test"}})
            self.scope.initialized = self.scope.ready = True

        def deny(self, message):
            before = len(self.forwarded)
            with self.assertRaises((Denied, OSError)):
                self.scope.handle(message)
            self.assertEqual(len(self.forwarded), before)

        def test_filtering_and_const_bindings(self):
            response = self.scope.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert response is not None
            listed = response["result"]
            self.assertEqual(len(listed["tools"]), 34)
            self.assertNotIn("load_toolset", self.scope.tools)
            self.assertNotIn("nextCursor", listed)
            for name, key, value in (("get_board_info", "board", self.policy.board),
                ("open_project", "path", self.policy.board), ("edit_schematic_component", "schematic", self.policy.schematic),
                ("search_footprints", "project_dir", self.policy.workspace_root)):
                self.assertEqual(self.scope.tools[name]["inputSchema"]["properties"][key]["const"], str(value))
            self.assertFalse(self.scope.tools["save_project"]["annotations"]["readOnlyHint"])
            self.assertNotIn("jlcpcb_cpl_corrections_path", self.scope.tools["export_manufacturing_package"]["inputSchema"]["properties"])
            self.scope.handle(call("get_board_info"))
            self.assertEqual(self.forwarded[-1]["arguments"]["board"], str(self.policy.board))

        def test_bypass_global_methods_and_unknown_keys(self):
            for name in ("load_toolset", "set_kicad_config", "register_footprint_library", "create_footprint",
                         "launch_kicad_ui", "run_action", "RunAction", "Undo", "undo", "reload_server"):
                self.deny(call(name))
            for method in ("resources/read", "resources/list", "prompts/get", "roots/list", "configuration/set"):
                self.deny({"jsonrpc": "2.0", "id": 1, "method": method})
            self.deny(call("save_project", {"board": str(self.policy.board)}))
            self.deny(call("get_board_info", {"force": True}))
            self.deny(call("search_footprints", {"query": "R", "project_dir": "/tmp"}))
            self.deny(call("get_installation_info", {"config": "/tmp/other"}))
            self.deny({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"cursor": "all"}})
            self.deny([call("save_project")])
            self.deny({"jsonrpc": "2.0", "id": True, "method": "ping"})
            self.deny(call("export_manufacturing_package", {"output_dir": str(self.policy.exports_root / "fab"), "jlcpcb_cpl_corrections_path": "/tmp/override.json"}))

        def test_nested_bypasses_and_types(self):
            self.deny(call("set_component_placements", {"placements": [{"reference": "R1", "x": 1, "y": 2, "rotation": 0, "board": "/other"}]}))
            self.deny(call("edit_schematic_component", {"reference": "R1", "fields": {"MPN": {"path": "/other"}}}))
            self.deny(call("edit_schematic_component", {"reference": "R1", "field_placements": {"Value": {"hide": True, "path": "/other"}}}))
            self.deny(call("move_component", {"reference": "R1", "x": True, "y": 1}))
            self.deny(call("move_component", {"reference": "R1", "x": float("nan"), "y": 1}))
            self.deny(call("check_kicad_ui", {"timeout_seconds": 300}))

        def test_paths_symlink_and_overwrite(self):
            self.deny(call("get_board_info", {"board": str(self.policy.workspace_root / "other.kicad_pcb")}))
            alias = self.policy.workspace_root / "alias.kicad_pcb"
            alias.symlink_to(self.policy.board)
            self.deny(call("get_board_info", {"board": str(alias)}))
            link = self.policy.exports_root / "escape"
            link.symlink_to(self.policy.workspace_root, target_is_directory=True)
            self.deny(call("run_drc", {"output": str(link / "settings.json")}))
            self.deny(call("run_drc", {"output": str(self.policy.exports_root / "../project.kicad_pro")}))
            for path in (self.policy.board, self.policy.schematic, self.policy.project,
                         self.policy.backend_config, self.journal.path, self.policy.workspace_root / "fp-lib-table"):
                self.deny(call("run_drc", {"output": str(path)}))
            output = self.policy.exports_root / "report.json"
            output.write_text("existing")
            self.deny(call("run_drc", {"output": str(output)}))
            self.deny(call("export_3d", {"format": "vrml", "output": str(self.policy.exports_root / "model.wrl")}))
            output.unlink()
            output.symlink_to(self.policy.project)
            self.deny(call("run_drc", {"output": str(output)}))

        def test_blank_bom_options_use_defaults(self):
            for name, options, output in (
                ("export_bom", ("fields", "labels", "group_by"), {"output": str(self.policy.exports_root / "bom.csv")}),
                ("export_manufacturing_package", ("bom_fields", "bom_labels", "bom_group_by"), {"output_dir": str(self.policy.exports_root / "package")})):
                arguments = self.scope.arguments(name, {**output, **{key: "  " for key in options}})
                self.assertFalse(set(options).intersection(arguments))
                arguments = self.scope.arguments(name, {**output, options[0]: "Reference,Value"})
                self.assertEqual(arguments[options[0]], "Reference,Value")
            args = self.scope.arguments("edit_schematic_component", {"reference": "R1", "fields": {"Trial": ""}})
            self.assertEqual(args["fields"]["Trial"], "", "Schematic field clears must not be normalized")

        def test_policy_denials(self):
            for updates in ({"writes_enabled": "true"}, {"binary_sha256": "0" * 64},
                            {"exports_root": self.raw["workspace_root"]},
                            {"logs_dir": self.raw["prefs_dir"]}, {"project": self.raw["board"]},
                            {"library_root": self.raw["exports_root"]}, {"unknown": True}):
                self.filename.write_text(json.dumps({**self.raw, **updates}))
                with self.assertRaises(Denied):
                    Policy(self.filename)

        def test_read_only_catalog_matches_dispatch(self):
            self.filename.write_text(json.dumps({**self.raw, "writes_enabled": False}))
            policy = Policy(self.filename)
            readonly = Scope(policy, self.backend, self.owner, self.journal, fixtures(), self.scope.initialization)
            self.assertEqual(set(readonly.tools), set(READ_TOOLS) | {"update_pcb_from_schematic", "run_drc", "run_erc"})
            for name, args in (("save_project", {}), ("run_drc", {"sync_live_board": True}),
                               ("run_drc", {"output": str(policy.exports_root / "drc.json")}),
                               ("run_erc", {"output": str(policy.exports_root / "erc.json")}),
                               ("update_pcb_from_schematic", {"dry_run": False, "expected_plan_revision": self.revision})):
                with self.assertRaises(Denied):
                    readonly.authorize(call(name, args))
            readonly.authorize(call("run_drc", {"sync_live_board": False}))
            readonly.authorize(call("update_pcb_from_schematic"))

        def test_revision_review_and_consumption(self):
            self.deny(call("update_pcb_from_schematic", {"dry_run": False}))
            self.deny(call("update_pcb_from_schematic", {"dry_run": False, "expected_plan_revision": self.revision}))
            self.scope.handle(call("update_pcb_from_schematic"))
            self.deny(call("update_pcb_from_schematic", {"dry_run": False, "expected_plan_revision": "b" * 64}))
            self.scope.handle(call("update_pcb_from_schematic", {"dry_run": False, "expected_plan_revision": self.revision}))
            self.assertIsNone(self.scope.reviewed_revision)
            self.deny(call("update_pcb_from_schematic", {"dry_run": False, "expected_plan_revision": self.revision}))

        def test_saved_preimages_and_argless_save_journal(self):
            self.scope.handle(call("save_project"))
            self.scope.handle(call("save_project"))
            directories = sorted(self.policy.backups_dir.glob("call-*"))
            self.assertEqual(len(directories), 2)
            self.assertGreaterEqual(sum(c.args[1]["name"] == "open_project" for c in self.backend.rpc.call_args_list), 4)
            for directory in directories:
                row = strict_json((directory / "request.json").read_bytes())
                for name, image in row["preimages"].items():
                    self.assertEqual(image["present"], name != "sym-lib-table")
                    if image["present"]:
                        self.assertEqual(sha((directory / name).read_bytes()), image["sha256"])
                self.assertEqual(row["request"]["params"]["arguments"], {})
            self.assertFalse(self.journal.blocked)

        def test_journal_failure_never_forward(self):
            with mock.patch.object(self.journal, "append", side_effect=OSError("journal fsync failed")):
                self.deny(call("save_project"))
            self.assertTrue(self.journal.blocked)
            self.deny(call("save_project"))

        def test_snapshot_failure_never_forward(self):
            table = self.policy.workspace_root / "fp-lib-table"
            table.unlink()
            table.symlink_to(self.policy.project)
            self.deny(call("save_project"))
            self.assertTrue(self.journal.blocked)

        def test_schematic_locks_and_hierarchy(self):
            for name in ("~demo.kicad_sch.lck", "demo.kicad_sch.lck"):
                lock = self.policy.workspace_root / name
                lock.symlink_to(self.policy.workspace_root / "missing-lock-target")
                self.deny(call("edit_schematic_component", {"reference": "R1", "value": "1k"}))
                lock.unlink()
            self.policy.schematic.write_text('(kicad_sch (sheet (property "Sheetfile" "../../other.kicad_sch")))')
            self.deny(call("update_pcb_from_schematic"))

        def test_sole_board_preflight_and_offline_fail_closed(self):
            self.backend.rpc.return_value = result({"ipc_available": False})
            self.backend.rpc.side_effect = None
            self.deny(call("save_project"))
            self.assertFalse(list(self.policy.backups_dir.iterdir()))
            self.owner.verify.side_effect = Denied("recycled socket")
            before = self.backend.rpc.call_count
            self.deny(call("get_board_info"))
            self.assertEqual(self.backend.rpc.call_count, before)

        def test_changed_saved_preimage_never_forward(self):
            original = self.scope.preflight
            count = 0
            def preflight():
                nonlocal count
                count += 1
                reply = original()
                if count == 2:
                    self.policy.board.write_text("external save after snapshot")
                return reply
            with mock.patch.object(self.scope, "preflight", side_effect=preflight):
                self.deny(call("save_project"))
            rows = [strict_json(line) for line in self.journal.path.read_bytes().splitlines()]
            self.assertEqual([r["phase"] for r in rows], ["request", "not_forwarded"])

        def test_pinned_policy_and_config_changes_fail_closed(self):
            self.filename.write_text(json.dumps({**self.raw, "writes_enabled": False}))
            with self.assertRaises(Denied):
                self.policy.check()
            self.filename.write_bytes(self.policy.policy_bytes)
            config = {**self.policy.config, "ipc_address": "ipc:///tmp/recycled.sock"}
            self.policy.backend_config.write_text(json.dumps(config))
            with self.assertRaises(Denied):
                self.policy.check()

        def test_pipe_rpc_deadlines_and_bad_response_poison(self):
            for response in (None, {"jsonrpc": "2.0", "id": 999, "result": {}}):
                input_read, input_write = os.pipe()
                output_read, output_write = os.pipe()
                with os.fdopen(input_read, "rb") as reader, os.fdopen(input_write, "wb", buffering=0) as writer, os.fdopen(output_read, "rb") as stdout, os.fdopen(output_write, "wb", buffering=0) as sender:
                    backend = Backend.__new__(Backend)
                    backend.sequence, backend.buffer, backend.dead = 0, b"", False
                    backend.stdin, backend.stdout = writer, stdout
                    os.set_blocking(writer.fileno(), False)
                    os.set_blocking(stdout.fileno(), False)
                    with selectors.DefaultSelector() as selector:
                        backend.selector = selector
                        selector.register(stdout, selectors.EVENT_READ)
                        if response is not None:
                            sender.write(encoded(response))
                        with self.assertRaises(TransportFailure):
                            backend.rpc("ping", {}, timeout=0.02)
                        self.assertTrue(backend.dead)
                        sent = reader.read1(MAX_FRAME)
                        self.assertEqual(strict_json(sent)["id"], 1)
                        with self.assertRaises(TransportFailure):
                            backend.rpc("ping", {})

        def test_not_forwarded_guard_after_prepare(self):
            original = self.scope.preflight
            count = 0
            def preflight():
                nonlocal count
                count += 1
                if count == 2:
                    raise Denied("Board changed after snapshot")
                return original()
            with mock.patch.object(self.scope, "preflight", side_effect=preflight):
                self.deny(call("save_project"))
            rows = [strict_json(line) for line in self.journal.path.read_bytes().splitlines()]
            self.assertEqual([r["phase"] for r in rows], ["request", "not_forwarded"])
            self.assertFalse(self.journal.blocked)

        def test_ambiguous_response_and_restart_guard(self):
            original = self.backend.rpc.side_effect
            unknown = result({"error": {"kind": "ipc_outcome_unknown", "board_state": "unknown", "retry_safe": False}}, error=True)
            def rpc(method, params, timeout=90):
                return original(method, params, timeout) if params["name"] == "open_project" else unknown
            self.backend.rpc.side_effect = rpc
            reply = self.scope.handle(call("save_project"))
            assert reply is not None
            self.assertEqual(reply["result"], unknown["result"], "Do not rewrite backend classifications")
            self.assertTrue(self.journal.blocked)
            self.deny(call("save_project"))
            self.journal.close()
            reopened = Journal(self.policy)
            self.addCleanup(reopened.close)
            self.assertTrue(reopened.blocked)

        def test_transport_failure_is_not_retried(self):
            original = self.backend.rpc.side_effect
            sent = []
            def rpc(method, params, timeout=90):
                if params["name"] == "open_project":
                    return original(method, params, timeout)
                sent.append(params)
                raise TransportFailure("timeout after delivery")
            self.backend.rpc.side_effect = rpc
            with self.assertRaises(TransportFailure):
                self.scope.handle(call("save_project"))
            self.assertEqual(len(sent), 1)
            self.assertTrue(self.journal.blocked)
            self.deny(call("save_project"))
            self.assertEqual(len(sent), 1)
            self.journal.close()
            reopened = Journal(self.policy)
            self.addCleanup(reopened.close)
            self.assertTrue(reopened.blocked)

        def test_pending_journal_and_exclusive_bridge(self):
            with self.assertRaises((OSError, Denied)):
                Journal(self.policy)
            self.journal.prepare(call("save_project"))
            self.journal.close()
            reopened = Journal(self.policy)
            self.addCleanup(reopened.close)
            self.assertTrue(reopened.blocked)

        def test_ownership_pid_executable_board_socket_and_reuse(self):
            p = self.policy
            def probe(argv):
                if argv[0] == "/bin/ps":
                    return str(os.getuid()) + " Mon Oct 5 12:00:00 2026 " + str(p.editor) + " " + str(p.board) + "\n"
                if "-d" in argv:
                    return "p" + str(p.runtime["pid"]) + "\nf1\nn" + str(p.editor) + "\n"
                return "p" + str(p.runtime["pid"]) + "\nf3\ntunix\nn" + str(p.socket) + "\n"
            owned = Ownership(p)
            with mock.patch.object(Ownership, "probe", side_effect=probe):
                owned.verify()
                owned.verify()
            for bad in (str(p.runtime["pid"] + 1), str(p.runtime["pid"]) + "\nf4\ntunix\nn" + str(p.socket) + "\np" + str(p.runtime["pid"] + 1)):
                owned = Ownership(p)
                def reused(argv, bad=bad):
                    if argv[0] == "/usr/sbin/lsof" and "-U" in argv:
                        return "p" + bad + "\nf3\ntunix\nn" + str(p.socket) + "\n"
                    return probe(argv)
                with mock.patch.object(Ownership, "probe", side_effect=reused), self.assertRaises(Denied):
                    owned.verify()
                self.assertTrue(owned.invalid)
                with self.assertRaises(Denied):
                    owned.verify()
            owned = Ownership(p)
            with mock.patch.object(Ownership, "probe", side_effect=probe):
                owned.verify()
                assert owned.identity is not None
                owned.identity = ("different process start",) + owned.identity[1:]
                with self.assertRaises(Denied):
                    owned.verify()

        def test_runtime_ownership_identity_shape(self):
            runtime = strict_json(self.policy.runtime_bytes)
            identity = runtime["ownership_identity"]
            invalid = [None, {}, "identity", [], identity[:4], identity + [0],
                       [0, *identity[1:]], ["", *identity[1:]], ["bad\nstart", *identity[1:]]]
            for index in range(1, 5):
                for value in (-1, True, False, 0.0, "0", None):
                    changed = identity.copy()
                    changed[index] = value
                    invalid.append(changed)
            try:
                for index, value in enumerate(invalid):
                    with self.subTest(case=index):
                        runtime["ownership_identity"] = value
                        self.policy.runtime_file.write_bytes(encoded(runtime))
                        with self.assertRaises(Denied):
                            Policy(self.filename)
                del runtime["ownership_identity"]
                self.policy.runtime_file.write_bytes(encoded(runtime))
                with self.assertRaises(Denied):
                    Policy(self.filename)
                runtime["ownership_identity"] = [identity[0], 0, 0, 0, 0]
                self.policy.runtime_file.write_bytes(encoded(runtime))
                self.assertEqual(Policy(self.filename).runtime["ownership_identity"], runtime["ownership_identity"])
            finally:
                self.policy.runtime_file.write_bytes(self.policy.runtime_bytes)

        def test_ownership_bootstrap_requires_explicit_success(self):
            p = self.policy
            expected = p.runtime["ownership_identity"].copy()
            p.runtime["ownership_identity"] = None  # Launcher bootstrap state, never a production Policy input.

            def probe(argv):
                if argv[0] == "/bin/ps":
                    return f"{os.getuid()} {expected[0]} {p.editor} {p.board}\n"
                if "-d" in argv:
                    return f"p{p.runtime['pid']}\nf1\nn{p.editor}\n"
                return f"p{p.runtime['pid']}\nf3\ntunix\nn{p.socket}\n"

            with mock.patch.object(Ownership, "probe", side_effect=probe):
                for owned in (Ownership(p), Ownership(p, establish_identity=1), Ownership(p, establish_identity="true")):
                    with self.assertRaises(Denied):
                        owned.verify()
                    self.assertTrue(owned.invalid)
                    self.assertIsNone(owned.identity)
                    self.assertIsNone(p.runtime["ownership_identity"])
                owned = Ownership(p, establish_identity=True)
                owned.identity = ("different process start", *expected[1:])
                with self.assertRaises(Denied):
                    owned.verify()
                self.assertTrue(owned.invalid)
                self.assertIsNone(p.runtime["ownership_identity"], "Session latch must precede bootstrap capture")
            owned = Ownership(p, establish_identity=True)
            with mock.patch.object(Ownership, "probe", side_effect=lambda argv: "" if "-U" in argv else probe(argv)):
                with self.assertRaises(Denied):
                    owned.verify()
            self.assertTrue(owned.invalid)
            self.assertIsNone(owned.identity)
            self.assertIsNone(p.runtime["ownership_identity"], "Failed OS ownership checks must not capture identity")
            with mock.patch.object(Ownership, "probe", side_effect=probe):
                owned = Ownership(p, establish_identity=True)
                owned.verify()
                self.assertEqual(p.runtime["ownership_identity"], expected)
                self.assertEqual(owned.identity, tuple(expected))
                owned.verify()
                p.runtime["ownership_identity"] = ["Mon Oct 5 12:00:01 2026", *expected[1:]]
                provided = p.runtime["ownership_identity"].copy()
                owned = Ownership(p, establish_identity=True)
                with self.assertRaises(Denied):
                    owned.verify()
                self.assertTrue(owned.invalid)
                self.assertIsNone(owned.identity)
                self.assertEqual(p.runtime["ownership_identity"], provided, "Bootstrap must not replace a provided identity")

        def test_fresh_ownership_refuses_reused_launch_identity(self):
            p = self.policy
            start = p.runtime["ownership_identity"][0]

            def probe(argv):
                if argv[0] == "/bin/ps":
                    return f"{os.getuid()} {start} {p.editor} {p.board}\n"
                if "-d" in argv:
                    return f"p{p.runtime['pid']}\nf1\nn{p.editor}\n"
                return f"p{p.runtime['pid']}\nf3\ntunix\nn{p.socket}\n"

            def refuse_first_probe():
                owned = Ownership(p)
                self.assertIsNone(owned.identity)
                with mock.patch.object(Ownership, "probe", side_effect=probe) as probes:
                    with self.assertRaises(Denied):
                        owned.verify()
                    self.assertTrue(owned.invalid)
                    self.assertIsNone(owned.identity)
                    count = probes.call_count
                    with self.assertRaises(Denied):
                        owned.verify()
                    self.assertEqual(probes.call_count, count, "Ownership loss must remain latched")

            with mock.patch.object(Ownership, "probe", side_effect=probe):
                owned = Ownership(p)
                owned.verify()
                self.assertEqual(list(owned.identity), p.runtime["ownership_identity"])
            with self.subTest(change="process start"):
                start = "Mon Oct 5 12:00:01 2026"
                refuse_first_probe()
            start = p.runtime["ownership_identity"][0]
            for path in (p.socket, p.editor):
                with self.subTest(change="socket inode" if path == p.socket else "editor inode"):
                    previous = path.with_name(path.name + "-previous")
                    path.rename(previous)
                    try:
                        if path == p.socket:
                            with socket.socket(socket.AF_UNIX) as replacement:
                                replacement.bind(str(path))
                                self.assertNotEqual(path.stat().st_ino, previous.stat().st_ino)
                                refuse_first_probe()
                        else:
                            path.write_bytes(b"replacement editor, never executed\n")
                            path.chmod(0o700)
                            self.assertNotEqual(path.stat().st_ino, previous.stat().st_ino)
                            refuse_first_probe()
                    finally:
                        path.unlink()
                        previous.rename(path)

        def test_nonregular_inputs_and_empty_mutation_response(self):
            pipe = self.policy.workspace_root / "not-a-design.kicad_pcb"
            os.mkfifo(pipe)
            with self.assertRaises(Denied):
                regular_bytes(pipe)
            self.assertTrue(uncertain({"result": {"content": [], "isError": False}}))
            self.assertTrue(uncertain(result({"error": {"kind": "handler_error"}}, error=True)))
            self.assertFalse(uncertain(result({"error": {"kind": "invalid_argument"}}, error=True)))

        def test_schema_drift_and_strict_json(self):
            raw_tools = fixtures()
            raw_tools[0]["inputSchema"]["properties"]["arbitrary_path"] = {"type": "string"}
            with self.assertRaises(Denied):
                catalog(raw_tools, self.policy)
            for data in ('{"writes_enabled":false,"writes_enabled":true}', '{"x":NaN}'):
                with self.assertRaises(Denied):
                    strict_json(data)

    # Authorization tests must NEVER accidentally spawn Konnect, native KiCad,
    # ps, lsof, or any other process. Ownership probes above are explicitly mocked.
    with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("Self-test attempted a subprocess")):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
        passed = unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful()
    if not passed:
        raise SystemExit(1)
    print("PASS: pure scoped authorization, schemas, ownership mocks, snapshots/journal guards; no subprocesses")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--policy", type=Path, help="Absolute parent-supplied JSON policy")
    parser.add_argument("--self-test", action="store_true", help="Pure temp-dir/mock tests; no subprocesses")
    args = parser.parse_args()
    if args.self_test:
        if args.policy is not None:
            parser.error("--self-test and --policy are mutually exclusive")
        self_test()
        return
    if args.policy is None:
        parser.error("--policy is required for stdio mode")
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))
    try:
        serve(args.policy)
    except (OSError, ValueError, TransportFailure, subprocess.SubprocessError) as error:
        print("Scoped MCP refused startup/session: " + str(error), file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
