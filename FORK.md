# Personal-use Konnect fork

Repository: https://github.com/MarcusAndreasSvensson/Konnect

Upstream: https://github.com/mixelpixx/Konnect

Selected upstream baseline: `b0817e2da444910e55102e2d1cd50d2ce90a58c0` (2026-10-04), merged in `4382e4d` without conflicts.

Functionality on macOS ARM64 / KiCad 10.0.6 / Zed comes first. Public portability and upstream PR preparation are not requirements; focused changes make our own upstream updates easier. Upstream licensing and notices remain intact.

## Current patches

- `10f917b` — full-fidelity fresh schematic-to-PCB import and field ECOs. Reuse the richer library converter for attributes, description/tags, models, hidden custom fields and mandatory text presentation. Propagate schematic field add/change/explicit clear while preserving existing identities, layout, copper and models. Include library contents and board fields in reviewed plan revisions. Round library dimensions to the nearest nanometre rather than truncate them.
- `366ffed` — modify straight traces in place, preserving UUID, lock and parent. Validate the exact board, observed item type, quantized dimensions, enabled copper layer and net before mutation. Publish one typed update in a recoverable native commit and require fresh readback. Committed-but-unverified outcomes are not retry-safe. Malformed accepted BeginCommit/EndCommit replies are uncertain, not definite refusals; do not blindly roll back or retry them.
- `52020e7` — generated courtyards enclose the union of nominal body and rotation-aware pad envelopes. Invalid dimensions are refused before directories/files are written. Library search respects explicit/configured project directories, nickname shadowing, metadata and limits. Honor `KICAD_CONFIG_HOME`; resolve relative paths against each table's own directory while retaining the original `${KIPRJMOD}` base across nested tables.

- Workbench deployment slice — DRC and top-down renders use unique `TMPDIR`-respecting scratch directories instead of overwriting/deleting board-adjacent files. Updated fake CLI tests write to the requested report path. Added the bounded macOS launcher, default-deny stdio broker and a private native Undo acceptance example.

Absent schematic fields preserve PCB-only fields. Automatic field deletion, footprint replacement and repair of previously lossy imports remain outside this slice. Machine-specific policies, designs, snapshots, journals and build reports are never committed.

## Validation

Rust 1.96.0 and the existing lockfile:

- Core library: **1,713 passed, 20 ignored**.
- IPC library: **85 passed, 1 ignored**; native-probe example: **1 passed**.
- Workspace Clippy, all targets, warnings denied: passed.
- rustfmt and diff whitespace checks: passed.
- Optimized release: built and qualified as the exact SHA256-pinned installed artifact. Its embedded build commit remains the pre-patch base; the local installation manifest records the final source commit and source hashes separately.
- Broker authorization/ownership tests: **25 passed**; launcher mocked guards/readiness/detachment tests passed.

Live disposable scenarios passed for trace identity/lock/group preservation, invalid-edit refusal, subsequent deletion using the same UUID, field ECO identity preservation, courtyard geometry, private configuration and project/global library search.

A fresh disposable LED demo went directly through MCP import, placement/routing and native ERC/DRC/schematic parity with zero findings, without native repair. All three stock models and hidden fields remained. Exports yielded 12 manufacturing artifacts with matching BOM/placements and a STEP containing the board plus three component solids. Rules, severities and exclusions match the original failing lab; no validation findings were suppressed.

The previous final-build startup block is now resolved and its failed attempts remain archived. The first editor may own `/tmp/kicad/api.sock`, not a PID-named socket; endpoint discovery now uses actual ownership. Detached native launch survives terminal-task exit. Explicit startup-not-ready observations are polled read-only under a deadline, never mistaken for a mutation retry. The original historical editor's unexplained exit remains unexplained.

The exact optimized artifact passed **27 circuit-workflow checks**. The actual broker passed **32 live authorization/journal/read-only checks** before the final identity-pinning refinement. After that refinement, first-probe process-start/socket/executable identity refusals were tested, and the final installed connector passed **13 live deployment gates**, including a freshly launched six-field runtime, native Undo on a locked/grouped track, save persistence, and clean ERC/DRC/parity. Zed's own launched connector answered installation/editor-state calls on the designated demo.

Ignored unit tests were not opted into. Native Undo was verified through one version-specific `RunAction` invocation per private acceptance stage, strict outer/inner status checks, and complete same-session typed/serialized restoration; inverse edits are not Undo. The probe's action name is not a stable API and is not exposed through the production broker.

Save/reopen preserved the complete native serialized board, apart from top-level item ordering, and the full target Track, apart from its runtime-only root container UUID. Raw footprint/via/zone IPC protobufs resolve some unspecified/inherited defaults on reload and were **not byte-identical**; exhaustive effective-default equivalence is not claimed. Undo comparisons within one instance were exact.

This is illustrative design validation, not hardware, part-rating, high-speed, thermal or fabrication qualification. KiCad 10 IPC is live-PCB/GUI-only; schematic and export operations still require supported CLI/file paths. External autorouting is not installed or qualified by these patches.

## Updating upstream

`origin` points to this fork; `upstream` points to the original repository. Use ordinary merges on the long-lived fork branch rather than rewriting shared history.

With a clean tree and local work committed:

```sh
git --no-pager --no-optional-locks status --short
git fetch upstream
GIT_EDITOR=true git merge upstream/main
cargo test --locked -p konnect-core --lib
cargo test --locked -p konnect-ipc --lib
cargo clippy --locked -p konnect-core -p konnect-ipc --all-targets -- -D warnings
cargo build --locked --release -p konnect --bin konnect
```

On macOS, use a short private `TMPDIR` for Unix-socket tests and isolated KiCad preference/document directories. Run the controlled native regressions before promoting a candidate. Once verified, publish with `git push origin main`. Retain the previous executable for rollback. Retire a local patch when upstream genuinely replaces it; an overlapping unmerged upstream branch is not a replacement.

Do not automatically pull into a dirty tree, stash user changes, force-push, activate an unverified binary, or edit board files underneath an open editor.

## Deployment state

The implementation is maintained on this fork's `main`. A durable independent checkout and pinned installation live in the local project's `.kicad-workbench/`, outside the old `.cache` trial. Zed's active `kicad-workbench` connector exposes **34 reviewed tools**, with bounded writes enabled only for the exact disposable LED demo; read-only policy mode exposes 19 tools. The original executable/wrapper and original project Zed settings are retained for rollback. This does not authorize writes to other designs or normal KiCad preferences.

`scripts/workbench/scoped_mcp.py` is the stdlib-only authorization boundary, **not an OS sandbox**. It pins the executable/config/policy/runtime, checks the original launch identity from the first probe, requires the exact sole board, default-denies methods/keys/paths, backs up saved files before writes, and fsyncs mutation intents/results. Uncertain or pending requests persistently block writes. Backup files do not capture unsaved GUI state; same-user interference and GUI races are not atomically excluded.

`scripts/workbench/launch_workbench.py --policy /absolute/policy.json` performs an explicit private macOS launch. It never guesses a socket or restarts an ambiguous session. Runtime has six exact fields: `ready`, `pid`, `executable`, `board`, `socket`, and `ownership_identity` (process start plus socket/executable device and inode identities). If the editor closes, an operator must inspect the old process, saved/unsaved state and journal, archive reconciled runtime/config/logs and proven stale owned locks, then launch and restart the Zed connector. There is no automatic journal reset, lock deletion or reconnect.

The historical integrity exception was reconciled at content level without restoring the original trial or suppressing design rules. Changes to original router-option defaults and the original exit cause were not fully established; the new workbench started with a fresh private profile. Original trial design and normal KiCad preferences stayed unchanged against the separately recorded deployment baseline. Global Zed settings changed during qualification; their origin was not established and they were not manually edited/restored by the agent. Local evidence retains those distinctions.

Promotion still requires exact-artifact native/editor checks. An upstream merge does **not** automatically replace the pinned deployed executable or scripts; build, qualify and deliberately promote a new artifact, retaining rollback. No actual product circuit has been selected yet.
