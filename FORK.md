# Personal-use Konnect fork

Repository: https://github.com/MarcusAndreasSvensson/Konnect

Upstream: https://github.com/mixelpixx/Konnect

Selected upstream baseline: `b0817e2da444910e55102e2d1cd50d2ce90a58c0` (2026-10-04), merged in `4382e4d` without conflicts.

Functionality on macOS ARM64 / KiCad 10.0.6 / Zed comes first. Public portability and upstream PR preparation are not requirements; focused changes make our own upstream updates easier. Upstream licensing and notices remain intact.

## Current patches

- `10f917b` — full-fidelity fresh schematic-to-PCB import and field ECOs. Reuse the richer library converter for attributes, description/tags, models, hidden custom fields and mandatory text presentation. Propagate schematic field add/change/explicit clear while preserving existing identities, layout, copper and models. Include library contents and board fields in reviewed plan revisions. Round library dimensions to the nearest nanometre rather than truncate them.
- `366ffed` — modify straight traces in place, preserving UUID, lock and parent. Validate the exact board, observed item type, quantized dimensions, enabled copper layer and net before mutation. Publish one typed update in a recoverable native commit and require fresh readback. Committed-but-unverified outcomes are not retry-safe. Malformed accepted BeginCommit/EndCommit replies are uncertain, not definite refusals; do not blindly roll back or retry them.
- `52020e7` — generated courtyards enclose the union of nominal body and rotation-aware pad envelopes. Invalid dimensions are refused before directories/files are written. Library search respects explicit/configured project directories, nickname shadowing, metadata and limits. Honor `KICAD_CONFIG_HOME`; resolve relative paths against each table's own directory while retaining the original `${KIPRJMOD}` base across nested tables.

Seven source files carry these patches. Absent schematic fields preserve PCB-only fields. Automatic field deletion, footprint replacement and repair of previously lossy imports are outside this slice.

## Validation

Rust 1.96.0 and the existing lockfile:

- Core library: **1,711 passed, 20 ignored**.
- IPC library: **85 passed, 1 ignored**.
- Scoped Clippy, all targets, warnings denied: passed.
- Scoped rustfmt and diff whitespace checks: passed.
- Debug candidate: built successfully; source hashes retained with local gate logs.

Live disposable scenarios passed for trace identity/lock/group preservation, invalid-edit refusal, subsequent deletion using the same UUID, field ECO identity preservation, courtyard geometry, private configuration and project/global library search.

A fresh disposable LED demo went directly through MCP import, placement/routing and native ERC/DRC/schematic parity with zero findings, without native repair. All three stock models and hidden fields remained. Exports yielded 12 manufacturing artifacts with matching BOM/placements and a STEP containing the board plus three component solids. Rules, severities and exclusions match the original failing lab; no validation findings were suppressed.

After the final nested-table path refinement, the final build passed the full unit/lint/build gates plus library search, native footprint geometry and native ERC/DRC file-based checks. **A final live GUI confirmation was blocked by KiCad startup/readiness failures before mutation. It is not a pass.** Earlier successful live evidence is retained separately; do not equate it with a completed final-build GUI rerun.

Ignored unit tests were not opted into. Native GUI Undo was not verified; inverse edits are not Undo. This is illustrative design validation, not hardware, part-rating, high-speed, thermal or fabrication qualification. KiCad 10 IPC is live-PCB/GUI-only; schematic and export operations still require supported CLI/file paths. External autorouting is not installed or qualified by these patches.

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
cargo build --locked -p konnect --bin konnect
```

On macOS, use a short private `TMPDIR` for Unix-socket tests and isolated KiCad preference/document directories. Run the controlled native regressions before promoting a candidate. Once verified, publish with `git push origin main`. Retain the previous executable for rollback. Retire a local patch when upstream genuinely replaces it; an overlapping unmerged upstream branch is not a replacement.

Do not automatically pull into a dirty tree, stash user changes, force-push, activate an unverified binary, or edit board files underneath an open editor.

## Deployment state

The implementation is maintained on this fork's `main`. The local candidate is a **debug build**, retained separately from the original executable. The active Zed configuration remains the original pinned, read-only integration; write tools have not been enabled there.

Candidate activation remains gated on a healthy exact live-editor check and reconciliation of the local integrity exceptions recorded in the lab report. Source, unit and saved-file checks alone do not prove live deployment readiness. Disposable designs, logs and machine-specific reports remain outside this Git repository and are not uploaded.
