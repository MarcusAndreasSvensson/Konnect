# Personal-use Konnect fork

Repository: https://github.com/MarcusAndreasSvensson/Konnect
Upstream: https://github.com/mixelpixx/Konnect
Validated upstream baseline: `3ad01f8b6de263d66b4d23801a1ea4cd1043704d` (2026-10-04).

Functionality on macOS ARM64 / KiCad 10.0.6 / Zed comes first. Public portability and upstream PR preparation are not required; focused changes make our own upstream updates easier. Upstream licensing and notices remain intact.

## Current patch

Only three source files change:

- `pcb_footprint_update.rs`: reuse the richer library converter for fresh import; retain stock attributes, description/tags, models, hidden custom fields and mandatory text presentation. Refresh keeps its existing placed-state semantics. Incomplete mandatory presentation is refused for fresh import instead of silently discarded.
- `pcb_sync.rs`: propagate schematic fields; support add/change/explicit clear and merge-only field ECOs while preserving existing identities, layout, copper and models. Hash library content and board fields into reviewed revisions. Verify field values/identities/presentation after commits, and report committed-but-unverified outcomes honestly.
- `konnect-ipc/src/builders.rs`: nearest-nanometre conversion rather than truncation of decimal library dimensions.

Absent schematic fields preserve PCB-only fields. Automatic field deletion, footprint replacement and repair of previously lossy imports are outside this patch.

## Validation

Rust 1.96.0 and the existing lockfile:

- Core library: 1,666 tests passed, 20 ignored.
- IPC library: 80 tests passed, 1 ignored.
- Scoped Clippy with all targets and warnings denied: passed.
- Scoped rustfmt and diff whitespace checks: passed.
- Debug candidate built successfully.

The disposable LED demo went directly through MCP import, placement/routing and field/value ECOs to native ERC/DRC/schematic parity with zero findings, without native repair. All three stock models remained; exports produced 12 manufacturing artifacts and a STEP containing the board plus three component solids. Existing field/pad/footprint/copper identities survived the exercised ECOs. The validation profile matches the original failing lab; no exclusions were added or severities weakened.

Ignored unit-suite tests were not opted into. In particular, native GUI Undo was not verified. This is illustrative design validation, not hardware, part-rating or fabrication qualification.

## Updating upstream

`origin` points to this fork; `upstream` points to the original repository. Use ordinary merges on the long-lived fork branch rather than rewriting shared history.

After authorized commits have preserved our changes, and with a clean working tree:

```sh
git --no-pager --no-optional-locks status --short
git fetch upstream
GIT_EDITOR=true git merge upstream/main
cargo test --locked -p konnect-core --lib
cargo test --locked -p konnect-ipc --lib
cargo clippy --locked -p konnect-core -p konnect-ipc --all-targets -- -D warnings
cargo build --locked -p konnect --bin konnect
```

On macOS, use a short private `TMPDIR` for Unix-socket tests and isolated KiCad preference directories. Repeat the native demo gates before promoting a new candidate. Keep the previous working executable for rollback. Retire a local patch when upstream genuinely replaces it.

Do not automatically pull into a dirty tree, stash user changes, force-push, activate an unverified binary, or edit files underneath an open editor.

## Deployment state

The verified implementation is maintained on this fork's `main`. The current candidate is `target/debug/konnect`, not an optimized release build. The active Zed integration still uses the original pinned read-only server. Lab designs and reports stay outside this repository and are not uploaded.
