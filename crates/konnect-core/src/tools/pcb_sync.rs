//! Pure schematic-to-board synchronization planning.
//!
//! The public tool handler and KiCad IPC adapter live outside this module.
//! This module owns the deep planning interface: turn a KiCad-exported
//! flattened netlist plus a board snapshot into a complete, immutable plan.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::mcp::protocol::{CallToolResult, ToolContent};
use crate::tools::{
    pcb_board::{attempt_ipc_write, BoardWrite},
    pcb_footprint_update::{build_import_instance, parse_library_footprint, LibraryFootprint},
    ToolContext,
};
use anyhow::{bail, Context, Result};
use konnect_sexp::SexpNode;
use prost::Message;
use serde::Serialize;
use sha2::{Digest, Sha256};

// Count bound only: this does not claim a byte-size or listener-size limit.
const SYNC_CREATE_CHUNK_SIZE: usize = 32;

fn create_sync_items_in(
    client: &konnect_ipc::KiCadIpcClient,
    document: &konnect_ipc::gen::kiapi::common::types::DocumentSpecifier,
    creates: &[prost_types::Any],
) -> Result<()> {
    for chunk in creates.chunks(SYNC_CREATE_CHUNK_SIZE) {
        client.create_items_in(document.clone(), chunk.to_vec())?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportedDesign {
    components: Vec<DesignComponent>,
    skipped: Vec<SkippedComponent>,
    /// Components the export names but carries no `(footprint …)` for: their
    /// `Footprint` property is empty. Nothing can be placed for them, so they
    /// are reported rather than planned — and never fatal (#507).
    unassigned: Vec<UnassignedComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnassignedComponent {
    reference: String,
    value: String,
    lib_id: Option<String>,
    symbol_path: String,
}

/// What the board holds for a component whose schematic footprint is empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum UnassignedBoardState {
    /// No footprint on the board: nothing is added, the part is reported.
    Absent,
    /// A footprint with this identity or reference already exists; it is left
    /// exactly as it is, the way eeschema skips "cannot update … no footprint
    /// assigned" and continues.
    Kept,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct UnassignedFootprint {
    reference: String,
    value: String,
    lib_id: Option<String>,
    symbol_path: String,
    board_state: UnassignedBoardState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SkippedComponent {
    reference: String,
    symbol_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesignComponent {
    reference: String,
    value: String,
    footprint_id: String,
    symbol_path: String,
    dnp: bool,
    fields: BTreeMap<String, String>,
    pad_nets: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
struct Point {
    x: f64,
    y: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
struct Bounds {
    min_x: f64,
    min_y: f64,
    max_x: f64,
    max_y: f64,
}

#[derive(Debug, Clone, PartialEq)]
struct BoardFootprint {
    kiid: String,
    reference: String,
    value: String,
    footprint_id: String,
    symbol_path: Option<String>,
    fields: BTreeMap<String, String>,
    pad_nets: BTreeMap<String, String>,
    /// Every pad the live footprint has, netted or not. `pad_nets` holds only
    /// pads that carry a net, so it cannot answer whether a pad exists.
    pad_numbers: BTreeSet<String>,
    position: Point,
    rotation: f64,
    layer: String,
    locked: bool,
    dnp: bool,
    not_in_schematic: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct BoardState {
    footprints: Vec<BoardFootprint>,
    /// Net name to the number of routed copper objects (tracks, arcs, vias,
    /// and zones) carrying the net.
    routed_nets: BTreeMap<String, usize>,
    bounds: Bounds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PlanStatus {
    Ready,
    Noop,
    Conflict,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
struct CountPair {
    planned: usize,
    applied: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
struct SyncCounts {
    added: CountPair,
    updated: CountPair,
    pads_reassigned: CountPair,
    board_only_preserved: CountPair,
    skipped_by_flag: CountPair,
    /// Schematic components with no footprint assigned: reported, never
    /// planned, never fatal (#507).
    unassigned_footprint: CountPair,
    conflicts: CountPair,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct PreservedBoardState {
    position: Point,
    rotation: f64,
    layer: String,
    locked: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PlannedChange {
    Add {
        reference: String,
        value: String,
        footprint_id: String,
        symbol_path: String,
        dnp: bool,
        fields: BTreeMap<String, String>,
        pad_nets: BTreeMap<String, String>,
        position: Point,
    },
    Update {
        kiid: String,
        reference: String,
        value: String,
        symbol_path: String,
        dnp: bool,
        fields: BTreeMap<String, String>,
        pad_nets: BTreeMap<String, String>,
        preserve: PreservedBoardState,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SyncDiagnostic {
    code: String,
    message: String,
    /// The one part the diagnostic concerns; `None` when it concerns several
    /// parts or the board as a whole.
    reference: Option<String>,
    /// Every part the diagnostic concerns. One unusable library footprint
    /// blocks each part that uses it, and the caller has to be told all of
    /// them to know what to substitute (#657).
    references: Vec<String>,
    /// The library footprint the diagnostic is about, when it is about one.
    footprint_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct SyncPlan {
    status: PlanStatus,
    plan_revision: String,
    counts: SyncCounts,
    changes: Vec<PlannedChange>,
    diagnostics: Vec<SyncDiagnostic>,
    /// Survives a conflict: it is a report about the schematic, not a change
    /// the plan would make.
    unassigned: Vec<UnassignedFootprint>,
}

#[derive(Debug)]
struct LiveSnapshot {
    state: BoardState,
    items: BTreeMap<String, prost_types::Any>,
    net_codes: BTreeMap<String, i32>,
    document: konnect_ipc::gen::kiapi::common::types::DocumentSpecifier,
}

#[derive(Debug)]
struct PreparedFootprint {
    library: LibraryFootprint,
    width: f64,
    height: f64,
}

pub(crate) async fn handle_update_pcb_from_schematic(
    args: &serde_json::Value,
    ctx: &ToolContext,
) -> Result<CallToolResult> {
    let schematic = crate::tools::get_path(args, "schematic")?;
    let board = crate::tools::get_path(args, "board")?;
    let dry_run = args["dry_run"].as_bool().unwrap_or(true);
    let expected_revision = args["expected_plan_revision"].as_str().map(str::to_string);
    if !dry_run && expected_revision.is_none() {
        return Ok(CallToolResult::error_kind(
            crate::mcp::error::ToolErrorKind::InvalidArgument {
                field: "expected_plan_revision".to_string(),
                reason: "required when dry_run is false".to_string(),
            },
            "Apply requires the plan revision returned by a current dry run.",
        ));
    }
    if !schematic.exists() || !board.exists() {
        let missing = if !schematic.exists() {
            &schematic
        } else {
            &board
        };
        return Ok(CallToolResult::error_kind(
            crate::mcp::error::ToolErrorKind::FileNotFound {
                path: missing.display().to_string(),
            },
            format!("{} does not exist", missing.display()),
        ));
    }

    let hierarchy = match saved_hierarchy_files(&schematic) {
        Ok(files) => files,
        Err(error) => {
            return Ok(conflict_result(format!(
                "saved schematic preflight failed: {error:#}"
            )))
        }
    };
    let temp = tempfile::Builder::new().suffix(".net").tempfile()?;
    if let Err(error) =
        super::cli::export_netlist(&ctx.config.kicad_cli, &schematic, temp.path(), "kicadsexpr")
            .await
    {
        return Ok(conflict_result(format!(
            "KiCad netlist export failed: {error:#}"
        )));
    }
    let netlist_source = match std::fs::read_to_string(temp.path()) {
        Ok(source) => source,
        Err(error) => {
            return Ok(conflict_result(format!(
                "KiCad netlist export could not be read: {error}"
            )))
        }
    };
    let mut design = match parse_exported_netlist(&netlist_source) {
        Ok(design) => design,
        Err(error) => {
            return Ok(conflict_result(format!(
                "netlist preflight failed: {error:#}"
            )))
        }
    };
    if let Err(error) = apply_saved_symbol_flags(&hierarchy, &mut design) {
        return Ok(conflict_result(format!(
            "schematic flag preflight failed: {error:#}"
        )));
    }

    let what = if dry_run {
        "PCB sync dry run"
    } else {
        "PCB sync apply"
    };
    let ipc_board = board.clone();
    let library_board = board.clone();
    let result = attempt_ipc_write(
        ctx,
        &board,
        what,
        move |client| {
            let snapshot = snapshot_board(client, &ipc_board)?;
            let mut plan = plan_sync(&netlist_source, &design, &snapshot.state);
            let (prepared, unprepared) = prepare_additions(&library_board, &plan);
            // Everything that would fail the apply is found here, so `ready`
            // means ready: each footprint that cannot be prepared, named with
            // the parts that need it, and each connected pad a prepared
            // footprint does not have.
            let mut preflight = unprepared
                .into_iter()
                .map(UnpreparedFootprint::into_diagnostic)
                .collect::<Vec<_>>();
            preflight.extend(additions_missing_pads(&plan, &prepared));
            if !preflight.is_empty() {
                refuse_plan(&mut plan, preflight);
                return Ok(sync_response(&plan, "conflict", hierarchy.len(), false));
            }
            restage_additions(&mut plan, &prepared, snapshot.state.bounds);
            refresh_revision_with_staging(&mut plan, &prepared);

            if dry_run || plan.status == PlanStatus::Conflict {
                let status = match plan.status {
                    PlanStatus::Ready => "ready",
                    PlanStatus::Noop => "noop",
                    PlanStatus::Conflict => "conflict",
                };
                return Ok(sync_response(&plan, status, hierarchy.len(), false));
            }
            if expected_revision.as_deref() != Some(plan.plan_revision.as_str()) {
                plan.status = PlanStatus::Conflict;
                plan.counts.conflicts.planned += 1;
                plan.diagnostics.push(conflict(
                    "stale_plan_revision",
                    "The live board, saved schematic or footprint library changed; rerun dry run and apply its new plan revision."
                        .to_string(),
                    None,
                ));
                plan.changes.clear();
                return Ok(sync_response(&plan, "conflict", hierarchy.len(), false));
            }
            if plan.status == PlanStatus::Noop {
                return Ok(sync_response(&plan, "noop", hierarchy.len(), false));
            }

            let (creates, updates) = build_mutation_items(&plan, &prepared, &snapshot)?;
            // What we are about to send, so the board can be held to it.
            let expected = footprint_readback(creates.iter().chain(updates.iter()))?;
            client.run_commit_recovering_in(snapshot.document.clone(), "Update PCB from saved schematic", |client| {
                create_sync_items_in(client, &snapshot.document, &creates)?;
                client.update_items_in(snapshot.document.clone(), updates)?;
                Ok(())
            })?;
            let verification = match verify_committed_footprints(client, &snapshot.document, &expected) {
                Ok(details) => details,
                Err(result) => return Ok(result),
            };
            for detail in verification {
                plan.diagnostics.push(conflict(
                    "board_readback_differs",
                    format!(
                        "the board KiCad wrote differs from what was sent — {detail}. \
                         No pad was invented, so this is reported rather than \
                         refused; check the footprint before relying on it."
                    ),
                    None,
                ));
            }
            plan.counts.added.applied = plan.counts.added.planned;
            plan.counts.updated.applied = plan.counts.updated.planned;
            plan.counts.pads_reassigned.applied = plan.counts.pads_reassigned.planned;
            plan.counts.board_only_preserved.applied =
                plan.counts.board_only_preserved.planned;
            plan.counts.skipped_by_flag.applied = plan.counts.skipped_by_flag.planned;
            plan.counts.unassigned_footprint.applied = plan.counts.unassigned_footprint.planned;
            Ok(sync_response(&plan, "applied", hierarchy.len(), true))
        },
    )
    .await?;

    Ok(match result {
        BoardWrite::Ipc(result) => result,
        BoardWrite::File(reason) => conflict_result(format!(
            "{} update_pcb_from_schematic is live-IPC-only and never edits the board file \
             directly. Open the requested board in KiCad and retry.",
            reason.premise()
        )),
        BoardWrite::Refused(result) => {
            // Preserve the structured uncertain outcome instead of claiming
            // the sync was a preflight conflict with no applied changes.
            if matches!(
                crate::mcp::error::extract_error_kind(&result).as_deref(),
                Some("ipc_outcome_unknown" | "ipc_batch_recovered")
            ) {
                return Ok(result);
            }
            let message = result
                .content
                .into_iter()
                .find_map(|content| match content {
                    ToolContent::Text { text } => Some(text),
                    _ => None,
                })
                .unwrap_or_else(|| "KiCad refused the sync request".to_string());
            conflict_result(message)
        }
    })
}

fn sync_response(
    plan: &SyncPlan,
    status: &str,
    hierarchy_files: usize,
    applied: bool,
) -> CallToolResult {
    let value = serde_json::json!({
        "status": status,
        "plan_revision": plan.plan_revision,
        "coverage": {
            "source": "saved_schematic_hierarchy",
            "hierarchy_files": hierarchy_files,
            "transport": "live_kicad_ipc",
            "atomicity": "single_kicad_undo_commit",
            "footprints_added": plan.counts.added,
            "footprints_updated": plan.counts.updated,
            "pads_reassigned": plan.counts.pads_reassigned,
            "board_only_preserved": plan.counts.board_only_preserved,
            "skipped_by_flag": plan.counts.skipped_by_flag,
            "unassigned_footprint": plan.counts.unassigned_footprint,
            "conflicts": plan.counts.conflicts
        },
        "changes": plan.changes,
        "diagnostics": plan.diagnostics,
        // Schematic components with no footprint: reported per part with what
        // the board holds for them, never planned and never fatal (#507). A
        // collection takes a plural noun (docs/NAMING_CONVENTIONS.md); the
        // `coverage` entry beside it is a count category and stays singular.
        "unassigned_footprints": plan.unassigned,
        "undo": if applied { Some("Ctrl-Z reverses the whole schematic-to-PCB update.") } else { None }
    });
    CallToolResult::json(&value)
}

/// A refusal before any plan exists: the saved hierarchy, the netlist export
/// or the IPC preflight failed. Its one diagnostic is built by `conflict`, the
/// constructor every planned diagnostic uses, so a caller reads the same
/// fields whichever stage refused.
fn conflict_result(message: String) -> CallToolResult {
    let value = serde_json::json!({
        "status": "conflict",
        "coverage": {
            "transport": "live_kicad_ipc",
            "footprints_added": CountPair::default(),
            "footprints_updated": CountPair::default(),
            "pads_reassigned": CountPair::default(),
            "board_only_preserved": CountPair::default(),
            "skipped_by_flag": CountPair::default(),
            "unassigned_footprint": CountPair::default(),
            "conflicts": CountPair { planned: 1, applied: 0 }
        },
        "diagnostics": [conflict("preflight_conflict", message, None)]
    });
    CallToolResult {
        content: vec![ToolContent::Text {
            text: value.to_string(),
        }],
        is_error: true,
    }
}

fn plan_sync(netlist_source: &str, design: &ExportedDesign, board: &BoardState) -> SyncPlan {
    let mut diagnostics = Vec::new();
    let mut counts = SyncCounts::default();
    let mut changes = Vec::new();
    let mut board_by_path = HashMap::new();
    let mut board_by_reference = HashMap::new();

    // Every reference the schematic export names, on either side of the
    // `on_board` flag. A duplicate board reference only matters when this set
    // contains it: `board_by_reference` is consulted at four sites below, and
    // each one looks up a reference that came from the export —
    // `skipped.reference` once and `component.reference` three times. A
    // reference the export never names is therefore never looked up, so which
    // of the duplicates `insert` happened to keep is unobservable.
    //
    // The map is still built from every footprint, duplicates included. Only
    // the diagnostic is scoped; suppressing the insert would change which
    // footprint an unrelated adoption resolves to.
    let exported_references = design
        .components
        .iter()
        .map(|component| component.reference.as_str())
        .chain(
            design
                .skipped
                .iter()
                .map(|skipped| skipped.reference.as_str()),
        )
        .chain(
            design
                .unassigned
                .iter()
                .map(|unassigned| unassigned.reference.as_str()),
        )
        .collect::<HashSet<_>>();

    for (index, footprint) in board.footprints.iter().enumerate() {
        let duplicate_reference = board_by_reference
            .insert(footprint.reference.as_str(), index)
            .is_some();
        if duplicate_reference && exported_references.contains(footprint.reference.as_str()) {
            diagnostics.push(conflict(
                "duplicate_board_reference",
                format!("board contains duplicate reference {}", footprint.reference),
                Some(&footprint.reference),
            ));
        }
        if let Some(path) = footprint.symbol_path.as_deref() {
            if board_by_path.insert(path, index).is_some() {
                diagnostics.push(conflict(
                    "duplicate_board_identity",
                    format!("board contains duplicate schematic identity {path}"),
                    Some(&footprint.reference),
                ));
            }
        }
    }

    let mut matched = std::collections::HashSet::new();
    let mut design_references = std::collections::HashSet::new();
    let mut design_paths = std::collections::HashSet::new();
    let staging_x = board.bounds.max_x + 10.0;
    let mut add_index = 0usize;

    let mut skipped_references = HashSet::new();
    let mut skipped_paths = HashSet::new();
    for skipped in &design.skipped {
        if !skipped_references.insert(skipped.reference.as_str())
            || !skipped_paths.insert(skipped.symbol_path.as_str())
        {
            diagnostics.push(conflict(
                "duplicate_skipped_identity",
                format!(
                    "on_board=no instance {} has a duplicate reference or identity",
                    skipped.reference
                ),
                Some(&skipped.reference),
            ));
            continue;
        }
        counts.skipped_by_flag.planned += 1;
        let existing = board_by_path
            .get(skipped.symbol_path.as_str())
            .copied()
            .or_else(|| board_by_reference.get(skipped.reference.as_str()).copied());
        if let Some(index) = existing {
            matched.insert(index);
            diagnostics.push(conflict(
                "on_board_exclusion_conflict",
                format!(
                    "{} is marked on_board=no but already exists on the board",
                    skipped.reference
                ),
                Some(&skipped.reference),
            ));
        }
    }

    // No footprint assigned: nothing can be placed, so the part is reported
    // with what the board holds for it and the sync goes on for everything
    // else — eeschema's own Update PCB behaviour. Never a diagnostic: a
    // diagnostic clears the whole plan, which is exactly what #507 fixes.
    let mut unassigned = Vec::new();
    for component in &design.unassigned {
        counts.unassigned_footprint.planned += 1;
        let existing = board_by_path
            .get(component.symbol_path.as_str())
            .copied()
            .or_else(|| {
                board_by_reference
                    .get(component.reference.as_str())
                    .copied()
            });
        let board_state = match existing {
            Some(index) => {
                // Left untouched, as KiCad leaves it; counted as matched so
                // it is not reported as a board-only footprint.
                matched.insert(index);
                UnassignedBoardState::Kept
            }
            None => UnassignedBoardState::Absent,
        };
        unassigned.push(UnassignedFootprint {
            reference: component.reference.clone(),
            value: component.value.clone(),
            lib_id: component.lib_id.clone(),
            symbol_path: component.symbol_path.clone(),
            board_state,
        });
    }

    for component in &design.components {
        if !design_references.insert(component.reference.as_str()) {
            diagnostics.push(conflict(
                "duplicate_schematic_reference",
                format!(
                    "schematic export contains duplicate reference {}",
                    component.reference
                ),
                Some(&component.reference),
            ));
            continue;
        }
        if !design_paths.insert(component.symbol_path.as_str()) {
            diagnostics.push(conflict(
                "duplicate_schematic_identity",
                format!(
                    "schematic export contains duplicate identity {}",
                    component.symbol_path
                ),
                Some(&component.reference),
            ));
            continue;
        }

        let matched_index = board_by_path
            .get(component.symbol_path.as_str())
            .copied()
            .or_else(|| {
                board_by_reference
                    .get(component.reference.as_str())
                    .copied()
                    .filter(|index| board.footprints[*index].symbol_path.is_none())
            });

        let Some(index) = matched_index else {
            if let Some(index) = board_by_reference
                .get(component.reference.as_str())
                .copied()
            {
                diagnostics.push(conflict(
                    "reference_identity_conflict",
                    format!(
                        "reference {} belongs to a different schematic identity on the board",
                        component.reference
                    ),
                    Some(&board.footprints[index].reference),
                ));
                continue;
            }
            let possible_renames = board
                .footprints
                .iter()
                .enumerate()
                .filter(|(index, footprint)| {
                    !matched.contains(index)
                        && footprint.symbol_path.is_none()
                        && !footprint.not_in_schematic
                        && footprint.footprint_id == component.footprint_id
                        && footprint.value == component.value
                })
                .collect::<Vec<_>>();
            if !possible_renames.is_empty() {
                diagnostics.push(conflict(
                    "reference_only_rename_ambiguous",
                    format!(
                        "{} has no stable board identity and could be a rename of {}; link or resolve the identity in KiCad",
                        component.reference,
                        possible_renames
                            .iter()
                            .map(|(_, footprint)| footprint.reference.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    Some(&component.reference),
                ));
                continue;
            }
            let position = Point {
                x: staging_x,
                y: board.bounds.min_y + add_index as f64 * 10.0,
            };
            add_index += 1;
            changes.push(PlannedChange::Add {
                reference: component.reference.clone(),
                value: component.value.clone(),
                footprint_id: component.footprint_id.clone(),
                symbol_path: component.symbol_path.clone(),
                dnp: component.dnp,
                fields: component.fields.clone(),
                pad_nets: component.pad_nets.clone(),
                position,
            });
            counts.added.planned += 1;
            continue;
        };

        matched.insert(index);
        let footprint = &board.footprints[index];
        if footprint.reference != component.reference {
            if let Some(other_index) = board_by_reference
                .get(component.reference.as_str())
                .copied()
                .filter(|other_index| *other_index != index)
            {
                diagnostics.push(conflict(
                    "reference_rename_collision",
                    format!(
                        "cannot rename {} to {} because that reference belongs to board footprint {}",
                        footprint.reference,
                        component.reference,
                        board.footprints[other_index].kiid
                    ),
                    Some(&component.reference),
                ));
                continue;
            }
        }
        if footprint.footprint_id != component.footprint_id {
            diagnostics.push(conflict(
                "footprint_id_changed",
                format!(
                    "{} uses {} on the board but {} in the schematic",
                    component.reference, footprint.footprint_id, component.footprint_id
                ),
                Some(&component.reference),
            ));
            continue;
        }
        // A pad the schematic connects and the live footprint lacks used to
        // reach `apply_footprint_fields` and fail the apply, after a dry run
        // that said `ready` (#657).
        let missing = missing_pads(&component.pad_nets, &footprint.pad_numbers);
        if !missing.is_empty() {
            diagnostics.push(pad_missing_conflict(
                &component.reference,
                &footprint.footprint_id,
                &missing,
            ));
            continue;
        }

        let mut changed_pads = 0usize;
        let pad_numbers = component
            .pad_nets
            .keys()
            .chain(footprint.pad_nets.keys())
            .collect::<std::collections::BTreeSet<_>>();
        for number in pad_numbers {
            let new_net = component
                .pad_nets
                .get(number)
                .map(String::as_str)
                .unwrap_or("");
            let old_net = footprint
                .pad_nets
                .get(number)
                .map(String::as_str)
                .unwrap_or("");
            if old_net == new_net {
                continue;
            }
            if board.routed_nets.contains_key(old_net) || board.routed_nets.contains_key(new_net) {
                diagnostics.push(conflict(
                    "routed_pad_net_change",
                    format!(
                        "{} pad {} would change from '{}' to '{}' while routed copper uses that net",
                        component.reference, number, old_net, new_net
                    ),
                    Some(&component.reference),
                ));
            } else {
                changed_pads += 1;
            }
        }

        let needs_update = footprint.reference != component.reference
            || footprint.value != component.value
            || footprint.symbol_path.as_deref() != Some(component.symbol_path.as_str())
            || footprint.dnp != component.dnp
            || component
                .fields
                .iter()
                .any(|(name, value)| footprint.fields.get(name) != Some(value))
            || changed_pads > 0;
        if needs_update {
            changes.push(PlannedChange::Update {
                kiid: footprint.kiid.clone(),
                reference: component.reference.clone(),
                value: component.value.clone(),
                symbol_path: component.symbol_path.clone(),
                dnp: component.dnp,
                fields: component.fields.clone(),
                pad_nets: component.pad_nets.clone(),
                preserve: PreservedBoardState {
                    position: footprint.position,
                    rotation: footprint.rotation,
                    layer: footprint.layer.clone(),
                    locked: footprint.locked,
                },
            });
            counts.updated.planned += 1;
            counts.pads_reassigned.planned += changed_pads;
        }
    }

    counts.board_only_preserved.planned = board.footprints.len() - matched.len();
    counts.conflicts.planned = diagnostics.len();
    if !diagnostics.is_empty() {
        changes.clear();
        counts.added.planned = 0;
        counts.updated.planned = 0;
        counts.pads_reassigned.planned = 0;
    }
    let status = if !diagnostics.is_empty() {
        PlanStatus::Conflict
    } else if changes.is_empty() {
        PlanStatus::Noop
    } else {
        PlanStatus::Ready
    };
    let plan_revision = plan_revision(netlist_source, board);
    SyncPlan {
        status,
        plan_revision,
        counts,
        changes,
        diagnostics,
        unassigned,
    }
}

fn conflict(code: &str, message: String, reference: Option<&str>) -> SyncDiagnostic {
    SyncDiagnostic {
        code: code.to_string(),
        message,
        reference: reference.map(str::to_string),
        references: reference.map(str::to_string).into_iter().collect(),
        footprint_id: None,
    }
}

/// A diagnostic about one library footprint and every part that uses it.
/// `reference` keeps its single-part meaning, so it is set only when exactly
/// one part is concerned.
fn footprint_conflict(
    code: &str,
    message: String,
    footprint_id: &str,
    references: Vec<String>,
) -> SyncDiagnostic {
    SyncDiagnostic {
        code: code.to_string(),
        message,
        reference: match references.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        },
        references,
        footprint_id: Some(footprint_id.to_string()),
    }
}

/// References for a message, bounded: a common footprint can block hundreds
/// of parts, and the complete list is in the diagnostic's `references`.
fn listed(references: &[String]) -> String {
    const SHOWN: usize = 8;
    let shown = references
        .iter()
        .take(SHOWN)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    match references.len().saturating_sub(SHOWN) {
        0 => shown,
        more => format!("{shown} and {more} more"),
    }
}

/// The schematic connects a pad the footprint does not have. `missing` is
/// never empty.
fn pad_missing_conflict(reference: &str, footprint_id: &str, missing: &[&str]) -> SyncDiagnostic {
    let pads = if missing.len() == 1 { "pad" } else { "pads" };
    footprint_conflict(
        "footprint_pad_missing",
        format!(
            "the schematic connects {reference} {pads} {}, which footprint {footprint_id} does not have",
            missing.join(", ")
        ),
        footprint_id,
        vec![reference.to_string()],
    )
}

/// Pad numbers the schematic connects that `available` does not contain.
fn missing_pads<'a>(
    pad_nets: &'a BTreeMap<String, String>,
    available: &BTreeSet<String>,
) -> Vec<&'a str> {
    pad_nets
        .keys()
        .filter(|number| !available.contains(*number))
        .map(String::as_str)
        .collect()
}

/// A stable identity for the design-bearing netlist sections.
///
/// `kicad-cli sch export netlist` stamps `(date "…T14:48:16")` and the
/// exporting tool's version into every export, so hashing the raw source
/// yields a different revision **every second** for a design nobody touched —
/// and since apply requires the revision a dry run returned, apply could only
/// ever succeed if both calls landed inside the same wall-clock second. That
/// is a race, not a guarantee: it passes on a fast machine and fails on a
/// human reviewing the plan first, which is the whole point of the plan.
///
/// The revision must cover what the plan *read*: the complete top-level
/// `components` and `nets` trees. Hashing those trees structurally ignores the
/// volatile header without confusing nested nodes or quoted text for header
/// metadata.
fn netlist_identity(netlist_source: &str) -> Vec<u8> {
    let Ok(root) = konnect_sexp::parse_sexp(netlist_source) else {
        // Production reaches this function only after successful netlist
        // parsing. Keeping invalid synthetic planner inputs distinct makes the
        // pure planner tests useful without creating a second error path here.
        return netlist_source.as_bytes().to_vec();
    };

    let mut identity = Vec::new();
    for tag in ["components", "nets"] {
        match root.find(tag) {
            Some(node) => {
                identity.push(1);
                append_sexp_identity(node, &mut identity);
            }
            None => identity.push(0),
        }
    }
    identity
}

fn append_sexp_identity(node: &SexpNode, identity: &mut Vec<u8>) {
    match node {
        SexpNode::Atom(value) => {
            identity.push(0);
            append_identity_bytes(value.as_bytes(), identity);
        }
        SexpNode::Str(value) => {
            identity.push(1);
            append_identity_bytes(value.as_bytes(), identity);
        }
        SexpNode::List(children) => {
            identity.push(2);
            identity.extend_from_slice(&(children.len() as u64).to_le_bytes());
            for child in children {
                append_sexp_identity(child, identity);
            }
        }
    }
}

fn append_identity_bytes(value: &[u8], identity: &mut Vec<u8>) {
    identity.extend_from_slice(&(value.len() as u64).to_le_bytes());
    identity.extend_from_slice(value);
}

fn plan_revision(netlist_source: &str, board: &BoardState) -> String {
    let mut footprints = board.footprints.iter().collect::<Vec<_>>();
    footprints.sort_by(|a, b| a.kiid.cmp(&b.kiid));
    let mut hasher = Sha256::new();
    hasher.update(netlist_identity(netlist_source));
    hasher.update(serde_json::to_vec(&board.bounds).expect("bounds serialize"));
    for footprint in footprints {
        hasher.update(footprint.kiid.as_bytes());
        hasher.update(footprint.reference.as_bytes());
        hasher.update(footprint.footprint_id.as_bytes());
        hasher.update(footprint.symbol_path.as_deref().unwrap_or("").as_bytes());
        hasher.update(serde_json::to_vec(&footprint.fields).expect("footprint fields serialize"));
        for (pad, net) in &footprint.pad_nets {
            hasher.update(pad.as_bytes());
            hasher.update(net.as_bytes());
        }
    }
    for (net, count) in &board.routed_nets {
        hasher.update(net.as_bytes());
        hasher.update(count.to_le_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn refresh_revision_with_staging(
    plan: &mut SyncPlan,
    prepared: &BTreeMap<String, PreparedFootprint>,
) {
    let mut hasher = Sha256::new();
    hasher.update(plan.plan_revision.as_bytes());
    hasher.update(serde_json::to_vec(&plan.changes).expect("planned changes serialize"));
    for (library_id, part) in prepared {
        hasher.update(serde_json::to_vec(library_id).expect("library ID serializes"));
        hasher.update(part.library.source_digest);
    }
    plan.plan_revision = format!("{:x}", hasher.finalize());
}

fn parse_exported_netlist(source: &str) -> Result<ExportedDesign> {
    let root = konnect_sexp::parse_sexp(source).context("invalid KiCad netlist S-expression")?;
    let components_node = root
        .find("components")
        .context("KiCad netlist has no components section")?;

    let mut components = Vec::new();
    let mut by_reference = HashMap::new();
    let mut unassigned = Vec::new();
    let mut unassigned_references = HashSet::new();
    let mut seen_references = HashSet::new();
    for component_node in components_node.find_all("comp") {
        let reference = required_value(component_node, "ref")?;
        // One invariant for every exported component, checked before the
        // footprint branch: an unassigned component never enters
        // `by_reference`, so a check there alone let a reference repeat
        // across the two roles and reach the plan (#507 review).
        if !seen_references.insert(reference.clone()) {
            bail!("KiCad netlist contains duplicate component reference {reference}");
        }

        let sheet_stamp = component_node
            .find("sheetpath")
            .and_then(|sheet| sheet.find_str("tstamps"))
            .context("KiCad netlist component has no sheet timestamp")?;
        let symbol_stamp = component_node
            .find_str("tstamps")
            .context("KiCad netlist component has no symbol timestamp")?;
        let symbol_path = format!(
            "/{}/{}",
            sheet_stamp.trim_matches('/'),
            symbol_stamp.trim_matches('/')
        )
        .replace("//", "/");
        let dnp = component_node.find_all("property").iter().any(|property| {
            property.find_str("name") == Some("dnp")
                || property.get(1).and_then(SexpNode::as_str) == Some("dnp")
        });

        let value = required_value(component_node, "value")?;
        let fields = parse_component_fields(component_node)
            .with_context(|| format!("component {reference} has invalid schematic fields"))?;
        // kicad-cli writes no `(footprint …)` node at all for a symbol whose
        // Footprint property is empty — only a bare `(field (name
        // "Footprint"))`. That is a legitimate state (a generic `Device:R`
        // whose package has not been chosen yet), and it used to fail the
        // whole sync for every other component with it (#507).
        let footprint_id = component_node
            .find_str("footprint")
            .map(str::trim)
            .filter(|footprint| !footprint.is_empty())
            .map(str::to_owned);
        let Some(footprint_id) = footprint_id else {
            let lib_id = component_node.find("libsource").and_then(|source| {
                let lib = source.find_str("lib")?;
                let part = source.find_str("part")?;
                (!lib.is_empty() || !part.is_empty()).then(|| format!("{lib}:{part}"))
            });
            unassigned_references.insert(reference.clone());
            unassigned.push(UnassignedComponent {
                reference,
                value,
                lib_id,
                symbol_path,
            });
            continue;
        };

        let index = components.len();
        by_reference.insert(reference.clone(), index);
        components.push(DesignComponent {
            reference,
            value,
            footprint_id,
            symbol_path,
            dnp,
            fields,
            pad_nets: BTreeMap::new(),
        });
    }

    if components.is_empty() && unassigned.is_empty() {
        bail!("KiCad netlist contains zero components");
    }

    if let Some(nets_node) = root.find("nets") {
        for net_node in nets_node.find_all("net") {
            let net_name = required_value(net_node, "name")?;
            for node in net_node.find_all("node") {
                let reference = required_value(node, "ref")?;
                let pin = required_value(node, "pin")?;
                let Some(&index) = by_reference.get(&reference) else {
                    // A wired pin of a component with no footprint: there is
                    // no pad to carry the net, so the node is dropped, not
                    // fatal.
                    if unassigned_references.contains(&reference) {
                        continue;
                    }
                    bail!("net {net_name} refers to unknown component {reference}");
                };
                if components[index]
                    .pad_nets
                    .insert(pin.clone(), net_name.clone())
                    .is_some()
                {
                    bail!("component {reference} pad {pin} appears in more than one net");
                }
            }
        }
    }

    Ok(ExportedDesign {
        components,
        skipped: Vec::new(),
        unassigned,
    })
}

/// KiCad's export puts the value at index 2, not in a `(value ...)` node.
/// A bare `(field (name "Datasheet"))` explicitly requests an empty value.
fn parse_component_fields(component: &SexpNode) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    let sections = component.find_all("fields");
    if sections.len() > 1 {
        bail!("schematic component has more than one fields section");
    }
    if let Some(section) = sections.first() {
        for field in section.children().unwrap_or_default().iter().skip(1) {
            let children = field.children().context("schematic field is not a list")?;
            if field.head() != Some("field") || !(2..=3).contains(&children.len()) {
                bail!("malformed schematic field");
            }
            let name_node = field.get(1).context("schematic field has no name")?;
            if name_node.head() != Some("name")
                || name_node.children().map(|children| children.len()) != Some(2)
            {
                bail!("malformed schematic field name");
            }
            let name = name_node
                .get(1)
                .and_then(SexpNode::as_str)
                .filter(|name| !name.trim().is_empty())
                .context("schematic field has no scalar, non-empty name")?;
            let value = match field.get(2) {
                Some(value) => value
                    .as_str()
                    .context("schematic field value is not a scalar")?,
                None => "",
            };
            if fields.insert(name.to_string(), value.to_string()).is_some() {
                bail!("schematic field '{name}' appears more than once");
            }
        }
    }
    if !fields.contains_key("Datasheet") {
        if let Some(value) = optional_netlist_scalar(component, "datasheet")? {
            fields.insert("Datasheet".to_string(), value);
        }
    }
    if !fields.contains_key("Description") {
        let mut description = optional_netlist_scalar(component, "description")?;
        if description.is_none() {
            if let Some(libsource) = component.find("libsource") {
                description = optional_netlist_scalar(libsource, "description")?;
            }
        }
        if let Some(value) = description {
            fields.insert("Description".to_string(), value);
        }
    }
    fields.retain(|name, _| !matches!(name.as_str(), "Reference" | "Value" | "Footprint"));
    // Exporter property nodes also contain sheet names, filters and flags; they
    // are not schematic fields. DNP is handled separately by the caller.
    Ok(fields)
}

fn optional_netlist_scalar(node: &SexpNode, tag: &str) -> Result<Option<String>> {
    let nodes = node.find_all(tag);
    if nodes.len() > 1 {
        bail!("KiCad netlist repeats {tag}");
    }
    let Some(node) = nodes.first() else {
        return Ok(None);
    };
    if node.children().map(|children| children.len()).unwrap_or(0) > 2 {
        bail!("KiCad netlist has malformed {tag}");
    }
    Ok(Some(match node.get(1) {
        Some(value) => value
            .as_str()
            .with_context(|| format!("{tag} is not a scalar"))?
            .to_string(),
        None => String::new(),
    }))
}

fn required_value(node: &SexpNode, tag: &str) -> Result<String> {
    node.find_str(tag)
        .map(str::to_owned)
        .with_context(|| format!("KiCad netlist node is missing {tag}"))
}

fn update_footprint_item(
    item: &prost_types::Any,
    change: &PlannedChange,
    net_codes: &BTreeMap<String, i32>,
) -> Result<prost_types::Any> {
    use konnect_ipc::gen::kiapi;
    use prost::Message;

    let PlannedChange::Update {
        kiid,
        reference,
        value,
        symbol_path,
        dnp,
        fields,
        pad_nets,
        ..
    } = change
    else {
        bail!("an add change cannot update an existing footprint");
    };
    let mut footprint = kiapi::board::types::FootprintInstance::decode(item.value.as_slice())
        .context("KiCad returned an invalid footprint item")?;
    if footprint.id.as_ref().map(|id| id.value.as_str()) != Some(kiid.as_str()) {
        bail!("planned footprint {kiid} no longer matches the live board item");
    }

    apply_footprint_fields(
        &mut footprint,
        reference,
        value,
        symbol_path,
        *dnp,
        fields,
        pad_nets,
        net_codes,
    )?;

    Ok(konnect_ipc::builders::pack_any(
        &footprint,
        "kiapi.board.types.FootprintInstance",
    ))
}

#[allow(clippy::too_many_arguments)]
fn apply_footprint_fields(
    footprint: &mut konnect_ipc::gen::kiapi::board::types::FootprintInstance,
    reference: &str,
    value: &str,
    symbol_path: &str,
    dnp: bool,
    fields: &BTreeMap<String, String>,
    pad_nets: &BTreeMap<String, String>,
    net_codes: &BTreeMap<String, i32>,
) -> Result<()> {
    use konnect_ipc::gen::kiapi;

    overlay_schematic_fields(footprint, fields)?;
    set_field_text(&mut footprint.reference_field, "Reference", reference);
    set_field_text(&mut footprint.value_field, "Value", value);
    let definition = footprint
        .definition
        .as_mut()
        .context("board footprint has no library definition")?;
    set_field_text(&mut definition.reference_field, "Reference", reference);
    set_field_text(&mut definition.value_field, "Value", value);

    if board_symbol_path(footprint.symbol_path.as_ref()).as_deref() != Some(symbol_path) {
        footprint.symbol_path = Some(kiapi::common::types::SheetPath {
            path: symbol_path
                .split('/')
                .filter(|part| !part.is_empty())
                .map(|part| kiapi::common::types::Kiid {
                    value: part.to_string(),
                })
                .collect(),
            path_human_readable: String::new(),
        });
    }
    if dnp || footprint.attributes.is_some() {
        footprint
            .attributes
            .get_or_insert_with(Default::default)
            .do_not_populate = dnp;
    }
    if dnp || definition.attributes.is_some() {
        definition
            .attributes
            .get_or_insert_with(Default::default)
            .do_not_populate = dnp;
    }

    let mut seen_pads = std::collections::HashSet::new();
    for child in &mut definition.items {
        // `definition.items` mixes pads, graphics and text in one repeated
        // field, so the type URL is the only sound discriminator. Filtering by
        // "did `Pad::decode` succeed" instead accepted every graphic — proto3
        // skips unrecognised field numbers rather than failing — and the write
        // back below then re-typed each one as a pad, so every footprint this
        // tool touched lost its artwork and gained a nameless pad at (0,0)
        // for each shape it used to have (#244).
        if !konnect_ipc::builders::any_is(child, "kiapi.board.types.Pad") {
            continue;
        }
        // A child that *declares* itself a pad and will not decode is a real
        // failure, not something to skip past silently.
        let mut pad =
            kiapi::board::types::Pad::decode(child.value.as_slice()).with_context(|| {
                format!("footprint {reference} has a pad KiCad sent in a form Konnect cannot read")
            })?;
        seen_pads.insert(pad.number.clone());
        let desired_net = pad_nets.get(&pad.number).map(String::as_str).unwrap_or("");
        if pad.net.as_ref().map(|net| net.name.as_str()).unwrap_or("") == desired_net {
            // Keep the original Any bytes (including unknown protobuf fields)
            // and KiCad's net code when only schematic fields changed.
            continue;
        }
        pad.net = pad_nets
            .get(&pad.number)
            .map(|name| kiapi::board::types::Net {
                // Net codes are KiCad-internal. Preserve a resolved live code
                // when one exists; for a schematic-only net, the name is the
                // public identity and lets KiCad create the new board net.
                code: net_codes
                    .get(name)
                    .copied()
                    .map(|value| kiapi::board::types::NetCode { value }),
                name: name.clone(),
            });
        child.value = pad.encode_to_vec();
    }
    for number in pad_nets.keys() {
        if !seen_pads.contains(number) {
            bail!("footprint {reference} has no pad {number}");
        }
    }

    Ok(())
}

fn overlay_schematic_fields(
    footprint: &mut konnect_ipc::gen::kiapi::board::types::FootprintInstance,
    fields: &BTreeMap<String, String>,
) -> Result<()> {
    use konnect_ipc::gen::kiapi;

    // Validate the entire typed field set before mutating any of it. Unknown
    // item types are not fields, even when their bytes happen to decode as one.
    let current = footprint_field_slots(footprint)?;
    for name in fields.keys() {
        if name.trim().is_empty() || matches!(name.as_str(), "Reference" | "Value" | "Footprint") {
            bail!("invalid schematic metadata field '{name}'");
        }
    }
    let position = footprint.position.as_ref();
    let layer = if footprint.layer == kiapi::board::types::BoardLayer::BlBCu as i32 {
        "B.Fab"
    } else {
        "F.Fab"
    };
    let definition = footprint
        .definition
        .as_mut()
        .context("board footprint has no library definition")?;
    for (name, instance_slot, definition_slot) in [
        (
            "Datasheet",
            &mut footprint.datasheet_field,
            &mut definition.datasheet_field,
        ),
        (
            "Description",
            &mut footprint.description_field,
            &mut definition.description_field,
        ),
    ] {
        if let Some(value) = fields.get(name) {
            for slot in [instance_slot, definition_slot] {
                if slot.is_none() {
                    *slot = Some(hidden_footprint_field(name, value, position, layer)?);
                }
                set_field_text(slot, name, value);
            }
        }
    }
    for child in &mut definition.items {
        if !konnect_ipc::builders::any_is(child, "kiapi.board.types.Field") {
            continue;
        }
        let mut field = kiapi::board::types::Field::decode(child.value.as_slice())?;
        if let Some(value) = fields.get(&field.name) {
            if validated_field_value(&field)? != value {
                // Only nested text changes: numeric FieldId, BoardText KIID,
                // parent, visibility and the complete presentation survive.
                field.text.as_mut().unwrap().text.as_mut().unwrap().text = value.clone();
                child.value = field.encode_to_vec();
            }
        }
    }
    for (name, value) in fields {
        if !matches!(name.as_str(), "Datasheet" | "Description")
            && !current.contains_key(&format!("custom.{name}"))
        {
            definition.items.push(konnect_ipc::builders::pack_any(
                &hidden_footprint_field(name, value, position, layer)?,
                "kiapi.board.types.Field",
            ));
        }
    }
    Ok(())
}

fn hidden_footprint_field(
    name: &str,
    value: &str,
    position: Option<&konnect_ipc::gen::kiapi::common::types::Vector2>,
    layer: &str,
) -> Result<konnect_ipc::gen::kiapi::board::types::Field> {
    let position =
        position.context("cannot anchor a new field on a footprint without a position")?;
    let mut text = konnect_ipc::builders::board_text(layer, value, 0.0, 0.0, 1.0, 0.0, false);
    let content = text
        .text
        .as_mut()
        .expect("board text builder supplies text");
    content.position = Some(*position);
    content
        .attributes
        .as_mut()
        .expect("board text builder supplies attributes")
        .visible = false;
    Ok(konnect_ipc::gen::kiapi::board::types::Field {
        name: name.to_string(),
        visible: false,
        text: Some(text),
        ..Default::default()
    })
}

/// How many pads and how many drawn items a footprint carries.
///
/// The two numbers #244 got wrong in opposite directions: every graphic became
/// a pad, so pads went up by exactly the number of drawings, and drawings went
/// to zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct FootprintShape {
    pads: usize,
    drawings: usize,
}

/// Tally the pads and drawings of each footprint in a set of packed items,
/// keyed by reference.
fn footprint_shapes<'a>(
    items: impl Iterator<Item = &'a prost_types::Any>,
) -> BTreeMap<String, FootprintShape> {
    use konnect_ipc::gen::kiapi;
    use prost::Message;

    let mut out = BTreeMap::new();
    for item in items {
        let Ok(footprint) = kiapi::board::types::FootprintInstance::decode(item.value.as_slice())
        else {
            continue;
        };
        let Some(definition) = footprint.definition.as_ref() else {
            continue;
        };
        let reference = field_text(&footprint.reference_field);
        if reference.is_empty() {
            continue;
        }
        let mut shape = FootprintShape::default();
        for child in &definition.items {
            match konnect_ipc::builders::any_type_name(child) {
                "kiapi.board.types.Pad" => shape.pads += 1,
                "kiapi.board.types.BoardGraphicShape" | "kiapi.board.types.BoardText" => {
                    shape.drawings += 1
                }
                _ => {}
            }
        }
        out.insert(reference, shape);
    }
    out
}

#[derive(Debug)]
struct FootprintReadback {
    shape: FootprintShape,
    kiid: Option<String>,
    fields: BTreeMap<String, konnect_ipc::gen::kiapi::board::types::Field>,
}

fn footprint_readback<'a>(
    items: impl Iterator<Item = &'a prost_types::Any>,
) -> Result<BTreeMap<String, FootprintReadback>> {
    use konnect_ipc::gen::kiapi;

    let mut out = BTreeMap::new();
    for item in items {
        let footprint = kiapi::board::types::FootprintInstance::decode(item.value.as_slice())
            .context("readback contains an invalid footprint item")?;
        let reference = field_text(&footprint.reference_field);
        let fields = footprint_field_slots(&footprint)?;
        let shape = footprint_shapes(std::iter::once(item))
            .remove(&reference)
            .unwrap_or_default();
        out.insert(
            reference,
            FootprintReadback {
                shape,
                kiid: footprint
                    .id
                    .as_ref()
                    .map(|id| id.value.clone())
                    .filter(|id| !id.is_empty()),
                fields,
            },
        );
    }
    Ok(out)
}

/// Read the board back and hold it to what was just sent.
///
/// `create_items`/`update_items` only confirm that KiCad *accepted* each item,
/// and the counts this tool reports are copied from the plan — so when #244
/// turned every footprint graphic into a nameless pad, KiCad returned ISC_OK
/// for each one and the response said the sync succeeded. Nothing anywhere
/// looked at what actually landed.
///
/// This is a backstop for that class, not for that bug: with the type-URL fix
/// in place it should never fire. `delete_footprint` already re-queries after
/// mutating; this follows it.
///
/// Missing footprints, field values or existing field identities fail closed:
/// accepting a shape-only match would hide an ECO KiCad did not retain.
/// A gained pad also fails the call: it is #244's exact signature. A *drop* in
/// drawings is reported instead of refused, because it has a benign
/// explanation this check cannot yet rule out — KiCad re-creates a footprint's
/// children from the message on deserialize, and if it promotes a `BoardText`
/// child into a `Field` (which this tally deliberately ignores) the count
/// would fall without anything being wrong. Turning a working sync into an
/// error over that is worse than the warning. Tighten it once it has been
/// watched against a live KiCad; see the note on #244.
fn verify_board_matches_what_was_sent(
    client: &konnect_ipc::KiCadIpcClient,
    document: &konnect_ipc::gen::kiapi::common::types::DocumentSpecifier,
    expected: &BTreeMap<String, FootprintReadback>,
) -> Result<Vec<String>> {
    use konnect_ipc::gen::kiapi;

    if expected.is_empty() {
        return Ok(Vec::new());
    }
    let items = client.get_items_in(
        document.clone(),
        kiapi::common::types::KiCadObjectType::KotPcbFootprint,
    )?;
    let actual = footprint_readback(items.iter())?;

    let mut corrupted = Vec::new();
    let mut field_errors = Vec::new();
    let mut suspicious = Vec::new();
    for (reference, want) in expected {
        let Some(got) = actual.get(reference) else {
            field_errors.push(format!(
                "{reference}: the sent footprint is missing from readback"
            ));
            continue;
        };
        field_errors.extend(footprint_field_verification_errors(reference, want, got)?);
        let detail = format!(
            "{reference}: sent {} pads and {} drawings, board now has {} and {}",
            want.shape.pads, want.shape.drawings, got.shape.pads, got.shape.drawings
        );
        if got.shape.pads > want.shape.pads {
            corrupted.push(detail);
        } else if got.shape != want.shape {
            suspicious.push(detail);
        }
    }
    if !corrupted.is_empty() {
        bail!(
            "KiCad's board gained pads this sync never sent, so the footprints on \
             it are not the ones that were planned — inspect the board and do not \
             save it: {}",
            corrupted.join("; ")
        );
    }
    if !field_errors.is_empty() {
        bail!(
            "KiCad's board did not retain the fields or existing identities this sync sent — \
             inspect the board before saving: {}",
            field_errors.join("; ")
        );
    }
    Ok(suspicious)
}

/// This is called only after EndCommit confirmed publication. Never let an
/// ordinary readback error reach attempt_ipc_write's preflight classification.
fn verify_committed_footprints(
    client: &konnect_ipc::KiCadIpcClient,
    document: &konnect_ipc::gen::kiapi::common::types::DocumentSpecifier,
    expected: &BTreeMap<String, FootprintReadback>,
) -> std::result::Result<Vec<String>, CallToolResult> {
    verify_board_matches_what_was_sent(client, document, expected).map_err(|error| {
        let reason = format!("KiCad committed the schematic-to-PCB update, but readback could not verify it: {error:#}");
        CallToolResult::error_kind(
            crate::mcp::error::ToolErrorKind::IpcOutcomeUnknown {
                board_state: "committed".to_string(),
                retry_safe: false,
                reason: reason.clone(),
            },
            format!("{reason}. Do not save, repeat the mutation or edit the saved file. Inspect the live board and use KiCad's native Undo (Ctrl-Z / Cmd-Z) to reverse this committed update if needed. No automatic rollback or file fallback was attempted."),
        )
    })
}

fn footprint_field_verification_errors(
    reference: &str,
    want: &FootprintReadback,
    got: &FootprintReadback,
) -> Result<Vec<String>> {
    let mut errors = Vec::new();
    if want.kiid.is_some() && want.kiid != got.kiid {
        errors.push(format!("{reference}: footprint KIID changed"));
    }
    for (slot, want_field) in &want.fields {
        let alias = slot.split_once('.').and_then(|(location, name)| {
            let other = match location {
                "definition" => "instance",
                "instance" => "definition",
                _ => return None,
            };
            Some(format!("{other}.{name}"))
        });
        let exact = got.fields.get(slot);
        let got_field = exact.or_else(|| alias.as_ref().and_then(|key| got.fields.get(key)));
        let Some(got_field) = got_field else {
            errors.push(format!("{reference}: field {slot} is missing"));
            continue;
        };
        if validated_field_value(want_field)? != validated_field_value(got_field)? {
            errors.push(format!(
                "{reference}: field {slot} value differs from what was sent"
            ));
        }
        // New fields have no IDs yet: KiCad may assign both IDs on creation.
        if want_field.id.is_some() && want_field.id != got_field.id {
            errors.push(format!("{reference}: field {slot} numeric ID changed"));
        }
        let want_id = want_field.text.as_ref().and_then(|text| text.id.as_ref());
        let got_id = got_field.text.as_ref().and_then(|text| text.id.as_ref());
        if want_id.is_some() && want_id != got_id {
            errors.push(format!("{reference}: field {slot} text KIID changed"));
        }
        // Captures emit mandatory fields only in instance slots. If a slot
        // was omitted, compare its effective counterpart's presentation, not
        // a synthesized definition slot's unset/default style. IDs above are
        // still checked against the original slot, never discarded as aliases.
        let presentation = if exact.is_none() {
            alias
                .as_ref()
                .and_then(|key| want.fields.get(key))
                .unwrap_or(want_field)
        } else {
            want_field
        };
        if presentation.visible != got_field.visible {
            errors.push(format!(
                "{reference}: field {slot} visibility differs from what was sent"
            ));
        }
        if !field_presentations_match(presentation, got_field) {
            errors.push(format!(
                "{reference}: field {slot} presentation differs from what was sent"
            ));
        }
    }
    Ok(errors)
}

fn field_presentations_match(
    want: &konnect_ipc::gen::kiapi::board::types::Field,
    got: &konnect_ipc::gen::kiapi::board::types::Field,
) -> bool {
    use konnect_ipc::gen::kiapi;

    let (Some(want_board), Some(got_board)) = (&want.text, &got.text) else {
        return false;
    };
    let (Some(want_text), Some(got_text)) = (&want_board.text, &got_board.text) else {
        return false;
    };
    if want_board.layer != got_board.layer
        || want_board.knockout != got_board.knockout
        || (want_board.locked == kiapi::common::types::LockedState::LsLocked as i32)
            != (got_board.locked == kiapi::common::types::LockedState::LsLocked as i32)
        || want_text.hyperlink != got_text.hyperlink
        || want_text
            .position
            .as_ref()
            .is_some_and(|position| Some(position) != got_text.position.as_ref())
    {
        return false;
    }
    let Some(want) = want_text.attributes.as_ref() else {
        // No presentation was authored in a sparse mandatory slot; KiCad
        // initializes it. Existing native fields and new hidden fields carry
        // attributes, so their presentation is always constrained below.
        return true;
    };
    let Some(got) = got_text.attributes.as_ref() else {
        return false;
    };
    // KiCad's stroke font has an empty native name; "KiCad Font" is its UI
    // alias. The retained native captures use centered alignment, line spacing
    // 1 and LS_UNLOCKED; unspecified proto defaults denote those defaults.
    let font = |name: &str| name.is_empty() || name == "KiCad Font";
    let same_font =
        want.font_name == got.font_name || (font(&want.font_name) && font(&got.font_name));
    let horizontal = |value| {
        if value == 0 {
            kiapi::common::types::HorizontalAlignment::HaCenter as i32
        } else {
            value
        }
    };
    let vertical = |value| {
        if value == 0 {
            kiapi::common::types::VerticalAlignment::VaCenter as i32
        } else {
            value
        }
    };
    let spacing = |value| if value == 0.0 { 1.0 } else { value };
    let want_angle = want
        .angle
        .as_ref()
        .map(|angle| angle.value_degrees)
        .unwrap_or(0.0);
    let got_angle = got
        .angle
        .as_ref()
        .map(|angle| angle.value_degrees)
        .unwrap_or(0.0);
    // Whole-turn aliases can differ in their final floating-point bits.
    let same_angle = ((want_angle - got_angle + 180.0).rem_euclid(360.0) - 180.0).abs() <= 1e-9;
    same_font && same_angle
        && horizontal(want.horizontal_alignment) == horizontal(got.horizontal_alignment)
        && vertical(want.vertical_alignment) == vertical(got.vertical_alignment)
        && spacing(want.line_spacing) == spacing(got.line_spacing)
        && want.size.as_ref().is_none_or(|size| Some(size) == got.size.as_ref())
        // An unset/zero pen width is resolved by KiCad. Authored widths from
        // native captures, library fields and the hidden-field builder must
        // survive exactly; no synthesized default is compared to that width.
        && want.stroke_width.as_ref().filter(|width| width.value_nm > 0)
            .is_none_or(|width| Some(width) == got.stroke_width.as_ref())
        && want.italic == got.italic && want.bold == got.bold
        && want.underlined == got.underlined && want.mirrored == got.mirrored
        && want.multiline == got.multiline && want.keep_upright == got.keep_upright
    // TextAttributes.visible is deprecated since 9.0.1: native captures set it
    // true even on hidden fields. Only Field.visible determines visibility.
    // BoardText.parent is read-only and may be assigned to a newly added field.
}

fn set_field_text(
    field: &mut Option<konnect_ipc::gen::kiapi::board::types::Field>,
    name: &str,
    value: &str,
) {
    let field = field.get_or_insert_with(Default::default);
    field.name = name.to_string();
    let board_text = field.text.get_or_insert_with(Default::default);
    board_text.text.get_or_insert_with(Default::default).text = value.to_string();
}

fn saved_hierarchy_files(root: &Path) -> Result<Vec<PathBuf>> {
    fn visit(
        path: &Path,
        seen: &mut HashSet<PathBuf>,
        active: &mut HashSet<PathBuf>,
        files: &mut Vec<PathBuf>,
    ) -> Result<()> {
        let canonical = path
            .canonicalize()
            .with_context(|| format!("cannot resolve schematic {}", path.display()))?;
        if active.contains(&canonical) {
            bail!(
                "schematic hierarchy contains a cycle at {}",
                canonical.display()
            );
        }
        if !seen.insert(canonical.clone()) {
            return Ok(());
        }
        active.insert(canonical.clone());
        let name = canonical
            .file_name()
            .and_then(|name| name.to_str())
            .context("schematic path has no file name")?;
        let lock = canonical.with_file_name(format!("~{name}.lck"));
        if lock.exists() {
            bail!(
                "{} is open in the schematic editor; save and close the hierarchy before syncing",
                canonical.display()
            );
        }
        let schematic = konnect_schematic_editor::Schematic::load(&canonical)
            .with_context(|| format!("cannot load schematic {}", canonical.display()))?;
        files.push(canonical.clone());
        let parent = canonical.parent().unwrap_or_else(|| Path::new("."));
        for sheet in schematic.sheets.iter() {
            let child = parent.join(sheet.file());
            if !child.exists() {
                bail!(
                    "hierarchical sheet {} referenced by {} does not exist",
                    child.display(),
                    canonical.display()
                );
            }
            visit(&child, seen, active, files)?;
        }
        active.remove(&canonical);
        Ok(())
    }

    let mut files = Vec::new();
    visit(root, &mut HashSet::new(), &mut HashSet::new(), &mut files)?;
    Ok(files)
}

fn apply_saved_symbol_flags(files: &[PathBuf], design: &mut ExportedDesign) -> Result<()> {
    #[derive(Debug)]
    struct Flags {
        reference: String,
        symbol_path: String,
        in_bom: bool,
        on_board: bool,
        dnp: bool,
    }

    let mut flags = Vec::new();
    for file in files {
        let source = std::fs::read_to_string(file)?;
        let tree = konnect_sexp::parse_sexp(&source)?;
        let root_uuid = tree.find_str("uuid").unwrap_or("");
        for symbol in tree.find_all("symbol") {
            let Some(uuid) = symbol.find_str("uuid") else {
                continue;
            };
            let in_bom = symbol.find_str("in_bom") != Some("no");
            let on_board = symbol.find_str("on_board") != Some("no");
            let dnp = symbol.find_str("dnp") == Some("yes");
            let projects = symbol
                .find("instances")
                .map(|instances| instances.find_all("project"))
                .unwrap_or_default();
            for project in projects {
                for path in project.find_all("path") {
                    let Some(reference) = path.find_str("reference") else {
                        continue;
                    };
                    let instance = path.get(1).and_then(SexpNode::as_str).unwrap_or("/");
                    let base = if instance == "/" && !root_uuid.is_empty() {
                        format!("/{root_uuid}")
                    } else {
                        instance.trim_end_matches('/').to_string()
                    };
                    flags.push(Flags {
                        reference: reference.to_string(),
                        symbol_path: format!("{base}/{uuid}").replace("//", "/"),
                        in_bom,
                        on_board,
                        dnp,
                    });
                }
            }
        }
    }

    for reference in flags
        .iter()
        .map(|entry| entry.reference.as_str())
        .collect::<HashSet<_>>()
    {
        let entries = flags
            .iter()
            .filter(|entry| entry.reference == reference)
            .collect::<Vec<_>>();
        if entries.iter().any(|entry| {
            entry.in_bom != entries[0].in_bom
                || entry.on_board != entries[0].on_board
                || entry.dnp != entries[0].dnp
        }) {
            bail!("multi-unit reference {reference} has inconsistent board/BOM/DNP flags");
        }
    }

    design.components.retain_mut(|component| {
        let path_match = flags
            .iter()
            .find(|entry| entry.symbol_path == component.symbol_path);
        let reference_matches = flags
            .iter()
            .filter(|entry| entry.reference == component.reference)
            .collect::<Vec<_>>();
        let entry = path_match.or_else(|| reference_matches.first().copied());
        let Some(entry) = entry else {
            return true;
        };
        if !entry.in_bom {
            return false;
        }
        if !entry.on_board {
            design.skipped.push(SkippedComponent {
                reference: entry.reference.clone(),
                symbol_path: entry.symbol_path.clone(),
            });
            return false;
        }
        component.dnp = entry.dnp;
        true
    });
    // The same flags govern a component with no footprint: excluded from the
    // BOM it is dropped, excluded from the board it is skipped by flag rather
    // than reported as unassigned.
    design.unassigned.retain(|component| {
        let path_match = flags
            .iter()
            .find(|entry| entry.symbol_path == component.symbol_path);
        let entry = path_match.or_else(|| {
            flags
                .iter()
                .find(|entry| entry.reference == component.reference)
        });
        let Some(entry) = entry else {
            return true;
        };
        if !entry.in_bom {
            return false;
        }
        if !entry.on_board {
            design.skipped.push(SkippedComponent {
                reference: entry.reference.clone(),
                symbol_path: entry.symbol_path.clone(),
            });
            return false;
        }
        true
    });
    let mut skipped_references = HashSet::new();
    for entry in flags.iter().filter(|entry| entry.in_bom && !entry.on_board) {
        if !skipped_references.insert(entry.reference.as_str()) {
            continue;
        }
        if !design
            .skipped
            .iter()
            .any(|skipped| skipped.symbol_path == entry.symbol_path)
        {
            design.skipped.push(SkippedComponent {
                reference: entry.reference.clone(),
                symbol_path: entry.symbol_path.clone(),
            });
        }
    }
    Ok(())
}

fn snapshot_board(client: &konnect_ipc::KiCadIpcClient, board: &Path) -> Result<LiveSnapshot> {
    use kiapi::common::types::KiCadObjectType as ObjectType;
    use konnect_ipc::gen::kiapi;

    let document = client.find_open_board(board)?;
    let footprint_items = client.get_items_in(document.clone(), ObjectType::KotPcbFootprint)?;
    let mut footprints = Vec::new();
    let mut items = BTreeMap::new();
    for item in footprint_items {
        let instance = kiapi::board::types::FootprintInstance::decode(item.value.as_slice())
            .context("KiCad returned an invalid footprint item")?;
        let footprint = board_footprint_from_instance(&instance)?;
        let kiid = footprint.kiid.clone();
        footprints.push(footprint);
        items.insert(kiid, item);
    }

    let nets = client.get_nets_in(document.clone())?;
    let net_codes = nets
        .iter()
        .map(|net| (net.name.clone(), net.netcode))
        .collect::<BTreeMap<_, _>>();
    let mut routed_nets = BTreeMap::new();
    for item in client.get_items_in(document.clone(), ObjectType::KotPcbTrace)? {
        if let Ok(track) = kiapi::board::types::Track::decode(item.value.as_slice()) {
            record_routed_net(&mut routed_nets, track.net.as_ref());
        }
    }
    for item in client.get_items_in(document.clone(), ObjectType::KotPcbArc)? {
        if let Ok(arc) = kiapi::board::types::Arc::decode(item.value.as_slice()) {
            record_routed_net(&mut routed_nets, arc.net.as_ref());
        }
    }
    for item in client.get_items_in(document.clone(), ObjectType::KotPcbVia)? {
        if let Ok(via) = kiapi::board::types::Via::decode(item.value.as_slice()) {
            record_routed_net(&mut routed_nets, via.net.as_ref());
        }
    }
    if !client
        .get_items_in(document.clone(), ObjectType::KotPcbZone)?
        .is_empty()
    {
        // KiCad 10's Zone protobuf does not expose the zone net. A pad-net
        // reassignment on a zoned board therefore fails closed.
        for net in net_codes.keys() {
            *routed_nets.entry(net.clone()).or_insert(0) += 1;
        }
    }
    // Every item KiCad holds, measured as KiCad measures it (#688). Only a
    // board with no items at all has no extent, and stages from the origin.
    let extents = client
        .get_board_bounds_in(document.clone())?
        .extents
        .unwrap_or(konnect_ipc::IpcBoardExtents {
            min: konnect_ipc::IpcVector2 { x: 0.0, y: 0.0 },
            max: konnect_ipc::IpcVector2 { x: 0.0, y: 0.0 },
        });
    Ok(LiveSnapshot {
        state: BoardState {
            footprints,
            routed_nets,
            bounds: Bounds {
                min_x: extents.min.x,
                min_y: extents.min.y,
                max_x: extents.max.x,
                max_y: extents.max.y,
            },
        },
        items,
        net_codes,
        document,
    })
}

/// Convert one live KiCad footprint into the planner's board-side view.
///
/// Split out of [`snapshot_board`] so the IPC-to-planner mapping is reachable
/// without a live editor: the planner's own tests build `BoardFootprint`
/// directly and therefore cannot see a defect that lives in this conversion.
fn board_footprint_from_instance(
    footprint: &konnect_ipc::gen::kiapi::board::types::FootprintInstance,
) -> Result<BoardFootprint> {
    use konnect_ipc::gen::kiapi;

    let kiid = footprint
        .id
        .as_ref()
        .map(|id| id.value.clone())
        .filter(|id| !id.is_empty())
        .context("KiCad returned a footprint without a KIID")?;
    let definition = footprint
        .definition
        .as_ref()
        .context("KiCad returned a footprint without a definition")?;
    let mut pad_nets = BTreeMap::new();
    let mut pad_numbers = BTreeSet::new();
    for child in &definition.items {
        // Same discriminator as `apply_footprint_fields`, for the same
        // reason: a graphic can decode as an empty pad.
        //
        // No test covers this one, and deliberately so: it has no effect
        // that a message KiCad actually sends can show. Every drawing, field
        // and text in the checked-in KiCad 10 captures fails `Pad::decode` on
        // a wire-type mismatch and is skipped by the `else` below, so
        // neutering this check changes nothing. That was measured again for
        // #657, which added `pad_numbers` to this loop: a shape that did
        // decode would add the empty pad number. It stays so the next person
        // to touch this loop does not have to rediscover why reading
        // `definition.items` untyped is unsafe.
        if !konnect_ipc::builders::any_is(child, "kiapi.board.types.Pad") {
            continue;
        }
        let Ok(pad) = kiapi::board::types::Pad::decode(child.value.as_slice()) else {
            continue;
        };
        pad_numbers.insert(pad.number.clone());
        if let Some(net) = pad.net.filter(|net| !net.name.is_empty()) {
            pad_nets.insert(pad.number, net.name);
        }
    }
    let position = footprint.position.as_ref();
    Ok(BoardFootprint {
        kiid,
        reference: field_text(&footprint.reference_field),
        value: field_text(&footprint.value_field),
        footprint_id: definition
            .id
            .as_ref()
            .map(|id| format!("{}:{}", id.library_nickname, id.entry_name))
            .unwrap_or_default(),
        symbol_path: board_symbol_path(footprint.symbol_path.as_ref()),
        fields: board_field_values(footprint)?,
        pad_nets,
        pad_numbers,
        position: Point {
            x: position
                .map(|point| konnect_ipc::builders::nm_to_mm(point.x_nm))
                .unwrap_or(0.0),
            y: position
                .map(|point| konnect_ipc::builders::nm_to_mm(point.y_nm))
                .unwrap_or(0.0),
        },
        rotation: footprint
            .orientation
            .as_ref()
            .map(|angle| angle.value_degrees)
            .unwrap_or(0.0),
        layer: board_layer_name(footprint.layer),
        locked: footprint.locked == kiapi::common::types::LockedState::LsLocked as i32,
        dnp: footprint
            .attributes
            .as_ref()
            .map(|attributes| attributes.do_not_populate)
            .unwrap_or(false),
        not_in_schematic: footprint
            .attributes
            .as_ref()
            .map(|attributes| attributes.not_in_schematic)
            .unwrap_or(false),
    })
}

fn validated_field_value(field: &konnect_ipc::gen::kiapi::board::types::Field) -> Result<&str> {
    if field.name.trim().is_empty() {
        bail!("board footprint contains a field without a name");
    }
    field
        .text
        .as_ref()
        .and_then(|text| text.text.as_ref())
        .map(|text| text.text.as_str())
        .with_context(|| format!("board field '{}' has no nested text value", field.name))
}

/// Keep both mandatory slots distinct for readback and identity checks. They
/// are two presentations of one field, not duplicate custom properties.
fn footprint_field_slots(
    footprint: &konnect_ipc::gen::kiapi::board::types::FootprintInstance,
) -> Result<BTreeMap<String, konnect_ipc::gen::kiapi::board::types::Field>> {
    use konnect_ipc::gen::kiapi;

    let definition = footprint
        .definition
        .as_ref()
        .context("board footprint has no library definition")?;
    let mut slots = BTreeMap::new();
    for (name, instance, library) in [
        (
            "Reference",
            &footprint.reference_field,
            &definition.reference_field,
        ),
        ("Value", &footprint.value_field, &definition.value_field),
        (
            "Datasheet",
            &footprint.datasheet_field,
            &definition.datasheet_field,
        ),
        (
            "Description",
            &footprint.description_field,
            &definition.description_field,
        ),
    ] {
        for (location, slot) in [("instance", instance), ("definition", library)] {
            if let Some(field) = slot {
                if field.name != name {
                    bail!("board {location} {name} slot is named '{}'", field.name);
                }
                validated_field_value(field)?;
                slots.insert(format!("{location}.{name}"), field.clone());
            }
        }
    }
    for item in &definition.items {
        if !konnect_ipc::builders::any_is(item, "kiapi.board.types.Field") {
            continue;
        }
        let field = kiapi::board::types::Field::decode(item.value.as_slice())
            .context("board footprint contains an invalid typed custom field")?;
        validated_field_value(&field)?;
        if matches!(
            field.name.as_str(),
            "Reference" | "Value" | "Footprint" | "Datasheet" | "Description"
        ) {
            bail!(
                "board footprint contains a duplicate or reserved custom field '{}'",
                field.name
            );
        }
        let key = format!("custom.{}", field.name);
        if slots.insert(key, field.clone()).is_some() {
            bail!(
                "board footprint contains more than one custom field named '{}'",
                field.name
            );
        }
    }
    Ok(slots)
}

fn board_field_values(
    footprint: &konnect_ipc::gen::kiapi::board::types::FootprintInstance,
) -> Result<BTreeMap<String, String>> {
    let slots = footprint_field_slots(footprint)?;
    let mut values = BTreeMap::new();
    for name in ["Datasheet", "Description"] {
        if let Some(field) = slots
            .get(&format!("instance.{name}"))
            .or_else(|| slots.get(&format!("definition.{name}")))
        {
            values.insert(name.to_string(), validated_field_value(field)?.to_string());
        }
    }
    for (key, field) in &slots {
        if key.starts_with("custom.") {
            values.insert(
                field.name.clone(),
                validated_field_value(field)?.to_string(),
            );
        }
    }
    Ok(values)
}

fn field_text(field: &Option<konnect_ipc::gen::kiapi::board::types::Field>) -> String {
    field
        .as_ref()
        .and_then(|field| field.text.as_ref())
        .and_then(|text| text.text.as_ref())
        .map(|text| text.text.clone())
        .unwrap_or_default()
}

/// The board-side schematic identity of a footprint, or `None` when it has no
/// schematic symbol behind it at all.
///
/// KiCad's IPC layer sends a *present but empty* `SheetPath` for a footprint
/// placed directly on the board — a logo, a fiducial, a mounting hole. Passing
/// that through [`sheet_path_string`] renders `/`, so every such footprint
/// arrives carrying the same synthetic identity and the planner reads them as
/// duplicates of one another, blocking the sync (#452). Absence of an identity
/// must arrive as absence, which is what the rest of this module already
/// assumes `None` to mean.
fn board_symbol_path(
    path: Option<&konnect_ipc::gen::kiapi::common::types::SheetPath>,
) -> Option<String> {
    let path = path?;
    // A path made only of empty KIIDs names no symbol either, so it is absence
    // too. Only this all-empty case is normalised: an empty segment *inside* an
    // otherwise real path is left to render as it always has, because that is a
    // shape KiCad does not emit and inventing a meaning for it here would be
    // guessing. `apply_footprint_fields` drops empty segments on the way out, so
    // the round trip is exact for every path either side can actually produce.
    if path.path.iter().all(|part| part.value.is_empty()) {
        return None;
    }
    Some(sheet_path_string(path))
}

fn sheet_path_string(path: &konnect_ipc::gen::kiapi::common::types::SheetPath) -> String {
    format!(
        "/{}",
        path.path
            .iter()
            .map(|part| part.value.as_str())
            .collect::<Vec<_>>()
            .join("/")
    )
}

fn board_layer_name(layer: i32) -> String {
    use konnect_ipc::gen::kiapi::board::types::BoardLayer;
    match BoardLayer::try_from(layer).ok() {
        Some(BoardLayer::BlFCu) => "F.Cu".to_string(),
        Some(BoardLayer::BlBCu) => "B.Cu".to_string(),
        Some(layer) => layer.as_str_name().to_string(),
        None => format!("layer_{layer}"),
    }
}

fn record_routed_net(
    routed: &mut BTreeMap<String, usize>,
    net: Option<&konnect_ipc::gen::kiapi::board::types::Net>,
) {
    if let Some(net) = net.filter(|net| !net.name.is_empty()) {
        *routed.entry(net.name.clone()).or_insert(0) += 1;
    }
}

/// A library footprint the plan wants to place and Konnect could not prepare,
/// with every part that needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnpreparedFootprint {
    footprint_id: String,
    references: Vec<String>,
    code: &'static str,
    reason: String,
}

impl UnpreparedFootprint {
    fn into_diagnostic(self) -> SyncDiagnostic {
        let message = format!(
            "{} cannot be placed (needed by {}): {}",
            self.footprint_id,
            listed(&self.references),
            self.reason
        );
        footprint_conflict(self.code, message, &self.footprint_id, self.references)
    }
}

/// Read one library footprint into what the typed placement path sends. The
/// three codes are the ones `update_footprints_from_library` uses for the
/// same three failures, because the caller's next step differs: fix the
/// library table, fix the file, or substitute the footprint.
fn prepare_footprint(
    footprint_id: &str,
    board_path: &Path,
) -> std::result::Result<PreparedFootprint, (&'static str, String)> {
    let path = super::pcb_components::resolve_footprint_file(footprint_id, board_path)
        .map_err(|error| ("footprint_library_resolution_failed", format!("{error:#}")))?;
    let source = std::fs::read_to_string(&path).map_err(|error| {
        (
            "footprint_library_read_failed",
            format!("failed to read {}: {error}", path.display()),
        )
    })?;
    let unsupported =
        |error: anyhow::Error| ("unsupported_library_footprint", format!("{error:#}"));
    let library = parse_library_footprint(footprint_id, &source).map_err(unsupported)?;
    // Refresh can accept partial mandatory presentation that a fresh import
    // refuses. Exercise the pure constructor before a dry run reports ready.
    build_import_instance(&library, 0.0, 0.0).map_err(unsupported)?;
    let (width, height) = footprint_dimensions(&library.pads, &library.graphics);
    Ok(PreparedFootprint {
        library,
        width,
        height,
    })
}

/// Prepare every footprint the plan adds. One that cannot be prepared does
/// not stop the rest: stopping at the first produced a single diagnostic that
/// named neither the footprint nor a part, and hid every other unusable
/// footprint behind it (#657).
fn prepare_additions(
    board_path: &Path,
    plan: &SyncPlan,
) -> (
    BTreeMap<String, PreparedFootprint>,
    Vec<UnpreparedFootprint>,
) {
    let mut prepared = BTreeMap::new();
    let mut unprepared: BTreeMap<String, UnpreparedFootprint> = BTreeMap::new();
    for change in &plan.changes {
        let PlannedChange::Add {
            footprint_id,
            reference,
            ..
        } = change
        else {
            continue;
        };
        if prepared.contains_key(footprint_id) {
            continue;
        }
        if let Some(failed) = unprepared.get_mut(footprint_id) {
            failed.references.push(reference.clone());
            continue;
        }
        match prepare_footprint(footprint_id, board_path) {
            Ok(part) => {
                prepared.insert(footprint_id.clone(), part);
            }
            Err((code, reason)) => {
                unprepared.insert(
                    footprint_id.clone(),
                    UnpreparedFootprint {
                        footprint_id: footprint_id.clone(),
                        references: vec![reference.clone()],
                        code,
                        reason,
                    },
                );
            }
        }
    }
    (prepared, unprepared.into_values().collect())
}

/// Additions whose schematic connects a pad the prepared library footprint
/// does not have. The update path is checked in `plan_sync`, which holds the
/// live footprint's pads; this is the same rule against the library's.
fn additions_missing_pads(
    plan: &SyncPlan,
    prepared: &BTreeMap<String, PreparedFootprint>,
) -> Vec<SyncDiagnostic> {
    let mut diagnostics = Vec::new();
    for change in &plan.changes {
        let PlannedChange::Add {
            reference,
            footprint_id,
            pad_nets,
            ..
        } = change
        else {
            continue;
        };
        // An unprepared footprint is already reported, with this part named.
        let Some(part) = prepared.get(footprint_id) else {
            continue;
        };
        let available = part
            .library
            .pads
            .iter()
            .map(|pad| pad.number.clone())
            .collect::<BTreeSet<_>>();
        let missing = missing_pads(pad_nets, &available);
        if !missing.is_empty() {
            diagnostics.push(pad_missing_conflict(reference, footprint_id, &missing));
        }
    }
    diagnostics
}

/// Turn a plan into a conflict the way `plan_sync` does for its own
/// diagnostics: nothing stays planned, so nothing can be applied.
fn refuse_plan(plan: &mut SyncPlan, diagnostics: Vec<SyncDiagnostic>) {
    plan.status = PlanStatus::Conflict;
    plan.counts.added.planned = 0;
    plan.counts.updated.planned = 0;
    plan.counts.pads_reassigned.planned = 0;
    plan.counts.conflicts.planned += diagnostics.len();
    plan.diagnostics.extend(diagnostics);
    plan.changes.clear();
}

fn footprint_dimensions(
    pads: &[konnect_ipc::IpcPadDefinition],
    graphics: &[konnect_ipc::IpcGraphicDefinition],
) -> (f64, f64) {
    use konnect_ipc::IpcGraphicDefinition as Graphic;

    let (mut min_x, mut min_y) = (f64::INFINITY, f64::INFINITY);
    let (mut max_x, mut max_y) = (f64::NEG_INFINITY, f64::NEG_INFINITY);
    let mut include = |x: f64, y: f64| {
        min_x = min_x.min(x);
        min_y = min_y.min(y);
        max_x = max_x.max(x);
        max_y = max_y.max(y);
    };
    for pad in pads {
        include(pad.x - pad.size_x / 2.0, pad.y - pad.size_y / 2.0);
        include(pad.x + pad.size_x / 2.0, pad.y + pad.size_y / 2.0);
    }
    for graphic in graphics {
        match graphic {
            Graphic::Line { start, end, .. } | Graphic::Rect { start, end, .. } => {
                include(start.0, start.1);
                include(end.0, end.1);
            }
            Graphic::Circle { center, end, .. } => {
                let radius = ((end.0 - center.0).powi(2) + (end.1 - center.1).powi(2)).sqrt();
                include(center.0 - radius, center.1 - radius);
                include(center.0 + radius, center.1 + radius);
            }
            Graphic::Arc {
                start, mid, end, ..
            } => {
                include(start.0, start.1);
                include(mid.0, mid.1);
                include(end.0, end.1);
            }
            Graphic::Poly { points, .. } => {
                for point in points {
                    include(point.0, point.1);
                }
            }
            Graphic::Text { position, size, .. } => {
                include(position.0 - size / 2.0, position.1 - size / 2.0);
                include(position.0 + size / 2.0, position.1 + size / 2.0);
            }
        }
    }
    if !min_x.is_finite() {
        return (10.0, 10.0);
    }
    ((max_x - min_x).max(1.0), (max_y - min_y).max(1.0))
}

fn restage_additions(
    plan: &mut SyncPlan,
    prepared: &BTreeMap<String, PreparedFootprint>,
    bounds: Bounds,
) {
    let mut next_y = bounds.min_y;
    for change in &mut plan.changes {
        let PlannedChange::Add {
            footprint_id,
            position,
            ..
        } = change
        else {
            continue;
        };
        let dimensions = prepared.get(footprint_id);
        let width = dimensions.map(|part| part.width).unwrap_or(10.0);
        let height = dimensions.map(|part| part.height).unwrap_or(10.0);
        *position = Point {
            x: bounds.max_x + 5.0 + width / 2.0,
            y: next_y + height / 2.0,
        };
        next_y += height + 5.0;
    }
}

fn build_mutation_items(
    plan: &SyncPlan,
    prepared: &BTreeMap<String, PreparedFootprint>,
    snapshot: &LiveSnapshot,
) -> Result<(Vec<prost_types::Any>, Vec<prost_types::Any>)> {
    let mut creates = Vec::new();
    let mut updates = Vec::new();
    for change in &plan.changes {
        match change {
            PlannedChange::Add {
                reference,
                value,
                footprint_id,
                symbol_path,
                dnp,
                fields,
                pad_nets,
                position,
            } => {
                let part = prepared
                    .get(footprint_id)
                    .with_context(|| format!("no prepared footprint for {footprint_id}"))?;
                let mut footprint = build_import_instance(&part.library, position.x, position.y)?;
                apply_footprint_fields(
                    &mut footprint,
                    reference,
                    value,
                    symbol_path,
                    *dnp,
                    fields,
                    pad_nets,
                    &snapshot.net_codes,
                )?;
                creates.push(konnect_ipc::builders::pack_any(
                    &footprint,
                    "kiapi.board.types.FootprintInstance",
                ));
            }
            PlannedChange::Update { kiid, .. } => {
                let item = snapshot
                    .items
                    .get(kiid)
                    .with_context(|| format!("planned footprint {kiid} disappeared"))?;
                updates.push(update_footprint_item(item, change, &snapshot.net_codes)?);
            }
        }
    }
    Ok((creates, updates))
}

#[cfg(test)]
mod chunk_tests {
    use super::*;
    use crate::test_support::MockIpcServer;
    use konnect_ipc::{builders::pack_any, gen::kiapi, KiCadIpcClient};
    use std::sync::{Arc, Mutex};

    fn footprints(count: usize) -> Vec<prost_types::Any> {
        let source = include_str!("../../tests/fixtures/c_0603_1608metric_kicad10.kicad_mod");
        let pads = super::super::pcb_components::extract_pad_definitions(source).unwrap();
        let graphics = super::super::pcb_components::extract_graphic_definitions(source).unwrap();
        let fields = super::super::pcb_components::extract_field_placement(source);
        (0..count)
            .map(|i| {
                KiCadIpcClient::build_footprint_item(
                    "Capacitor_SMD:C_0603_1608Metric",
                    &format!("C{}", i + 1),
                    "100n",
                    &pads,
                    &graphics,
                    &fields,
                    5.0 + (i % 10) as f64 * 4.0,
                    5.0 + (i / 10) as f64 * 4.0,
                    0.0,
                    "F.Cu",
                )
                .unwrap()
            })
            .collect()
    }

    #[derive(Default)]
    struct Observed {
        chunks: Vec<usize>,
        references: Vec<String>,
        staged: usize,
        begins: usize,
        actions: Vec<i32>,
        updates: usize,
    }

    fn exercise(count: usize, refusal: bool, malformed: bool) -> (Result<()>, Observed) {
        let directory = tempfile::tempdir().unwrap();
        let board = directory.path().join("chunk.kicad_pcb");
        let document =
            super::super::pcb_board::board_mock::board_document(&board.to_string_lossy());
        let target = document.clone();
        let state = Arc::new(Mutex::new(Observed::default()));
        let observed = state.clone();
        let mock = MockIpcServer::spawn("sync-chunks", move |request| {
            let command = request.message.unwrap();
            let mut state = observed.lock().unwrap();
            let mut response = kiapi::common::ApiResponse {
                status: Some(kiapi::common::ApiResponseStatus {
                    status: kiapi::common::ApiStatusCode::AsOk as i32,
                    error_message: String::new(),
                }),
                ..Default::default()
            };
            response.message = match command.type_url.rsplit('.').next().unwrap() {
                "GetOpenDocuments" => Some(pack_any(
                    &kiapi::common::commands::GetOpenDocumentsResponse {
                        documents: vec![target.clone()],
                    },
                    "kiapi.common.commands.GetOpenDocumentsResponse",
                )),
                "SaveDocumentToString" => {
                    let request = kiapi::common::commands::SaveDocumentToString::decode(
                        command.value.as_slice(),
                    )
                    .unwrap();
                    assert_eq!(request.document, Some(target.clone()));
                    Some(pack_any(
                        &kiapi::common::commands::SavedDocumentResponse {
                            document: Some(target.clone()),
                            contents: include_str!(
                                "../../../konnect-sexp/tests/fixtures/gr_poly_outline.kicad_pcb"
                            )
                            .into(),
                        },
                        "kiapi.common.commands.SavedDocumentResponse",
                    ))
                }
                "BeginCommit" => {
                    state.begins += 1;
                    Some(pack_any(
                        &kiapi::common::commands::BeginCommitResponse {
                            id: Some(kiapi::common::types::Kiid {
                                value: "chunk-commit".into(),
                            }),
                        },
                        "kiapi.common.commands.BeginCommitResponse",
                    ))
                }
                "CreateItems" => {
                    let request =
                        kiapi::common::commands::CreateItems::decode(command.value.as_slice())
                            .unwrap();
                    assert_eq!(request.header.unwrap().document, Some(target.clone()));
                    state.chunks.push(request.items.len());
                    for item in &request.items {
                        let fp =
                            kiapi::board::types::FootprintInstance::decode(item.value.as_slice())
                                .unwrap();
                        state
                            .references
                            .push(fp.reference_field.unwrap().text.unwrap().text.unwrap().text);
                    }
                    state.staged += request.items.len();
                    if state.chunks.len() == 2 && refusal {
                        response.status.as_mut().unwrap().status =
                            kiapi::common::ApiStatusCode::AsBadRequest as i32;
                        response.status.as_mut().unwrap().error_message =
                            "injected second-chunk refusal".into();
                        None
                    } else if state.chunks.len() == 2 && malformed {
                        response.status = None;
                        None
                    } else {
                        Some(pack_any(
                            &kiapi::common::commands::CreateItemsResponse {
                                header: None,
                                status: kiapi::common::types::ItemRequestStatus::IrsOk as i32,
                                created_items: request
                                    .items
                                    .into_iter()
                                    .map(|item| kiapi::common::commands::ItemCreationResult {
                                        status: Some(kiapi::common::commands::ItemStatus {
                                            code: kiapi::common::commands::ItemStatusCode::IscOk
                                                as i32,
                                            error_message: String::new(),
                                        }),
                                        item: Some(item),
                                    })
                                    .collect(),
                            },
                            "kiapi.common.commands.CreateItemsResponse",
                        ))
                    }
                }
                "UpdateItems" => {
                    state.updates += 1;
                    let request =
                        kiapi::common::commands::UpdateItems::decode(command.value.as_slice())
                            .unwrap();
                    assert_eq!(request.header.unwrap().document, Some(target.clone()));
                    Some(pack_any(
                        &kiapi::common::commands::UpdateItemsResponse {
                            header: None,
                            status: kiapi::common::types::ItemRequestStatus::IrsOk as i32,
                            updated_items: request
                                .items
                                .into_iter()
                                .map(|item| kiapi::common::commands::ItemUpdateResult {
                                    status: Some(kiapi::common::commands::ItemStatus {
                                        code: kiapi::common::commands::ItemStatusCode::IscOk as i32,
                                        error_message: String::new(),
                                    }),
                                    item: Some(item),
                                })
                                .collect(),
                        },
                        "kiapi.common.commands.UpdateItemsResponse",
                    ))
                }
                "EndCommit" => {
                    let request =
                        kiapi::common::commands::EndCommit::decode(command.value.as_slice())
                            .unwrap();
                    assert_eq!(request.id.unwrap().value, "chunk-commit");
                    state.actions.push(request.action);
                    if request.action == kiapi::common::commands::CommitAction::CmaDrop as i32 {
                        state.staged = 0;
                    }
                    Some(pack_any(
                        &kiapi::common::commands::EndCommitResponse {},
                        "kiapi.common.commands.EndCommitResponse",
                    ))
                }
                other => panic!("unexpected {other}"),
            };
            response
        });
        let items = footprints(count);
        let result = KiCadIpcClient::new(mock.address()).run_commit_recovering_in(
            document.clone(),
            "sync",
            |client| {
                create_sync_items_in(client, &document, &items)?;
                client.update_items_in(document.clone(), footprints(1))?;
                Ok(())
            },
        );
        drop(mock);
        let state = Arc::try_unwrap(state).ok().unwrap().into_inner().unwrap();
        (result, state)
    }

    #[test]
    fn sync_chunk_boundaries_preserve_order_and_one_commit() {
        for (count, expected) in [
            (0, vec![]),
            (1, vec![1]),
            (32, vec![32]),
            (33, vec![32, 1]),
            (70, vec![32, 32, 6]),
        ] {
            let (result, state) = exercise(count, false, false);
            assert!(result.is_ok(), "{result:?}");
            assert_eq!(state.chunks, expected);
            assert_eq!(
                state.references,
                (1..=count).map(|i| format!("C{i}")).collect::<Vec<_>>()
            );
            assert_eq!(state.begins, 1);
            assert_eq!(
                state.actions,
                vec![kiapi::common::commands::CommitAction::CmaCommit as i32]
            );
            assert_eq!(state.staged, count);
            assert_eq!(state.updates, 1);
        }
    }

    #[test]
    fn sync_chunk_failure_stops_and_drops_without_publishing_partial_work() {
        let (result, state) = exercise(70, true, false);
        assert!(result.unwrap_err().to_string().contains("changes dropped"));
        assert_eq!(state.chunks, vec![32, 32]);
        assert_eq!(
            state.actions,
            vec![kiapi::common::commands::CommitAction::CmaDrop as i32]
        );
        assert_eq!(state.staged, 0);
        assert_eq!(state.updates, 0);
    }

    #[test]
    fn sync_chunk_uncertainty_stops_without_blind_drop_or_publish() {
        let (result, state) = exercise(70, false, true);
        assert!(matches!(
            konnect_ipc::IpcFailure::from_error(result.unwrap_err()),
            konnect_ipc::IpcFailure::Uncertain(_)
        ));
        assert_eq!(state.chunks, vec![32, 32]);
        assert!(state.actions.is_empty());
        assert_eq!(state.staged, 64);
        assert_eq!(state.updates, 0);
    }

    // RunAction is a version-specific acceptance probe, not a supported tool API.
    fn native_action(address: &str, action: &str) -> Result<()> {
        use nng::options::Options;
        let socket = nng::Socket::new(nng::Protocol::Req0)?;
        socket.set_opt::<nng::options::SendTimeout>(Some(std::time::Duration::from_secs(5)))?;
        socket.set_opt::<nng::options::RecvTimeout>(Some(std::time::Duration::from_secs(5)))?;
        socket.dial(address)?;
        let request = kiapi::common::ApiRequest {
            header: Some(kiapi::common::ApiRequestHeader {
                kicad_token: std::env::var("KICAD_API_TOKEN").unwrap_or_default(),
                client_name: "konnect-chunk-acceptance".into(),
            }),
            message: Some(pack_any(
                &kiapi::common::commands::RunAction {
                    action: action.into(),
                },
                "kiapi.common.commands.RunAction",
            )),
        };
        socket
            .send(request.encode_to_vec().as_slice())
            .map_err(|(_, error)| error)?;
        let response = socket.recv()?;
        let response = kiapi::common::ApiResponse::decode(response.as_slice())?;
        anyhow::ensure!(
            response.status.context("missing action status")?.status
                == kiapi::common::ApiStatusCode::AsOk as i32,
            "action API refusal"
        );
        let message = response.message.context("missing action response")?;
        anyhow::ensure!(
            message
                .type_url
                .ends_with("kiapi.common.commands.RunActionResponse"),
            "unexpected action response"
        );
        let response =
            kiapi::common::commands::RunActionResponse::decode(message.value.as_slice())?;
        anyhow::ensure!(
            response.status == kiapi::common::commands::RunActionStatus::RasOk as i32,
            "native action not submitted"
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires KONNECT_LIVE_CHUNK_BOARD: disposable sole open PCB and KiCad 10.0.6 API"]
    fn sync_chunk_live_one_undo_restores_entire_board() {
        let board = std::path::PathBuf::from(
            std::env::var("KONNECT_LIVE_CHUNK_BOARD").expect("disposable board required"),
        );
        let address = std::env::var("KICAD_API_SOCKET")
            .ok()
            .or_else(konnect_ipc::detect_ipc_address)
            .expect("KiCad IPC required");
        let client = KiCadIpcClient::new(address.clone());
        let document = client.find_open_board(&board).unwrap();
        assert_eq!(
            client.get_open_documents().unwrap(),
            vec![document.clone()],
            "actions require sole disposable board"
        );
        let baseline = client.save_document_to_string_in(document.clone()).unwrap();
        let before = client
            .get_items_in(
                document.clone(),
                kiapi::common::types::KiCadObjectType::KotPcbFootprint,
            )
            .unwrap();
        let items = footprints(70);
        client
            .run_commit_recovering_in(
                document.clone(),
                "70-footprint sync chunk acceptance",
                |client| create_sync_items_in(client, &document, &items),
            )
            .unwrap();
        let after = client
            .get_items_in(
                document.clone(),
                kiapi::common::types::KiCadObjectType::KotPcbFootprint,
            )
            .unwrap();
        assert_eq!(after.len(), before.len() + 70);
        let mut references = after
            .iter()
            .map(|item| {
                kiapi::board::types::FootprintInstance::decode(item.value.as_slice())
                    .unwrap()
                    .reference_field
                    .unwrap()
                    .text
                    .unwrap()
                    .text
                    .unwrap()
                    .text
            })
            .collect::<Vec<_>>();
        references.sort();
        for i in 1..=70 {
            assert!(references.contains(&format!("C{i}")));
        }
        let published = client.save_document_to_string_in(document.clone()).unwrap();
        assert_ne!(published, baseline);
        let wait_for = |expected: &str| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if client.save_document_to_string_in(document.clone()).unwrap() == expected {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "native action did not restore entire serialized board"
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        };
        native_action(&address, "common.Interactive.undo").unwrap();
        wait_for(&baseline);
        native_action(&address, "common.Interactive.redo").unwrap();
        wait_for(&published);
        native_action(&address, "common.Interactive.undo").unwrap();
        wait_for(&baseline);
        eprintln!("LIVE PASS: 70 footprints in 32/32/6 chunks; one Undo restores full baseline; Redo restores full published state; final Undo leaves baseline.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_RESISTOR: &str = r#"
(export
  (components
    (comp
      (ref "R1")
      (value "10k")
      (footprint "Resistor_SMD:R_0603_1608Metric")
      (sheetpath (names "/Power/") (tstamps "/sheet-uuid/"))
      (tstamps "symbol-uuid")
      (units (unit (name "A") (pins (pin (num "1")) (pin (num "2")))))))
  (nets
    (net (code "1") (name "/Power/VCC") (class "Default")
      (node (ref "R1") (pin "1") (pintype "passive")))
    (net (code "2") (name "GND") (class "Default")
      (node (ref "R1") (pin "2") (pintype "passive")))))
"#;

    #[test]
    fn exported_netlist_is_one_flattened_source_of_component_and_pad_truth() {
        let design = parse_exported_netlist(ONE_RESISTOR).expect("valid KiCad netlist");

        assert_eq!(design.components.len(), 1);
        let component = &design.components[0];
        assert_eq!(component.reference, "R1");
        assert_eq!(component.value, "10k");
        assert_eq!(component.footprint_id, "Resistor_SMD:R_0603_1608Metric");
        assert_eq!(component.symbol_path, "/sheet-uuid/symbol-uuid");
        assert_eq!(
            component.pad_nets.get("1").map(String::as_str),
            Some("/Power/VCC")
        );
        assert_eq!(component.pad_nets.get("2").map(String::as_str), Some("GND"));
        assert!(!component.dnp);
    }

    fn netlist_with_fields(extra: &str) -> String {
        ONE_RESISTOR.replace("(sheetpath", &format!("{extra}\n      (sheetpath"))
    }

    #[test]
    fn exported_fields_use_kicad_scalar_values_and_do_not_copy_exporter_properties() {
        let source = netlist_with_fields(
            r#"
            (fields
                (field (name "Reference") "ignored")
                (field (name "Value") "ignored")
                (field (name "Footprint") "ignored")
                (field (name "Trial") "headless")
                (field (name "CircuitNote") "Illustrative 5 V; not hardware-qualified")
                (field (name "Datasheet"))
                (field (name "Description") ""))
            (datasheet "must not override an explicit clear")
            (description "must not override an explicit clear")
            (libsource (description "library fallback"))
            (property (name "Trial") (value "exporter duplicate"))
            (property (name "Sheetname") (value "Power"))
            (property (name "Sheetfile") (value "power.kicad_sch"))
            (property (name "ki_keywords") (value "resistor"))
            (property (name "ki_fp_filters") (value "R_*"))
        "#,
        );
        let design = parse_exported_netlist(&source).unwrap();
        assert_eq!(
            design.components[0].fields,
            BTreeMap::from([
                (
                    "CircuitNote".to_string(),
                    "Illustrative 5 V; not hardware-qualified".to_string()
                ),
                ("Datasheet".to_string(), String::new()),
                ("Description".to_string(), String::new()),
                ("Trial".to_string(), "headless".to_string()),
            ])
        );
        assert_eq!(design.components[0].reference, "R1");
        assert_eq!(design.components[0].value, "10k");
        let real_export = parse_exported_netlist(UNASSIGNED).unwrap();
        let capacitor = real_export
            .components
            .iter()
            .find(|part| part.reference == "C1")
            .unwrap();
        assert_eq!(capacitor.fields["Datasheet"], "");
        assert_eq!(capacitor.fields["Description"], "Unpolarized capacitor");
    }

    #[test]
    fn field_fallbacks_apply_only_when_the_field_is_absent() {
        let design = parse_exported_netlist(&netlist_with_fields(
            r#"
            (datasheet "https://example.test/r.pdf")
            (libsource (description "library description"))
        "#,
        ))
        .unwrap();
        assert_eq!(
            design.components[0].fields,
            BTreeMap::from([
                (
                    "Datasheet".to_string(),
                    "https://example.test/r.pdf".to_string()
                ),
                ("Description".to_string(), "library description".to_string()),
            ])
        );
        let design = parse_exported_netlist(&netlist_with_fields(
            r#"
            (fields (field (name "Description")))
            (libsource (description "library description"))
        "#,
        ))
        .unwrap();
        assert_eq!(design.components[0].fields["Description"], "");
        assert!(!design.components[0].fields.contains_key("Datasheet"));
        assert!(parse_exported_netlist(ONE_RESISTOR).unwrap().components[0]
            .fields
            .is_empty());
    }

    #[test]
    fn duplicate_or_malformed_exported_fields_fail_before_planning() {
        for extra in [
            r#"(fields (field))"#,
            r#"(fields (field "Trial" "headless"))"#,
            r#"(fields (field (name "") "headless"))"#,
            r#"(fields (field (name " ") "headless"))"#,
            r#"(fields (field (name (nested "Trial")) "headless"))"#,
            r#"(fields (field (name "Trial" "extra") "headless"))"#,
            r#"(fields (field (name "Trial") (value "headless")))"#,
            r#"(fields (field (name "Trial") "one" "two"))"#,
            r#"(fields (field (name "Trial") "one") (field (name "Trial")))"#,
            r#"(fields (field (name "Reference") "one") (field (name "Reference") "two"))"#,
            r#"(fields (property (name "Trial") "headless"))"#,
            r#"(fields bad)"#,
            r#"(fields) (fields)"#,
            r#"(datasheet (value "bad"))"#,
            r#"(libsource (description "one" "two"))"#,
        ] {
            let error = parse_exported_netlist(&netlist_with_fields(extra)).expect_err(extra);
            assert!(
                format!("{error:#}").contains("schematic fields"),
                "{extra}: {error:#}"
            );
        }
    }

    fn identified_field(
        name: &str,
        value: &str,
        id: i32,
    ) -> konnect_ipc::gen::kiapi::board::types::Field {
        use konnect_ipc::gen::kiapi;
        let mut text =
            konnect_ipc::builders::board_text("B.SilkS", value, 4.0, 5.0, 1.25, 17.0, true);
        text.id = Some(kiapi::common::types::Kiid {
            value: format!("field-{id}-uuid"),
        });
        text.parent = Some(kiapi::common::types::Kiid {
            value: "u1-kiid".to_string(),
        });
        text.locked = kiapi::common::types::LockedState::LsLocked as i32;
        text.text
            .as_mut()
            .unwrap()
            .attributes
            .as_mut()
            .unwrap()
            .bold = true;
        kiapi::board::types::Field {
            id: Some(kiapi::board::types::FieldId { id }),
            name: name.to_string(),
            visible: true,
            text: Some(text),
        }
    }

    fn field_eco_instance() -> konnect_ipc::gen::kiapi::board::types::FootprintInstance {
        use konnect_ipc::gen::kiapi;
        let item = footprint_with_artwork("U1");
        let mut footprint =
            kiapi::board::types::FootprintInstance::decode(item.value.as_slice()).unwrap();
        footprint.layer = kiapi::board::types::BoardLayer::BlBCu as i32;
        footprint.orientation = Some(kiapi::common::types::Angle {
            value_degrees: 90.0,
        });
        footprint.locked = kiapi::common::types::LockedState::LsLocked as i32;
        footprint.symbol_path = Some(kiapi::common::types::SheetPath {
            path: vec![
                kiapi::common::types::Kiid {
                    value: "root".to_string(),
                },
                kiapi::common::types::Kiid {
                    value: "u1".to_string(),
                },
            ],
            path_human_readable: "/Power/".to_string(),
        });
        footprint.datasheet_field = Some(identified_field("Datasheet", "old.pdf", 2));
        footprint.description_field = Some(identified_field("Description", "old description", 3));
        let definition = footprint.definition.as_mut().unwrap();
        definition.datasheet_field = Some(identified_field("Datasheet", "old.pdf", 22));
        definition.description_field = Some(identified_field("Description", "old description", 23));
        for child in &mut definition.items {
            if konnect_ipc::builders::any_is(child, "kiapi.board.types.Pad") {
                let mut pad = kiapi::board::types::Pad::decode(child.value.as_slice()).unwrap();
                pad.id = Some(kiapi::common::types::Kiid {
                    value: "pad-uuid".to_string(),
                });
                pad.net = Some(kiapi::board::types::Net {
                    name: "GND".to_string(),
                    code: Some(kiapi::board::types::NetCode { value: 42 }),
                });
                child.value = pad.encode_to_vec();
                // An unknown, valid varint property must survive a field-only
                // update; decoding/repacking an unchanged pad would lose it.
                child.value.extend_from_slice(&[0xf8, 0x07, 0x01]);
                child.type_url = "capture/kiapi.board.types.Pad".to_string();
            }
        }
        for field in [
            identified_field("Trial", "before", 10),
            identified_field("PCBOnly", "keep", 11),
        ] {
            definition.items.push(konnect_ipc::builders::pack_any(
                &field,
                "kiapi.board.types.Field",
            ));
        }
        let library = parse_library_footprint(
            STOCK_0603,
            include_str!("../../tests/fixtures/c_0603_1608metric_kicad10.kicad_mod"),
        )
        .unwrap();
        let stock = build_import_instance(&library, 25.0, 30.0).unwrap();
        definition
            .items
            .extend(stock.definition.unwrap().items.into_iter().filter(|item| {
                konnect_ipc::builders::any_is(item, "kiapi.board.types.Footprint3DModel")
            }));
        footprint
    }

    fn field_design(
        footprint: &konnect_ipc::gen::kiapi::board::types::FootprintInstance,
        fields: BTreeMap<String, String>,
    ) -> ExportedDesign {
        let board = board_footprint_from_instance(footprint).unwrap();
        ExportedDesign {
            components: vec![DesignComponent {
                reference: board.reference,
                value: board.value,
                footprint_id: board.footprint_id,
                symbol_path: board.symbol_path.unwrap(),
                dnp: board.dnp,
                fields,
                pad_nets: board.pad_nets,
            }],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        }
    }

    fn field_snapshot(
        footprint: &konnect_ipc::gen::kiapi::board::types::FootprintInstance,
    ) -> LiveSnapshot {
        let board = board_footprint_from_instance(footprint).unwrap();
        LiveSnapshot {
            items: BTreeMap::from([(
                board.kiid.clone(),
                konnect_ipc::builders::pack_any(footprint, "kiapi.board.types.FootprintInstance"),
            )]),
            state: board_with(vec![board]),
            // Deliberately different from the pad's live code: a field-only
            // ECO must leave the existing pad Any and code exactly unchanged.
            net_codes: BTreeMap::from([("GND".to_string(), 99)]),
            document: Default::default(),
        }
    }

    #[test]
    fn field_only_eco_keeps_field_ids_presentation_pose_models_path_and_pad_bytes() {
        use konnect_ipc::gen::kiapi;
        let before = field_eco_instance();
        let desired = BTreeMap::from([
            ("Trial".to_string(), "after".to_string()),
            ("Datasheet".to_string(), String::new()),
            (
                "Description".to_string(),
                "schematic description".to_string(),
            ),
            ("NewField".to_string(), "added".to_string()),
        ]);
        let design = field_design(&before, desired.clone());
        let snapshot = field_snapshot(&before);
        let plan = plan_sync("field ECO", &design, &snapshot.state);
        assert_eq!(plan.status, PlanStatus::Ready);
        assert_eq!(plan.counts.updated.planned, 1);
        assert_eq!(plan.counts.pads_reassigned.planned, 0);
        assert!(
            matches!(&plan.changes[0], PlannedChange::Update { fields, .. } if fields == &desired)
        );
        let (creates, updates) = build_mutation_items(&plan, &BTreeMap::new(), &snapshot).unwrap();
        assert!(
            creates.is_empty(),
            "an ECO never reconstructs from a library"
        );
        let after =
            kiapi::board::types::FootprintInstance::decode(updates[0].value.as_slice()).unwrap();
        let before_fields = footprint_field_slots(&before).unwrap();
        let after_fields = footprint_field_slots(&after).unwrap();
        for (slot, old) in &before_fields {
            let mut expected = old.clone();
            if let Some(value) = desired.get(&old.name) {
                expected.text.as_mut().unwrap().text.as_mut().unwrap().text = value.clone();
            }
            assert_eq!(
                &after_fields[slot], &expected,
                "{slot}: only nested text may change"
            );
        }
        let new_field = &after_fields["custom.NewField"];
        assert_eq!(new_field.id, None);
        assert!(!new_field.visible);
        let text = new_field.text.as_ref().unwrap();
        assert_eq!(text.id, None);
        assert_eq!(text.parent, None);
        assert_eq!(text.text.as_ref().unwrap().position, before.position);
        assert!(
            !text
                .text
                .as_ref()
                .unwrap()
                .attributes
                .as_ref()
                .unwrap()
                .visible
        );
        assert_eq!(text.layer, kiapi::board::types::BoardLayer::BlBFab as i32);
        let mut unrelated_before = before.clone();
        let mut unrelated_after = after.clone();
        for footprint in [&mut unrelated_before, &mut unrelated_after] {
            footprint.datasheet_field = None;
            footprint.description_field = None;
            let definition = footprint.definition.as_mut().unwrap();
            definition.datasheet_field = None;
            definition.description_field = None;
            definition
                .items
                .retain(|item| !konnect_ipc::builders::any_is(item, "kiapi.board.types.Field"));
        }
        assert_eq!(
            unrelated_after, unrelated_before,
            "all non-field payloads must survive verbatim"
        );
        let noop = plan_sync("field ECO", &design, &field_snapshot(&after).state);
        assert_eq!(noop.status, PlanStatus::Noop);
    }

    #[test]
    fn absent_fields_preserve_board_only_values_and_explicit_empty_clears_without_deletion() {
        use konnect_ipc::gen::kiapi;
        let before = field_eco_instance();
        for desired in [
            BTreeMap::new(),
            BTreeMap::from([("Trial".to_string(), "before".to_string())]),
        ] {
            let plan = plan_sync(
                "subset",
                &field_design(&before, desired),
                &field_snapshot(&before).state,
            );
            assert_eq!(
                plan.status,
                PlanStatus::Noop,
                "PCB-only fields are not schematic deletions"
            );
        }
        let desired = BTreeMap::from([("Trial".to_string(), String::new())]);
        let design = field_design(&before, desired);
        let snapshot = field_snapshot(&before);
        let plan = plan_sync("clear", &design, &snapshot.state);
        let (_, updates) = build_mutation_items(&plan, &BTreeMap::new(), &snapshot).unwrap();
        let after =
            kiapi::board::types::FootprintInstance::decode(updates[0].value.as_slice()).unwrap();
        let fields = footprint_field_slots(&after).unwrap();
        let mut cleared = footprint_field_slots(&before).unwrap()["custom.Trial"].clone();
        cleared
            .text
            .as_mut()
            .unwrap()
            .text
            .as_mut()
            .unwrap()
            .text
            .clear();
        assert_eq!(fields["custom.Trial"], cleared);
        assert_eq!(board_field_values(&after).unwrap()["PCBOnly"], "keep");
        assert_eq!(after.datasheet_field, before.datasheet_field);
        assert_eq!(after.description_field, before.description_field);
        assert_eq!(
            plan_sync("clear", &design, &field_snapshot(&after).state).status,
            PlanStatus::Noop
        );
    }

    #[test]
    fn board_fields_are_typed_and_duplicate_or_malformed_typed_fields_fail_closed() {
        use konnect_ipc::gen::kiapi;
        let before = field_eco_instance();
        assert_eq!(
            board_field_values(&before).unwrap(),
            BTreeMap::from([
                ("Datasheet".to_string(), "old.pdf".to_string()),
                ("Description".to_string(), "old description".to_string()),
                ("PCBOnly".to_string(), "keep".to_string()),
                ("Trial".to_string(), "before".to_string()),
            ])
        );
        let mut untyped = before.clone();
        untyped
            .definition
            .as_mut()
            .unwrap()
            .items
            .push(konnect_ipc::builders::pack_any(
                &identified_field("Trial", "not a field", 99),
                "kiapi.board.types.BoardText",
            ));
        assert_eq!(
            board_field_values(&untyped).unwrap(),
            board_field_values(&before).unwrap()
        );
        let malformed = kiapi::board::types::Field {
            name: "Malformed".to_string(),
            ..Default::default()
        };
        for bad in [
            konnect_ipc::builders::pack_any(
                &identified_field("Trial", "duplicate", 99),
                "kiapi.board.types.Field",
            ),
            konnect_ipc::builders::pack_any(
                &identified_field("", "no name", 99),
                "kiapi.board.types.Field",
            ),
            konnect_ipc::builders::pack_any(
                &identified_field("Datasheet", "reserved", 99),
                "kiapi.board.types.Field",
            ),
            konnect_ipc::builders::pack_any(&malformed, "kiapi.board.types.Field"),
            prost_types::Any {
                type_url: "type.googleapis.com/kiapi.board.types.Field".to_string(),
                value: vec![0xff, 0xff],
            },
        ] {
            let mut footprint = before.clone();
            footprint.definition.as_mut().unwrap().items.push(bad);
            assert!(board_footprint_from_instance(&footprint).is_err());
            assert!(overlay_schematic_fields(&mut footprint, &BTreeMap::new()).is_err());
        }
        let mut fallback = before.clone();
        fallback.datasheet_field = None;
        assert_eq!(
            board_field_values(&fallback).unwrap()["Datasheet"],
            "old.pdf"
        );
        overlay_schematic_fields(
            &mut fallback,
            &BTreeMap::from([("Datasheet".to_string(), "new.pdf".to_string())]),
        )
        .unwrap();
        assert_eq!(
            fallback
                .definition
                .as_ref()
                .unwrap()
                .datasheet_field
                .as_ref()
                .unwrap()
                .id,
            before
                .definition
                .as_ref()
                .unwrap()
                .datasheet_field
                .as_ref()
                .unwrap()
                .id
        );
        assert_eq!(
            fallback.datasheet_field.as_ref().unwrap().id,
            None,
            "a new slot must not inherit an existing field's identity"
        );
    }

    #[test]
    fn readback_rejects_missing_fields_wrong_values_and_changed_existing_field_identities() {
        use konnect_ipc::gen::kiapi;
        use std::sync::{Arc, Mutex};
        let mut sent = field_eco_instance();
        overlay_schematic_fields(
            &mut sent,
            &BTreeMap::from([("NewHidden".to_string(), "hidden value".to_string())]),
        )
        .unwrap();
        let packed = konnect_ipc::builders::pack_any(&sent, "kiapi.board.types.FootprintInstance");
        let expected = footprint_readback(std::iter::once(&packed)).unwrap();
        let items = Arc::new(Mutex::new(vec![packed.clone()]));
        let served_items = items.clone();
        let directory = tempfile::tempdir().unwrap();
        let board = directory.path().join("readback.kicad_pcb");
        std::fs::write(
            &board,
            include_bytes!("../../tests/fixtures/specctra_two_resistors.kicad_pcb"),
        )
        .unwrap();
        let server = crate::tools::pcb_board::board_mock::spawn_kicad_holding_board(
            &board,
            move |command| {
                if command.type_url.ends_with("GetItems") {
                    return Some(konnect_ipc::builders::pack_any(
                        &kiapi::common::commands::GetItemsResponse {
                            header: None,
                            status: kiapi::common::types::ItemRequestStatus::IrsOk as i32,
                            items: served_items.lock().unwrap().clone(),
                        },
                        "kiapi.common.commands.GetItemsResponse",
                    ));
                }
                None
            },
        );
        let client = konnect_ipc::KiCadIpcClient::new(server.address().to_string());
        let document = client.find_open_board(&board).unwrap();
        assert!(
            verify_board_matches_what_was_sent(&client, &document, &expected)
                .unwrap()
                .is_empty()
        );
        for (damage, message) in [
            (0, "value differs"),
            (1, "numeric ID changed"),
            (2, "text KIID changed"),
            (3, "field custom.Trial is missing"),
            (4, "field definition.Datasheet value differs"),
            (5, "field custom.Trial visibility differs"),
            (6, "field custom.NewHidden visibility differs"),
            (7, "field custom.Trial presentation differs"),
        ] {
            let mut wrong = sent.clone();
            if damage == 4 {
                set_field_text(
                    &mut wrong.definition.as_mut().unwrap().datasheet_field,
                    "Datasheet",
                    "lost.pdf",
                );
            } else {
                let children = &mut wrong.definition.as_mut().unwrap().items;
                let index = children
                    .iter()
                    .position(|item| {
                        konnect_ipc::builders::any_is(item, "kiapi.board.types.Field")
                            && kiapi::board::types::Field::decode(item.value.as_slice())
                                .unwrap()
                                .name
                                == if damage == 6 { "NewHidden" } else { "Trial" }
                    })
                    .unwrap();
                if damage == 3 {
                    children.remove(index);
                } else {
                    let mut field =
                        kiapi::board::types::Field::decode(children[index].value.as_slice())
                            .unwrap();
                    match damage {
                        0 => {
                            field.text.as_mut().unwrap().text.as_mut().unwrap().text =
                                "lost update".to_string()
                        }
                        1 => field.id = Some(kiapi::board::types::FieldId { id: 999 }),
                        2 => field.text.as_mut().unwrap().id = None,
                        5 => field.visible = false,
                        6 => field.visible = true,
                        7 => {
                            field
                                .text
                                .as_mut()
                                .unwrap()
                                .text
                                .as_mut()
                                .unwrap()
                                .attributes
                                .as_mut()
                                .unwrap()
                                .size
                                .as_mut()
                                .unwrap()
                                .x_nm += 1_000_000
                        }
                        _ => unreachable!(),
                    }
                    children[index].value = field.encode_to_vec();
                }
            }
            let wrong =
                konnect_ipc::builders::pack_any(&wrong, "kiapi.board.types.FootprintInstance");
            assert_eq!(
                footprint_shapes(std::iter::once(&wrong)),
                footprint_shapes(std::iter::once(&packed)),
                "shape-only validation would miss this ECO failure"
            );
            *items.lock().unwrap() = vec![wrong];
            let error =
                verify_board_matches_what_was_sent(&client, &document, &expected).unwrap_err();
            assert!(format!("{error:#}").contains(message), "{error:#}");
        }
        let mut mandatory_in_both_slots = sent.clone();
        let definition = mandatory_in_both_slots.definition.as_mut().unwrap();
        definition.datasheet_field = mandatory_in_both_slots.datasheet_field.clone();
        definition.description_field = mandatory_in_both_slots.description_field.clone();
        let sent_slots = konnect_ipc::builders::pack_any(
            &mandatory_in_both_slots,
            "kiapi.board.types.FootprintInstance",
        );
        let native_expected = footprint_readback(std::iter::once(&sent_slots)).unwrap();
        let definition = mandatory_in_both_slots.definition.as_mut().unwrap();
        definition.reference_field = None;
        definition.value_field = None;
        definition.datasheet_field = None;
        definition.description_field = None;
        *items.lock().unwrap() = vec![konnect_ipc::builders::pack_any(
            &mandatory_in_both_slots,
            "kiapi.board.types.FootprintInstance",
        )];
        assert!(verify_board_matches_what_was_sent(&client, &document, &native_expected).unwrap().is_empty(),
            "KiCad's native instance-only mandatory serialization still validates values and identities");
        items.lock().unwrap().clear();
        assert!(
            verify_board_matches_what_was_sent(&client, &document, &expected)
                .unwrap_err()
                .to_string()
                .contains("missing from readback")
        );
    }

    #[test]
    fn field_verification_accepts_native_defaults_and_assigned_new_ids_without_ignoring_presentation(
    ) {
        use konnect_ipc::gen::kiapi;
        let captured = kiapi::board::types::FootprintInstance::decode(BOARD_ONLY_CAPTURE).unwrap();
        let native = captured.reference_field.as_ref().unwrap();
        assert!(
            !native.visible,
            "the retained native capture's reference is hidden"
        );
        let native_attributes = native
            .text
            .as_ref()
            .unwrap()
            .text
            .as_ref()
            .unwrap()
            .attributes
            .as_ref()
            .unwrap();
        assert!(
            native_attributes.visible,
            "the deprecated text flag is not field visibility"
        );
        let mut requested = native.clone();
        requested.id = None;
        let board_text = requested.text.as_mut().unwrap();
        board_text.id = None;
        board_text.parent = None;
        board_text.locked = kiapi::common::types::LockedState::LsUnknown as i32;
        let attributes = board_text
            .text
            .as_mut()
            .unwrap()
            .attributes
            .as_mut()
            .unwrap();
        attributes.font_name = "KiCad Font".to_string();
        attributes.horizontal_alignment =
            kiapi::common::types::HorizontalAlignment::HaUnknown as i32;
        attributes.vertical_alignment = kiapi::common::types::VerticalAlignment::VaUnknown as i32;
        attributes.line_spacing = 0.0;
        attributes.visible = false;
        attributes
            .angle
            .get_or_insert_with(Default::default)
            .value_degrees += 360.0;
        let want = FootprintReadback {
            shape: Default::default(),
            kiid: None,
            fields: BTreeMap::from([("instance.Reference".to_string(), requested)]),
        };
        let mut got = FootprintReadback {
            shape: Default::default(),
            kiid: captured.id.as_ref().map(|id| id.value.clone()),
            fields: BTreeMap::from([("instance.Reference".to_string(), native.clone())]),
        };
        assert!(footprint_field_verification_errors("MH1", &want, &got).unwrap().is_empty(),
            "native assigned IDs, stroke-font/default aliases and deprecated visibility are not loss");
        got.fields.get_mut("instance.Reference").unwrap().visible = true;
        assert!(footprint_field_verification_errors("MH1", &want, &got)
            .unwrap()
            .iter()
            .any(|error| error.contains("visibility differs")));
        for damage in 0..10 {
            let mut field = native.clone();
            let board_text = field.text.as_mut().unwrap();
            match damage {
                0 => board_text.layer = kiapi::board::types::BoardLayer::BlBFab as i32,
                1 => board_text.knockout = !board_text.knockout,
                2 => board_text.locked = kiapi::common::types::LockedState::LsLocked as i32,
                3 => {
                    board_text
                        .text
                        .as_mut()
                        .unwrap()
                        .position
                        .as_mut()
                        .unwrap()
                        .x_nm += 1_000_000
                }
                _ => {
                    let attributes = board_text
                        .text
                        .as_mut()
                        .unwrap()
                        .attributes
                        .as_mut()
                        .unwrap();
                    match damage {
                        4 => attributes.font_name = "a different font".to_string(),
                        5 => {
                            attributes.horizontal_alignment =
                                kiapi::common::types::HorizontalAlignment::HaLeft as i32
                        }
                        6 => {
                            attributes
                                .angle
                                .get_or_insert_with(Default::default)
                                .value_degrees += 90.0
                        }
                        7 => attributes.stroke_width.as_mut().unwrap().value_nm += 100_000,
                        8 => attributes.size.as_mut().unwrap().x_nm += 1_000_000,
                        9 => attributes.mirrored = !attributes.mirrored,
                        _ => unreachable!(),
                    }
                }
            }
            got.fields.insert("instance.Reference".to_string(), field);
            assert!(
                footprint_field_verification_errors("MH1", &want, &got)
                    .unwrap()
                    .iter()
                    .any(|error| error.contains("presentation differs")),
                "presentation loss {damage} must be detected"
            );
        }
    }

    #[test]
    fn plan_revision_tracks_exported_and_current_fields_including_pcb_only_values() {
        let mut board = board_with(vec![board_resistor("R1", Some("/sheet-uuid/symbol-uuid"))]);
        board.footprints[0]
            .fields
            .insert("PCBOnly".to_string(), "one".to_string());
        let source = netlist_with_fields(r#"(fields (field (name "Trial") "one"))"#);
        let baseline = plan_revision(&source, &board);
        assert_ne!(
            baseline,
            plan_revision(&source.replace("\"one\"", "\"two\""), &board)
        );
        board.footprints[0]
            .fields
            .insert("PCBOnly".to_string(), "two".to_string());
        assert_ne!(baseline, plan_revision(&source, &board));
        assert_ne!(
            plan_revision(ONE_RESISTOR, &board),
            plan_revision(
                &netlist_with_fields(r#"(fields (field (name "Trial")))"#),
                &board
            )
        );
    }

    /// Real `kicad-cli sch export netlist` output: `R1` never had a footprint
    /// assigned, so the export carries no `(footprint …)` node for it and
    /// still nets its pin 1 to `C1`. Provenance in
    /// `tests/fixtures/unassigned_footprint.README.md`.
    const UNASSIGNED: &str = include_str!("../../tests/fixtures/unassigned_footprint.net");

    /// #507: one footprint-less symbol failed the whole sync with "KiCad
    /// netlist node is missing footprint" — nothing about which component,
    /// every other component blocked with it.
    #[test]
    fn a_component_without_a_footprint_is_reported_not_fatal() {
        let design = parse_exported_netlist(UNASSIGNED).expect("a real export parses");

        let mut placed: Vec<&str> = design
            .components
            .iter()
            .map(|component| component.reference.as_str())
            .collect();
        placed.sort_unstable();
        assert_eq!(placed, ["C1", "R2"]);
        assert_eq!(design.unassigned.len(), 1);
        let unassigned = &design.unassigned[0];
        assert_eq!(unassigned.reference, "R1");
        assert_eq!(unassigned.value, "R");
        assert_eq!(unassigned.lib_id.as_deref(), Some("Device:R"));
        assert!(unassigned.symbol_path.starts_with('/'));
        // Its wired pin names a component with no pads; the net node is
        // dropped, and C1's side of the same net is kept.
        let c1 = design
            .components
            .iter()
            .find(|component| component.reference == "C1")
            .unwrap();
        assert_eq!(
            c1.pad_nets.get("1").map(String::as_str),
            Some("Net-(C1-Pad1)")
        );
    }

    fn unassigned_design() -> ExportedDesign {
        parse_exported_netlist(UNASSIGNED).unwrap()
    }

    /// The real export with one `(comp …)` block copied under another
    /// reference's name, placed *after* `after`. kicad-cli cannot produce a
    /// duplicate reference, so the order-sensitive inputs are the real file
    /// with one block duplicated by hand.
    fn with_duplicate_of(copied: &str, renamed_to: &str, after: &str) -> String {
        let block = comp_block(UNASSIGNED, copied).replace(
            &format!("(ref \"{copied}\")"),
            &format!("(ref \"{renamed_to}\")"),
        );
        let anchor = comp_block(UNASSIGNED, after);
        let at = UNASSIGNED.find(anchor).unwrap() + anchor.len();
        format!("{}{}{}", &UNASSIGNED[..at], block, &UNASSIGNED[at..])
    }

    fn comp_block<'a>(source: &'a str, reference: &str) -> &'a str {
        let start = source.find(&format!("(ref \"{reference}\")")).unwrap();
        let start = source[..start].rfind("(comp").unwrap();
        let mut depth = 0usize;
        for (offset, ch) in source[start..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return &source[start..start + offset + 1];
                    }
                }
                _ => {}
            }
        }
        unreachable!("unbalanced comp block")
    }

    fn refuses_duplicate(source: &str) {
        let error = parse_exported_netlist(source)
            .expect_err("a duplicate reference must refuse before any plan")
            .to_string();
        assert!(error.contains("duplicate component reference"), "{error}");
    }

    /// Order-sensitive: the second `R1` is unassigned like the first.
    #[test]
    fn a_repeated_unassigned_reference_is_refused() {
        refuses_duplicate(&with_duplicate_of("R1", "R1", "R1"));
    }

    /// Unassigned `R1` first, then an assigned component renamed to `R1`.
    #[test]
    fn an_assigned_repeat_of_an_unassigned_reference_is_refused() {
        refuses_duplicate(&with_duplicate_of("R2", "R1", "R1"));
    }

    /// Assigned `C1` first, then an unassigned component renamed to `C1`.
    #[test]
    fn an_unassigned_repeat_of_an_assigned_reference_is_refused() {
        refuses_duplicate(&with_duplicate_of("R1", "C1", "C1"));
    }

    /// Assigned then assigned, the case the parser already refused.
    #[test]
    fn a_repeated_assigned_reference_is_still_refused() {
        refuses_duplicate(&with_duplicate_of("R2", "C1", "R2"));
    }

    /// Nothing asserted the *response* keys — every other test here reads the
    /// `SyncPlan` struct — so a renamed or dropped JSON field was invisible to
    /// the suite. This pins the two names a caller reads.
    #[test]
    fn the_response_names_the_collection_in_the_plural_and_the_count_in_the_singular() {
        let design = unassigned_design();
        let plan = plan_sync(UNASSIGNED, &design, &board_with(vec![]));
        let result = sync_response(&plan, "ready", 1, false);
        let text = match result.content.first() {
            Some(crate::mcp::protocol::ToolContent::Text { text }) => text.clone(),
            other => panic!("expected text content, got {other:?}"),
        };
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        let unassigned = value["unassigned_footprints"]
            .as_array()
            .expect("the collection is a plural-named array");
        assert_eq!(unassigned.len(), 1);
        assert_eq!(unassigned[0]["reference"], "R1");
        assert_eq!(unassigned[0]["board_state"], "absent");
        // The count category keeps its singular name.
        assert_eq!(value["coverage"]["unassigned_footprint"]["planned"], 1);
        assert!(value.get("unassigned_footprint").is_none());
    }

    /// The helper builds what it claims: the duplicated block parses as a
    /// second component when it is given a fresh reference instead.
    #[test]
    fn the_duplicate_helper_produces_a_parseable_export() {
        let design = parse_exported_netlist(&with_duplicate_of("R2", "R3", "R2")).unwrap();
        assert_eq!(design.components.len(), 3);
        assert_eq!(design.unassigned.len(), 1);
    }

    /// Empty board: the two assigned components are planned as additions, the
    /// unassigned one is listed as absent, and the plan is ready — not a
    /// conflict, and R1 is not counted under `added`.
    #[test]
    fn the_sync_goes_on_for_every_assigned_component() {
        let design = unassigned_design();
        let plan = plan_sync(UNASSIGNED, &design, &board_with(vec![]));

        assert_eq!(plan.status, PlanStatus::Ready);
        assert!(plan.diagnostics.is_empty());
        assert_eq!(plan.counts.added.planned, 2);
        assert_eq!(plan.counts.unassigned_footprint.planned, 1);
        assert_eq!(plan.unassigned.len(), 1);
        assert_eq!(plan.unassigned[0].reference, "R1");
        assert_eq!(plan.unassigned[0].board_state, UnassignedBoardState::Absent);
        assert!(plan.changes.iter().all(|change| {
            !matches!(change, PlannedChange::Add { reference, .. } if reference == "R1")
        }));
    }

    /// A footprint already on the board for the unassigned symbol is kept as
    /// it is and counted as matched — not board-only, not a conflict.
    #[test]
    fn an_existing_board_footprint_for_an_unassigned_symbol_is_kept() {
        let design = unassigned_design();
        let r1_path = design.unassigned[0].symbol_path.clone();
        let plan = plan_sync(
            UNASSIGNED,
            &design,
            &board_with(vec![board_resistor("R1", Some(&r1_path))]),
        );

        assert_eq!(plan.status, PlanStatus::Ready);
        assert!(plan.diagnostics.is_empty());
        assert_eq!(plan.unassigned[0].board_state, UnassignedBoardState::Kept);
        assert_eq!(plan.counts.board_only_preserved.planned, 0);
        assert!(!plan.changes.iter().any(
            |change| matches!(change, PlannedChange::Update { reference, .. } if reference == "R1")
        ));
    }

    /// Nothing but unassigned parts is a no-op that still names them.
    #[test]
    fn an_all_unassigned_schematic_is_a_noop_with_the_list() {
        let mut design = unassigned_design();
        design.components.clear();
        let plan = plan_sync(UNASSIGNED, &design, &board_with(vec![]));

        assert_eq!(plan.status, PlanStatus::Noop);
        assert_eq!(plan.counts.unassigned_footprint.planned, 1);
        assert_eq!(plan.unassigned.len(), 1);
    }

    /// A genuine conflict still clears the changes, but the report about the
    /// schematic survives it.
    #[test]
    fn the_unassigned_list_survives_a_conflict() {
        let design = unassigned_design();
        let mut stranger = board_resistor("C1", Some("/other/identity"));
        stranger.footprint_id = "Capacitor_SMD:C_0603_1608Metric".to_string();
        let plan = plan_sync(UNASSIGNED, &design, &board_with(vec![stranger]));

        assert_eq!(plan.status, PlanStatus::Conflict);
        assert!(plan.changes.is_empty());
        assert_eq!(plan.unassigned.len(), 1);
    }

    fn resistor(reference: &str, symbol_path: &str) -> DesignComponent {
        DesignComponent {
            reference: reference.to_string(),
            value: "10k".to_string(),
            footprint_id: "Resistor_SMD:R_0603_1608Metric".to_string(),
            symbol_path: symbol_path.to_string(),
            dnp: false,
            fields: BTreeMap::new(),
            pad_nets: BTreeMap::from([
                ("1".to_string(), "VCC".to_string()),
                ("2".to_string(), "GND".to_string()),
            ]),
        }
    }

    fn board_resistor(reference: &str, symbol_path: Option<&str>) -> BoardFootprint {
        BoardFootprint {
            kiid: format!("{reference}-kiid"),
            reference: reference.to_string(),
            value: "10k".to_string(),
            footprint_id: "Resistor_SMD:R_0603_1608Metric".to_string(),
            symbol_path: symbol_path.map(str::to_string),
            fields: BTreeMap::new(),
            pad_nets: BTreeMap::from([
                ("1".to_string(), "VCC".to_string()),
                ("2".to_string(), "GND".to_string()),
            ]),
            pad_numbers: BTreeSet::from(["1".to_string(), "2".to_string()]),
            position: Point { x: 1.0, y: 2.0 },
            rotation: 0.0,
            layer: "F.Cu".to_string(),
            locked: false,
            dnp: false,
            not_in_schematic: false,
        }
    }

    fn board_with(footprints: Vec<BoardFootprint>) -> BoardState {
        BoardState {
            footprints,
            routed_nets: BTreeMap::new(),
            bounds: Bounds {
                min_x: 0.0,
                min_y: 0.0,
                max_x: 10.0,
                max_y: 10.0,
            },
        }
    }

    #[test]
    fn planner_matches_identity_preserves_pose_and_stages_new_parts_deterministically() {
        let design = ExportedDesign {
            components: vec![
                resistor("R2", "/sheet/existing"),
                resistor("R3", "/sheet/new"),
            ],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };
        let board = BoardState {
            footprints: vec![
                BoardFootprint {
                    kiid: "existing-kiid".to_string(),
                    reference: "R1".to_string(),
                    value: "1k".to_string(),
                    footprint_id: "Resistor_SMD:R_0603_1608Metric".to_string(),
                    symbol_path: Some("/sheet/existing".to_string()),
                    fields: BTreeMap::new(),
                    pad_nets: BTreeMap::from([
                        ("1".to_string(), "VCC".to_string()),
                        ("2".to_string(), "GND".to_string()),
                    ]),
                    pad_numbers: BTreeSet::from(["1".to_string(), "2".to_string()]),
                    position: Point { x: 25.0, y: 30.0 },
                    rotation: 90.0,
                    layer: "B.Cu".to_string(),
                    locked: true,
                    dnp: false,
                    not_in_schematic: false,
                },
                BoardFootprint {
                    kiid: "board-only".to_string(),
                    reference: "MH1".to_string(),
                    value: "MountingHole".to_string(),
                    footprint_id: "MountingHole:MountingHole_3.2mm_M3".to_string(),
                    symbol_path: None,
                    fields: BTreeMap::new(),
                    pad_nets: BTreeMap::new(),
                    pad_numbers: BTreeSet::new(),
                    position: Point { x: 2.0, y: 2.0 },
                    rotation: 0.0,
                    layer: "F.Cu".to_string(),
                    locked: true,
                    dnp: false,
                    not_in_schematic: true,
                },
            ],
            routed_nets: BTreeMap::new(),
            bounds: Bounds {
                min_x: 0.0,
                min_y: 0.0,
                max_x: 50.0,
                max_y: 40.0,
            },
        };

        let first = plan_sync("netlist bytes", &design, &board);
        let second = plan_sync("netlist bytes", &design, &board);

        assert_eq!(first.status, PlanStatus::Ready);
        assert_eq!(first.plan_revision, second.plan_revision);
        assert_eq!(first.counts.added.planned, 1);
        assert_eq!(first.counts.updated.planned, 1);
        assert_eq!(first.counts.board_only_preserved.planned, 1);
        assert_eq!(first.changes, second.changes);
        assert!(first.changes.iter().any(|change| matches!(
            change,
            PlannedChange::Update { kiid, reference, preserve, .. }
                if kiid == "existing-kiid"
                    && reference == "R2"
                    && preserve.position == Point { x: 25.0, y: 30.0 }
                    && preserve.rotation == 90.0
                    && preserve.layer == "B.Cu"
                    && preserve.locked
        )));
        assert!(first.changes.iter().any(|change| matches!(
            change,
            PlannedChange::Add { reference, position, .. }
                if reference == "R3" && position.x > board.bounds.max_x
        )));
    }

    /// Build a footprint carrying one pad and one child of every graphic kind,
    /// the way a real library footprint arrives from KiCad. The existing sync
    /// test passes `&[]` for graphics, which is precisely why #244 survived it.
    fn footprint_with_artwork(reference: &str) -> prost_types::Any {
        use konnect_ipc::gen::kiapi;
        use prost::Message;
        let silk = || "F.SilkS".to_string();
        let item = konnect_ipc::KiCadIpcClient::build_footprint_item(
            "Package_SO:SOIC-8_3.9x4.9mm_P1.27mm",
            reference,
            "NE555",
            &[konnect_ipc::IpcPadDefinition {
                number: "1".to_string(),
                pad_type: "smd".to_string(),
                shape: "rect".to_string(),
                x: 0.0,
                y: 0.0,
                rotation: 0.0,
                size_x: 1.0,
                size_y: 1.0,
                drill_x: None,
                drill_y: None,
                drill_oval: false,
                layers: vec!["F.Cu".to_string()],
                roundrect_ratio: 0.0,
            }],
            &[
                konnect_ipc::IpcGraphicDefinition::Line {
                    start: (-2.0, -2.5),
                    end: (2.0, -2.5),
                    layer: silk(),
                    width: 0.12,
                },
                konnect_ipc::IpcGraphicDefinition::Rect {
                    start: (-2.6, -3.0),
                    end: (2.6, 3.0),
                    layer: "F.CrtYd".to_string(),
                    width: 0.05,
                    filled: false,
                },
                konnect_ipc::IpcGraphicDefinition::Circle {
                    center: (-1.8, -1.8),
                    end: (-1.6, -1.8),
                    layer: silk(),
                    width: 0.12,
                    filled: true,
                },
                konnect_ipc::IpcGraphicDefinition::Arc {
                    start: (-1.0, -2.5),
                    mid: (0.0, -2.0),
                    end: (1.0, -2.5),
                    layer: "F.Fab".to_string(),
                    width: 0.1,
                },
                konnect_ipc::IpcGraphicDefinition::Poly {
                    points: vec![(-1.0, 2.0), (1.0, 2.0), (0.0, 2.8)],
                    layer: "F.Fab".to_string(),
                    width: 0.1,
                    filled: true,
                },
                konnect_ipc::IpcGraphicDefinition::Text {
                    text: "U1".to_string(),
                    position: (0.0, -3.5),
                    rotation: 0.0,
                    layer: silk(),
                    size: 1.0,
                    stroke_width_mm: 0.15,
                },
            ],
            &konnect_ipc::IpcFieldPlacement::default(),
            25.0,
            30.0,
            0.0,
            "F.Cu",
        )
        .unwrap();
        // Give it the KIID the update path matches against.
        let mut footprint =
            kiapi::board::types::FootprintInstance::decode(item.value.as_slice()).unwrap();
        footprint.id = Some(kiapi::common::types::Kiid {
            value: format!("{}-kiid", reference.to_lowercase()),
        });
        konnect_ipc::builders::pack_any(&footprint, "kiapi.board.types.FootprintInstance")
    }

    /// Tally a footprint definition's children by the protobuf type they
    /// declare — the property #244 destroyed.
    fn child_types(item: &prost_types::Any) -> BTreeMap<String, usize> {
        use konnect_ipc::gen::kiapi;
        use prost::Message;
        let footprint =
            kiapi::board::types::FootprintInstance::decode(item.value.as_slice()).unwrap();
        let mut counts = BTreeMap::new();
        for child in &footprint.definition.as_ref().unwrap().items {
            *counts
                .entry(konnect_ipc::builders::any_type_name(child).to_string())
                .or_insert(0) += 1;
        }
        counts
    }

    /// #244. A footprint's pads, graphics and text all live in one repeated
    /// `Any` field, and proto3 skips field numbers it does not recognise rather
    /// than failing — so a `BoardGraphicShape` decodes cleanly as a near-empty
    /// `Pad`. Filtering that list with `Pad::decode(..).ok()` therefore matched
    /// every graphic, and packing the decoded value back re-typed it. In
    /// neusse's benchmark an 8-pad SOIC-8 came out of a sync with 28 pads —
    /// the 20 extras nameless, at (0,0), one per lost graphic — and no artwork.
    #[test]
    fn syncing_a_footprint_leaves_its_graphics_as_graphics() {
        use konnect_ipc::gen::kiapi;
        use prost::Message;
        let item = footprint_with_artwork("U1");
        let before = child_types(&item);

        // Sanity: the fixture must actually carry the mixture, or this test
        // proves nothing — which is the trap the pre-existing sync test fell
        // into by passing `&[]` graphics.
        assert_eq!(before.get("kiapi.board.types.Pad"), Some(&1));
        assert_eq!(before.get("kiapi.board.types.BoardGraphicShape"), Some(&5));
        assert_eq!(before.get("kiapi.board.types.BoardText"), Some(&1));

        let change = PlannedChange::Update {
            kiid: "u1-kiid".to_string(),
            reference: "U1".to_string(),
            value: "NE555".to_string(),
            symbol_path: "/root/u1".to_string(),
            dnp: false,
            fields: BTreeMap::new(),
            pad_nets: BTreeMap::from([("1".to_string(), "GND".to_string())]),
            preserve: PreservedBoardState {
                position: Point { x: 25.0, y: 30.0 },
                rotation: 0.0,
                layer: "F.Cu".to_string(),
                locked: false,
            },
        };
        let updated =
            update_footprint_item(&item, &change, &BTreeMap::from([("GND".to_string(), 1)]))
                .unwrap();

        assert_eq!(
            child_types(&updated),
            before,
            "sync re-typed footprint children; graphics must survive as graphics"
        );

        // And the pad still got the net it was there to get.
        let footprint =
            kiapi::board::types::FootprintInstance::decode(updated.value.as_slice()).unwrap();
        let pad = footprint
            .definition
            .as_ref()
            .unwrap()
            .items
            .iter()
            .filter(|child| konnect_ipc::builders::any_is(child, "kiapi.board.types.Pad"))
            .map(|child| kiapi::board::types::Pad::decode(child.value.as_slice()).unwrap())
            .next()
            .expect("the pad survived");
        assert_eq!(pad.net.as_ref().unwrap().name, "GND");
    }

    /// The add path calls `apply_footprint_fields` too (`build_mutation_items`),
    /// so a brand-new footprint was corrupted before it ever reached KiCad.
    #[test]
    fn a_newly_added_footprint_keeps_its_graphics_too() {
        use konnect_ipc::gen::kiapi;
        use prost::Message;
        let item = footprint_with_artwork("U2");
        let before = child_types(&item);
        let mut footprint =
            kiapi::board::types::FootprintInstance::decode(item.value.as_slice()).unwrap();

        apply_footprint_fields(
            &mut footprint,
            "U2",
            "NE555",
            "/root/u2",
            false,
            &BTreeMap::new(),
            &BTreeMap::from([("1".to_string(), "VCC".to_string())]),
            &BTreeMap::from([("VCC".to_string(), 3)]),
        )
        .unwrap();

        let repacked =
            konnect_ipc::builders::pack_any(&footprint, "kiapi.board.types.FootprintInstance");
        assert_eq!(child_types(&repacked), before);
    }

    /// The invariant that would have caught #244 on its own.
    ///
    /// `create_items`/`update_items` only confirm KiCad *accepted* each item,
    /// and the reported counts are copied from the plan — so the corruption
    /// travelled all the way to a success message. Here the exact damage is
    /// reproduced (every drawing re-typed as a pad, which is what the old
    /// `Pad::decode` filter did) and the shape comparison is shown to see it.
    #[test]
    fn the_post_apply_check_sees_drawings_turned_into_pads() {
        use konnect_ipc::gen::kiapi;
        use prost::Message;

        let sent = footprint_with_artwork("U4");
        let expected = footprint_shapes(std::iter::once(&sent));
        assert_eq!(
            expected["U4"],
            FootprintShape {
                pads: 1,
                drawings: 6
            }
        );

        // Exactly #244: decode every child as a Pad and pack it back as one.
        let mut corrupted =
            kiapi::board::types::FootprintInstance::decode(sent.value.as_slice()).unwrap();
        for child in &mut corrupted.definition.as_mut().unwrap().items {
            if let Ok(pad) = kiapi::board::types::Pad::decode(child.value.as_slice()) {
                *child = konnect_ipc::builders::pack_any(&pad, "kiapi.board.types.Pad");
            }
        }
        let corrupted =
            konnect_ipc::builders::pack_any(&corrupted, "kiapi.board.types.FootprintInstance");
        let actual = footprint_shapes(std::iter::once(&corrupted));

        // The reported symptom, reproduced: the five graphic shapes each become
        // a pad. The text survives — `BoardText`'s bytes genuinely fail to
        // decode as a `Pad`, while `BoardGraphicShape`'s do not — which is why
        // #239 reported footprints losing their *graphics* while their
        // reference and value text stayed put.
        assert_eq!(
            actual["U4"],
            FootprintShape {
                pads: 6,
                drawings: 1
            }
        );
        assert_ne!(actual["U4"], expected["U4"]);
    }

    /// A child that declares itself a pad and will not decode is a real
    /// failure, and has to be reported as *that*.
    ///
    /// Skipping it silently does still end in an error — the "footprint has no
    /// pad N" check downstream fires, because the pad never made it into
    /// `seen_pads` — but that error sends the reader looking for a missing pad
    /// that is in fact present and unreadable. So this asserts the specific
    /// message, not merely that something failed: a neuter that restored the
    /// silent skip passed an assertion that only checked for the reference.
    #[test]
    fn an_undecodable_pad_is_reported_not_skipped() {
        use konnect_ipc::gen::kiapi;
        use prost::Message;
        let item = footprint_with_artwork("U3");
        let mut footprint =
            kiapi::board::types::FootprintInstance::decode(item.value.as_slice()).unwrap();
        for child in &mut footprint.definition.as_mut().unwrap().items {
            if konnect_ipc::builders::any_is(child, "kiapi.board.types.Pad") {
                // Wire type 7 does not exist; nothing can decode this.
                child.value = vec![0xff, 0xff, 0xff];
            }
        }

        let error = apply_footprint_fields(
            &mut footprint,
            "U3",
            "NE555",
            "/root/u3",
            false,
            &BTreeMap::new(),
            &BTreeMap::from([("1".to_string(), "VCC".to_string())]),
            &BTreeMap::new(),
        )
        .expect_err("an unreadable pad must not pass silently");
        let text = format!("{error:#}");
        assert!(
            text.contains("U3") && text.contains("cannot read"),
            "must say the pad is unreadable, not that it is missing: {text}"
        );
    }

    #[test]
    fn update_item_changes_only_schematic_owned_fields() {
        use konnect_ipc::gen::kiapi;
        use prost::Message;

        let item = konnect_ipc::KiCadIpcClient::build_footprint_item(
            "Resistor_SMD:R_0603_1608Metric",
            "R1",
            "1k",
            &[konnect_ipc::IpcPadDefinition {
                number: "1".to_string(),
                pad_type: "smd".to_string(),
                shape: "rect".to_string(),
                x: 0.0,
                y: 0.0,
                rotation: 0.0,
                size_x: 1.0,
                size_y: 1.0,
                drill_x: None,
                drill_y: None,
                drill_oval: false,
                layers: vec!["F.Cu".to_string()],
                roundrect_ratio: 0.0,
            }],
            &[],
            &konnect_ipc::IpcFieldPlacement::default(),
            25.0,
            30.0,
            90.0,
            "F.Cu",
        )
        .unwrap();
        let mut footprint =
            kiapi::board::types::FootprintInstance::decode(item.value.as_slice()).unwrap();
        footprint.id = Some(kiapi::common::types::Kiid {
            value: "keep-kiid".to_string(),
        });
        footprint.locked = kiapi::common::types::LockedState::LsLocked as i32;
        let item =
            konnect_ipc::builders::pack_any(&footprint, "kiapi.board.types.FootprintInstance");
        let change = PlannedChange::Update {
            kiid: "keep-kiid".to_string(),
            reference: "R2".to_string(),
            value: "10k".to_string(),
            symbol_path: "/root/symbol".to_string(),
            dnp: true,
            fields: BTreeMap::new(),
            pad_nets: BTreeMap::from([("1".to_string(), "VCC".to_string())]),
            preserve: PreservedBoardState {
                position: Point { x: 25.0, y: 30.0 },
                rotation: 90.0,
                layer: "F.Cu".to_string(),
                locked: true,
            },
        };

        let updated =
            update_footprint_item(&item, &change, &BTreeMap::from([("VCC".to_string(), 7)]))
                .unwrap();
        let updated =
            kiapi::board::types::FootprintInstance::decode(updated.value.as_slice()).unwrap();

        assert_eq!(updated.id.as_ref().unwrap().value, "keep-kiid");
        assert_eq!(updated.position, footprint.position);
        assert_eq!(updated.orientation, footprint.orientation);
        assert_eq!(updated.layer, footprint.layer);
        assert_eq!(updated.locked, footprint.locked);
        assert!(updated.attributes.as_ref().unwrap().do_not_populate);
        let pad = updated
            .definition
            .as_ref()
            .unwrap()
            .items
            .iter()
            .find_map(|item| kiapi::board::types::Pad::decode(item.value.as_slice()).ok())
            .unwrap();
        assert_eq!(pad.net.as_ref().unwrap().name, "VCC");
        assert_eq!(pad.net.as_ref().unwrap().code.as_ref().unwrap().value, 7);
    }

    #[test]
    fn removing_a_pad_from_a_routed_net_conflicts_the_whole_plan() {
        let design = ExportedDesign {
            components: vec![DesignComponent {
                pad_nets: BTreeMap::new(),
                ..resistor("R1", "/sheet/existing")
            }],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };
        let board = BoardState {
            footprints: vec![BoardFootprint {
                kiid: "existing-kiid".to_string(),
                reference: "R1".to_string(),
                value: "10k".to_string(),
                footprint_id: "Resistor_SMD:R_0603_1608Metric".to_string(),
                symbol_path: Some("/sheet/existing".to_string()),
                fields: BTreeMap::new(),
                pad_nets: BTreeMap::from([("1".to_string(), "VCC".to_string())]),
                pad_numbers: BTreeSet::from(["1".to_string(), "2".to_string()]),
                position: Point { x: 1.0, y: 2.0 },
                rotation: 0.0,
                layer: "F.Cu".to_string(),
                locked: false,
                dnp: false,
                not_in_schematic: false,
            }],
            routed_nets: BTreeMap::from([("VCC".to_string(), 1)]),
            bounds: Bounds {
                min_x: 0.0,
                min_y: 0.0,
                max_x: 10.0,
                max_y: 10.0,
            },
        };

        let plan = plan_sync("netlist", &design, &board);

        assert_eq!(plan.status, PlanStatus::Conflict);
        assert!(plan.changes.is_empty());
        assert!(plan
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "routed_pad_net_change"));
    }

    #[test]
    fn already_synchronized_design_is_noop() {
        let design = ExportedDesign {
            components: vec![resistor("R1", "/sheet/existing")],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };
        let plan = plan_sync(
            "netlist",
            &design,
            &board_with(vec![board_resistor("R1", Some("/sheet/existing"))]),
        );

        assert_eq!(plan.status, PlanStatus::Noop);
        assert!(plan.changes.is_empty());
        assert_eq!(plan.counts.conflicts.planned, 0);
    }

    #[test]
    fn footprint_swap_conflicts_but_an_unrouted_net_change_is_planned() {
        let design = ExportedDesign {
            components: vec![resistor("R1", "/sheet/existing")],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };
        let mut footprint = board_resistor("R1", Some("/sheet/existing"));
        footprint.footprint_id = "Resistor_SMD:R_0805_2012Metric".to_string();
        let swap = plan_sync("netlist", &design, &board_with(vec![footprint]));
        assert_eq!(swap.status, PlanStatus::Conflict);
        assert!(swap
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "footprint_id_changed"));

        let mut footprint = board_resistor("R1", Some("/sheet/existing"));
        footprint
            .pad_nets
            .insert("1".to_string(), "OLD_VCC".to_string());
        let net_change = plan_sync("netlist", &design, &board_with(vec![footprint]));
        assert_eq!(net_change.status, PlanStatus::Ready);
        assert_eq!(net_change.counts.pads_reassigned.planned, 1);
    }

    #[test]
    fn on_board_no_skips_absent_but_conflicts_when_present() {
        let design = ExportedDesign {
            components: Vec::new(),
            skipped: vec![SkippedComponent {
                reference: "R1".to_string(),
                symbol_path: "/sheet/existing".to_string(),
            }],
            unassigned: Vec::new(),
        };
        let absent = plan_sync("netlist", &design, &board_with(Vec::new()));
        assert_eq!(absent.status, PlanStatus::Noop);
        assert_eq!(absent.counts.skipped_by_flag.planned, 1);

        let present = plan_sync(
            "netlist",
            &design,
            &board_with(vec![board_resistor("R1", Some("/sheet/existing"))]),
        );
        assert_eq!(present.status, PlanStatus::Conflict);
        assert!(present
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "on_board_exclusion_conflict"));
    }

    #[test]
    fn reference_only_possible_rename_is_a_conflict() {
        let design = ExportedDesign {
            components: vec![resistor("R2", "/sheet/existing")],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };
        let plan = plan_sync(
            "netlist",
            &design,
            &board_with(vec![board_resistor("R1", None)]),
        );

        assert_eq!(plan.status, PlanStatus::Conflict);
        assert!(plan
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "reference_only_rename_ambiguous"));
    }

    #[test]
    fn empty_and_duplicate_component_exports_are_rejected() {
        let empty = parse_exported_netlist("(export (components) (nets))")
            .unwrap_err()
            .to_string();
        assert!(empty.contains("zero components"), "{empty}");

        let duplicate = r#"
(export
  (components
    (comp (ref "R1") (value "1k") (footprint "Resistor_SMD:R_0603_1608Metric")
      (sheetpath (tstamps "/one/")) (tstamps "one"))
    (comp (ref "R1") (value "2k") (footprint "Resistor_SMD:R_0603_1608Metric")
      (sheetpath (tstamps "/two/")) (tstamps "two")))
  (nets))
"#;
        let duplicate = parse_exported_netlist(duplicate).unwrap_err().to_string();
        assert!(
            duplicate.contains("duplicate component reference R1"),
            "{duplicate}"
        );
    }

    #[test]
    fn plan_revision_changes_when_reviewed_board_bounds_change() {
        let design = ExportedDesign {
            components: vec![resistor("R1", "/sheet/new")],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };
        let first = plan_sync("netlist", &design, &board_with(Vec::new()));
        let mut changed_board = board_with(Vec::new());
        changed_board.bounds.max_x = 11.0;
        let second = plan_sync("netlist", &design, &changed_board);

        assert_ne!(first.plan_revision, second.plan_revision);
    }

    /// A plan revision must survive the clock. `kicad-cli` stamps the export
    /// time and its own version into every netlist, so hashing the raw source
    /// changed the revision every second — and apply, which requires the
    /// revision a dry run returned, could then only succeed if both calls
    /// landed inside the same wall-clock second.
    #[test]
    fn plan_revision_ignores_the_export_timestamp_and_tool_version() {
        let netlist = |date: &str, tool: &str| {
            format!(
                "(export (version \"E\")
  (design
    (source \"/tmp/x.kicad_sch\")
    (date \"{date}\")
    (tool \"{tool}\")
  )
  (components
    (comp (ref \"R1\")
      (value \"10k\")
      (footprint \"Resistor_SMD:R_0805\")
      (tstamps \"/aaa\")))
  (nets
    (net (code \"1\") (name \"GND\")
      (node (ref \"R1\") (pin \"1\")))))
"
            )
        };
        let board = BoardState {
            footprints: Vec::new(),
            routed_nets: BTreeMap::new(),
            bounds: Bounds {
                min_x: 0.0,
                min_y: 0.0,
                max_x: 0.0,
                max_y: 0.0,
            },
        };
        let a = plan_revision(
            &netlist("2026-08-15T14:48:16", "kicad-cli (10.0.5)"),
            &board,
        );
        let b = plan_revision(
            &netlist("2026-08-15T14:48:18", "kicad-cli (10.0.5)"),
            &board,
        );
        assert_eq!(a, b, "two seconds apart is not a design change");

        let c = plan_revision(
            &netlist("2026-08-15T14:48:16", "kicad-cli (10.1.0)"),
            &board,
        );
        assert_eq!(a, c, "a KiCad upgrade is not a design change");

        // A real change still moves it, or the guard is worthless.
        let changed = netlist("2026-08-15T14:48:16", "kicad-cli (10.0.5)")
            .replace("Resistor_SMD:R_0805", "Resistor_SMD:R_0603");
        assert_ne!(
            a,
            plan_revision(&changed, &board),
            "a footprint swap must move the revision"
        );
    }

    #[test]
    fn plan_revision_keeps_nested_and_quoted_design_content() {
        let netlist = |nested_date: &str, value: &str| {
            format!(
                r#"(export
  (design (date "2026-08-15T14:48:16") (tool "kicad-cli (10.0.5)"))
  (components
    (comp (ref "R1")
      (value "{value}")
      (footprint "Resistor_SMD:R_0805")
      (date "{nested_date}")
      (tstamps "/aaa")))
  (nets
    (net (code "1") (name "GND")
      (node (ref "R1") (pin "1")))))"#
            )
        };
        let board = board_with(Vec::new());
        let baseline = plan_revision(&netlist("2025-01-01", "literal (tool alpha)"), &board);

        assert_ne!(
            baseline,
            plan_revision(&netlist("2025-01-02", "literal (tool alpha)"), &board),
            "a nested date node is component content, not export metadata"
        );
        assert_ne!(
            baseline,
            plan_revision(&netlist("2025-01-01", "literal (tool beta)"), &board),
            "tool-like text inside a quoted value is design content"
        );
    }

    /// A real `FootprintInstance`, exactly as KiCad 10.0.6's IPC layer sent it
    /// for a mounting hole with no schematic symbol behind it.
    ///
    /// Captured from a running editor rather than hand-built, because a
    /// hand-built one encodes whatever the author assumed. This one already
    /// corrected two such assumptions: KiCad reports `symbol_path` as
    /// **present and empty** (not absent, and `path_human_readable` is `""`,
    /// not `"/"`), and it leaves `not_in_schematic` **false** on a board-only
    /// mounting hole — marking it `exclude_from_position_files` and
    /// `exclude_from_bill_of_materials` instead. The first hand-written
    /// fixture set that flag true, which made the rename branch below
    /// unreachable from its own tests.
    ///
    /// Regenerate with `KONNECT_CAPTURE_IPC_FIXTURE=1` on the ignored live
    /// test `kicad_reports_an_empty_sheet_path_for_a_board_only_footprint`;
    /// provenance is in the fixture's README.
    const BOARD_ONLY_CAPTURE: &[u8] =
        include_bytes!("../../tests/fixtures/board_only_footprint.ipc.bin");

    /// The captured footprint, with only its identity fields varied.
    ///
    /// A board carries several board-only graphics, and the planner keys on
    /// reference and KIID, so tests need more than one. Everything else — the
    /// empty `SheetPath`, the attributes, the pads and graphics — is the real
    /// message.
    fn board_only_instance(
        kiid: &str,
        reference: &str,
    ) -> konnect_ipc::gen::kiapi::board::types::FootprintInstance {
        use konnect_ipc::gen::kiapi;

        let mut instance = kiapi::board::types::FootprintInstance::decode(BOARD_ONLY_CAPTURE)
            .expect("the checked-in KiCad IPC capture must decode");
        instance.id = Some(kiapi::common::types::Kiid {
            value: kiid.to_string(),
        });
        set_field_text(&mut instance.reference_field, "Reference", reference);
        instance
    }

    /// A real `FootprintInstance` for a board-only footprint KiCad left
    /// carrying the library's own default reference, `REF**`.
    ///
    /// The capture above is a mounting hole someone had annotated `MH1`, so it
    /// cannot witness the case #452 actually reported: unannotated graphics,
    /// every one of them called `REF**`, colliding with each other. This one
    /// comes from `konnect-ipc/tests/fixtures/board_only_shared_reference.kicad_pcb`,
    /// a board KiCad wrote holding two such footprints — and `REF**` is the
    /// library's own string, not one an editing session left behind.
    ///
    /// Regenerate with `KONNECT_CAPTURE_IPC_FIXTURE=1` on the ignored live
    /// test `kicad_reports_the_same_reference_for_two_board_only_footprints`;
    /// provenance is in the fixture's README.
    const SHARED_REFERENCE_CAPTURE: &[u8] =
        include_bytes!("../../tests/fixtures/board_only_shared_reference.ipc.bin");

    /// One of that board's two `REF**` footprints, with only its KIID varied.
    ///
    /// The reference is deliberately *not* varied — it is the shared value the
    /// tests are about, and it is what KiCad really sent. That the board
    /// carries two of them is checked without KiCad by
    /// `the_shared_reference_fixture_still_carries_a_duplicate_board_only_reference`,
    /// so the second instance is a KIID away from the first rather than an
    /// assumption.
    fn ref_star_instance(kiid: &str) -> konnect_ipc::gen::kiapi::board::types::FootprintInstance {
        use konnect_ipc::gen::kiapi;

        let mut instance = kiapi::board::types::FootprintInstance::decode(SHARED_REFERENCE_CAPTURE)
            .expect("the checked-in KiCad IPC capture must decode");
        instance.id = Some(kiapi::common::types::Kiid {
            value: kiid.to_string(),
        });
        instance
    }

    /// The same real message, re-labelled as the resistor `resistor()` exports.
    ///
    /// Only the library id and value change: these tests are about the planner
    /// branches an absent identity unlocks, and they need a footprint whose
    /// `footprint_id` and `value` can match a schematic component. The
    /// `not_in_schematic` flag is left exactly as KiCad set it — false — which
    /// is what makes the rename branch reachable at all.
    fn unlinked_instance(
        kiid: &str,
        reference: &str,
    ) -> konnect_ipc::gen::kiapi::board::types::FootprintInstance {
        use konnect_ipc::gen::kiapi;

        let mut instance = board_only_instance(kiid, reference);
        if let Some(definition) = instance.definition.as_mut() {
            definition.id = Some(kiapi::common::types::LibraryIdentifier {
                library_nickname: "Resistor_SMD".to_string(),
                entry_name: "R_0603_1608Metric".to_string(),
            });
        }
        set_field_text(&mut instance.value_field, "Value", "10k");
        instance
    }

    #[test]
    fn issue_452_board_only_footprint_reads_as_no_identity_not_a_shared_one() {
        let logo = board_footprint_from_instance(&board_only_instance("logo-kiid", "LOGO1"))
            .expect("a board-only footprint is a valid footprint");

        assert_eq!(
            logo.symbol_path, None,
            "an empty SheetPath means no schematic symbol, not the identity `/`"
        );
        assert_eq!(logo.reference, "LOGO1");
        assert_eq!(logo.kiid, "logo-kiid");
        // KiCad does *not* set `not_in_schematic` on a board-only footprint —
        // it marks it excluded from position files and the BOM instead. The
        // first version of this test asserted the opposite and passed, because
        // the hand-built fixture it ran against said so. That flag is the
        // precondition for the rename branch two tests below, so getting it
        // wrong made that branch unreachable from the tests written to cover
        // this change.
        assert!(
            !logo.not_in_schematic,
            "real KiCad leaves not_in_schematic false on a board-only footprint"
        );
    }

    #[test]
    fn issue_452_two_board_only_footprints_do_not_collide_on_identity() {
        // The whole board as KiCad reports it: one schematic-backed resistor
        // and two pathless graphics. Before the fix both graphics arrived
        // carrying `/`, and the planner refused to sync the resistor.
        let board = board_with(vec![
            board_resistor("R1", Some("/sheet/existing")),
            board_footprint_from_instance(&board_only_instance("logo-kiid", "LOGO1")).unwrap(),
            board_footprint_from_instance(&board_only_instance("fiducial-kiid", "FID1")).unwrap(),
        ]);
        let design = ExportedDesign {
            components: vec![resistor("R1", "/sheet/existing")],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };

        let plan = plan_sync("netlist", &design, &board);

        assert_eq!(
            plan.diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "duplicate_board_identity")
                .count(),
            0,
            "footprints with no schematic identity are not duplicates of each other"
        );
        assert_eq!(plan.status, PlanStatus::Noop);
        assert_eq!(plan.counts.conflicts.planned, 0);
        assert_eq!(plan.counts.board_only_preserved.planned, 2);
    }

    #[test]
    fn a_schematic_backed_footprint_still_reads_its_identity() {
        use konnect_ipc::gen::kiapi;

        let mut instance = board_only_instance("r1-kiid", "R1");
        instance.symbol_path = Some(kiapi::common::types::SheetPath {
            path: vec![
                kiapi::common::types::Kiid {
                    value: "sheet-uuid".to_string(),
                },
                kiapi::common::types::Kiid {
                    value: "symbol-uuid".to_string(),
                },
            ],
            path_human_readable: "/Power/".to_string(),
        });

        let footprint = board_footprint_from_instance(&instance).unwrap();

        assert_eq!(
            footprint.symbol_path.as_deref(),
            Some("/sheet-uuid/symbol-uuid"),
            "the guard must not swallow a real schematic identity"
        );
    }
    // The two branches below test `symbol_path.is_none()`, so before #452 they
    // were unreachable for a board-only footprint: every one of them wore the
    // synthetic identity `/`. Reading absence correctly wakes both, which
    // changes plans on boards that never hit the duplicate-identity bug at all.
    // They are pinned here so the consequence is a decision rather than a
    // discovery. Note `board_resistor` leaves `not_in_schematic` false — a
    // footprint KiCad has not flagged — which is what makes them reachable.

    #[test]
    fn issue_452_an_unlinked_footprint_the_schematic_names_is_adopted_not_refused() {
        let design = ExportedDesign {
            components: vec![resistor("R1", "/sheet/existing")],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };

        let mut footprint =
            board_footprint_from_instance(&unlinked_instance("R1-kiid", "R1")).unwrap();
        footprint.pad_nets = BTreeMap::from([
            ("1".to_string(), "VCC".to_string()),
            ("2".to_string(), "GND".to_string()),
        ]);
        // The capture is a mounting hole dressed as the schematic's resistor,
        // so it is given the resistor's pads along with their nets.
        footprint.pad_numbers = BTreeSet::from(["1".to_string(), "2".to_string()]);
        let plan = plan_sync("netlist", &design, &board_with(vec![footprint]));

        // Was `reference_identity_conflict`: the board footprint appeared to
        // hold the identity `/`, so the schematic's R1 looked like a different
        // symbol wearing the same reference.
        assert_eq!(plan.status, PlanStatus::Ready);
        assert_eq!(plan.counts.updated.planned, 1);
        assert_eq!(plan.counts.board_only_preserved.planned, 0);
        let PlannedChange::Update {
            kiid, symbol_path, ..
        } = &plan.changes[0]
        else {
            panic!("adoption is an update, not an add: {:?}", plan.changes[0]);
        };
        assert_eq!(kiid, "R1-kiid");
        assert_eq!(
            symbol_path, "/sheet/existing",
            "adoption writes the schematic identity onto a footprint the \
             planner previously refused to touch"
        );
    }

    #[test]
    fn issue_452_an_unlinked_lookalike_blocks_a_new_component_instead_of_duplicating_it() {
        // The board carries a footprint with no schematic identity whose
        // library id and value match a component the schematic has just gained.
        let design = ExportedDesign {
            components: vec![resistor("R5", "/sheet/new")],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };

        let plan = plan_sync(
            "netlist",
            &design,
            &board_with(vec![board_footprint_from_instance(&unlinked_instance(
                "R1-kiid", "R1",
            ))
            .unwrap()]),
        );

        // This plan was `Ready` before #452, and it added a second identical
        // footprint beside the unlinked one. It is now the conflict the
        // `possible_renames` scan was written to raise. Better, but it is a
        // fix that can newly block a sync, and that belongs in the notes.
        assert_eq!(plan.status, PlanStatus::Conflict);
        assert_eq!(plan.counts.added.planned, 0);
        assert!(plan
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "reference_only_rename_ambiguous"));
    }
    #[test]
    fn issue_452_repeated_ref_star_graphics_are_not_a_duplicate_the_schematic_can_see() {
        // The reported board: a synchronized resistor plus two unannotated
        // graphics, both called `REF**` because that is what the library calls
        // them. Nothing in the schematic is named `REF**`, so no adoption ever
        // looks that reference up and there is nothing to disambiguate.
        let board = board_with(vec![
            board_resistor("R1", Some("/sheet/existing")),
            board_footprint_from_instance(&ref_star_instance("first-kiid")).unwrap(),
            board_footprint_from_instance(&ref_star_instance("second-kiid")).unwrap(),
        ]);
        let design = ExportedDesign {
            components: vec![resistor("R1", "/sheet/existing")],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };

        let plan = plan_sync("netlist", &design, &board);

        assert_eq!(
            plan.diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "duplicate_board_reference")
                .count(),
            0,
            "a reference the schematic never names has no adoption to make ambiguous"
        );
        assert_eq!(plan.status, PlanStatus::Noop);
        assert_eq!(plan.counts.conflicts.planned, 0);
        assert_eq!(
            plan.counts.board_only_preserved.planned, 2,
            "both graphics are preserved, not merely un-diagnosed"
        );
        assert!(plan.changes.is_empty());
    }

    #[test]
    fn issue_452_repeated_ref_star_graphics_no_longer_block_an_unrelated_update() {
        // The same board, with the resistor out of date. Before this change the
        // duplicate `REF**` diagnostic conflicted the whole plan, so the update
        // the user asked for could not be applied while those graphics existed
        // — which is the symptom #452 was filed about.
        let mut stale = board_resistor("R1", Some("/sheet/existing"));
        stale.value = "4k7".to_string();
        let board = board_with(vec![
            stale,
            board_footprint_from_instance(&ref_star_instance("first-kiid")).unwrap(),
            board_footprint_from_instance(&ref_star_instance("second-kiid")).unwrap(),
        ]);
        let design = ExportedDesign {
            components: vec![resistor("R1", "/sheet/existing")],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };

        let plan = plan_sync("netlist", &design, &board);

        assert_eq!(plan.status, PlanStatus::Ready);
        assert_eq!(plan.counts.updated.planned, 1);
        assert_eq!(plan.counts.board_only_preserved.planned, 2);
        let Some(PlannedChange::Update { kiid, value, .. }) = plan.changes.first() else {
            panic!("expected one update, got {:?}", plan.changes);
        };
        assert_eq!(kiid, "R1-kiid");
        assert_eq!(value, "10k");
    }

    /// A **scope test**: it passes with the narrowing removed, and that is the
    /// point of it.
    ///
    /// The guard tests above fail when the `exported_references` clause is
    /// deleted. This one cannot — it asserts the diagnostic that the
    /// unconditional version also raises. It exists to prove the narrowing did
    /// not go too far, so its silence under neutering is the finding, and
    /// counting it as coverage of the change would be a lie.
    #[test]
    fn issue_452_a_duplicate_reference_the_schematic_does_use_is_still_a_conflict() {
        // Two pathless footprints called `R1`, and a schematic component called
        // `R1` with no board identity to match on. The reference-only adoption
        // path keys on exactly that name, so with two candidates it would pick
        // whichever one `board_by_reference` happened to keep and write the
        // schematic identity onto it. That is the ambiguity the diagnostic
        // exists for, and scoping the rule to the schematic's own reference set
        // — rather than exempting board-only footprints as a kind — is what
        // keeps it.
        let board = board_with(vec![
            board_footprint_from_instance(&unlinked_instance("first-kiid", "R1")).unwrap(),
            board_footprint_from_instance(&unlinked_instance("second-kiid", "R1")).unwrap(),
        ]);
        let design = ExportedDesign {
            components: vec![resistor("R1", "/sheet/existing")],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };

        let plan = plan_sync("netlist", &design, &board);

        assert_eq!(plan.status, PlanStatus::Conflict);
        assert!(plan
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "duplicate_board_reference"));
        assert!(
            plan.changes.is_empty(),
            "an ambiguous adoption target must not be written to: {:?}",
            plan.changes
        );
        assert_eq!(plan.counts.updated.planned, 0);
        assert_eq!(plan.counts.added.planned, 0);
    }

    /// The `on_board=no` side of the export, which is a consult site too.
    ///
    /// One of the four `board_by_reference` lookups reads `skipped.reference`,
    /// so the set has to span both halves of the export or an excluded
    /// instance loses its ambiguity check. This test guards the `.chain(...)`
    /// specifically: it survives deleting the whole narrowing — the
    /// unconditional diagnostic raises it too — and fails only when the
    /// skipped half is dropped from the set. Do not read it as coverage of the
    /// narrowing itself; the two `ref_star` tests above are that.
    #[test]
    fn issue_452_a_duplicate_reference_only_an_on_board_no_instance_uses_still_conflicts() {
        let board = board_with(vec![
            board_footprint_from_instance(&unlinked_instance("first-kiid", "R9")).unwrap(),
            board_footprint_from_instance(&unlinked_instance("second-kiid", "R9")).unwrap(),
        ]);
        let design = ExportedDesign {
            components: vec![resistor("R1", "/sheet/existing")],
            skipped: vec![SkippedComponent {
                reference: "R9".to_string(),
                symbol_path: "/sheet/excluded".to_string(),
            }],
            unassigned: Vec::new(),
        };

        let plan = plan_sync("netlist", &design, &board);

        assert_eq!(plan.status, PlanStatus::Conflict);
        assert!(plan
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "duplicate_board_reference"));
    }
    /// One of a duplicate pair *can* still be written to — when the schematic
    /// matched it by path, which the duplicate reference plays no part in.
    ///
    /// A footprint can carry a schematic identity and still wear `REF**` if it
    /// was never back-annotated, and then it collides with the board's loose
    /// graphics. The old diagnostic blocked the whole sync, so the identity
    /// match could not be applied while such a graphic existed; now the
    /// path-matched footprint is renamed and the other is preserved.
    ///
    /// This is the honest limit of "un-diagnosed footprints are left alone":
    /// they are never *selected by reference*, because the reference is not in
    /// the export. Selection by path is a different and unambiguous route.
    #[test]
    fn issue_452_a_path_matched_footprint_is_still_adopted_despite_a_duplicate_reference() {
        let mut pathed = board_footprint_from_instance(&ref_star_instance("pathed-kiid")).unwrap();
        pathed.symbol_path = Some("/sheet/existing".to_string());
        pathed.footprint_id = "Resistor_SMD:R_0603_1608Metric".to_string();
        pathed.value = "10k".to_string();
        // A captured graphic dressed as the schematic's resistor, so it is
        // given the resistor's pads as well as its identity.
        pathed.pad_numbers = BTreeSet::from(["1".to_string(), "2".to_string()]);
        let board = board_with(vec![
            pathed,
            board_footprint_from_instance(&ref_star_instance("loose-kiid")).unwrap(),
        ]);
        let design = ExportedDesign {
            components: vec![resistor("R1", "/sheet/existing")],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };

        let plan = plan_sync("netlist", &design, &board);

        assert_eq!(plan.status, PlanStatus::Ready);
        let Some(PlannedChange::Update {
            kiid, reference, ..
        }) = plan.changes.first()
        else {
            panic!("expected one update, got {:?}", plan.changes);
        };
        assert_eq!(
            kiid, "pathed-kiid",
            "the path match selected it, not the reference"
        );
        assert_eq!(reference, "R1");
        assert_eq!(
            plan.counts.board_only_preserved.planned, 1,
            "the footprint the schematic never named is preserved untouched"
        );
    }

    /// A complete #474 sync through the registered tool, not just the pure
    /// planner. The mock speaks KiCad's real protobuf protocol and retains the
    /// live board between requests, so the assertions below are an independent
    /// readback of what the apply actually left behind.
    #[tokio::test]
    async fn issue_474_apply_preserves_every_board_only_object() {
        use crate::router::ToolRouter;
        use crate::tools::cli::test_support::write_script;
        use crate::tools::{ServerConfig, ToolContext};
        use konnect_ipc::gen::kiapi;
        use prost::Message;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct MockBoard {
            footprints: Arc<Mutex<Vec<prost_types::Any>>>,
            zones: Arc<Mutex<Vec<prost_types::Any>>>,
        }

        fn ok_item_status() -> kiapi::common::commands::ItemStatus {
            kiapi::common::commands::ItemStatus {
                code: kiapi::common::commands::ItemStatusCode::IscOk as i32,
                error_message: String::new(),
            }
        }

        fn schematic_backed_resistor() -> prost_types::Any {
            const CAPTURE: &[u8] = include_bytes!("../../tests/fixtures/issue_474_r1.ipc.bin");
            let mut footprint = kiapi::board::types::FootprintInstance::decode(CAPTURE)
                .expect("the checked-in KiCad IPC capture must decode");
            footprint.symbol_path = Some(kiapi::common::types::SheetPath {
                path: vec![
                    kiapi::common::types::Kiid {
                        value: "sheet-uuid".to_string(),
                    },
                    kiapi::common::types::Kiid {
                        value: "symbol-uuid".to_string(),
                    },
                ],
                path_human_readable: "/Power/".to_string(),
            });
            set_field_text(&mut footprint.value_field, "Value", "1k");
            let mut field = identified_field("Trial", "before", 12);
            field.text.as_mut().unwrap().parent = footprint.id.clone();
            footprint
                .definition
                .as_mut()
                .unwrap()
                .items
                .push(konnect_ipc::builders::pack_any(
                    &field,
                    "kiapi.board.types.Field",
                ));
            konnect_ipc::builders::pack_any(&footprint, "kiapi.board.types.FootprintInstance")
        }

        let directory = tempfile::tempdir().unwrap();
        let schematic = directory.path().join("preserve.kicad_sch");
        let board = directory.path().join("preserve.kicad_pcb");
        let exported = directory.path().join("preserve.net");
        std::fs::write(
            &schematic,
            include_bytes!("../../tests/fixtures/structural_scans_kicad10.kicad_sch"),
        )
        .unwrap();
        std::fs::write(
            &board,
            include_bytes!("../../tests/fixtures/specctra_two_resistors.kicad_pcb"),
        )
        .unwrap();
        std::fs::write(
            &exported,
            netlist_with_fields(r#"(fields (field (name "Trial") "after"))"#)
                .replace("Resistor_SMD:R_0603_1608Metric", "Resistor_SMD:R_0402")
                .replace("/Power/VCC", "VCC"),
        )
        .unwrap();

        let unix_source = exported.to_string_lossy().replace('\'', "'\\''");
        let windows_source = exported.to_string_lossy();
        let cli = write_script(
            directory.path(),
            "fake-kicad-cli-sync",
            &format!(
                "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then\n    shift\n    cp '{unix_source}' \"$1\"\n    exit $?\n  fi\n  shift\ndone\nexit 2\n"
            ),
            &format!(
                "@echo off\r\n:loop\r\nif \"%~1\"==\"\" exit /b 2\r\nif \"%~1\"==\"--output\" goto found\r\nshift\r\ngoto loop\r\n:found\r\nshift\r\ncopy /Y \"{windows_source}\" \"%~1\" >nul\r\nexit /b %ERRORLEVEL%\r\n"
            ),
        );

        let schematic_backed = schematic_backed_resistor();
        let logo = konnect_ipc::builders::pack_any(
            &board_only_instance("logo-live", "REF**"),
            "kiapi.board.types.FootprintInstance",
        );
        let fiducial = konnect_ipc::builders::pack_any(
            &board_only_instance("fiducial-live", "REF**"),
            "kiapi.board.types.FootprintInstance",
        );
        let copper_zone = prost_types::Any {
            type_url: "type.googleapis.com/kiapi.board.types.Zone".to_string(),
            value: include_bytes!("../../tests/fixtures/issue_474_copper_zone_0.ipc.bin").to_vec(),
        };
        let keepout = prost_types::Any {
            type_url: "type.googleapis.com/kiapi.board.types.Zone".to_string(),
            value: include_bytes!("../../tests/fixtures/issue_474_zone_0.ipc.bin").to_vec(),
        };
        let copper_kind = kiapi::board::types::Zone::decode(copper_zone.value.as_slice())
            .expect("captured copper zone");
        let keepout_kind = kiapi::board::types::Zone::decode(keepout.value.as_slice())
            .expect("captured rule area");
        assert_eq!(
            copper_kind.r#type,
            kiapi::board::types::ZoneType::ZtCopper as i32
        );
        assert_eq!(
            keepout_kind.r#type,
            kiapi::board::types::ZoneType::ZtRuleArea as i32
        );
        let state = MockBoard {
            footprints: Arc::new(Mutex::new(vec![schematic_backed, logo, fiducial])),
            zones: Arc::new(Mutex::new(vec![copper_zone, keepout])),
        };
        let footprints_before = state.footprints.lock().unwrap().clone();
        let zones_before = state.zones.lock().unwrap().clone();
        let responder_state = state.clone();
        let lose_field_after_commit = Arc::new(AtomicBool::new(false));
        let responder_loss = lose_field_after_commit.clone();

        let server = crate::tools::pcb_board::board_mock::spawn_kicad_holding_board(
            &board,
            move |command| {
                if command.type_url.ends_with("SaveDocumentToString") {
                    let request = kiapi::common::commands::SaveDocumentToString::decode(
                        command.value.as_slice(),
                    )
                    .expect("snapshot request");
                    return Some(konnect_ipc::builders::pack_any(
                        &kiapi::common::commands::SavedDocumentResponse {
                            document: request.document,
                            contents: include_str!(
                                "../../tests/fixtures/specctra_two_resistors.kicad_pcb"
                            )
                            .into(),
                        },
                        "kiapi.common.commands.SavedDocumentResponse",
                    ));
                }
                if command.type_url.ends_with("GetItems") {
                    let request =
                        kiapi::common::commands::GetItems::decode(command.value.as_slice())
                            .expect("GetItems request");
                    let requested = request.types.first().copied().unwrap_or_default();
                    let items = match kiapi::common::types::KiCadObjectType::try_from(requested) {
                        Ok(kiapi::common::types::KiCadObjectType::KotPcbFootprint) => {
                            responder_state.footprints.lock().unwrap().clone()
                        }
                        Ok(kiapi::common::types::KiCadObjectType::KotPcbZone) => {
                            responder_state.zones.lock().unwrap().clone()
                        }
                        _ => Vec::new(),
                    };
                    return Some(konnect_ipc::builders::pack_any(
                        &kiapi::common::commands::GetItemsResponse {
                            header: None,
                            status: kiapi::common::types::ItemRequestStatus::IrsOk as i32,
                            items,
                        },
                        "kiapi.common.commands.GetItemsResponse",
                    ));
                }
                if command.type_url.ends_with("GetNets") {
                    return Some(konnect_ipc::builders::pack_any(
                        &kiapi::board::commands::NetsResponse {
                            nets: vec![
                                kiapi::board::types::Net {
                                    code: Some(kiapi::board::types::NetCode { value: 1 }),
                                    name: "/Power/VCC".to_string(),
                                },
                                kiapi::board::types::Net {
                                    code: Some(kiapi::board::types::NetCode { value: 2 }),
                                    name: "GND".to_string(),
                                },
                            ],
                        },
                        "kiapi.board.commands.NetsResponse",
                    ));
                }
                if command.type_url.ends_with("GetBoundingBox") {
                    return Some(crate::tools::pcb_board::board_mock::kicad_bounding_boxes(
                        command,
                        |_| (0.0, 0.0, 50.0, 40.0),
                    ));
                }
                if command.type_url.ends_with("BeginCommit") {
                    return Some(konnect_ipc::builders::pack_any(
                        &kiapi::common::commands::BeginCommitResponse {
                            id: Some(kiapi::common::types::Kiid {
                                value: "commit-474".to_string(),
                            }),
                        },
                        "kiapi.common.commands.BeginCommitResponse",
                    ));
                }
                if command.type_url.ends_with("UpdateItems") {
                    let request =
                        kiapi::common::commands::UpdateItems::decode(command.value.as_slice())
                            .expect("UpdateItems request");
                    let mut board_footprints = responder_state.footprints.lock().unwrap();
                    let mut updated_items = Vec::new();
                    for updated in request.items {
                        let updated_fp = kiapi::board::types::FootprintInstance::decode(
                            updated.value.as_slice(),
                        )
                        .expect("updated footprint");
                        let updated_id =
                            updated_fp.id.as_ref().expect("updated KIID").value.clone();
                        let position = board_footprints
                            .iter()
                            .position(|item| {
                                kiapi::board::types::FootprintInstance::decode(
                                    item.value.as_slice(),
                                )
                                .ok()
                                .and_then(|fp| fp.id)
                                .is_some_and(|id| id.value == updated_id)
                            })
                            .expect("existing update target");
                        board_footprints[position] = updated.clone();
                        updated_items.push(kiapi::common::commands::ItemUpdateResult {
                            status: Some(ok_item_status()),
                            item: Some(updated),
                        });
                    }
                    return Some(konnect_ipc::builders::pack_any(
                        &kiapi::common::commands::UpdateItemsResponse {
                            header: None,
                            status: kiapi::common::types::ItemRequestStatus::IrsOk as i32,
                            updated_items,
                        },
                        "kiapi.common.commands.UpdateItemsResponse",
                    ));
                }
                if command.type_url.ends_with("EndCommit") {
                    if responder_loss.swap(false, Ordering::SeqCst) {
                        let mut items = responder_state.footprints.lock().unwrap();
                        let mut committed = kiapi::board::types::FootprintInstance::decode(
                            items[0].value.as_slice(),
                        )
                        .unwrap();
                        committed.definition.as_mut().unwrap().items.retain(|item| {
                            !konnect_ipc::builders::any_is(item, "kiapi.board.types.Field")
                                || kiapi::board::types::Field::decode(item.value.as_slice())
                                    .unwrap()
                                    .name
                                    != "Trial"
                        });
                        items[0] = konnect_ipc::builders::pack_any(
                            &committed,
                            "kiapi.board.types.FootprintInstance",
                        );
                    }
                    return Some(konnect_ipc::builders::pack_any(
                        &kiapi::common::commands::EndCommitResponse {},
                        "kiapi.common.commands.EndCommitResponse",
                    ));
                }
                None
            },
        );

        let router = Arc::new(ToolRouter::new());
        router.load("sch_export").await.expect("registered toolset");
        let tool = router
            .get_tool("update_pcb_from_schematic")
            .await
            .expect("registered sync tool");
        let context = Arc::new(ToolContext::new(
            ServerConfig {
                kicad_cli: cli.to_string_lossy().to_string(),
                kicad_binary: String::new(),
                ipc_address: server.address().to_string(),
                project_dir: None,
                jlcpcb_db_path: None,
                auto_load_toolsets: false,
                eager_toolsets: false,
            },
            router,
        ));
        let paths = serde_json::json!({
            "schematic": schematic.to_string_lossy(),
            "board": board.to_string_lossy(),
        });
        let dry_run = (tool.handler)(&paths, context.clone()).await.unwrap();
        let dry_run: serde_json::Value = serde_json::from_str(&match &dry_run.content[0] {
            ToolContent::Text { text } => text.clone(),
            _ => panic!("sync response was not JSON text"),
        })
        .unwrap();
        assert_eq!(dry_run["status"], "ready", "{dry_run:#}");
        let apply = serde_json::json!({
            "schematic": schematic.to_string_lossy(),
            "board": board.to_string_lossy(),
            "dry_run": false,
            "expected_plan_revision": dry_run["plan_revision"],
        });
        let applied = (tool.handler)(&apply, context.clone()).await.unwrap();
        let applied: serde_json::Value = serde_json::from_str(&match &applied.content[0] {
            ToolContent::Text { text } => text.clone(),
            _ => panic!("sync response was not JSON text"),
        })
        .unwrap();
        assert_eq!(applied["status"], "applied");
        assert_eq!(applied["coverage"]["conflicts"]["planned"], 0);
        assert_eq!(applied["coverage"]["conflicts"]["applied"], 0);
        assert_eq!(applied["coverage"]["board_only_preserved"]["applied"], 2);

        let readback = konnect_ipc::KiCadIpcClient::new(server.address().to_string());
        let document = readback
            .find_open_board(&board)
            .expect("the mock still holds the requested board");
        let footprints_after = readback
            .get_items_in(
                document.clone(),
                kiapi::common::types::KiCadObjectType::KotPcbFootprint,
            )
            .expect("footprint readback");
        let zones_after = readback
            .get_items_in(document, kiapi::common::types::KiCadObjectType::KotPcbZone)
            .expect("zone and rule-area readback");
        let before =
            kiapi::board::types::FootprintInstance::decode(footprints_before[0].value.as_slice())
                .expect("captured R1 before apply");
        let after =
            kiapi::board::types::FootprintInstance::decode(footprints_after[0].value.as_slice())
                .expect("captured R1 after apply");
        let mut expected_field = footprint_field_slots(&before).unwrap()["custom.Trial"].clone();
        expected_field
            .text
            .as_mut()
            .unwrap()
            .text
            .as_mut()
            .unwrap()
            .text = "after".to_string();
        assert_eq!(
            footprint_field_slots(&after).unwrap()["custom.Trial"],
            expected_field,
            "the served ECO changes nested text without replacing the field's IDs or presentation"
        );
        assert_eq!(after.symbol_path, before.symbol_path);
        let pads = |footprint: &kiapi::board::types::FootprintInstance| {
            footprint
                .definition
                .as_ref()
                .unwrap()
                .items
                .iter()
                .filter(|item| konnect_ipc::builders::any_is(item, "kiapi.board.types.Pad"))
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            pads(&after),
            pads(&before),
            "the served field/value ECO preserves pad Any payloads"
        );
        let before = board_footprint_from_instance(&before).expect("R1 identity before apply");
        let after = board_footprint_from_instance(&after).expect("R1 identity after apply");
        assert_eq!(before.value, "1k");
        assert_eq!(after.value, "10k");
        assert_eq!(after.footprint_id, before.footprint_id);
        assert_eq!(
            after.kiid, before.kiid,
            "the updated footprint keeps its KIID"
        );
        assert_eq!(
            after.position, before.position,
            "the updated footprint keeps its placement"
        );
        assert_eq!(
            &footprints_after[1..],
            &footprints_before[1..],
            "both board-only footprints must retain their complete protobuf identity and geometry"
        );
        assert_eq!(
            zones_after, zones_before,
            "the copper zone and keep-out/rule area must retain their complete protobuf identity and geometry"
        );

        // A second real handler apply commits the new value, then the mock
        // loses a field on publication. This is not a rejected/no-op preflight.
        std::fs::write(
            &exported,
            netlist_with_fields(r#"(fields (field (name "Trial") "after-committed"))"#)
                .replace("Resistor_SMD:R_0603_1608Metric", "Resistor_SMD:R_0402")
                .replace("/Power/VCC", "VCC")
                .replace("(value \"10k\")", "(value \"22k\")"),
        )
        .unwrap();
        let review = (tool.handler)(&paths, context.clone()).await.unwrap();
        let review: serde_json::Value = serde_json::from_str(&match &review.content[0] {
            ToolContent::Text { text } => text.clone(),
            _ => panic!("sync response was not JSON text"),
        })
        .unwrap();
        assert_eq!(review["status"], "ready", "{review:#}");
        lose_field_after_commit.store(true, Ordering::SeqCst);
        let failed = (tool.handler)(
            &serde_json::json!({
                "schematic": schematic.to_string_lossy(),
                "board": board.to_string_lossy(),
                "dry_run": false,
                "expected_plan_revision": review["plan_revision"],
            }),
            context,
        )
        .await
        .unwrap();
        assert!(
            failed.is_error,
            "post-commit field loss must not report success"
        );
        let failed: serde_json::Value = serde_json::from_str(&match &failed.content[0] {
            ToolContent::Text { text } => text.clone(),
            _ => panic!("sync error was not JSON text"),
        })
        .unwrap();
        assert_eq!(failed["error"]["kind"], "ipc_outcome_unknown", "{failed:#}");
        assert_eq!(failed["error"]["board_state"], "committed");
        assert_eq!(failed["error"]["retry_safe"], false);
        assert!(
            failed.get("coverage").is_none(),
            "do not invent preflight applied=0 counts after publication"
        );
        assert!(failed["message"].as_str().unwrap().contains("native Undo"));
        assert!(!failed.to_string().contains("preflight_conflict"));
        assert!(
            !lose_field_after_commit.load(Ordering::SeqCst),
            "EndCommit published the second mutation"
        );
        let committed = kiapi::board::types::FootprintInstance::decode(
            state.footprints.lock().unwrap()[0].value.as_slice(),
        )
        .unwrap();
        assert_eq!(
            field_text(&committed.value_field),
            "22k",
            "the update really was published"
        );
        assert!(!board_field_values(&committed)
            .unwrap()
            .contains_key("Trial"));
    }

    // ─── #657: name what cannot be prepared, and let `ready` mean ready ──────

    const TEXAS_VQFN: &str =
        "Package_DFN_QFN:Texas_RJE0020A_VQFN-20-1EP_3x3mm_P0.45mm_EP0.675x0.76mm";
    const GENERIC_VQFN: &str = "Package_DFN_QFN:VQFN-20-1EP_3x3mm_P0.45mm_EP1.55x1.55mm";
    const STOCK_0603: &str = "Capacitor_SMD:C_0603_1608Metric";

    /// A project whose own `fp-lib-table` resolves three stock KiCad 10.0.5
    /// footprints: the two with custom-shape pads that #657 met on a real
    /// board (provenance in `tests/fixtures/custom_pads_kicad10.README.md`)
    /// and a plain 0603. A project table shadows the global one, so these
    /// files are the ones read whether or not KiCad is installed.
    fn project_with_stock_footprints() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let board = temp.path().join("carrier.kicad_pcb");
        std::fs::write(
            &board,
            include_bytes!("../../tests/fixtures/specctra_two_resistors.kicad_pcb"),
        )
        .unwrap();
        let stock: [(&str, &[u8]); 3] = [
            (
                TEXAS_VQFN,
                include_bytes!("../../tests/fixtures/custom_pads_texas_rje0020a_kicad10.kicad_mod"),
            ),
            (
                GENERIC_VQFN,
                include_bytes!("../../tests/fixtures/custom_pads_vqfn20_kicad10.kicad_mod"),
            ),
            (
                STOCK_0603,
                include_bytes!("../../tests/fixtures/c_0603_1608metric_kicad10.kicad_mod"),
            ),
        ];
        for (footprint_id, source) in stock {
            let (library, name) = footprint_id.split_once(':').unwrap();
            let directory = temp.path().join(format!("{library}.pretty"));
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join(format!("{name}.kicad_mod")), source).unwrap();
        }
        std::fs::write(
            temp.path().join("fp-lib-table"),
            "(fp_lib_table\n  (lib (name \"Package_DFN_QFN\") (type \"KiCad\") (uri \"${KIPRJMOD}/Package_DFN_QFN.pretty\") (options \"\") (descr \"\"))\n  (lib (name \"Capacitor_SMD\") (type \"KiCad\") (uri \"${KIPRJMOD}/Capacitor_SMD.pretty\") (options \"\") (descr \"\"))\n)\n",
        )
        .unwrap();
        (temp, board)
    }

    fn planned_add(reference: &str, footprint_id: &str, pads: &[&str]) -> PlannedChange {
        PlannedChange::Add {
            reference: reference.to_string(),
            value: "part".to_string(),
            footprint_id: footprint_id.to_string(),
            symbol_path: format!("/{reference}-uuid"),
            dnp: false,
            fields: BTreeMap::new(),
            pad_nets: pads
                .iter()
                .map(|pad| (pad.to_string(), format!("{reference}-{pad}")))
                .collect(),
            position: Point { x: 0.0, y: 0.0 },
        }
    }

    #[test]
    fn additions_keep_stock_metadata_models_and_field_presentation_under_schematic_overlays() {
        use konnect_ipc::gen::kiapi;
        let (_temp, board) = project_with_stock_footprints();
        let source = exported_netlist(&[("C1", STOCK_0603, &["1", "2"])]).replace(
            "(sheetpath",
            r#"
                (fields
                    (field (name "Trial") "headless")
                    (field (name "CircuitNote") "Illustrative 5 V; not hardware-qualified")
                    (field (name "Datasheet"))
                    (field (name "Description") "schematic description"))
                (property (name "Sheetname") (value "do not import"))
                (property (name "dnp"))
                (sheetpath"#,
        );
        let design = parse_exported_netlist(&source).unwrap();
        let mut plan = plan_sync(&source, &design, &board_with(vec![]));
        assert!(
            matches!(&plan.changes[0], PlannedChange::Add { fields, .. } if fields == &design.components[0].fields)
        );
        let (prepared, unprepared) = prepare_additions(&board, &plan);
        assert!(unprepared.is_empty(), "{unprepared:?}");
        restage_additions(&mut plan, &prepared, board_with(vec![]).bounds);
        let snapshot = LiveSnapshot {
            state: board_with(vec![]),
            items: BTreeMap::new(),
            net_codes: BTreeMap::from([("C1-1".to_string(), 7)]),
            document: Default::default(),
        };
        let (creates, updates) = build_mutation_items(&plan, &prepared, &snapshot).unwrap();
        assert!(updates.is_empty());
        assert_eq!(creates.len(), 1);
        let instance =
            kiapi::board::types::FootprintInstance::decode(creates[0].value.as_slice()).unwrap();
        let PlannedChange::Add { position, .. } = &plan.changes[0] else {
            panic!("the stock footprint must be added");
        };
        let stock =
            build_import_instance(&prepared[STOCK_0603].library, position.x, position.y).unwrap();
        let slots = footprint_field_slots(&instance).unwrap();
        for (slot, field) in footprint_field_slots(&stock).unwrap() {
            let mut expected = field;
            let value = match expected.name.as_str() {
                "Reference" => "C1",
                "Value" => "part",
                _ => validated_field_value(&expected).unwrap(),
            }
            .to_string();
            expected.text.as_mut().unwrap().text.as_mut().unwrap().text = value;
            assert_eq!(
                slots[&slot], expected,
                "stock field presentation must survive {slot}"
            );
        }
        assert_eq!(
            slots["custom.KiLib_Generator"]
                .text
                .as_ref()
                .unwrap()
                .text
                .as_ref()
                .unwrap()
                .text,
            "SMD_2terminal_chip_molded"
        );
        let values = board_field_values(&instance).unwrap();
        for (name, value) in &design.components[0].fields {
            assert_eq!(values.get(name), Some(value), "schematic field {name}");
        }
        assert!(!values.contains_key("Sheetname"));
        assert!(!values.contains_key("dnp"));
        for name in ["Trial", "CircuitNote"] {
            let field = &slots[&format!("custom.{name}")];
            assert!(field.id.is_none() && !field.visible);
            let text = field.text.as_ref().unwrap();
            assert!(text.id.is_none() && text.parent.is_none());
            assert_eq!(text.text.as_ref().unwrap().position, instance.position);
        }
        let definition = instance.definition.as_ref().unwrap();
        assert_eq!(
            definition.attributes.as_ref().unwrap().description,
            stock
                .definition
                .as_ref()
                .unwrap()
                .attributes
                .as_ref()
                .unwrap()
                .description
        );
        assert_eq!(
            definition.attributes.as_ref().unwrap().keywords,
            "capacitor"
        );
        assert!(instance.attributes.as_ref().unwrap().do_not_populate);
        assert!(definition.attributes.as_ref().unwrap().do_not_populate);
        assert_eq!(
            instance.attributes.as_ref().unwrap().mounting_style,
            kiapi::board::types::FootprintMountingStyle::FmsSmd as i32
        );
        let artwork_and_models = |footprint: &kiapi::board::types::FootprintInstance| {
            footprint
                .definition
                .as_ref()
                .unwrap()
                .items
                .iter()
                .filter(|item| {
                    !konnect_ipc::builders::any_is(item, "kiapi.board.types.Pad")
                        && !konnect_ipc::builders::any_is(item, "kiapi.board.types.Field")
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(artwork_and_models(&instance), artwork_and_models(&stock));
        assert_eq!(
            child_types(&creates[0])["kiapi.board.types.Footprint3DModel"],
            1
        );
        assert_eq!(child_types(&creates[0])["kiapi.board.types.Field"], 3);
        assert_eq!(
            footprint_shapes(creates.iter())["C1"],
            FootprintShape {
                pads: 2,
                drawings: 5
            }
        );
        let view = board_footprint_from_instance(&{
            let mut with_id = instance.clone();
            with_id.id = Some(kiapi::common::types::Kiid {
                value: "created-uuid".to_string(),
            });
            with_id
        })
        .unwrap();
        assert_eq!(view.symbol_path.as_deref(), Some("/C1-uuid"));
        assert_eq!(view.pad_nets, design.components[0].pad_nets);
        let first_pad = definition
            .items
            .iter()
            .find(|item| konnect_ipc::builders::any_is(item, "kiapi.board.types.Pad"))
            .unwrap();
        let first_pad = kiapi::board::types::Pad::decode(first_pad.value.as_slice()).unwrap();
        assert_eq!(first_pad.net.unwrap().code.unwrap().value, 7);
    }

    fn plan_adding(changes: Vec<PlannedChange>) -> SyncPlan {
        SyncPlan {
            status: PlanStatus::Ready,
            plan_revision: "reviewed".to_string(),
            counts: SyncCounts {
                added: CountPair {
                    planned: changes.len(),
                    applied: 0,
                },
                ..SyncCounts::default()
            },
            changes,
            diagnostics: Vec::new(),
            unassigned: Vec::new(),
        }
    }

    /// #657: the first unusable footprint stopped preparation, so a plan that
    /// needed two of them heard about one, and about neither by name.
    #[test]
    fn every_unusable_footprint_is_named_with_the_parts_that_need_it() {
        let (_temp, board) = project_with_stock_footprints();
        let plan = plan_adding(vec![
            planned_add("U1", TEXAS_VQFN, &["1"]),
            planned_add("C1", STOCK_0603, &["1", "2"]),
            planned_add("U3", GENERIC_VQFN, &["1"]),
            planned_add("U2", TEXAS_VQFN, &["1"]),
        ]);

        let (prepared, unprepared) = prepare_additions(&board, &plan);

        assert_eq!(
            prepared.keys().map(String::as_str).collect::<Vec<_>>(),
            [STOCK_0603],
            "a footprint that can be placed is still prepared"
        );
        let diagnostics = unprepared
            .into_iter()
            .map(UnpreparedFootprint::into_diagnostic)
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 2, "{diagnostics:#?}");

        let texas = &diagnostics[0];
        assert_eq!(texas.code, "unsupported_library_footprint");
        assert_eq!(texas.footprint_id.as_deref(), Some(TEXAS_VQFN));
        assert_eq!(texas.references, ["U1", "U2"]);
        assert_eq!(
            texas.reference, None,
            "two parts are concerned, so no single one is named"
        );
        assert!(
            texas.message.contains(TEXAS_VQFN)
                && texas.message.contains("U1, U2")
                && texas.message.contains("pad shape 'custom'"),
            "{}",
            texas.message
        );

        let generic = &diagnostics[1];
        assert_eq!(generic.code, "unsupported_library_footprint");
        assert_eq!(generic.footprint_id.as_deref(), Some(GENERIC_VQFN));
        assert_eq!(generic.references, ["U3"]);
        assert_eq!(generic.reference.as_deref(), Some("U3"));
    }

    /// The caller's next step differs with the stage that failed: fix the
    /// library table, fix the file, or substitute the footprint. The codes are
    /// the ones `update_footprints_from_library` reports for the same three.
    #[test]
    fn each_stage_of_preparation_fails_under_its_own_code() {
        let (temp, board) = project_with_stock_footprints();
        std::fs::write(
            temp.path()
                .join("Capacitor_SMD.pretty/Unreadable.kicad_mod"),
            [0xff, 0xfe, 0x00, 0x28],
        )
        .unwrap();
        let plan = plan_adding(vec![
            planned_add("J1", "Konnect_No_Such_Library:Nothing", &["1"]),
            planned_add("C9", "Capacitor_SMD:Unreadable", &["1"]),
            planned_add("U1", TEXAS_VQFN, &["1"]),
        ]);

        let (prepared, unprepared) = prepare_additions(&board, &plan);

        assert!(prepared.is_empty());
        let by_reference = unprepared
            .iter()
            .map(|failed| (failed.references[0].as_str(), failed.code))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            by_reference,
            BTreeMap::from([
                ("C9", "footprint_library_read_failed"),
                ("J1", "footprint_library_resolution_failed"),
                ("U1", "unsupported_library_footprint"),
            ])
        );
    }

    /// A message names at most eight parts; `references` names them all.
    #[test]
    fn a_message_is_bounded_and_the_reference_list_is_complete() {
        let references = (1..=30).map(|n| format!("C{n}")).collect::<Vec<_>>();
        let diagnostic = UnpreparedFootprint {
            footprint_id: TEXAS_VQFN.to_string(),
            references: references.clone(),
            code: "unsupported_library_footprint",
            reason: "custom-shape pads".to_string(),
        }
        .into_diagnostic();

        assert_eq!(diagnostic.references, references);
        assert!(
            diagnostic.message.contains("C8 and 22 more") && !diagnostic.message.contains("C9,"),
            "{}",
            diagnostic.message
        );
    }

    /// Add path: `footprint C1 has no pad 3` used to be raised only inside
    /// the apply, after a dry run that said `ready`.
    #[test]
    fn a_connected_pad_the_library_footprint_lacks_is_found_while_planning() {
        let (_temp, board) = project_with_stock_footprints();
        let plan = plan_adding(vec![
            planned_add("C1", STOCK_0603, &["1", "2", "3", "4"]),
            planned_add("C2", STOCK_0603, &["1", "2"]),
        ]);
        let (prepared, unprepared) = prepare_additions(&board, &plan);
        assert!(unprepared.is_empty());

        let diagnostics = additions_missing_pads(&plan, &prepared);

        assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
        let missing = &diagnostics[0];
        assert_eq!(missing.code, "footprint_pad_missing");
        assert_eq!(missing.reference.as_deref(), Some("C1"));
        assert_eq!(missing.references, ["C1"]);
        assert_eq!(missing.footprint_id.as_deref(), Some(STOCK_0603));
        assert!(missing.message.contains("pads 3, 4"), "{}", missing.message);
    }

    /// Update path: the same rule against the pads of the live footprint.
    /// Before, this planned an update with one pad reassigned and said
    /// `ready`; the apply then failed on `footprint R1 has no pad 3`.
    #[test]
    fn a_connected_pad_the_live_footprint_lacks_is_found_while_planning() {
        let mut component = resistor("R1", "/sheet/existing");
        component
            .pad_nets
            .insert("3".to_string(), "SENSE".to_string());
        let design = ExportedDesign {
            components: vec![component],
            skipped: Vec::new(),
            unassigned: Vec::new(),
        };
        let board = board_with(vec![board_resistor("R1", Some("/sheet/existing"))]);

        let plan = plan_sync("netlist", &design, &board);

        assert_eq!(plan.status, PlanStatus::Conflict);
        assert!(plan.changes.is_empty());
        assert_eq!(plan.counts.updated.planned, 0);
        assert_eq!(plan.diagnostics.len(), 1, "{:#?}", plan.diagnostics);
        let missing = &plan.diagnostics[0];
        assert_eq!(missing.code, "footprint_pad_missing");
        assert_eq!(missing.reference.as_deref(), Some("R1"));
        assert_eq!(
            missing.footprint_id.as_deref(),
            Some("Resistor_SMD:R_0603_1608Metric")
        );
        assert!(missing.message.contains("pad 3"), "{}", missing.message);
    }

    /// The pad set is every pad KiCad sent, netted or not. The 0402 from the
    /// #474 capture has pads 1 and 2. The captured mounting hole has one pad,
    /// with the empty number and no net: exactly the pad `pad_nets` never
    /// held, which is why it cannot answer whether a pad exists.
    #[test]
    fn the_live_footprint_records_every_pad_kicad_sent() {
        use konnect_ipc::gen::kiapi;
        const RESISTOR: &[u8] = include_bytes!("../../tests/fixtures/issue_474_r1.ipc.bin");
        let resistor = kiapi::board::types::FootprintInstance::decode(RESISTOR)
            .expect("the checked-in KiCad IPC capture must decode");
        let mounting_hole = kiapi::board::types::FootprintInstance::decode(BOARD_ONLY_CAPTURE)
            .expect("the checked-in KiCad IPC capture must decode");

        let resistor = board_footprint_from_instance(&resistor).unwrap();
        let mounting_hole = board_footprint_from_instance(&mounting_hole).unwrap();

        assert_eq!(
            resistor.pad_numbers,
            BTreeSet::from(["1".to_string(), "2".to_string()])
        );
        assert_eq!(mounting_hole.pad_numbers, BTreeSet::from([String::new()]));
        assert!(mounting_hole.pad_nets.is_empty());
    }

    /// A single-part diagnostic lists that part in `references` too, so a
    /// caller can read one field for every diagnostic.
    #[test]
    fn a_single_part_diagnostic_lists_its_part() {
        let diagnostic = conflict("duplicate_board_reference", "message".into(), Some("R1"));
        assert_eq!(diagnostic.reference.as_deref(), Some("R1"));
        assert_eq!(diagnostic.references, ["R1"]);
        assert_eq!(diagnostic.footprint_id, None);

        let board_level = conflict("stale_plan_revision", "message".into(), None);
        assert!(board_level.references.is_empty());
    }

    /// One `(comp …)` per part and one net per pin, in the shape
    /// `kicad-cli sch export netlist --format kicadsexpr` writes.
    fn exported_netlist(components: &[(&str, &str, &[&str])]) -> String {
        let mut parts = String::new();
        let mut nets = String::new();
        let mut code = 0;
        for (reference, footprint_id, pins) in components {
            let pin_list = pins
                .iter()
                .map(|pin| format!("(pin (num \"{pin}\"))"))
                .collect::<String>();
            parts.push_str(&format!(
                "    (comp\n      (ref \"{reference}\")\n      (value \"part\")\n      (footprint \"{footprint_id}\")\n      (sheetpath (names \"/\") (tstamps \"/\"))\n      (tstamps \"{reference}-uuid\")\n      (units (unit (name \"A\") (pins {pin_list}))))\n"
            ));
            for pin in *pins {
                code += 1;
                nets.push_str(&format!(
                    "    (net (code \"{code}\") (name \"{reference}-{pin}\") (class \"Default\")\n      (node (ref \"{reference}\") (pin \"{pin}\") (pintype \"passive\")))\n"
                ));
            }
        }
        format!("(export\n  (components\n{parts}  )\n  (nets\n{nets}  ))\n")
    }

    /// Everything a served dry run needs without KiCad: a stand-in
    /// `kicad-cli` that hands back `netlist`, and a protobuf mock holding the
    /// project's board open with nothing on it.
    struct ServedSync {
        _temp: tempfile::TempDir,
        _kicad: crate::test_support::MockIpcServer,
        handler: crate::mcp::handler::McpHandler,
        schematic: PathBuf,
        board: PathBuf,
        exported: PathBuf,
    }

    impl ServedSync {
        async fn new() -> Self {
            Self::holding_outline(None).await
        }

        /// As [`Self::new`], with KiCad also holding one board graphic whose
        /// box is `outline`, `(x, y, width, height)` in mm.
        async fn holding_outline(outline: Option<(f64, f64, f64, f64)>) -> Self {
            use crate::tools::cli::test_support::write_script;
            use konnect_ipc::gen::kiapi;

            let (temp, board) = project_with_stock_footprints();
            let schematic = temp.path().join("carrier.kicad_sch");
            std::fs::write(
                &schematic,
                include_bytes!("../../tests/fixtures/structural_scans_kicad10.kicad_sch"),
            )
            .unwrap();
            let exported = temp.path().join("carrier.net");
            let unix_source = exported.to_string_lossy().replace('\'', "'\\''");
            let windows_source = exported.to_string_lossy();
            let cli = write_script(
                temp.path(),
                "fake-kicad-cli-657",
                &format!(
                    "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then\n    shift\n    cp '{unix_source}' \"$1\"\n    exit $?\n  fi\n  shift\ndone\nexit 2\n"
                ),
                &format!(
                    "@echo off\r\n:loop\r\nif \"%~1\"==\"\" exit /b 2\r\nif \"%~1\"==\"--output\" goto found\r\nshift\r\ngoto loop\r\n:found\r\nshift\r\ncopy /Y \"{windows_source}\" \"%~1\" >nul\r\nexit /b %ERRORLEVEL%\r\n"
                ),
            );
            let kicad = crate::tools::pcb_board::board_mock::spawn_kicad_holding_board(
                &board,
                move |command| {
                    if command.type_url.ends_with("GetItems") {
                        let request =
                            kiapi::common::commands::GetItems::decode(command.value.as_slice())
                                .expect("GetItems request");
                        let shapes = kiapi::common::types::KiCadObjectType::KotPcbShape as i32;
                        let items = match outline {
                            Some(_) if request.types.contains(&shapes) => {
                                vec![crate::tools::pcb_board::board_mock::listed_item(
                                    kiapi::common::types::KiCadObjectType::KotPcbShape,
                                    "outline",
                                )]
                            }
                            _ => Vec::new(),
                        };
                        return Some(konnect_ipc::builders::pack_any(
                            &kiapi::common::commands::GetItemsResponse {
                                header: None,
                                status: kiapi::common::types::ItemRequestStatus::IrsOk as i32,
                                items,
                            },
                            "kiapi.common.commands.GetItemsResponse",
                        ));
                    }
                    if command.type_url.ends_with("GetNets") {
                        return Some(konnect_ipc::builders::pack_any(
                            &kiapi::board::commands::NetsResponse { nets: Vec::new() },
                            "kiapi.board.commands.NetsResponse",
                        ));
                    }
                    if command.type_url.ends_with("GetBoundingBox") {
                        return Some(crate::tools::pcb_board::board_mock::kicad_bounding_boxes(
                            command,
                            |kiid| {
                                assert_eq!(kiid, "outline", "only the outline is listed");
                                outline.expect("an outline to measure")
                            },
                        ));
                    }
                    None
                },
            );
            let handler = crate::mcp::handler::McpHandler::new(crate::tools::ServerConfig {
                kicad_cli: cli.to_string_lossy().to_string(),
                kicad_binary: String::new(),
                ipc_address: kicad.address().to_string(),
                project_dir: None,
                jlcpcb_db_path: None,
                auto_load_toolsets: false,
                eager_toolsets: true,
            })
            .await
            .expect("handler builds");
            Self {
                _temp: temp,
                _kicad: kicad,
                handler,
                schematic,
                board,
                exported,
            }
        }

        /// A dry run through `tools/call`, for a schematic exporting `netlist`.
        async fn dry_run(&self, netlist: &str) -> serde_json::Value {
            self.dry_run_result(netlist).await.1
        }

        /// As [`Self::dry_run`], with the result's `isError` beside the body.
        async fn dry_run_result(&self, netlist: &str) -> (bool, serde_json::Value) {
            std::fs::write(&self.exported, netlist).unwrap();
            let response = self
                .handler
                .handle_message(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 657,
                    "method": "tools/call",
                    "params": {
                        "name": "update_pcb_from_schematic",
                        "arguments": {
                            "schematic": self.schematic.to_string_lossy(),
                            "board": self.board.to_string_lossy()
                        }
                    }
                }))
                .await
                .expect("tools/call receives a response");
            let result = response.result.expect("successful JSON-RPC response");
            (
                result["isError"] == serde_json::json!(true),
                serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap(),
            )
        }
    }

    #[tokio::test]
    async fn library_metadata_drift_changes_the_reviewed_revision_and_refuses_a_stale_apply() {
        let served = ServedSync::new().await;
        let source = exported_netlist(&[("C1", STOCK_0603, &["1", "2"])]);
        let first = served.dry_run(&source).await;
        assert_eq!(first["status"], "ready", "{first:#}");
        let library = served
            .board
            .parent()
            .unwrap()
            .join("Capacitor_SMD.pretty/C_0603_1608Metric.kicad_mod");
        let stock = include_str!("../../tests/fixtures/c_0603_1608metric_kicad10.kicad_mod");
        std::fs::write(
            library,
            stock.replace("(tags \"capacitor\")", "(tags \"changed-metadata\")"),
        )
        .unwrap();
        let second = served.dry_run(&source).await;
        assert_eq!(second["status"], "ready", "{second:#}");
        assert_eq!(
            first["changes"], second["changes"],
            "metadata drift need not move staging or schematic values"
        );
        assert_ne!(
            first["plan_revision"], second["plan_revision"],
            "the source digest is part of the reviewed revision"
        );
        let response = served
            .handler
            .handle_message(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 658,
                "method": "tools/call",
                "params": {
                    "name": "update_pcb_from_schematic",
                    "arguments": {
                        "schematic": served.schematic.to_string_lossy(),
                        "board": served.board.to_string_lossy(),
                        "dry_run": false,
                        "expected_plan_revision": first["plan_revision"],
                    }
                }
            }))
            .await
            .unwrap();
        let result = response.result.unwrap();
        let refused: serde_json::Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(refused["status"], "conflict", "{refused:#}");
        assert_eq!(refused["diagnostics"][0]["code"], "stale_plan_revision");
        assert_eq!(refused["changes"], serde_json::json!([]));
        assert_eq!(refused["coverage"]["footprints_added"]["applied"], 0);
        assert!(refused["undo"].is_null());
    }

    /// #688 through the served boundary: a part the board lacks is staged
    /// 5 mm to the right of what KiCad holds, measured item by item.
    ///
    /// KiCad answers `GetBoundingBox` only for the KIIDs a request names. The
    /// snapshot used to send an empty request, read the empty answer as an
    /// empty board, and stage every addition beside the page origin instead.
    #[tokio::test]
    async fn additions_are_staged_beside_the_board_kicad_holds() {
        // An outline away from the origin, as a real board is.
        let served = ServedSync::holding_outline(Some((100.0, 80.0, 50.0, 40.0))).await;

        let plan = served
            .dry_run(&exported_netlist(&[("C1", STOCK_0603, &["1", "2"])]))
            .await;

        assert_eq!(plan["status"], "ready", "{plan:#}");
        let added = &plan["changes"][0];
        assert_eq!(added["kind"], "add", "{plan:#}");
        let x = added["position"]["x"].as_f64().unwrap();
        let y = added["position"]["y"].as_f64().unwrap();
        // The staging column starts 5 mm past the board's right edge (150 mm)
        // and the first part is centred half its width further on.
        assert!(x > 155.0 && x < 165.0, "staged at x = {x}: {plan:#}");
        // Stacked down from the board's top edge (80 mm), not from y = 0.
        assert!(y > 80.0 && y < 90.0, "staged at y = {y}: {plan:#}");
    }

    #[tokio::test]
    async fn a_partial_reference_without_effects_refuses_the_served_dry_run_before_ready() {
        let served = ServedSync::new().await;
        let stock = include_str!("../../tests/fixtures/c_0603_1608metric_kicad10.kicad_mod");
        let reference_start = stock.find("(property \"Reference\"").unwrap();
        let value_start = stock.find("(property \"Value\"").unwrap();
        let partial = format!(
            "{}(property \"Reference\" \"REF**\" (at 0 -1.43 0) (layer \"F.SilkS\"))\n{}",
            &stock[..reference_start],
            &stock[value_start..],
        );
        parse_library_footprint(STOCK_0603, &partial)
            .expect("partial mandatory presentation remains a valid refresh input");
        std::fs::write(
            served
                .board
                .parent()
                .unwrap()
                .join("Capacitor_SMD.pretty/C_0603_1608Metric.kicad_mod"),
            partial,
        )
        .unwrap();

        let refused = served
            .dry_run(&exported_netlist(&[("C1", STOCK_0603, &["1", "2"])]))
            .await;
        assert_eq!(refused["status"], "conflict", "{refused:#}");
        assert_eq!(refused["changes"], serde_json::json!([]));
        assert_eq!(refused["coverage"]["footprints_added"]["planned"], 0);
        assert_eq!(refused["coverage"]["conflicts"]["planned"], 1);
        let diagnostics = refused["diagnostics"].as_array().unwrap();
        assert_eq!(diagnostics.len(), 1, "{refused:#}");
        assert_eq!(diagnostics[0]["code"], "unsupported_library_footprint");
        assert_eq!(diagnostics[0]["footprint_id"], STOCK_0603);
        assert_eq!(diagnostics[0]["reference"], "C1");
        assert_eq!(diagnostics[0]["references"], serde_json::json!(["C1"]));
        let message = diagnostics[0]["message"].as_str().unwrap();
        assert!(
            message.contains("partial mandatory presentation")
                && message.contains("Reference")
                && message.contains("effects"),
            "{message}"
        );
    }

    /// #657 through the served boundary. The run that found it needed two
    /// unusable footprints and was told of one, with `reference: null` and no
    /// footprint: every part and both footprints are named now, nothing is
    /// planned, and a plan that can be placed still says `ready`.
    #[tokio::test]
    async fn two_unusable_footprints_are_both_named_through_the_served_dispatch() {
        let served = ServedSync::new().await;

        let refused = served
            .dry_run(&exported_netlist(&[
                ("U1", TEXAS_VQFN, &["1", "2"]),
                ("C1", STOCK_0603, &["1", "2"]),
                ("U3", GENERIC_VQFN, &["1", "2"]),
                ("U2", TEXAS_VQFN, &["1", "2"]),
            ]))
            .await;

        assert_eq!(refused["status"], "conflict", "{refused:#}");
        assert_eq!(refused["changes"], serde_json::json!([]));
        assert_eq!(refused["coverage"]["footprints_added"]["planned"], 0);
        assert_eq!(refused["coverage"]["conflicts"]["planned"], 2);
        assert_eq!(
            refused["diagnostics"],
            serde_json::json!([
                {
                    "code": "unsupported_library_footprint",
                    "message": format!(
                        "{TEXAS_VQFN} cannot be placed (needed by U1, U2): pad shape 'custom' \
                         is not supported by typed library refresh"
                    ),
                    "reference": null,
                    "references": ["U1", "U2"],
                    "footprint_id": TEXAS_VQFN
                },
                {
                    "code": "unsupported_library_footprint",
                    "message": format!(
                        "{GENERIC_VQFN} cannot be placed (needed by U3): pad shape 'custom' \
                         is not supported by typed library refresh"
                    ),
                    "reference": "U3",
                    "references": ["U3"],
                    "footprint_id": GENERIC_VQFN
                }
            ])
        );

        let placeable = served
            .dry_run(&exported_netlist(&[("C1", STOCK_0603, &["1", "2"])]))
            .await;
        assert_eq!(placeable["status"], "ready", "{placeable:#}");
        assert_eq!(placeable["coverage"]["footprints_added"]["planned"], 1);
        assert_eq!(placeable["diagnostics"], serde_json::json!([]));
    }

    /// A dry run said `ready` for a part whose schematic connects a pad its
    /// footprint does not have, and the apply then failed its preflight. The
    /// dry run is where it is refused now, by name.
    #[tokio::test]
    async fn a_missing_pad_refuses_the_dry_run_through_the_served_dispatch() {
        let served = ServedSync::new().await;

        let refused = served
            .dry_run(&exported_netlist(&[
                ("C1", STOCK_0603, &["1", "2", "3"]),
                ("C2", STOCK_0603, &["1", "2"]),
            ]))
            .await;

        assert_eq!(refused["status"], "conflict", "{refused:#}");
        assert_eq!(refused["changes"], serde_json::json!([]));
        assert_eq!(refused["coverage"]["footprints_added"]["planned"], 0);
        let diagnostics = refused["diagnostics"].as_array().unwrap();
        assert_eq!(diagnostics.len(), 1, "{refused:#}");
        assert_eq!(diagnostics[0]["code"], "footprint_pad_missing");
        assert_eq!(diagnostics[0]["reference"], "C1");
        assert_eq!(diagnostics[0]["references"], serde_json::json!(["C1"]));
        assert_eq!(diagnostics[0]["footprint_id"], STOCK_0603);
        assert_eq!(
            diagnostics[0]["message"],
            format!("the schematic connects C1 pad 3, which footprint {STOCK_0603} does not have")
        );
    }

    /// A refusal before any plan exists (saved hierarchy, netlist export, IPC
    /// preflight) went out with a hand-built diagnostic of only `code` and
    /// `message`, so the responses that say least were also the ones missing
    /// the fields every other diagnostic carries. One constructor builds them
    /// all now. The whole object is compared: indexing a missing key yields
    /// `null` as well, so a per-field check could not tell absent from null.
    #[tokio::test]
    async fn a_preflight_refusal_has_the_same_diagnostic_fields_through_the_served_dispatch() {
        let served = ServedSync::new().await;

        // An export with no components section fails the netlist preflight.
        let (is_error, refused) = served.dry_run_result("(export (version \"E\"))").await;

        assert!(is_error, "{refused:#}");
        assert_eq!(refused["status"], "conflict");
        let message = refused["diagnostics"][0]["message"].as_str().unwrap();
        assert!(message.starts_with("netlist preflight failed"), "{message}");
        assert_eq!(
            refused["diagnostics"],
            serde_json::json!([{
                "code": "preflight_conflict",
                "message": message,
                "reference": null,
                "references": [],
                "footprint_id": null
            }])
        );

        // The same keys as a diagnostic from planning, so one reader serves both.
        let planned = served
            .dry_run(&exported_netlist(&[("U1", TEXAS_VQFN, &["1"])]))
            .await;
        let keys = |diagnostic: &serde_json::Value| {
            diagnostic
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(
            keys(&refused["diagnostics"][0]),
            keys(&planned["diagnostics"][0])
        );
    }
}
