//! KiCad 10.0.6-only native acceptance probe, not a supported action/MCP API.
//! The parent owns modification, GUI isolation, and save/reopen verification.
//! Output must be new; an intent journal must never authorize another Undo.

use anyhow::{bail, ensure, Context, Result};
use konnect_ipc::{
    builders::{any_is, any_type_name, pack_any},
    gen::kiapi::{
        board::types as board,
        common::{self as api, commands as command, types as common},
    },
    ApiStatusError, KiCadIpcClient,
};
use konnect_sexp::{parse_sexp, SexpNode};
use nng::options::Options;
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const SCHEMA: &str = "konnect.workbench_probe.v1";
const UNDO: &str = "common.Interactive.undo";
const SOCKET_BUDGET: Duration = Duration::from_secs(5);
const READ_BUDGET: Duration = Duration::from_secs(8);
const TRACK: &str = "kiapi.board.types.Track";
const GROUP: &str = "kiapi.board.types.Group";
// Container messages include their children. The full serialization also covers
// board settings and item classes which KiCad does not expose through GetItems.
const ITEM_TYPES: &[common::KiCadObjectType] = &[
    common::KiCadObjectType::KotPcbFootprint,
    common::KiCadObjectType::KotPcbShape,
    common::KiCadObjectType::KotPcbReferenceImage,
    common::KiCadObjectType::KotPcbText,
    common::KiCadObjectType::KotPcbTextbox,
    common::KiCadObjectType::KotPcbTable,
    common::KiCadObjectType::KotPcbTrace,
    common::KiCadObjectType::KotPcbVia,
    common::KiCadObjectType::KotPcbArc,
    common::KiCadObjectType::KotPcbDimension,
    common::KiCadObjectType::KotPcbZone,
    common::KiCadObjectType::KotPcbGroup,
    common::KiCadObjectType::KotPcbBarcode,
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Item {
    type_url: String,
    proto_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct SavedBoard {
    document_hex: String,
    contents: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Snapshot {
    version_hex: String,
    document_hex: String,
    server_token: String,
    target_track_hex: String,
    groups: BTreeMap<String, String>,
    item_types: Vec<i32>,
    items: Vec<Item>,
    saved_document: SavedBoard,
}

struct Journal {
    path: PathBuf,
    data: Value,
}

fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("create new journal {}", path.display()))
}

impl Journal {
    fn new(path: &Path, data: Value) -> Result<Self> {
        let mut file = private_file(path)?;
        file.write_all(&serde_json::to_vec_pretty(&data)?)?;
        file.sync_all()?;
        Ok(Self {
            path: fs::canonicalize(path)?,
            data,
        })
    }

    fn persist(&self) -> Result<()> {
        // Atomic replacement retains the previous valid JSON if writing fails.
        let temporary = self.path.with_file_name(format!(
            "{}.workbench-{}.tmp",
            self.path
                .file_name()
                .context("journal filename")?
                .to_string_lossy(),
            std::process::id()
        ));
        let mut file = private_file(&temporary)?;
        let result = (|| -> Result<()> {
            file.write_all(&serde_json::to_vec_pretty(&self.data)?)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &self.path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

fn proto_hex(message: &impl Message) -> String {
    hex(&message.encode_to_vec())
}

fn unhex(value: &str) -> Result<Vec<u8>> {
    ensure!(
        value.len().is_multiple_of(2) && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid protobuf hex"
    );
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).context("decode protobuf hex"))
        .collect()
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .context("read/socket deadline expired")?;
    ensure!(!remaining.is_zero(), "read/socket deadline expired");
    Ok(remaining.min(SOCKET_BUDGET))
}

struct Wire {
    endpoint: String,
    token: String,
}

impl Wire {
    fn exchange(
        &self,
        message: &impl Message,
        name: &str,
        deadline: Instant,
        send_attempted: &mut bool,
    ) -> Result<Vec<u8>> {
        let request = api::ApiRequest {
            header: Some(api::ApiRequestHeader {
                kicad_token: self.token.clone(),
                client_name: format!("konnect-workbench-probe-{}", std::process::id()),
            }),
            message: Some(pack_any(message, name)),
        };
        let socket = nng::Socket::new(nng::Protocol::Req0)?;
        socket.set_opt::<nng::options::protocol::reqrep::ResendTime>(None)?;
        socket.set_opt::<nng::options::SendTimeout>(Some(remaining(deadline)?))?;
        socket.set_opt::<nng::options::RecvTimeout>(Some(remaining(deadline)?))?;
        // Synchronous dial may spend NNG's ten-second handshake limit, exceeding
        // the polling budget. Timer resends are off; peer-disconnect resends are
        // still an NNG limitation, not an exactly-once delivery guarantee.
        socket.dial_async(&self.endpoint)?;
        socket.set_opt::<nng::options::SendTimeout>(Some(remaining(deadline)?))?;
        *send_attempted = true;
        socket
            .send(request.encode_to_vec().as_slice())
            .map_err(|(_, error)| error)?;
        socket.set_opt::<nng::options::RecvTimeout>(Some(remaining(deadline)?))?;
        Ok(socket.recv()?.as_slice().to_vec())
    }

    fn body(&mut self, response: api::ApiResponse, expected: &str) -> Result<prost_types::Any> {
        let header = response.header.context("missing response identity")?;
        ensure!(
            !header.kicad_token.is_empty(),
            "empty response instance token"
        );
        if self.token.is_empty() {
            self.token = header.kicad_token.clone();
        }
        ensure!(
            header.kicad_token == self.token,
            "KiCad endpoint instance changed"
        );
        let status = response.status.context("missing API status")?;
        let code = api::ApiStatusCode::try_from(status.status).context("unknown API status")?;
        if code != api::ApiStatusCode::AsOk {
            return Err(ApiStatusError {
                code: status.status,
                code_name: code.as_str_name().into(),
                message: status.error_message,
            }
            .into());
        }
        let message = response.message.context("missing typed response body")?;
        ensure!(
            any_is(&message, expected),
            "expected {expected}, received {}",
            message.type_url
        );
        Ok(message)
    }

    fn read<R: Message + Default>(
        &mut self,
        message: &impl Message,
        name: &str,
        response_name: &str,
        deadline: Instant,
    ) -> Result<R> {
        let bytes = self.exchange(message, name, deadline, &mut false)?;
        let response = api::ApiResponse::decode(bytes.as_slice()).context("decode API response")?;
        let body = self.body(response, response_name)?;
        R::decode(body.value.as_slice()).with_context(|| format!("decode {response_name}"))
    }

    fn prove_context(
        &mut self,
        document: &common::DocumentSpecifier,
        deadline: Instant,
    ) -> Result<common::KiCadVersion> {
        let response: command::GetVersionResponse = self.read(
            &command::GetVersion {},
            "kiapi.common.commands.GetVersion",
            "kiapi.common.commands.GetVersionResponse",
            deadline,
        )?;
        let version = response.version.context("missing KiCad version")?;
        ensure!(
            (version.major, version.minor, version.patch) == (10, 0, 6),
            "requires KiCad 10.0.6"
        );
        let response: command::GetOpenDocumentsResponse = self.read(
            &command::GetOpenDocuments {
                r#type: common::DocumentType::DoctypePcb as i32,
            },
            "kiapi.common.commands.GetOpenDocuments",
            "kiapi.common.commands.GetOpenDocumentsResponse",
            deadline,
        )?;
        ensure!(
            response.documents == [document.clone()],
            "requested exact document is not the sole endpoint-local PCB"
        );
        Ok(version)
    }

    fn saved_board(
        &mut self,
        document: &common::DocumentSpecifier,
        deadline: Instant,
    ) -> Result<SavedBoard> {
        let response: command::SavedDocumentResponse = self.read(
            &command::SaveDocumentToString {
                document: Some(document.clone()),
            },
            "kiapi.common.commands.SaveDocumentToString",
            "kiapi.common.commands.SavedDocumentResponse",
            deadline,
        )?;
        ensure!(
            response.document.as_ref() == Some(document),
            "serialized board names a different/missing document"
        );
        ensure!(!response.contents.is_empty(), "empty serialized board");
        Ok(SavedBoard {
            document_hex: proto_hex(document),
            contents: response.contents,
        })
    }

    fn snapshot(
        &mut self,
        document: &common::DocumentSpecifier,
        uuid: &str,
        deadline: Instant,
    ) -> Result<Option<Snapshot>> {
        let version = self.prove_context(document, deadline)?;
        let before = self.saved_board(document, deadline)?;
        let item_types: Vec<_> = ITEM_TYPES.iter().map(|kind| *kind as i32).collect();
        let response: command::GetItemsResponse = self.read(
            &command::GetItems {
                header: Some(common::ItemHeader {
                    document: Some(document.clone()),
                    container: None,
                    field_mask: None,
                }),
                types: item_types.clone(),
            },
            "kiapi.common.commands.GetItems",
            "kiapi.common.commands.GetItemsResponse",
            deadline,
        )?;
        ensure!(
            response.status == common::ItemRequestStatus::IrsOk as i32,
            "GetItems refused: {}",
            response.status
        );
        // Some versions omit this header; exact fresh context reads bracket the
        // observation. A supplied header must not contradict or mask the read.
        if let Some(header) = response.header {
            ensure!(
                header.document.as_ref() == Some(document),
                "GetItems response document mismatch"
            );
            ensure!(
                header
                    .container
                    .as_ref()
                    .is_none_or(|id| id.value.is_empty()),
                "partial container read"
            );
            ensure!(
                header
                    .field_mask
                    .as_ref()
                    .is_none_or(|mask| mask.paths.is_empty()),
                "partial field-mask read"
            );
        }
        let mut target = None;
        let mut groups = BTreeMap::new();
        let mut items = Vec::new();
        for mut item in response.items {
            ensure!(
                any_type_name(&item).starts_with("kiapi.board.types.") && !item.value.is_empty(),
                "invalid board item envelope"
            );
            if any_is(&item, TRACK) {
                let mut track = board::Track::decode(item.value.as_slice())?;
                normalize_net(&mut track.net);
                if track.id.as_ref().is_some_and(|id| id.value == uuid) {
                    validate_track(&track, uuid)?;
                    ensure!(
                        target.replace(proto_hex(&track)).is_none(),
                        "duplicate target Track"
                    );
                }
                item.value = track.encode_to_vec();
            } else if any_is(&item, "kiapi.board.types.Arc") {
                let mut arc = board::Arc::decode(item.value.as_slice())?;
                normalize_net(&mut arc.net);
                item.value = arc.encode_to_vec();
            } else if any_is(&item, "kiapi.board.types.Via") {
                let mut via = board::Via::decode(item.value.as_slice())?;
                normalize_net(&mut via.net);
                item.value = via.encode_to_vec();
            } else if any_is(&item, GROUP) {
                let group = board::Group::decode(item.value.as_slice())?;
                let id = group.id.as_ref().context("Group has no KIID")?;
                ensure!(
                    !id.value.is_empty() && group.items.iter().all(|id| !id.value.is_empty()),
                    "incomplete Group identity/membership"
                );
                ensure!(
                    groups.insert(id.value.clone(), proto_hex(&group)).is_none(),
                    "duplicate Group KIID"
                );
            }
            // Other classes retain their exact Any payload, not a lossy summary.
            items.push(Item {
                type_url: item.type_url,
                proto_hex: hex(&item.value),
            });
        }
        items.sort();
        let target_track_hex =
            target.context("UUID is not a complete straight Track on the requested board")?;
        let saved_document = self.saved_board(document, deadline)?;
        ensure!(
            self.prove_context(document, deadline)? == version,
            "KiCad version changed during snapshot"
        );
        if before != saved_document {
            return Ok(None); // Undo or an external edit crossed the read sequence.
        }
        Ok(Some(Snapshot {
            version_hex: proto_hex(&version),
            document_hex: proto_hex(document),
            server_token: self.token.clone(),
            target_track_hex,
            groups,
            item_types,
            items,
            saved_document,
        }))
    }
}

fn normalize_net(net: &mut Option<board::Net>) {
    if let Some(net) = net {
        net.code = None;
    }
}

fn validate_track(track: &board::Track, uuid: &str) -> Result<()> {
    ensure!(
        track.id.as_ref().is_some_and(|id| id.value == uuid),
        "Track identity mismatch"
    );
    ensure!(
        matches!(
            track.locked(),
            common::LockedState::LsLocked | common::LockedState::LsUnlocked
        ),
        "unknown Track lock state"
    );
    ensure!(
        track.start.is_some()
            && track.end.is_some()
            && track.start != track.end
            && track.width.as_ref().is_some_and(|width| width.value_nm > 0)
            && track.net.is_some(),
        "incomplete Track geometry/net"
    );
    ensure!(
        track.parent.as_ref().is_none_or(|id| !id.value.is_empty()),
        "empty Track parent KIID"
    );
    Ok(())
}

fn geometry_only(before: &board::Track, current: &board::Track) -> Result<()> {
    ensure!(
        current != before,
        "target Track has no real change from baseline"
    );
    let mut restored = current.clone();
    restored.start = before.start;
    restored.end = before.end;
    restored.width = before.width;
    ensure!(&restored == before, "only target start/end/width may change; UUID, lock, parent, layer and net must remain unchanged");
    Ok(())
}

fn preflight(baseline: &Snapshot, current: &Snapshot, uuid: &str) -> Result<()> {
    ensure!(
        baseline.document_hex == current.document_hex
            && baseline.version_hex == current.version_hex
            && baseline.server_token == current.server_token
            && baseline.item_types == current.item_types
            && baseline.saved_document.document_hex == current.saved_document.document_hex,
        "baseline document/version/instance/read scope differs"
    );
    let before = board::Track::decode(unhex(&baseline.target_track_hex)?.as_slice())?;
    let after = board::Track::decode(unhex(&current.target_track_hex)?.as_slice())?;
    validate_track(&before, uuid)?;
    validate_track(&after, uuid)?;
    geometry_only(&before, &after)?;
    ensure!(
        baseline.groups == current.groups,
        "Group/membership changed before Undo"
    );
    let mut restored_items = current.items.clone();
    let mut replaced = 0;
    for item in &mut restored_items {
        if item.type_url.rsplit('/').next() == Some(TRACK)
            && item.proto_hex == current.target_track_hex
        {
            item.proto_hex = baseline.target_track_hex.clone();
            replaced += 1;
        }
    }
    restored_items.sort();
    ensure!(
        replaced == 1 && restored_items == baseline.items,
        "non-target board-item/copper state changed"
    );
    ensure!(
        current.saved_document.contents != baseline.saved_document.contents,
        "serialized board has no real change"
    );

    // Economically rule out edits to unmodelled items/settings too. Normalize
    // only the three permitted target geometry nodes for this preflight check;
    // post-Undo verification below still demands exact serialized bytes.
    let old = parse_sexp(&baseline.saved_document.contents)?;
    let mut new = parse_sexp(&current.saved_document.contents)?;
    let segments: Vec<_> = old
        .find_all("segment")
        .into_iter()
        .filter(|node| node.find_str("uuid") == Some(uuid))
        .collect();
    ensure!(
        segments.len() == 1,
        "baseline serialization has no unique target segment"
    );
    let SexpNode::List(children) = &mut new else {
        bail!("invalid serialized PCB");
    };
    let indices: Vec<_> = children
        .iter()
        .enumerate()
        .filter(|(_, node)| node.head() == Some("segment") && node.find_str("uuid") == Some(uuid))
        .map(|(i, _)| i)
        .collect();
    ensure!(
        indices.len() == 1,
        "current serialization has no unique target segment"
    );
    let SexpNode::List(fields) = &mut children[indices[0]] else {
        bail!("invalid segment");
    };
    for name in ["start", "end", "width"] {
        let slots: Vec<_> = fields
            .iter()
            .enumerate()
            .filter(|(_, node)| node.head() == Some(name))
            .map(|(i, _)| i)
            .collect();
        ensure!(
            slots.len() == 1 && segments[0].find_all(name).len() == 1,
            "incomplete/duplicate segment geometry"
        );
        fields[slots[0]] = segments[0]
            .find(name)
            .context("missing baseline geometry")?
            .clone();
    }
    ensure!(
        new == old,
        "serialized board changed outside the target geometry"
    );
    Ok(())
}

fn submit_undo(wire: &mut Wire, journal: &mut Journal) -> Result<bool> {
    journal.data["phase"] = json!("undo_intent");
    journal.data["submission"] = json!("intent_recorded_do_not_repeat");
    journal.data["action"] = json!({ "name": UNDO, "invocation_count": 1, "timer_resends": "disabled", "socket_lifetime_ms": 5000 });
    journal.persist()?; // No request is sent unless intent has been synced.
    let mut sent = false;
    let reply = wire.exchange(
        &command::RunAction {
            action: UNDO.into(),
        },
        "kiapi.common.commands.RunAction",
        Instant::now() + SOCKET_BUDGET,
        &mut sent,
    );
    journal.data["send_attempted"] = json!(sent);
    let result = (|| -> Result<bool> {
        let bytes = reply?;
        journal.data["action_response_hex"] = json!(hex(&bytes));
        journal.persist()?;
        let response = api::ApiResponse::decode(bytes.as_slice())?;
        journal.data["api_status"] = json!(response.status.as_ref().map(|status| status.status));
        let body = wire.body(response, "kiapi.common.commands.RunActionResponse")?;
        let response = command::RunActionResponse::decode(body.value.as_slice())?;
        journal.data["action_status"] = json!(response.status);
        match command::RunActionStatus::try_from(response.status)
            .context("unknown action status")?
        {
            command::RunActionStatus::RasOk => Ok(true),
            command::RunActionStatus::RasInvalid | command::RunActionStatus::RasFrameNotOpen => {
                Ok(false)
            }
            _ => bail!("action response does not establish submission"),
        }
    })();
    let accepted = match result {
        Ok(accepted) => {
            journal.data["submission"] = json!(if accepted {
                "accepted_deferred"
            } else {
                "rejected"
            });
            accepted
        }
        Err(error) => {
            let rejected = ApiStatusError::from_error(&error)
                .is_some_and(|status| matches!(status.code, 3..=8));
            journal.data["submission"] = json!(if !sent {
                "not_sent"
            } else if rejected {
                "rejected"
            } else {
                "uncertain"
            });
            journal.data["submission_error"] = json!(format!("{error:#}"));
            false
        }
    };
    journal.persist()?;
    Ok(accepted)
}

fn probe(
    mode: &str,
    endpoint: &str,
    board_path: &Path,
    uuid: &str,
    baseline_path: Option<&str>,
    journal: &mut Journal,
) -> Result<()> {
    let mut wire = Wire {
        endpoint: endpoint.into(),
        token: std::env::var("KICAD_API_TOKEN").unwrap_or_default(),
    };
    let client = KiCadIpcClient::new_with_token(endpoint, &wire.token);
    let version = client.get_kicad_version()?;
    ensure!(
        (version.major, version.minor, version.patch) == (10, 0, 6),
        "requires KiCad 10.0.6"
    );
    let document = client.find_open_board(board_path)?;
    ensure!(
        document.r#type == common::DocumentType::DoctypePcb as i32
            && client.get_open_documents()? == [document.clone()],
        "requested board is not the exact sole endpoint-local PCB"
    );
    journal.data["kicad_version"] = json!(version);
    journal.data["document_hex"] = json!(proto_hex(&document));
    journal.data["phase"] = json!("capturing");
    journal.persist()?;
    let current = wire
        .snapshot(&document, uuid, Instant::now() + READ_BUDGET)?
        .context("board changed during pre-action snapshot; no action sent")?;
    if mode == "snapshot" {
        journal.data["snapshot"] = serde_json::to_value(current)?;
        journal.data["phase"] = json!("snapshot_complete");
        return Ok(());
    }
    journal.data["before_undo"] = serde_json::to_value(&current)?;
    journal.persist()?;
    let baseline_json: Value =
        serde_json::from_reader(File::open(baseline_path.context("baseline required")?)?)?;
    ensure!(
        baseline_json["schema"] == SCHEMA
            && baseline_json["mode"] == "snapshot"
            && baseline_json["phase"] == "snapshot_complete"
            && baseline_json["ok"] == true,
        "baseline is not a completed workbench snapshot"
    );
    for key in ["endpoint", "board", "uuid"] {
        ensure!(
            baseline_json[key] == journal.data[key],
            "baseline {key} mismatch"
        );
    }
    let baseline: Snapshot = serde_json::from_value(baseline_json["snapshot"].clone())?;
    preflight(&baseline, &current, uuid)?;
    wire.prove_context(&document, Instant::now() + SOCKET_BUDGET)?;
    let accepted = submit_undo(&mut wire, journal)?;
    ensure!(
        accepted || journal.data["submission"] == "uncertain",
        "Undo submission failed; do not issue another Undo"
    );

    let started = Instant::now();
    let deadline = started + READ_BUDGET;
    let mut attempts = 0;
    journal.data["phase"] = json!("polling_reads_only");
    journal.data["poll"] = json!({ "budget_ms": 8000, "attempts": 0 });
    journal.persist()?;
    while Instant::now() < deadline {
        attempts += 1;
        let observation = wire.snapshot(&document, uuid, deadline);
        journal.data["poll"]["attempts"] = json!(attempts);
        journal.data["poll"]["elapsed_ms"] = json!(started.elapsed().as_millis());
        match observation {
            Ok(Some(observed)) => {
                let restored = observed == baseline;
                journal.data["last_observation"] = serde_json::to_value(observed)?;
                journal.data["effect"] = json!(if restored {
                    "baseline_observed"
                } else {
                    "baseline_not_observed"
                });
                if restored {
                    journal.data["live_undo_verified"] = json!(accepted);
                    journal.data["phase"] = json!(if accepted {
                        "live_undo_verified"
                    } else {
                        "baseline_observed_submission_uncertain"
                    });
                    journal.persist()?;
                    ensure!(
                        accepted,
                        "baseline returned, but strict action submission was not confirmed"
                    );
                    return Ok(());
                }
            }
            Ok(None) => {
                journal.data["poll"]["last_read_error"] =
                    json!("board changed during read sequence");
            }
            Err(error) => {
                journal.data["poll"]["last_read_error"] = json!(format!("{error:#}"));
                journal.data["effect"] = json!("unverified");
                journal.persist()?;
                let busy = ApiStatusError::from_error(&error)
                    .is_some_and(|status| status.code == api::ApiStatusCode::AsBusy as i32);
                ensure!(
                    busy && Instant::now() < deadline,
                    "post-Undo observation failed: {error:#}; no action will be repeated"
                );
            }
        }
        journal.persist()?;
        std::thread::sleep(
            Duration::from_millis(50).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    journal.data["phase"] = json!("verification_timed_out");
    bail!("baseline did not return within the eight-second read budget; submission is not Undo-effect proof")
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    ensure!((mode == "snapshot" && args.len() == 6) || (mode == "undo" && args.len() == 7), "usage: workbench_probe snapshot <endpoint> <board> <uuid> <output-json> | undo <endpoint> <board> <uuid> <baseline-json> <output-json>");
    ensure!(
        !args[2].is_empty() && !args[4].is_empty(),
        "endpoint and UUID must be nonempty"
    );
    let endpoint = if args[2].contains("://") {
        args[2].clone()
    } else {
        format!("ipc://{}", args[2])
    };
    let board_path = fs::canonicalize(&args[3]).context("canonicalize existing board")?;
    ensure!(board_path.is_file(), "board must be an existing file");
    let board_name = board_path.to_str().context("board path must be UTF-8")?;
    let baseline_path = if mode == "undo" {
        Some(args[5].as_str())
    } else {
        None
    };
    let mut journal = Journal::new(
        Path::new(args.last().context("output required")?),
        json!({
            "schema": SCHEMA, "mode": mode, "endpoint": endpoint, "board": board_name, "uuid": args[4],
            "baseline": baseline_path, "phase": "preflight", "ok": false,
            "submission": "not_attempted", "effect": "unverified", "live_undo_verified": false,
            "save_reopen": "not_performed_parent_owned",
            "limitations": ["Endpoint-local sole PCB is not global GUI/focus proof", "Req0 peer-disconnect resends cannot guarantee exactly-once delivery", "RunAction names are version-specific prototyping, not a stable API"]
        }),
    )?;
    let result = probe(
        mode,
        &endpoint,
        &board_path,
        &args[4],
        baseline_path,
        &mut journal,
    );
    journal.data["ok"] = json!(result.is_ok());
    if let Err(error) = &result {
        journal.data["error"] = json!(format!("{error:#}"));
    }
    journal.persist().context(
        "persist final verification journal; any recorded Undo intent must not be repeated",
    )?;
    result
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_guard_and_hex_fail_closed() {
        let before = board::Track {
            id: Some(common::Kiid {
                value: "target".into(),
            }),
            locked: common::LockedState::LsLocked as i32,
            parent: Some(common::Kiid {
                value: "group".into(),
            }),
            width: Some(common::Distance { value_nm: 250_000 }),
            ..Default::default()
        };
        assert!(geometry_only(&before, &before).is_err());
        let mut after = before.clone();
        after.width = Some(common::Distance { value_nm: 300_000 });
        assert!(geometry_only(&before, &after).is_ok());
        after.parent = None;
        assert!(geometry_only(&before, &after).is_err());
        after.parent = before.parent.clone();
        after.locked = common::LockedState::LsUnlocked as i32;
        assert!(geometry_only(&before, &after).is_err());
        assert_eq!(unhex(&proto_hex(&before)).unwrap(), before.encode_to_vec());
        for invalid in ["0", "gg", "é"] {
            assert!(unhex(invalid).is_err());
        }
    }
}
