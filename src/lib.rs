//! # hop-ffi
//!
//! The cross-platform binding surface (DESIGN.md §12): a thin, UniFFI-exported
//! wrapper around [`hop_core::node::Node`]. The host app links this (as a
//! `cdylib`/`staticlib`), runs the BLE bearer natively, and drives the node loop
//! through [`HopNode`] — feeding connection/data events in, draining outgoing
//! bytes out, and reading the inbox.
//!
//! Native bindings (Swift/Kotlin) are generated from this crate with the
//! `uniffi-bindgen` CLI; the exported types below are what those bindings expose.
//! Everything here is also callable from Rust, so the loop is testable end to end
//! without a device (see the tests).

use std::sync::{Arc, Mutex};

use hop_core::prelude::*;
use hop_store_sqlite::SqliteStore;

/// libhop — the stable C ABI (cbindgen → `include/hop.h`): the universal client SDK + bearer seam,
/// for every non-UniFFI target (C/C++, ESP32, …). Wraps the SAME `HopNode` as the UniFFI surface.
pub mod cabi;

uniffi::setup_scaffolding!();

/// Build an identity from saved secret bytes, or a fresh one if absent/invalid.
fn identity_from(secret: &[u8]) -> Identity {
    match <[u8; 32]>::try_from(secret) {
        Ok(b) => Identity::from_secret_bytes(&b),
        Err(_) => Identity::generate(),
    }
}

/// Render an address as base58 (compact, copy/paste/QR-friendly).
#[uniffi::export]
pub fn address_base58(address: Vec<u8>) -> String {
    bs58::encode(address).into_string()
}

/// Decode a base58 address back to bytes (empty on invalid input).
#[uniffi::export]
pub fn address_from_base58(text: String) -> Vec<u8> {
    bs58::decode(text).into_vec().unwrap_or_default()
}

/// Hex of a short (8-byte) trace hop for display.
fn hex8(b: &[u8; 8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The 8-byte short form of a full address — matches what trace hops carry, so the app
/// can index its known addresses by this and resolve trace hops to display names (§27).
#[uniffi::export]
pub fn short_address(address: Vec<u8>) -> Vec<u8> {
    match to32(&address) {
        Ok(a) => short_addr(&a).to_vec(),
        Err(_) => Vec::new(),
    }
}

/// The built-in identity service name (`hop.identify`) — call it on a peer to learn its
/// display name + kind (DESIGN.md §29).
#[uniffi::export]
pub fn service_identify() -> String {
    SERVICE_IDENTIFY.to_string()
}

/// Decode a `hop.identify` response body into an [`IdentityInfo`]. Returns `None` if the
/// bytes aren't a valid identity record (e.g. the response was for a different service).
#[uniffi::export]
pub fn decode_identity(body: Vec<u8>) -> Option<IdentityInfo> {
    let rec: IdentityRecord = postcard::from_bytes(&body).ok()?;
    Some(IdentityInfo {
        address: rec.address.to_vec(),
        name: rec.name.unwrap_or_default(),
        kind: match rec.kind {
            NodeKind::Device => "device",
            NodeKind::Relay => "relay",
            NodeKind::Gateway => "gateway",
            NodeKind::Endpoint => "endpoint",
        }
        .to_string(),
    })
}

/// Human label for a trace hop's carrying app (DESIGN.md §27). Only public infra
/// nodes self-identify ("Hop Relay"); end-user devices stamp the generic fabric app
/// so a trace never advertises which app a device runs (privacy, §27).
fn label_app(app: &ShortApp) -> String {
    if *app == short_app(&relay_app_id()) {
        "Hop Relay".to_string()
    } else if *app == short_app(&FABRIC_APP) {
        "device".to_string()
    } else {
        hex8(app)
    }
}

/// Opaque bytes to ship over the bearer on a given connection.
#[derive(uniffi::Record)]
pub struct OutPacket {
    pub link: u64,
    pub bytes: Vec<u8>,
}

/// A decrypted message delivered to this node.
#[derive(uniffi::Record)]
pub struct InboxMessage {
    /// Sender's hop address (Ed25519 public key).
    pub from: Vec<u8>,
    pub content_type: String,
    pub body: Vec<u8>,
    /// How many hops it travelled to reach us (A→B path length).
    pub hops: u8,
    /// Sender's clock (ms) when the message was created — signed by the sender.
    /// Subtract from local receive time for an end-to-end latency estimate.
    pub created_at: u64,
    /// Provenance: one hop per node that forwarded this message, in order (DESIGN.md
    /// §27). Empty for a direct (0-relay) delivery. Each hop carries the forwarder's
    /// 8-byte short address (resolve it against your address book to a display name via
    /// `short_address`) plus a label for the carrying app.
    pub trace: Vec<TraceHopInfo>,
}

/// One forwarding hop in a message's provenance trace (DESIGN.md §27).
#[derive(uniffi::Record)]
pub struct TraceHopInfo {
    /// The forwarder's 8-byte short address. Compare to `short_address(full)` of a known
    /// peer/relay/contact to resolve it to a display name; show hex if unknown.
    pub node: Vec<u8>,
    /// Carrying-app label: "Hop Relay" for infra, "device" for end-user nodes, else hex.
    pub app_label: String,
}

/// A node's identity, decoded from a `hop.identify` response (DESIGN.md §29).
#[derive(uniffi::Record)]
pub struct IdentityInfo {
    /// The node's full hop address.
    pub address: Vec<u8>,
    /// Display name, if the node set one. Empty string = unset → show the short address
    /// (devices are unnamed by default; relays report their region domain).
    pub name: String,
    /// "device" | "relay" | "gateway".
    pub kind: String,
}

/// A custom (non-`hop.`) service request addressed to this node for the app to fulfill.
#[derive(uniffi::Record)]
pub struct ServiceReq {
    pub from: Vec<u8>,
    /// Request id — pass back to `send_service_response` as `for_request_id`.
    pub request_id: Vec<u8>,
    pub service: String,
    pub method: String,
    pub args: Vec<u8>,
}

/// A service response sealed back to this node as a caller.
#[derive(uniffi::Record)]
pub struct ServiceResp {
    pub from: Vec<u8>,
    pub for_request_id: Vec<u8>,
    pub status: u16,
    pub body: Vec<u8>,
}

/// A service advert discovered via gossip (direct or relayed). The `publisher` is
/// the address to message — its sealing key is derived from it. Apps build presence
/// and contacts on this (e.g. a "presence" service whose `title` is a display name).
#[derive(uniffi::Record)]
pub struct ServiceHit {
    /// Publisher's hop address (Ed25519 public key) — message this to reach them.
    pub publisher: Vec<u8>,
    pub service: String,
    pub title: String,
    pub summary: String,
    pub tags: Vec<String>,
    /// Hops away through the mesh (1 = direct neighbour, ≥2 = via relays; 0 = unknown).
    pub hops: u8,
    /// Publisher clock (ms) when this advert was created — lets the app pick the
    /// freshest record per publisher (e.g. current foreground/background state).
    pub created_at: u64,
}

/// An egress HTTP request a gateway should fulfill (Use Case A, §9).
#[derive(uniffi::Record)]
pub struct HttpReq {
    /// Requester's address (seal the response back to this).
    pub from: Vec<u8>,
    /// The request bundle id (pass back as `for_request_id`).
    pub request_id: Vec<u8>,
    /// The authorized target domain (the endpoint validates this against its own origin).
    pub host: String,
    pub method: String,
    pub url: String,
    pub body: Vec<u8>,
    pub max_resp: u32,
}

/// An HTTP response sealed back to the requester.
#[derive(uniffi::Record)]
pub struct HttpResp {
    pub from: Vec<u8>,
    pub for_request_id: Vec<u8>,
    pub status: u16,
    /// The response's content-type (e.g. `text/html`), so a WebView renders it correctly.
    /// Empty if the responder didn't set one.
    pub content_type: String,
    pub body: Vec<u8>,
}

/// A finished HNS resolution (DESIGN.md §30). `address` empty = the domain has no
/// `_hopaddress` record (a resolution error, e.g. `hops://thisdoesnotexist.com`).
#[derive(uniffi::Record)]
pub struct HnsRecord {
    pub domain: String,
    pub address: Vec<u8>,
}

/// A live HNS cache entry for the debug view (DESIGN.md §30). `address` empty = a cached
/// negative; `ttl_secs` is the remaining lifetime, ticking down to expiry.
#[derive(uniffi::Record)]
pub struct HnsCacheEntry {
    pub domain: String,
    pub address: Vec<u8>,
    pub ttl_secs: u32,
}

/// Outcome of starting an HNS resolution (DESIGN.md §30).
#[derive(uniffi::Enum)]
pub enum HnsLookupResult {
    /// Served from a fresh cache entry. `address` empty = a cached negative.
    Cached { address: Vec<u8> },
    /// A lookup was kicked off; the result arrives via `take_hns_results`. If this device
    /// is internet-connected the host must service `take_dns_lookups`.
    Pending,
    /// This device has no internet and no resolver was given — call `resolve_hns_via` with a
    /// known internet-connected peer (e.g. a relay address).
    NeedsResolver,
}

/// The kind of `hps://` topic hosted at a path (DESIGN.md §32).
#[derive(uniffi::Enum)]
pub enum HpsKind {
    /// Anyone with the content key reads AND writes; each post signed by its writer.
    Channel,
    /// Only the owner broadcasts (signed by the service key); subscribers read.
    Service,
}

/// Who may obtain a topic's keys (DESIGN.md §32).
#[derive(uniffi::Enum)]
pub enum HpsAccess {
    /// Keys handed to anyone who asks (anonymous membership).
    Open,
    /// Requester asks; the host approves before keys are handed off.
    RequestToJoin,
    /// Host invites a destination; the destination accepts, then receives keys.
    Invite,
}

/// Whether a topic announces itself for discovery (DESIGN.md §32).
#[derive(uniffi::Enum)]
pub enum HpsVisibility {
    /// Reachable only by known address+path or an invite.
    Private,
    /// Host broadcasts an (app-encrypted) discovery advert so same-app peers can browse it.
    Discoverable,
}

/// A received `hps://` message, after decryption + sender verification (DESIGN.md §32).
#[derive(uniffi::Record)]
pub struct HpsMessage {
    pub path: String,
    /// The verified sender's address (for a channel, the writer; for a service, the host).
    pub sender: Vec<u8>,
    pub body: Vec<u8>,
}

/// An invite we (member) received and may accept (DESIGN.md §32 Invite mode).
#[derive(uniffi::Record)]
pub struct HpsInvite {
    pub path: String,
    pub host: Vec<u8>,
    pub kind: HpsKind,
}

/// A discoverable topic surfaced by `browse_discoverable` (same-app only).
#[derive(uniffi::Record)]
pub struct HpsTopicInfo {
    pub host: Vec<u8>,
    pub path: String,
    pub kind: HpsKind,
    pub title: String,
    pub summary: String,
    pub access: HpsAccess,
}

/// A topic we host or follow — for rebuilding the app's channel list after a restart.
#[derive(uniffi::Record)]
pub struct HpsMyTopic {
    pub host: Vec<u8>,
    pub path: String,
    pub kind: HpsKind,
    pub hosting: bool,
    pub access: HpsAccess,
}

fn kind_to_core(k: &HpsKind) -> hop_core::hps::ServiceKind {
    match k {
        HpsKind::Channel => hop_core::hps::ServiceKind::Channel,
        HpsKind::Service => hop_core::hps::ServiceKind::Service,
    }
}
fn kind_from_core(k: hop_core::hps::ServiceKind) -> HpsKind {
    match k {
        hop_core::hps::ServiceKind::Channel => HpsKind::Channel,
        hop_core::hps::ServiceKind::Service => HpsKind::Service,
    }
}
fn access_to_core(a: &HpsAccess) -> hop_core::hps::AccessMode {
    match a {
        HpsAccess::Open => hop_core::hps::AccessMode::Open,
        HpsAccess::RequestToJoin => hop_core::hps::AccessMode::RequestToJoin,
        HpsAccess::Invite => hop_core::hps::AccessMode::Invite,
    }
}
fn access_from_core(a: hop_core::hps::AccessMode) -> HpsAccess {
    match a {
        hop_core::hps::AccessMode::Open => HpsAccess::Open,
        hop_core::hps::AccessMode::RequestToJoin => HpsAccess::RequestToJoin,
        hop_core::hps::AccessMode::Invite => HpsAccess::Invite,
    }
}
fn vis_to_core(v: &HpsVisibility) -> hop_core::hps::Visibility {
    match v {
        HpsVisibility::Private => hop_core::hps::Visibility::Private,
        HpsVisibility::Discoverable => hop_core::hps::Visibility::Discoverable,
    }
}

/// A live link to a directly-connected peer: its address + the bearer link id. The
/// host maps the link id to a transport (e.g. < 10000 = Bluetooth, ≥ 10000 = Wi-Fi).
#[derive(uniffi::Record)]
pub struct PeerLink {
    pub address: Vec<u8>,
    pub link: u64,
}

/// Delivery status of a message we sent (Sending / Sent N / Delivered).
#[derive(uniffi::Record)]
pub struct MessageStatus {
    /// Distinct peers we've handed a copy to ("Sent N").
    pub relayed: u32,
    /// The destination confirmed receipt back across the network.
    pub delivered: bool,
    /// Forward path length the destination observed (hops to delivery; 0 until delivered).
    pub delivery_hops: u8,
    /// **Forward-path** (A→B) latency in ms the destination observed and reported in its ACK —
    /// how long the message took to *reach* the recipient, NOT the round trip. 0 until delivered.
    pub delivery_ms: u32,
}

/// An item in the relay queue: ours awaiting send, or a peer's awaiting relay.
#[derive(uniffi::Record)]
pub struct QueueItem {
    pub id: Vec<u8>,
    /// True = our own message (pinned). False = relaying for a peer (decays).
    pub own: bool,
    /// Destination address (empty if internet-egress).
    pub to: Vec<u8>,
    pub priority: u8,
    pub hops: u8,
}

/// Errors crossing the FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("invalid key length (want 32 bytes)")]
    BadKey,
    #[error("hop error: {0}")]
    Hop(String),
}

fn to32(v: &[u8]) -> std::result::Result<[u8; 32], FfiError> {
    v.try_into().map_err(|_| FfiError::BadKey)
}

/// A running Hop node the host drives. Thread-safe (interior `Mutex`), handed to
/// the foreign side as a reference-counted object.
#[derive(uniffi::Object)]
pub struct HopNode {
    inner: Mutex<Node<SqliteStore>>,
    /// True iff this node has durable storage. `open` sets it false only when the db path was
    /// unusable even after quarantine, so the host can tell the difference between persistent
    /// and silently-ephemeral (F-26). `new`/`with_secret` are ephemeral by construction.
    persistent: bool,
    /// How many persisted records failed to decode on startup (F-03) — non-zero means an
    /// upgrade changed a struct layout and dropped state; the host should surface it.
    rehydrate_dropped: u32,
}

/// Open the persistent store, or if the file is unusable, quarantine it and retry once so a
/// corrupt/read-only db becomes a clean fresh start rather than permanent per-launch amnesia.
/// Returns `(store, persistent)`; only falls back to in-memory if even a fresh file won't open.
/// See F-26 — the old code did `open(path).or_else(in_memory)`, so a bad path silently ran
/// ephemeral forever with no signal to the host.
fn open_store_persistent(db_path: &str, key: &[u8]) -> (SqliteStore, bool) {
    // F-25: an empty key opens plain; a 32-byte key opens SQLCipher-encrypted (under the store's
    // `sqlcipher` feature). Same quarantine-on-failure behavior either way.
    if let Ok(s) = SqliteStore::open_keyed(db_path, key) {
        return (s, true);
    }
    let quarantine = format!("{db_path}.corrupt");
    let _ = std::fs::remove_file(&quarantine);
    if std::fs::rename(db_path, &quarantine).is_ok() {
        if let Ok(s) = SqliteStore::open_keyed(db_path, key) {
            eprintln!(
                "hop: quarantined unusable db to {quarantine}; started a fresh persistent store"
            );
            return (s, true);
        }
    }
    eprintln!(
        "hop: WARNING db path {db_path} is unusable even after quarantine; running EPHEMERAL \
         (state will NOT survive restart). is_persistent() is false."
    );
    (
        SqliteStore::open_in_memory().expect("in-memory sqlite"),
        false,
    )
}

/// Shared body of the `open` / `open_keyed` UniFFI constructors (F-25). A free function because UniFFI
/// doesn't allow a private associated fn inside an exported impl.
fn open_node_inner(db_path: &str, secret: &[u8], app_secret: &[u8], key: &[u8]) -> Arc<HopNode> {
    let (store, persistent) = open_store_persistent(db_path, key);
    let mut node = Node::with_store(identity_from(secret), store);
    if let Ok(s) = <[u8; 32]>::try_from(app_secret) {
        node.set_app_keys(hop_core::app::AppKeys::from_secret(s));
    }
    // Surface any state silently lost to a struct-layout change across an upgrade (F-03).
    let report = node.take_rehydrate_report();
    if !report.is_empty() {
        eprintln!(
            "hop: rehydrate dropped {} persisted record(s) across an upgrade: {:?}",
            report.total(),
            report.dropped
        );
    }
    Arc::new(HopNode {
        inner: Mutex::new(node),
        persistent,
        rehydrate_dropped: report.total(),
    })
}

#[uniffi::export]
impl HopNode {
    /// Create a node with a fresh identity and ephemeral in-memory storage.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        let store = SqliteStore::open_in_memory().expect("in-memory sqlite");
        Arc::new(Self {
            inner: Mutex::new(Node::with_store(Identity::generate(), store)),
            persistent: false,
            rehydrate_dropped: 0,
        })
    }

    /// Restore a node from a saved identity secret with ephemeral storage. Pass
    /// empty/invalid bytes to get a fresh identity.
    #[uniffi::constructor]
    pub fn with_secret(secret: Vec<u8>) -> Arc<Self> {
        let store = SqliteStore::open_in_memory().expect("in-memory sqlite");
        Arc::new(Self {
            inner: Mutex::new(Node::with_store(identity_from(&secret), store)),
            persistent: false,
            rehydrate_dropped: 0,
        })
    }

    /// Open a node with **persistent** storage at `db_path` (messages survive
    /// restarts; bounded — older relayed messages are evicted to make room), a
    /// saved identity secret, and a 32-byte **app secret** that isolates this app's
    /// `hps://` channels/services from other apps (DESIGN.md §32). Pass empty/short
    /// app-secret bytes to stay on the open shared fabric. If the path can't be opened it is
    /// quarantined and reopened fresh; only if that also fails does it run ephemeral, and then
    /// [`HopNode::is_persistent`] returns false so the host can tell (F-26).
    #[uniffi::constructor]
    pub fn open(db_path: String, secret: Vec<u8>, app_secret: Vec<u8>) -> Arc<Self> {
        open_node_inner(&db_path, &secret, &app_secret, &[])
    }

    /// Like [`HopNode::open`], but ENCRYPTS the store at rest with a raw 32-byte `key` the host derives
    /// and stores in the platform Keychain/Keystore (F-25). Real encryption requires the store's
    /// `sqlcipher` cargo feature; without it the key is accepted but the db stays plain. An empty key
    /// behaves exactly like `open`.
    #[uniffi::constructor]
    pub fn open_keyed(
        db_path: String,
        secret: Vec<u8>,
        app_secret: Vec<u8>,
        key: Vec<u8>,
    ) -> Arc<Self> {
        open_node_inner(&db_path, &secret, &app_secret, &key)
    }

    /// Whether this node has durable storage. `false` means the db path was unusable and state
    /// will NOT survive a restart; the host should surface a warning rather than assume the
    /// database is the ground truth (F-26).
    pub fn is_persistent(&self) -> bool {
        self.persistent
    }

    /// How many persisted records failed to decode on startup (F-03). Non-zero means an upgrade
    /// changed a struct's on-disk layout and dropped that state; the host should tell the user
    /// (e.g. queued sends or sessions were lost) instead of it vanishing silently.
    pub fn rehydrate_dropped(&self) -> u32 {
        self.rehydrate_dropped
    }

    // Note: there is intentionally no `set_app` here. End-user devices must NOT stamp
    // their app id into trace hops — that would advertise which app a device runs to
    // every relay on the path (DESIGN.md §27 privacy). Devices stay on FABRIC_APP;
    // only infra relays self-identify (hop-relayd calls Node::set_app(relay_app_id())).

    /// Export this node's identity secret to persist (store it in the Keychain).
    pub fn secret(&self) -> Vec<u8> {
        self.inner.lock().unwrap().identity_secret().to_vec()
    }

    /// This node's hop address (Ed25519 public key).
    pub fn address(&self) -> Vec<u8> {
        self.inner.lock().unwrap().address().to_vec()
    }

    /// A bearer connection came up; `initiator` = we dialed it (BLE central).
    pub fn connected(&self, link: u64, initiator: bool) {
        let role = if initiator {
            Role::Initiator
        } else {
            Role::Responder
        };
        self.inner
            .lock()
            .unwrap()
            .handle(BearerEvent::Connected(link, role));
    }

    /// A bearer connection dropped.
    pub fn disconnected(&self, link: u64) {
        self.inner
            .lock()
            .unwrap()
            .handle(BearerEvent::Disconnected(link));
    }

    /// Bytes arrived on a connection.
    pub fn received(&self, link: u64, bytes: Vec<u8>) {
        self.inner
            .lock()
            .unwrap()
            .handle(BearerEvent::Data(link, bytes));
    }

    /// Bytes the host must send over the bearer (then clears them).
    pub fn drain_outgoing(&self) -> Vec<OutPacket> {
        self.inner
            .lock()
            .unwrap()
            .drain_outgoing()
            .into_iter()
            .map(|(link, bytes)| OutPacket { link, bytes })
            .collect()
    }

    /// Advance time: expire adverts, retransmit unacked bundles, prune dedup.
    pub fn tick(&self, now_ms: u64) {
        self.inner.lock().unwrap().tick(now_ms);
    }

    /// Subscribe the directory to a service topic.
    pub fn subscribe(&self, topic: String) {
        self.inner.lock().unwrap().subscribe(topic);
    }

    /// Send a peer message to `dst` (an address — sealing key is derived from it).
    /// **Untraceable by default** (DESIGN.md §39): no cleartext src/dst, the bundle floods
    /// and is recognized only by `dst`. Still forward-secret + sender-authenticated. Returns
    /// the bundle id. Set `request_ack` for a private delivery confirmation.
    pub fn send_message(
        &self,
        dst: Vec<u8>,
        content_type: String,
        body: Vec<u8>,
        request_ack: bool,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let dst = to32(&dst)?;
        let id = self
            .inner
            .lock()
            .unwrap()
            .send_message(dst, content_type, body, request_ack)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Send a peer message to `dst` with full §27 provenance — cleartext src/dst, route
    /// learning, relay-vaccinating ACKs. The **opt-in traced** path; prefer [`Self::send_message`]
    /// (untraceable) unless the user has explicitly chosen a traceable send.
    pub fn send_message_traced(
        &self,
        dst: Vec<u8>,
        content_type: String,
        body: Vec<u8>,
        request_ack: bool,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let dst = to32(&dst)?;
        let id = self
            .inner
            .lock()
            .unwrap()
            .send_message_traced(dst, content_type, body, request_ack)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Publish a signed service advert that gossips across the mesh (even multiple
    /// hops away). Returns the advert id. Apps build presence on this — e.g. publish
    /// a "presence" service whose `title` is the user's display name. `ttlMs` bounds
    /// how long the record lives before it must be refreshed.
    pub fn publish_service(
        &self,
        service: String,
        title: String,
        summary: String,
        tags: Vec<String>,
        ttl_ms: u32,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let id = self
            .inner
            .lock()
            .unwrap()
            .publish_service(service, title, summary, tags, ttl_ms)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Browse a service namespace (optionally filtered by tag) for adverts discovered
    /// across the mesh, with hop distance. Pass an empty `tag` for no filter.
    pub fn browse(&self, service: String, tag: String) -> Vec<ServiceHit> {
        let tag = if tag.is_empty() { None } else { Some(tag) };
        self.inner
            .lock()
            .unwrap()
            .browse(&service, tag.as_deref())
            .into_iter()
            .filter_map(|a| match a.body.kind {
                AdvertKind::Service {
                    service,
                    title,
                    summary,
                    tags,
                } => Some(ServiceHit {
                    publisher: a.body.publisher.to_vec(),
                    service,
                    title,
                    summary,
                    tags,
                    hops: a.hops,
                    created_at: a.body.created_at,
                }),
                _ => None,
            })
            .collect()
    }

    /// Delivery status of a message we sent, by its bundle id.
    pub fn message_status(&self, id: Vec<u8>) -> MessageStatus {
        let blank = MessageStatus {
            relayed: 0,
            delivered: false,
            delivery_hops: 0,
            delivery_ms: 0,
        };
        let id = match to32(&id) {
            Ok(i) => i,
            Err(_) => return blank,
        };
        match self.inner.lock().unwrap().message_status(&id) {
            Some((relayed, delivered, delivery_hops, delivery_ms)) => MessageStatus {
                relayed,
                delivered,
                delivery_hops,
                delivery_ms,
            },
            None => blank,
        }
    }

    /// Clear the relay queue: drop our undelivered messages (stop retransmitting) and any
    /// bundles held for peers. Does not touch chat history or sessions.
    pub fn clear_queue(&self) {
        self.inner.lock().unwrap().clear_queue();
    }

    /// The relay queue: our messages awaiting send (pinned) + peers' awaiting relay.
    pub fn queue(&self) -> Vec<QueueItem> {
        self.inner
            .lock()
            .unwrap()
            .queue()
            .into_iter()
            .map(|q| QueueItem {
                id: q.id.to_vec(),
                own: q.own,
                to: q.to.map(|a| a.to_vec()).unwrap_or_default(),
                priority: q.priority,
                hops: q.hops,
            })
            .collect()
    }

    /// Whether messaging `address` is forward-secret (a ratchet session exists)
    /// rather than static-sealed (DESIGN.md §25). Drives a lock indicator in the UI.
    pub fn is_secured(&self, address: Vec<u8>) -> bool {
        match to32(&address) {
            Ok(a) => self.inner.lock().unwrap().has_session(&a),
            Err(_) => false,
        }
    }

    /// Addresses of currently-connected, authenticated peers.
    pub fn peers(&self) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .unwrap()
            .peers()
            .iter()
            .map(|a| a.to_vec())
            .collect()
    }

    /// Whether this node has learned a live route toward `address` from observed
    /// deliveries (DESIGN.md §27). Drives a "known route" indicator in the UI.
    pub fn knows_route(&self, address: Vec<u8>) -> bool {
        match to32(&address) {
            Ok(a) => self.inner.lock().unwrap().knows_route(&a),
            Err(_) => false,
        }
    }

    /// Live links `(address, link id)` — the host maps link ids to transports to show
    /// the route to each direct neighbour.
    pub fn peer_links(&self) -> Vec<PeerLink> {
        self.inner
            .lock()
            .unwrap()
            .peer_links()
            .into_iter()
            .map(|(address, link)| PeerLink {
                address: address.to_vec(),
                link,
            })
            .collect()
    }

    /// Send a message to a directly-connected peer (sealed with the key learned at
    /// handshake). Returns the bundle id; errors if not connected to that address.
    pub fn send_to(
        &self,
        address: Vec<u8>,
        content_type: String,
        body: Vec<u8>,
        request_ack: bool,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let address = to32(&address)?;
        match self
            .inner
            .lock()
            .unwrap()
            .send_to(&address, content_type, body, request_ack)
            .map_err(|e| FfiError::Hop(e.to_string()))?
        {
            Some(id) => Ok(id.to_vec()),
            None => Err(FfiError::Hop("peer not connected".into())),
        }
    }

    /// Drain decrypted messages addressed to this node since the last call. Handles
    /// both static-sealed and forward-secret session messages uniformly.
    pub fn take_inbox(&self) -> Vec<InboxMessage> {
        let mut node = self.inner.lock().unwrap();
        let bundles = node.take_inbox();
        bundles
            .iter()
            .filter_map(|b| match node.read_message(b) {
                Ok(Some(m)) => Some(InboxMessage {
                    from: m.from.to_vec(),
                    content_type: m.content_type,
                    body: m.body,
                    hops: b.env.hops,
                    created_at: b.inner.created_at,
                    // Structured hops so the app can resolve each forwarder to a name.
                    trace: b
                        .trace()
                        .iter()
                        .map(|h| TraceHopInfo {
                            node: h.node.to_vec(),
                            app_label: label_app(&h.app),
                        })
                        .collect(),
                }),
                _ => None,
            })
            .collect()
    }

    /// Publish this node's prekey so peers can open forward-secret sessions to it
    /// (DESIGN.md §25). Call at startup and re-publish periodically. Returns the
    /// advert id.
    pub fn publish_prekey(&self) -> std::result::Result<Vec<u8>, FfiError> {
        let id = self
            .inner
            .lock()
            .unwrap()
            .publish_prekey()
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Number of locally-sent bundles still awaiting an ACK.
    pub fn pending_count(&self) -> u32 {
        self.inner.lock().unwrap().pending_count() as u32
    }

    /// Send a `hops://` request sealed and addressed to a specific endpoint's Hop address
    /// (DESIGN.md §30). `host` is the authorized domain (the endpoint validates it and
    /// refuses anything else); `url` is the path+query only. Returns the request bundle id;
    /// the response arrives via [`take_http_responses`].
    pub fn send_hops_request(
        &self,
        endpoint: Vec<u8>,
        host: String,
        method: String,
        url: String,
        body: Vec<u8>,
        max_resp: u32,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let ep = to32(&endpoint)?;
        let id = self
            .inner
            .lock()
            .unwrap()
            .send_hops_request(ep, host, method, url, vec![], body, max_resp)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    // ---- HNS: the Hop Name System (DESIGN.md §30) ----------------------------------------

    /// Declare whether this device can reach the public internet (and thus public DNS). When
    /// on, the host must service `take_dns_lookups` so the node can resolve HNS on its own
    /// without any relay round-trip.
    pub fn set_internet(&self, on: bool) {
        self.inner.lock().unwrap().set_internet(on);
    }

    /// Whether this device is marked internet-connected.
    pub fn is_internet(&self) -> bool {
        self.inner.lock().unwrap().is_internet()
    }

    /// Resolve `domain` to its hops endpoint address (DESIGN.md §30). See [`HnsLookupResult`].
    pub fn resolve_hns(&self, domain: String) -> HnsLookupResult {
        match self.inner.lock().unwrap().resolve_hns(&domain) {
            HnsLookup::Cached(Some(addr)) => HnsLookupResult::Cached {
                address: addr.to_vec(),
            },
            HnsLookup::Cached(None) => HnsLookupResult::Cached { address: vec![] },
            HnsLookup::Pending => HnsLookupResult::Pending,
            HnsLookup::NeedsResolver => HnsLookupResult::NeedsResolver,
        }
    }

    /// Resolve `domain` by asking a known internet-connected peer (e.g. a relay) over the
    /// mesh. The answer arrives via `take_hns_results`. Returns the query bundle id.
    pub fn resolve_hns_via(
        &self,
        resolver: Vec<u8>,
        domain: String,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let r = to32(&resolver)?;
        let id = self
            .inner
            .lock()
            .unwrap()
            .resolve_hns_via(r, &domain)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Domains the node needs the host to resolve (DESIGN.md §30). For each, fetch the full
    /// DNSSEC chain over DoH — the `_hopaddress.<domain>` TXT (`type=16`) plus, for every zone
    /// from the domain up to the root, DNSKEY (`type=48`) and DS (`type=43`) — all with `do=1`,
    /// then hand the raw response bodies to `provide_dns_proof`. Core validates; the host never
    /// decides the address.
    pub fn take_dns_lookups(&self) -> Vec<String> {
        self.inner.lock().unwrap().take_dns_lookups()
    }

    /// Feed back the raw DoH response bodies for a domain's chain. Core validates the DNSSEC
    /// chain to the root anchors and caches the address only if it verifies (DESIGN.md §30).
    pub fn provide_dns_proof(&self, domain: String, bodies: Vec<String>) {
        self.inner
            .lock()
            .unwrap()
            .provide_dns_proof(&domain, bodies);
    }

    /// A snapshot of the live HNS cache (for the debug view): each cached domain, its address
    /// (empty = negative), and the remaining TTL in seconds (ticks down to expiry).
    pub fn hns_cache(&self) -> Vec<HnsCacheEntry> {
        self.inner
            .lock()
            .unwrap()
            .hns_cache_snapshot()
            .into_iter()
            .map(|(domain, addr, remaining_ms)| HnsCacheEntry {
                domain,
                address: addr.map(|a| a.to_vec()).unwrap_or_default(),
                ttl_secs: (remaining_ms / 1000) as u32,
            })
            .collect()
    }

    /// Finished HNS resolutions (positive or negative), clearing the queue.
    pub fn take_hns_results(&self) -> Vec<HnsRecord> {
        self.inner
            .lock()
            .unwrap()
            .take_hns_results()
            .into_iter()
            .map(|r| HnsRecord {
                domain: r.domain,
                address: r.address.map(|a| a.to_vec()).unwrap_or_default(),
            })
            .collect()
    }

    // ---- hps:// pub/sub: services & channels (DESIGN.md §32) ------------------------------

    /// Register (host) an `hps://` topic at `path`, minting + persisting its keys. `access`
    /// governs key handoff and `visibility` whether it's advertised for discovery (DESIGN.md
    /// §32). Returns the service's public key for a `Service`, or empty for a `Channel`.
    pub fn register_service(
        &self,
        path: String,
        kind: HpsKind,
        access: HpsAccess,
        visibility: HpsVisibility,
    ) -> Vec<u8> {
        self.inner
            .lock()
            .unwrap()
            .register_service(
                &path,
                kind_to_core(&kind),
                access_to_core(&access),
                vis_to_core(&visibility),
            )
            .map(|pk| pk.to_vec())
            .unwrap_or_default()
    }

    /// Host → destination: invite an address to a topic we host (Invite mode). Returns the
    /// invite bundle id.
    pub fn hps_invite(
        &self,
        path: String,
        dest: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let dest = to32(&dest)?;
        let id = self
            .inner
            .lock()
            .unwrap()
            .hps_invite(&path, dest)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Member → host: accept an invite we received; the host then seals us the keys.
    pub fn hps_accept_invite(
        &self,
        host: Vec<u8>,
        path: String,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let host = to32(&host)?;
        let id = self
            .inner
            .lock()
            .unwrap()
            .hps_accept_invite(host, &path)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Decline a received invite — drops it from durable storage so it won't reappear on restart.
    pub fn hps_decline_invite(
        &self,
        host: Vec<u8>,
        path: String,
    ) -> std::result::Result<(), FfiError> {
        let host = to32(&host)?;
        self.inner.lock().unwrap().hps_decline_invite(host, &path);
        Ok(())
    }

    /// Drain invites we've received (DESIGN.md §32 Invite mode), clearing them.
    pub fn take_hps_invites(&self) -> Vec<HpsInvite> {
        self.inner
            .lock()
            .unwrap()
            .take_hps_invites()
            .into_iter()
            .map(|i| HpsInvite {
                path: i.path,
                host: i.host.to_vec(),
                kind: kind_from_core(i.kind),
            })
            .collect()
    }

    /// Member → host: leave a topic (stop being re-keyed). Returns the leave bundle id, if any.
    pub fn hps_leave(&self, path: String) -> std::result::Result<Vec<u8>, FfiError> {
        let id = self
            .inner
            .lock()
            .unwrap()
            .hps_leave(&path)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.map(|b| b.to_vec()).unwrap_or_default())
    }

    /// Host: pending join requests for a RequestToJoin topic (each is a requester address).
    pub fn hps_pending(&self, path: String) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .unwrap()
            .hps_pending(&path)
            .into_iter()
            .map(|a| a.to_vec())
            .collect()
    }

    /// Host: approve a pending requester, sealing them the keys. Returns the keys bundle id.
    pub fn hps_approve(
        &self,
        path: String,
        requester: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let requester = to32(&requester)?;
        let id = self
            .inner
            .lock()
            .unwrap()
            .hps_approve(&path, requester)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Host: deny/drop a pending requester (no keys).
    pub fn hps_deny(&self, path: String, requester: Vec<u8>) -> std::result::Result<(), FfiError> {
        let requester = to32(&requester)?;
        self.inner.lock().unwrap().hps_deny(&path, requester);
        Ok(())
    }

    /// Host: selective forward rotation (revocation). Re-keys retained members except `remove`;
    /// removed members keep the dead key. `new_path` empty = keep the same path. Returns the
    /// rekey bundle ids.
    pub fn hps_rekey(
        &self,
        path: String,
        new_path: String,
        remove: Vec<Vec<u8>>,
    ) -> std::result::Result<Vec<Vec<u8>>, FfiError> {
        let mut removed = Vec::with_capacity(remove.len());
        for r in &remove {
            removed.push(to32(r)?);
        }
        let np = if new_path.trim().is_empty() {
            None
        } else {
            Some(new_path.as_str())
        };
        let ids = self
            .inner
            .lock()
            .unwrap()
            .hps_rekey(&path, np, &removed)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(ids.into_iter().map(|b| b.to_vec()).collect())
    }

    /// Host: unique acking addresses for a topic (its reach / delivery sense, DESIGN.md §32).
    pub fn hps_reach(&self, path: String) -> u32 {
        self.inner.lock().unwrap().hps_reach(&path) as u32
    }

    /// Host: the retained-member set (addresses) for a topic.
    pub fn hps_members(&self, path: String) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .unwrap()
            .hps_members(&path)
            .into_iter()
            .map(|a| a.to_vec())
            .collect()
    }

    /// Topics this node hosts or follows — the app calls this at startup to rebuild its channel
    /// list, since the node persists topics but the app's in-memory list doesn't.
    pub fn hps_my_topics(&self) -> Vec<HpsMyTopic> {
        self.inner
            .lock()
            .unwrap()
            .hps_my_topics()
            .into_iter()
            .map(|t| HpsMyTopic {
                host: t.host.to_vec(),
                path: t.path,
                kind: kind_from_core(t.kind),
                hosting: t.hosting,
                access: access_from_core(t.access),
            })
            .collect()
    }

    /// Same-app discoverable topics visible on the mesh (decrypted descriptors + host address).
    pub fn browse_discoverable(&self) -> Vec<HpsTopicInfo> {
        self.inner
            .lock()
            .unwrap()
            .browse_discoverable(None)
            .into_iter()
            .map(|(host, m)| HpsTopicInfo {
                host: host.to_vec(),
                path: m.path,
                kind: kind_from_core(m.kind),
                title: m.title,
                summary: m.summary,
                access: access_from_core(m.access),
            })
            .collect()
    }

    /// Subscribe to `hps://{host}/{path}`: send a sealed request to `host`, which (for an open
    /// topic) replies with the topic keys. Messages then arrive via `take_hps_messages`. Returns
    /// the subscribe request's bundle id.
    pub fn hps_subscribe(
        &self,
        host: Vec<u8>,
        path: String,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let host = to32(&host)?;
        let id = self
            .inner
            .lock()
            .unwrap()
            .hps_subscribe(host, &path)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Publish to a topic we host or (for a channel) belong to. Floods to all subscribers,
    /// signed by the service key (service) or our own identity (channel). Returns the bundle id.
    pub fn hps_publish(
        &self,
        path: String,
        body: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let id = self
            .inner
            .lock()
            .unwrap()
            .hps_publish(&path, &body)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Drain received `hps://` messages (already decrypted + sender-verified), clearing them.
    pub fn take_hps_messages(&self) -> Vec<HpsMessage> {
        self.inner
            .lock()
            .unwrap()
            .take_hps_messages()
            .into_iter()
            .map(|m| HpsMessage {
                path: m.path,
                sender: m.sender.to_vec(),
                body: m.body,
            })
            .collect()
    }

    /// Seal an HTTP response back to a requester (gateway side).
    pub fn send_http_response(
        &self,
        to: Vec<u8>,
        for_request_id: Vec<u8>,
        status: u16,
        body: Vec<u8>,
    ) -> std::result::Result<(), FfiError> {
        let to = to32(&to)?;
        let for_id = to32(&for_request_id)?;
        self.inner
            .lock()
            .unwrap()
            .send_http_response(to, for_id, status, vec![], body)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(())
    }

    /// Drain egress HTTP requests addressed to this node as a gateway.
    pub fn take_http_requests(&self) -> Vec<HttpReq> {
        self.inner
            .lock()
            .unwrap()
            .take_http_requests()
            .into_iter()
            .map(|r| HttpReq {
                from: r.from.to_vec(),
                request_id: r.id.to_vec(),
                host: r.host,
                method: r.method,
                url: r.url,
                body: r.body,
                max_resp: r.max_resp,
            })
            .collect()
    }

    /// Drain HTTP responses sealed back to this node as a requester.
    pub fn take_http_responses(&self) -> Vec<HttpResp> {
        self.inner
            .lock()
            .unwrap()
            .take_http_responses()
            .into_iter()
            .map(|r| HttpResp {
                from: r.from.to_vec(),
                for_request_id: r.for_id.to_vec(),
                status: r.status,
                content_type: r
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default(),
                body: r.body,
            })
            .collect()
    }

    // --- service calls (DESIGN.md §29) ----------------------------------------

    /// Set this node's display name, returned by the built-in `hop.identify` service.
    /// Pass an empty string to clear it (then identify reports no name → peers show the
    /// short address).
    pub fn set_name(&self, name: String) {
        let name = if name.is_empty() { None } else { Some(name) };
        self.inner.lock().unwrap().set_name(name);
    }

    /// This node's display name (empty string if unset).
    pub fn name(&self) -> String {
        self.inner
            .lock()
            .unwrap()
            .name()
            .unwrap_or_default()
            .to_string()
    }

    /// Call a service/command on `dst` (DESIGN.md §29). For the built-in identity
    /// service pass `service_identify()` as `service`; the reply arrives via
    /// `take_service_responses` (decode an identify reply with `decode_identity`).
    /// Returns the request id.
    pub fn send_service_request(
        &self,
        dst: Vec<u8>,
        service: String,
        method: String,
        args: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let dst = to32(&dst)?;
        let id = self
            .inner
            .lock()
            .unwrap()
            .send_service_request(dst, service, method, args)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Seal a response to a custom service request back to its caller (app side). Use
    /// the [`ServiceReq`]'s `from` as `to` and its `request_id` as `for_request_id`.
    pub fn send_service_response(
        &self,
        to: Vec<u8>,
        for_request_id: Vec<u8>,
        status: u16,
        body: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let to = to32(&to)?;
        let for_id = to32(&for_request_id)?;
        let id = self
            .inner
            .lock()
            .unwrap()
            .send_service_response(to, for_id, status, body)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Drain custom service requests addressed to this node (built-in `hop.` services
    /// are answered by the node and never appear here).
    pub fn take_service_requests(&self) -> Vec<ServiceReq> {
        self.inner
            .lock()
            .unwrap()
            .take_service_requests()
            .into_iter()
            .map(|r| ServiceReq {
                from: r.from.to_vec(),
                request_id: r.id.to_vec(),
                service: r.service,
                method: r.method,
                args: r.args,
            })
            .collect()
    }

    /// Drain service responses sealed back to this node as a caller.
    pub fn take_service_responses(&self) -> Vec<ServiceResp> {
        self.inner
            .lock()
            .unwrap()
            .take_service_responses()
            .into_iter()
            .map(|r| ServiceResp {
                from: r.from.to_vec(),
                for_request_id: r.for_id.to_vec(),
                status: r.status,
                body: r.body,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pump both nodes over a single symmetric link (id 1) until quiescent.
    fn pump(a: &HopNode, b: &HopNode) {
        for _ in 0..1000 {
            let oa = a.drain_outgoing();
            let ob = b.drain_outgoing();
            if oa.is_empty() && ob.is_empty() {
                break;
            }
            for p in oa {
                b.received(p.link, p.bytes);
            }
            for p in ob {
                a.received(p.link, p.bytes);
            }
        }
    }

    #[test]
    fn identity_secret_round_trips_address() {
        let a = HopNode::new();
        let addr = a.address();
        let sec = a.secret();
        assert_eq!(sec.len(), 32, "secret is the 32-byte Ed25519 seed");
        // Restoring from the saved secret MUST reproduce the same address.
        let b = HopNode::with_secret(sec.clone());
        assert_eq!(
            b.address(),
            addr,
            "restored identity keeps the same address"
        );
        // And the persistent constructor must do the same.
        let c = HopNode::open(":memory:".into(), sec, Vec::new());
        assert_eq!(
            c.address(),
            addr,
            "persistent restore keeps the same address"
        );
    }

    #[test]
    fn two_nodes_handshake_and_message_over_ffi() {
        let a = HopNode::new();
        let b = HopNode::new();

        // Publish prekeys (as a real device does at startup) so a forward-secret session can
        // form — content is never static-sealed; it defers until a prekey is known (DESIGN.md §25).
        a.publish_prekey().unwrap();
        b.publish_prekey().unwrap();

        a.connected(1, true);
        b.connected(1, false);
        pump(&a, &b);

        a.send_message(
            b.address(),
            "text/plain".into(),
            b"hi over ffi".to_vec(),
            false,
        )
        .unwrap();
        pump(&a, &b);
        pump(&a, &b);

        let inbox = b.take_inbox();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].body, b"hi over ffi");
        assert_eq!(inbox[0].from, a.address());
    }

    #[test]
    fn rejects_bad_key_length() {
        let a = HopNode::new();
        let err = a.send_message(vec![0u8; 10], "t".into(), vec![], false);
        assert!(matches!(err, Err(FfiError::BadKey)));
    }
}
