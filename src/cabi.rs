//! libhop — the stable C ABI for hop-core: the universal client SDK.
//!
//! This is the ONE contract every non-Rust client binds: mobile bearer libs (Swift/Kotlin via the
//! generated `hop.h`), C/C++ tools, and embedded FULL clients — e.g. an ESP32 that opens a node,
//! secures sessions, and pushes sensor data to a `hops://` service. cbindgen generates
//! `include/hop.h` from this module (see `cbindgen.toml`).
//!
//! It is the poll-model byte seam — link up / bytes in / link down / drain out, keyed by `LinkId`
//! (u64) + `HopLinkRole` — PLUS the full client surface (open, identity, subscribe, send). Nothing
//! transport-specific crosses it: no BLE, no beacon, no service id — pure bytes + ids. The optional
//! UniFFI layer (the rest of this crate) wraps the SAME `HopNode`, so mobile gets ergonomic bindings
//! while every other target binds this C ABI.

#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_void, CStr};
use std::os::raw::c_char;
use std::sync::Arc;

use crate::HopNode;

/// Which side opened a bearer link (the Noise role). Mirrors hop-core's internal `Role`.
#[repr(C)]
pub enum HopLinkRole {
    /// We dialed out (BLE central / TCP connect / Wi-Fi inviter) → Noise initiator.
    Dialer = 0,
    /// A peer connected in (peripheral / listener / invitee) → Noise responder.
    Acceptor = 1,
}

// ---- internal helpers (not exported) ----------------------------------------------------------

unsafe fn node_ref<'a>(node: *const HopNode) -> Option<&'a HopNode> {
    if node.is_null() {
        None
    } else {
        Some(&*node)
    }
}
unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok()
}
unsafe fn slice<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(p, len)
    }
}

// ---- lifecycle --------------------------------------------------------------------------------

/// The libhop C-ABI version. Bump on any signature or semantic change to an exported `hop_*`
/// function. A wrapper should assert `hop_abi_version() == HOP_ABI_VERSION` at load so a wrapper
/// built against a newer header fails loudly instead of drifting silently (F-28). This is the
/// *ABI* version and is independent of the *wire* format version (bundle.rs `BUNDLE_VERSION`).
pub const HOP_ABI_VERSION: u32 = 2;

/// Returns the ABI version this shared library implements (see [`HOP_ABI_VERSION`]).
#[no_mangle]
pub extern "C" fn hop_abi_version() -> u32 {
    HOP_ABI_VERSION
}

/// Run a constructor closure, converting a panic into a NULL return so it never unwinds across
/// the `extern "C"` boundary (which is undefined behavior). See F-26.
fn catch_ctor(f: impl FnOnce() -> *const HopNode) -> *const HopNode {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(std::ptr::null())
}

/// Run a closure, swallowing any panic so it can never unwind across the `extern "C"` boundary
/// (which is UB and aborts the whole host process) (core-ffi-01). A panic in hop-core reached via
/// hostile/malformed network bytes (`hop_bytes_received`) must degrade to a dropped operation, not
/// take down every C-ABI consumer (ESP32, C tools, JNA/Swift wrappers). The node's lock is
/// poison-tolerant, so a panic mid-call does not brick the node either. Returns `r` on panic.
fn catch<R>(default: R, f: impl FnOnce() -> R) -> R {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(default)
}

/// Open a node with persistent storage at `db_path` (UTF-8 C string), a saved 32-byte identity
/// `secret` (pass NULL/0 for a fresh identity), and a 32-byte `app_secret` (NULL/0 = open fabric).
/// Returns an owning handle to free with `hop_node_free`, or NULL on a NULL/non-UTF-8 `db_path`.
///
/// If the db path exists but can't be opened it is quarantined and reopened fresh; only if that
/// also fails does the node run with EPHEMERAL storage (call `hop_node_is_persistent` to detect
/// this) rather than silently, and rather than NULL (F-26).
#[no_mangle]
pub unsafe extern "C" fn hop_node_open(
    db_path: *const c_char,
    secret: *const u8,
    secret_len: usize,
    app_secret: *const u8,
    app_secret_len: usize,
) -> *const HopNode {
    let Some(path) = cstr(db_path) else {
        return std::ptr::null();
    };
    let path = path.to_string();
    let secret = slice(secret, secret_len).to_vec();
    let app = slice(app_secret, app_secret_len).to_vec();
    catch_ctor(|| Arc::into_raw(HopNode::open(path, secret, app)))
}

/// Like `hop_node_open`, but ENCRYPTS the store at rest with a raw `key` (typically 32 bytes) the host
/// derives and stores in the platform Keychain/Keystore (F-25). Real encryption requires libhop to be
/// built with the store's `sqlcipher` feature; otherwise the key is accepted but the db stays plain.
/// A NULL/empty key behaves like `hop_node_open`. NULL/non-UTF-8 `db_path` ⇒ NULL.
#[no_mangle]
pub unsafe extern "C" fn hop_node_open_keyed(
    db_path: *const c_char,
    secret: *const u8,
    secret_len: usize,
    app_secret: *const u8,
    app_secret_len: usize,
    key: *const u8,
    key_len: usize,
) -> *const HopNode {
    let Some(path) = cstr(db_path) else {
        return std::ptr::null();
    };
    let path = path.to_string();
    let secret = slice(secret, secret_len).to_vec();
    let app = slice(app_secret, app_secret_len).to_vec();
    let key = slice(key, key_len).to_vec();
    catch_ctor(|| Arc::into_raw(HopNode::open_keyed(path, secret, app, key)))
}

/// Create a node with a fresh identity and ephemeral (in-memory) storage. Free with `hop_node_free`.
#[no_mangle]
pub unsafe extern "C" fn hop_node_new() -> *const HopNode {
    catch_ctor(|| Arc::into_raw(HopNode::new()))
}

/// Open a node from a saved 32-byte identity `secret` with ephemeral (in-memory) storage. Pass
/// NULL/0 for a fresh identity. Free with `hop_node_free`.
#[no_mangle]
pub unsafe extern "C" fn hop_node_with_secret(
    secret: *const u8,
    secret_len: usize,
) -> *const HopNode {
    let secret = slice(secret, secret_len).to_vec();
    catch_ctor(|| Arc::into_raw(HopNode::with_secret(secret)))
}

/// Whether this node has durable storage. Returns false when the db path was unusable and the
/// node is running ephemerally (state will not survive a restart) — the host should surface this
/// rather than treat the database as ground truth (F-26). NULL handle ⇒ false.
#[no_mangle]
pub unsafe extern "C" fn hop_node_is_persistent(node: *const HopNode) -> bool {
    node_ref(node).map(|n| n.is_persistent()).unwrap_or(false)
}

/// How many persisted records failed to decode on startup (F-03). Non-zero ⇒ an upgrade changed
/// a struct's on-disk layout and dropped that state; surface it to the user. NULL handle ⇒ 0.
#[no_mangle]
pub unsafe extern "C" fn hop_node_rehydrate_dropped(node: *const HopNode) -> u32 {
    node_ref(node).map(|n| n.rehydrate_dropped()).unwrap_or(0)
}

/// Free a node handle returned by any constructor. Safe to pass NULL.
///
/// Ownership: this consumes the one strong reference each constructor returned. The caller must
/// ensure no other thread is calling into the same handle concurrently with free (the ABI does
/// not expose a retain/clone), and must not use the pointer afterward.
#[no_mangle]
pub unsafe extern "C" fn hop_node_free(node: *const HopNode) {
    if !node.is_null() {
        drop(Arc::from_raw(node));
    }
}

// ---- identity ---------------------------------------------------------------------------------

/// Write this node's 32-byte address into `out` (must have room for 32 bytes). False on NULL.
#[no_mangle]
pub unsafe extern "C" fn hop_node_address(node: *const HopNode, out: *mut u8) -> bool {
    catch(false, || {
        let (Some(node), false) = (node_ref(node), out.is_null()) else {
            return false;
        };
        let addr = node.address();
        std::ptr::copy_nonoverlapping(addr.as_ptr(), out, addr.len().min(32));
        true
    })
}

/// Write this node's 32-byte identity secret into `out` (room for 32 bytes) so the host can persist
/// it (e.g. in the Keychain) and restore the node later with `hop_node_with_secret`/`hop_node_open`.
/// Returns the number of bytes written (32), or 0 on NULL.
#[no_mangle]
pub unsafe extern "C" fn hop_node_secret(node: *const HopNode, out: *mut u8) -> usize {
    catch(0, || {
        let (Some(node), false) = (node_ref(node), out.is_null()) else {
            return 0;
        };
        let s = node.secret();
        let n = s.len().min(32);
        std::ptr::copy_nonoverlapping(s.as_ptr(), out, n);
        n
    })
}

/// Set the display name this node reports via presence / `hop.identify` (DESIGN.md §29).
#[no_mangle]
pub unsafe extern "C" fn hop_node_set_name(node: *const HopNode, name: *const c_char) {
    catch((), || {
        if let (Some(node), Some(name)) = (node_ref(node), cstr(name)) {
            node.set_name(name.to_string());
        }
    })
}

// ---- clock ------------------------------------------------------------------------------------

/// Advance time: expire adverts, retransmit unacked bundles, prune dedup. Call ~1 Hz.
#[no_mangle]
pub unsafe extern "C" fn hop_node_tick(node: *const HopNode, now_ms: u64) {
    catch((), || {
        if let Some(node) = node_ref(node) {
            node.tick(now_ms);
        }
    })
}

// ---- bearer seam: inbound (bearer -> core) ----------------------------------------------------

/// A bearer link came up. `role` = which side dialed (the Noise initiator/responder selector),
/// using the [`HopLinkRole`] discriminants (0 = Dialer, 1 = Acceptor).
///
/// core-ffi-05: `role` is taken as a plain `u32`, not the `HopLinkRole` enum by value. A C caller
/// passing an out-of-range int would otherwise materialize an invalid Rust enum (instant UB) before
/// any validation runs. Here only `0` selects Dialer; any other value is treated as Acceptor, so a
/// bad int can never be UB.
#[no_mangle]
pub unsafe extern "C" fn hop_link_up(node: *const HopNode, link: u64, role: u32) {
    catch((), || {
        if let Some(node) = node_ref(node) {
            let is_dialer = role == HopLinkRole::Dialer as u32;
            node.connected(link, is_dialer);
        }
    })
}

/// One frame of opaque bytes arrived on `link`.
#[no_mangle]
pub unsafe extern "C" fn hop_bytes_received(
    node: *const HopNode,
    link: u64,
    data: *const u8,
    len: usize,
) {
    catch((), || {
        if let Some(node) = node_ref(node) {
            node.received(link, slice(data, len).to_vec());
        }
    })
}

/// A bearer link dropped.
#[no_mangle]
pub unsafe extern "C" fn hop_link_down(node: *const HopNode, link: u64) {
    catch((), || {
        if let Some(node) = node_ref(node) {
            node.disconnected(link);
        }
    })
}

// ---- bearer seam: outbound (core -> bearer, POLLED) -------------------------------------------

/// Drain queued outbound packets. Synchronously invokes `sink(ctx, link, bytes_ptr, bytes_len)`
/// once per packet during this call — this is the POLL model; core never pushes asynchronously.
/// The byte pointer is valid only for the duration of each `sink` call; copy what you keep.
#[no_mangle]
pub unsafe extern "C" fn hop_drain_outgoing(
    node: *const HopNode,
    sink: Option<extern "C" fn(ctx: *mut c_void, link: u64, bytes: *const u8, len: usize)>,
    ctx: *mut c_void,
) {
    let (Some(node), Some(sink)) = (node_ref(node), sink) else {
        return;
    };
    // core-ffi-01: the node-side drain may panic; contain it so it can't unwind across the ABI. The
    // sink is a foreign fn: if IT panics that's the host's contract to uphold, outside our reach.
    let packets = catch(Vec::new(), || node.drain_outgoing());
    for pkt in packets {
        sink(ctx, pkt.link, pkt.bytes.as_ptr(), pkt.bytes.len());
    }
}

// ---- client API (full client, e.g. ESP32) -----------------------------------------------------

/// Subscribe the directory to a service `topic` (UTF-8 C string).
#[no_mangle]
pub unsafe extern "C" fn hop_subscribe(node: *const HopNode, topic: *const c_char) {
    catch((), || {
        if let (Some(node), Some(topic)) = (node_ref(node), cstr(topic)) {
            node.subscribe(topic.to_string());
        }
    })
}

/// Publish this node's prekey advert (DESIGN.md §25) so peers can seal forward-secret messages to
/// us; it gossips on link-up. Call once after opening (and after the first `hop_node_tick` sets a
/// real clock, else the advert is judged expired). Returns true on success.
#[no_mangle]
pub unsafe extern "C" fn hop_publish_prekey(node: *const HopNode) -> bool {
    catch(
        false,
        || matches!(node_ref(node), Some(node) if node.publish_prekey().is_ok()),
    )
}

/// Drain newly-received messages (poll model). Invokes
/// `sink(ctx, from32, content_type_cstr, body_ptr, body_len, hops, created_at_ms)` once per message
/// during this call. `from` points at 32 address bytes; `content_type` is a NUL-terminated UTF-8
/// string; `body` is `body_len` bytes — all valid only for the duration of each `sink` call.
#[no_mangle]
pub unsafe extern "C" fn hop_poll_inbox(
    node: *const HopNode,
    sink: Option<
        extern "C" fn(
            ctx: *mut c_void,
            from: *const u8,
            content_type: *const c_char,
            body: *const u8,
            body_len: usize,
            hops: u8,
            created_at: u64,
        ),
    >,
    ctx: *mut c_void,
) {
    let (Some(node), Some(sink)) = (node_ref(node), sink) else {
        return;
    };
    let inbox = catch(Vec::new(), || node.take_inbox());
    for m in inbox {
        let ct = std::ffi::CString::new(m.content_type).unwrap_or_default();
        sink(
            ctx,
            m.from.as_ptr(),
            ct.as_ptr(),
            m.body.as_ptr(),
            m.body.len(),
            m.hops,
            m.created_at,
        );
    }
}

/// Send to a DIRECTLY-CONNECTED peer `dst` (32 bytes), sealed with the key learned at handshake
/// (the directed §27 path; prefer `hop_send_message` unless you specifically want a directed send).
/// On success writes the 32-byte bundle id to `out_id` (may be NULL) and returns true; false if not
/// connected to that peer or on error.
#[no_mangle]
pub unsafe extern "C" fn hop_send_to(
    node: *const HopNode,
    dst: *const u8,
    content_type: *const c_char,
    body: *const u8,
    body_len: usize,
    request_ack: bool,
    out_id: *mut u8,
) -> bool {
    catch(false, || {
        let Some(node) = node_ref(node) else {
            return false;
        };
        let Some(ct) = cstr(content_type) else {
            return false;
        };
        if dst.is_null() {
            return false;
        }
        match node.send_to(
            slice(dst, 32).to_vec(),
            ct.to_string(),
            slice(body, body_len).to_vec(),
            request_ack,
        ) {
            Ok(id) => {
                if !out_id.is_null() {
                    std::ptr::copy_nonoverlapping(id.as_ptr(), out_id, id.len().min(32));
                }
                true
            }
            Err(_) => false,
        }
    })
}

/// Delivery status of a message we sent, by its 32-byte bundle `id`. Writes each field to its
/// (nullable) out-param: `relayed` = distinct peers handed a copy; `delivered` = destination
/// confirmed; `hops`/`ms` = the FORWARD-path (A→B) length + latency the destination reported (§39
/// private ACK), 0 until delivered. Returns false on NULL node/id.
#[no_mangle]
pub unsafe extern "C" fn hop_message_status(
    node: *const HopNode,
    id: *const u8,
    out_relayed: *mut u32,
    out_delivered: *mut bool,
    out_hops: *mut u8,
    out_ms: *mut u32,
) -> bool {
    catch(false, || {
        let Some(node) = node_ref(node) else {
            return false;
        };
        if id.is_null() {
            return false;
        }
        let st = node.message_status(slice(id, 32).to_vec());
        if !out_relayed.is_null() {
            *out_relayed = st.relayed;
        }
        if !out_delivered.is_null() {
            *out_delivered = st.delivered;
        }
        if !out_hops.is_null() {
            *out_hops = st.delivery_hops;
        }
        if !out_ms.is_null() {
            *out_ms = st.delivery_ms;
        }
        true
    })
}

/// True iff messaging `addr` (32 bytes) is forward-secret — a ratchet session exists (DESIGN.md §25)
/// rather than a static seal. Drives a lock indicator. False on NULL.
#[no_mangle]
pub unsafe extern "C" fn hop_is_secured(node: *const HopNode, addr: *const u8) -> bool {
    catch(
        false,
        || matches!((node_ref(node), addr.is_null()), (Some(node), false) if node.is_secured(slice(addr, 32).to_vec())),
    )
}

// ---- hops:// request/response (a FULL round trip — HDP in BOTH directions) --------------------
//
// Distinct from `hop_send_message` (a one-way HDP datagram whose only "response" is the network
// delivery-ACK): a hops:// service request expects a sealed RESPONSE back over the network. The
// caller fires a request and later drains the reply; the host drains requests and seals responses.
// This is what makes an ESP32 a full hops:// client (e.g. POST weather → get an ack/result body).

/// Send a hops:// service request to `dst` (32 bytes): invoke `method` on `service` with `args`.
/// The reply arrives later via `hop_poll_service_responses`. Writes the 32-byte request id to
/// `out_id` (may be NULL) and returns true.
#[no_mangle]
pub unsafe extern "C" fn hop_send_service_request(
    node: *const HopNode,
    dst: *const u8,
    service: *const c_char,
    method: *const c_char,
    args: *const u8,
    args_len: usize,
    out_id: *mut u8,
) -> bool {
    catch(false, || {
        let Some(node) = node_ref(node) else {
            return false;
        };
        let (Some(service), Some(method)) = (cstr(service), cstr(method)) else {
            return false;
        };
        if dst.is_null() {
            return false;
        }
        match node.send_service_request(
            slice(dst, 32).to_vec(),
            service.to_string(),
            method.to_string(),
            slice(args, args_len).to_vec(),
        ) {
            Ok(id) => {
                if !out_id.is_null() {
                    std::ptr::copy_nonoverlapping(id.as_ptr(), out_id, id.len().min(32));
                }
                true
            }
            Err(_) => false,
        }
    })
}

/// Seal a hops:// response back to a request's caller (host side). `to` = the request's `from`;
/// `for_request_id` = its `request_id`. Returns true on success.
#[no_mangle]
pub unsafe extern "C" fn hop_send_service_response(
    node: *const HopNode,
    to: *const u8,
    for_request_id: *const u8,
    status: u16,
    body: *const u8,
    body_len: usize,
) -> bool {
    catch(false, || {
        let Some(node) = node_ref(node) else {
            return false;
        };
        if to.is_null() || for_request_id.is_null() {
            return false;
        }
        node.send_service_response(
            slice(to, 32).to_vec(),
            slice(for_request_id, 32).to_vec(),
            status,
            slice(body, body_len).to_vec(),
        )
        .is_ok()
    })
}

/// Drain hops:// service requests addressed to this node (host side). Invokes
/// `sink(ctx, from32, request_id32, service_cstr, method_cstr, args_ptr, args_len)` per request.
#[no_mangle]
pub unsafe extern "C" fn hop_poll_service_requests(
    node: *const HopNode,
    sink: Option<
        extern "C" fn(
            ctx: *mut c_void,
            from: *const u8,
            request_id: *const u8,
            service: *const c_char,
            method: *const c_char,
            args: *const u8,
            args_len: usize,
        ),
    >,
    ctx: *mut c_void,
) {
    let (Some(node), Some(sink)) = (node_ref(node), sink) else {
        return;
    };
    // core-ffi-01: the node-side drain may panic; contain it so it can't unwind across the ABI (the
    // sink is a foreign fn: if IT panics that is the host's contract, outside our reach).
    let requests = catch(Vec::new(), || node.take_service_requests());
    for r in requests {
        let svc = std::ffi::CString::new(r.service).unwrap_or_default();
        let mth = std::ffi::CString::new(r.method).unwrap_or_default();
        sink(
            ctx,
            r.from.as_ptr(),
            r.request_id.as_ptr(),
            svc.as_ptr(),
            mth.as_ptr(),
            r.args.as_ptr(),
            r.args.len(),
        );
    }
}

/// Drain hops:// service responses sealed back to this node (caller side). Invokes
/// `sink(ctx, from32, for_request_id32, status, body_ptr, body_len)` per response.
#[no_mangle]
pub unsafe extern "C" fn hop_poll_service_responses(
    node: *const HopNode,
    sink: Option<
        extern "C" fn(
            ctx: *mut c_void,
            from: *const u8,
            for_request_id: *const u8,
            status: u16,
            body: *const u8,
            body_len: usize,
        ),
    >,
    ctx: *mut c_void,
) {
    let (Some(node), Some(sink)) = (node_ref(node), sink) else {
        return;
    };
    // core-ffi-01: contain a panic in the node-side drain (see hop_poll_service_requests).
    let responses = catch(Vec::new(), || node.take_service_responses());
    for r in responses {
        sink(
            ctx,
            r.from.as_ptr(),
            r.for_request_id.as_ptr(),
            r.status,
            r.body.as_ptr(),
            r.body.len(),
        );
    }
}

// ---- address encoding helpers (base58) --------------------------------------------------------

/// Encode a 32-byte `addr` as base58 into the C buffer `out` (`out_cap` bytes incl. NUL). Returns
/// the string length (excluding NUL), or 0 on NULL / insufficient capacity.
#[no_mangle]
pub unsafe extern "C" fn hop_address_to_base58(
    addr: *const u8,
    out: *mut c_char,
    out_cap: usize,
) -> usize {
    if addr.is_null() || out.is_null() || out_cap == 0 {
        return 0;
    }
    let s = bs58::encode(slice(addr, 32)).into_string();
    let b = s.as_bytes();
    if b.len() + 1 > out_cap {
        return 0;
    }
    std::ptr::copy_nonoverlapping(b.as_ptr(), out as *mut u8, b.len());
    *out.add(b.len()) = 0; // NUL-terminate
    b.len()
}

/// Decode a base58 address C string `text` into `out32` (32 bytes). Returns true iff it decoded to
/// exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn hop_address_from_base58(text: *const c_char, out32: *mut u8) -> bool {
    let Some(text) = cstr(text) else {
        return false;
    };
    if out32.is_null() {
        return false;
    }
    match bs58::decode(text).into_vec() {
        Ok(v) if v.len() == 32 => {
            std::ptr::copy_nonoverlapping(v.as_ptr(), out32, 32);
            true
        }
        _ => false,
    }
}

/// Send a message to the 32-byte address `dst` — untraceable by default (DESIGN.md §39).
/// `content_type` is a UTF-8 C string (e.g. "text/plain"); `body`/`body_len` is the payload. If
/// `request_ack`, a private delivery confirmation is requested. On success writes the 32-byte
/// bundle id into `out_id` (room for 32 bytes, may be NULL to ignore) and returns true.
#[no_mangle]
pub unsafe extern "C" fn hop_send_message(
    node: *const HopNode,
    dst: *const u8,
    content_type: *const c_char,
    body: *const u8,
    body_len: usize,
    request_ack: bool,
    out_id: *mut u8,
) -> bool {
    catch(false, || {
        let Some(node) = node_ref(node) else {
            return false;
        };
        let Some(ct) = cstr(content_type) else {
            return false;
        };
        if dst.is_null() {
            return false;
        }
        match node.send_message(
            slice(dst, 32).to_vec(),
            ct.to_string(),
            slice(body, body_len).to_vec(),
            request_ack,
        ) {
            Ok(id) => {
                if !out_id.is_null() {
                    std::ptr::copy_nonoverlapping(id.as_ptr(), out_id, id.len().min(32));
                }
                true
            }
            Err(_) => false,
        }
    })
}

#[cfg(test)]
mod tests {
    //! quality-net-08: direct tests of the C ABI entry points (they had none; only the higher-level
    //! Rust API and the foreign wrappers were exercised). These call the `extern "C"` functions the
    //! way a C/Swift/Kotlin host does - through raw pointers - so a regression in the ABI seam itself
    //! (not just the Rust core) is caught here rather than only on-device.
    use super::*;

    #[test]
    fn abi_version_matches_the_constant() {
        assert_eq!(hop_abi_version(), HOP_ABI_VERSION);
    }

    #[test]
    fn null_handles_are_safe_and_falsey() {
        // Every accessor must tolerate a NULL handle (a host that failed a ctor) without UB.
        unsafe {
            let mut buf = [0u8; 32];
            assert!(!hop_node_address(std::ptr::null(), buf.as_mut_ptr()));
            assert_eq!(hop_node_secret(std::ptr::null(), buf.as_mut_ptr()), 0);
            assert!(!hop_node_is_persistent(std::ptr::null()));
            assert_eq!(hop_node_rehydrate_dropped(std::ptr::null()), 0);
            hop_node_free(std::ptr::null()); // documented no-op on NULL
        }
    }

    #[test]
    fn new_node_yields_a_nonzero_address_then_frees() {
        unsafe {
            let node = hop_node_new();
            assert!(!node.is_null(), "ctor returns a handle");
            let mut addr = [0u8; 32];
            assert!(hop_node_address(node, addr.as_mut_ptr()));
            assert_ne!(addr, [0u8; 32], "a real Ed25519 address, not zeros");
            hop_node_free(node);
        }
    }

    #[test]
    fn with_secret_is_deterministic_across_the_abi() {
        // The whole point of hop_node_secret + hop_node_with_secret: a host persists the secret and
        // restores the SAME identity. Prove the address round-trips through the C ABI.
        unsafe {
            let seed = [7u8; 32];
            let a = hop_node_with_secret(seed.as_ptr(), seed.len());
            let b = hop_node_with_secret(seed.as_ptr(), seed.len());
            let (mut aa, mut ba) = ([0u8; 32], [0u8; 32]);
            assert!(hop_node_address(a, aa.as_mut_ptr()));
            assert!(hop_node_address(b, ba.as_mut_ptr()));
            assert_eq!(aa, ba, "same secret -> same identity through the ABI");

            // And the secret read back out re-creates the same identity.
            let mut secret_out = [0u8; 32];
            assert_eq!(hop_node_secret(a, secret_out.as_mut_ptr()), 32);
            let c = hop_node_with_secret(secret_out.as_ptr(), secret_out.len());
            let mut ca = [0u8; 32];
            assert!(hop_node_address(c, ca.as_mut_ptr()));
            assert_eq!(ca, aa, "secret read back re-creates the identity");

            hop_node_free(a);
            hop_node_free(b);
            hop_node_free(c);
        }
    }

    // core-ffi-sdk-r2-01: panic-containment regression. Every hop_* body that calls into the node is
    // wrapped in `catch(default, ...)` so a panic reached via crafted/hostile state degrades to a
    // dropped op instead of unwinding across `extern "C"` (UB that aborts the whole host). These tests
    // prove the mechanism the wraps depend on: a panicking closure yields the default and DOES NOT
    // escape. Before the fix, hop_send_to / hop_message_status / hop_is_secured / the service
    // send+poll fns / hop_publish_prekey / hop_subscribe / hop_node_address|secret|set_name had no
    // such guard.

    #[test]
    fn catch_contains_an_unwinding_panic_and_returns_the_default() {
        // The bool-returning fns (hop_send_to, hop_is_secured, hop_message_status, the service
        // send fns, hop_publish_prekey, hop_node_address) default to false on panic.
        let r = catch(false, || -> bool { panic!("boom from a core path") });
        assert!(!r, "a panic yields the `false` default, not an unwind");

        // The usize-returning hop_node_secret defaults to 0.
        let n = catch(0usize, || -> usize { panic!("boom") });
        assert_eq!(
            n, 0,
            "hop_node_secret's default on panic is 0 bytes written"
        );

        // The Vec-returning drains (hop_poll_service_requests/responses) default to empty.
        let v = catch(Vec::<u8>::new(), || -> Vec<u8> { panic!("boom") });
        assert!(
            v.is_empty(),
            "a drain panic yields an empty batch, not an unwind"
        );

        // The unit-returning fns (hop_subscribe, hop_node_set_name) simply swallow it.
        catch((), || panic!("boom"));
    }

    #[test]
    fn catch_is_transparent_when_no_panic_occurs() {
        // Wrapping must NOT change the happy-path result: the fix is pure containment, no behavior
        // change on the normal path (adversarial self-check: no black-holing of a good return).
        assert!(catch(false, || true));
        assert_eq!(catch(0usize, || 7usize), 7);
        assert_eq!(catch(Vec::new(), || vec![1u8, 2, 3]), vec![1, 2, 3]);
    }

    #[test]
    fn wrapped_send_paths_run_clean_on_the_happy_path() {
        // Drive the newly-wrapped fns through a live node to confirm the catch wrapper didn't alter
        // their normal return (a `catch` mistakenly returning the default would surface here).
        unsafe {
            let node = hop_node_new();
            assert!(
                hop_publish_prekey(node),
                "prekey publishes cleanly through the wrap"
            );

            let ct = std::ffi::CString::new("text/plain").unwrap();
            let dst = [9u8; 32];
            let body = b"hi";
            let mut out_id = [0u8; 32];
            // Not connected to `dst`, so send_to must return false (its documented failure), NOT
            // panic and NOT the catch-default masking a real send. Either way: no unwind.
            let sent = hop_send_to(
                node,
                dst.as_ptr(),
                ct.as_ptr(),
                body.as_ptr(),
                body.len(),
                false,
                out_id.as_mut_ptr(),
            );
            assert!(!sent, "send_to to an unconnected peer is a clean false");

            // is_secured on an unknown peer is a clean false.
            assert!(!hop_is_secured(node, dst.as_ptr()));

            // message_status for an unknown id returns true (fields written) with delivered=false.
            let mut relayed = 1u32;
            let mut delivered = true;
            let ok = hop_message_status(
                node,
                out_id.as_ptr(),
                &mut relayed,
                &mut delivered,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            assert!(ok);
            assert!(!delivered, "an unknown bundle id is not delivered");
            assert_eq!(relayed, 0);

            hop_node_free(node);
        }
    }
}
