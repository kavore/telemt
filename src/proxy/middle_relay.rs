use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{oneshot, watch};
use tracing::{debug, trace, warn};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::{*, secure_padding_len};
use crate::proxy::handshake::HandshakeSuccess;
use crate::proxy::route_mode::{
    RelayRouteMode, RouteCutoverState, ROUTE_SWITCH_ERROR_MSG, affected_cutover_state,
    cutover_stagger_delay,
};
use crate::proxy::adaptive_buffers::{self, AdaptiveTier};
use crate::proxy::session_eviction::SessionLease;
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::middle_proxy::{CachedMeWriter, MePool, MeResponse, proto_flags_for_tag};

const DESYNC_DEDUP_WINDOW: Duration = Duration::from_secs(60);
const DESYNC_ERROR_CLASS: &str = "frame_too_large_crypto_desync";
const ME_D2C_FLUSH_BATCH_MAX_FRAMES_MIN: usize = 1;
const ME_D2C_FLUSH_BATCH_MAX_BYTES_MIN: usize = 4096;
const ME_ADAPTIVE_TICK: Duration = Duration::from_millis(250);
static DESYNC_DEDUP: OnceLock<Mutex<HashMap<u64, Instant>>> = OnceLock::new();

struct RelayForensicsState {
    trace_id: u64,
    conn_id: u64,
    user: String,
    peer: SocketAddr,
    peer_hash: u64,
    started_at: Instant,
    bytes_c2me: u64,
    bytes_me2c: Arc<AtomicU64>,
    desync_all_full: bool,
}

#[derive(Clone, Copy)]
struct MeD2cFlushPolicy {
    max_frames: usize,
    max_bytes: usize,
    max_delay: Duration,
    ack_flush_immediate: bool,
}

impl MeD2cFlushPolicy {
    fn from_config(config: &ProxyConfig, tier: AdaptiveTier) -> Self {
        let base = Self {
            max_frames: config
                .general
                .me_d2c_flush_batch_max_frames
                .max(ME_D2C_FLUSH_BATCH_MAX_FRAMES_MIN),
            max_bytes: config
                .general
                .me_d2c_flush_batch_max_bytes
                .max(ME_D2C_FLUSH_BATCH_MAX_BYTES_MIN),
            max_delay: Duration::from_micros(config.general.me_d2c_flush_batch_max_delay_us),
            ack_flush_immediate: config.general.me_d2c_ack_flush_immediate,
        };
        let (max_frames, max_bytes, max_delay) = adaptive_buffers::me_flush_policy_for_tier(
            tier,
            base.max_frames,
            base.max_bytes,
            base.max_delay,
        );
        Self {
            max_frames,
            max_bytes,
            max_delay,
            ack_flush_immediate: base.ack_flush_immediate,
        }
    }
}

fn hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn hash_ip(ip: IpAddr) -> u64 {
    hash_value(&ip)
}

fn should_emit_full_desync(key: u64, all_full: bool, now: Instant) -> bool {
    if all_full {
        return true;
    }

    let dedup = DESYNC_DEDUP.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = dedup.lock().expect("desync dedup mutex poisoned");
    guard.retain(|_, seen_at| now.duration_since(*seen_at) < DESYNC_DEDUP_WINDOW);

    match guard.get_mut(&key) {
        Some(seen_at) => {
            if now.duration_since(*seen_at) >= DESYNC_DEDUP_WINDOW {
                *seen_at = now;
                true
            } else {
                false
            }
        }
        None => {
            guard.insert(key, now);
            true
        }
    }
}

fn report_desync_frame_too_large(
    state: &RelayForensicsState,
    proto_tag: ProtoTag,
    frame_counter: u64,
    max_frame: usize,
    len: usize,
    raw_len_bytes: Option<[u8; 4]>,
    stats: &Stats,
) -> ProxyError {
    let len_buf = raw_len_bytes.unwrap_or((len as u32).to_le_bytes());
    let looks_like_tls = raw_len_bytes
        .map(|b| b[0] == 0x16 && b[1] == 0x03)
        .unwrap_or(false);
    let looks_like_http = raw_len_bytes
        .map(|b| matches!(b[0], b'G' | b'P' | b'H' | b'C' | b'D'))
        .unwrap_or(false);
    let now = Instant::now();
    let dedup_key = hash_value(&(
        state.user.as_str(),
        state.peer_hash,
        proto_tag,
        DESYNC_ERROR_CLASS,
    ));
    let emit_full = should_emit_full_desync(dedup_key, state.desync_all_full, now);
    let duration_ms = state.started_at.elapsed().as_millis() as u64;
    let bytes_me2c = state.bytes_me2c.load(Ordering::Relaxed);

    stats.increment_desync_total();
    stats.observe_desync_frames_ok(frame_counter);
    if emit_full {
        stats.increment_desync_full_logged();
        warn!(
            trace_id = format_args!("0x{:016x}", state.trace_id),
            conn_id = state.conn_id,
            user = %state.user,
            peer_hash = format_args!("0x{:016x}", state.peer_hash),
            proto = ?proto_tag,
            mode = "middle_proxy",
            is_tls = true,
            duration_ms,
            bytes_c2me = state.bytes_c2me,
            bytes_me2c,
            raw_len = len,
            raw_len_hex = format_args!("0x{:08x}", len),
            raw_bytes = format_args!(
                "{:02x} {:02x} {:02x} {:02x}",
                len_buf[0], len_buf[1], len_buf[2], len_buf[3]
            ),
            max_frame,
            tls_like = looks_like_tls,
            http_like = looks_like_http,
            frames_ok = frame_counter,
            dedup_window_secs = DESYNC_DEDUP_WINDOW.as_secs(),
            desync_all_full = state.desync_all_full,
            full_reason = if state.desync_all_full { "desync_all_full" } else { "first_in_dedup_window" },
            error_class = DESYNC_ERROR_CLASS,
            "Frame too large — crypto desync forensics"
        );
        debug!(
            trace_id = format_args!("0x{:016x}", state.trace_id),
            conn_id = state.conn_id,
            user = %state.user,
            peer = %state.peer,
            "Frame too large forensic peer detail"
        );
    } else {
        stats.increment_desync_suppressed();
        debug!(
            trace_id = format_args!("0x{:016x}", state.trace_id),
            conn_id = state.conn_id,
            user = %state.user,
            peer_hash = format_args!("0x{:016x}", state.peer_hash),
            proto = ?proto_tag,
            duration_ms,
            bytes_c2me = state.bytes_c2me,
            bytes_me2c,
            raw_len = len,
            frames_ok = frame_counter,
            dedup_window_secs = DESYNC_DEDUP_WINDOW.as_secs(),
            error_class = DESYNC_ERROR_CLASS,
            "Frame too large — crypto desync forensic suppressed"
        );
    }

    ProxyError::Proxy(format!(
        "Frame too large: {len} (max {max_frame}), frames_ok={frame_counter}, conn_id={}, trace_id=0x{:016x}",
        state.conn_id,
        state.trace_id
    ))
}

pub(crate) async fn handle_via_middle_proxy<R, W>(
    mut crypto_reader: CryptoReader<R>,
    crypto_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    me_pool: Arc<MePool>,
    stats: Arc<Stats>,
    config: Arc<ProxyConfig>,
    _buffer_pool: Arc<BufferPool>,
    local_addr: SocketAddr,
    rng: Arc<SecureRandom>,
    mut route_rx: watch::Receiver<RouteCutoverState>,
    route_snapshot: RouteCutoverState,
    session_id: u64,
    session_lease: SessionLease,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let user = success.user.clone();
    let peer = success.peer;
    let proto_tag = success.proto_tag;
    let pool_generation = me_pool.current_generation();
    let seed_tier = adaptive_buffers::seed_tier_for_user(&user);

    debug!(
        user = %user,
        peer = %peer,
        dc = success.dc_idx,
        proto = ?proto_tag,
        mode = "middle_proxy",
        pool_generation,
        "Routing via Middle-End"
    );

    let (conn_id, me_rx) = me_pool.registry().register().await;
    let trace_id = conn_id;
    let bytes_me2c = Arc::new(AtomicU64::new(0));
    let mut forensics = RelayForensicsState {
        trace_id,
        conn_id,
        user: user.clone(),
        peer,
        peer_hash: hash_ip(peer.ip()),
        started_at: Instant::now(),
        bytes_c2me: 0,
        bytes_me2c: bytes_me2c.clone(),
        desync_all_full: config.general.desync_all_full,
    };

    stats.increment_user_connects(&user);
    stats.increment_user_curr_connects(&user);
    stats.increment_current_connections_me();

    if let Some(cutover) = affected_cutover_state(
        &route_rx,
        RelayRouteMode::Middle,
        route_snapshot.generation,
    ) {
        let delay = cutover_stagger_delay(session_id, cutover.generation);
        warn!(
            conn_id,
            target_mode = cutover.mode.as_str(),
            cutover_generation = cutover.generation,
            delay_ms = delay.as_millis() as u64,
            "Cutover affected middle session before relay start, closing client connection"
        );
        tokio::time::sleep(delay).await;
        let _ = me_pool.send_close(conn_id).await;
        me_pool.registry().unregister(conn_id).await;
        stats.decrement_current_connections_me();
        stats.decrement_user_curr_connects(&user);
        return Err(ProxyError::Proxy(ROUTE_SWITCH_ERROR_MSG.to_string()));
    }

    if session_lease.is_stale() {
        stats.increment_reconnect_stale_close_total();
        let _ = me_pool.send_close(conn_id).await;
        me_pool.registry().unregister(conn_id).await;
        stats.decrement_current_connections_me();
        stats.decrement_user_curr_connects(&user);
        return Err(ProxyError::Proxy("Session evicted by reconnect".to_string()));
    }

    // Per-user ad_tag from access.user_ad_tags; fallback to general.ad_tag (hot-reloadable)
    let user_tag: Option<Vec<u8>> = config
        .access
        .user_ad_tags
        .get(&user)
        .and_then(|s| hex::decode(s).ok())
        .filter(|v| v.len() == 16);
    let global_tag: Option<Vec<u8>> = config
        .general
        .ad_tag
        .as_ref()
        .and_then(|s| hex::decode(s).ok())
        .filter(|v| v.len() == 16);
    let effective_tag = user_tag.or(global_tag);

    let proto_flags = proto_flags_for_tag(proto_tag, effective_tag.is_some());
    debug!(
        trace_id = format_args!("0x{:016x}", trace_id),
        user = %user,
        conn_id,
        peer_hash = format_args!("0x{:016x}", forensics.peer_hash),
        desync_all_full = forensics.desync_all_full,
        proto_flags = format_args!("0x{:08x}", proto_flags),
        pool_generation,
        "ME relay started"
    );

    let translated_local_addr = me_pool.translate_our_addr(local_addr);

    let frame_limit = config.general.max_client_frame;

    let effective_tag = effective_tag;
    // C2ME send state — inline in main loop instead of separate task.
    let mut cached_writer: Option<CachedMeWriter> = None;
    let target_dc = success.dc_idx;

    // Pre-bind writer BEFORE first client frame — eliminates slow path on first send.
    me_pool.pre_bind_writer(
        conn_id,
        target_dc,
        peer,
        translated_local_addr,
        proto_flags,
        effective_tag.as_deref(),
        &mut cached_writer,
    ).await;

    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let mut me_rx_task = me_rx;
    let stats_clone = stats.clone();
    let rng_clone = rng.clone();
    let user_clone = user.clone();
    let bytes_me2c_clone = bytes_me2c.clone();
    let config_clone = config.clone();
    let shared_max_tier = Arc::new(AtomicU8::new(seed_tier.as_u8()));
    let shared_max_tier_writer = shared_max_tier.clone();
    let me_writer = tokio::spawn(async move {
        let mut writer = crypto_writer;
        let mut frame_buf = Vec::with_capacity(16 * 1024);
        let mut d2c_flush_policy = MeD2cFlushPolicy::from_config(&config_clone, seed_tier);

        // Adaptive tier runtime tracking — mirrors direct_relay watchdog.
        let mut adaptive = adaptive_buffers::SessionAdaptiveController::new(seed_tier);
        let mut adaptive_tick = tokio::time::interval(ME_ADAPTIVE_TICK);
        adaptive_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut prev_me2c_sample: u64 = 0;

        loop {
            tokio::select! {
                biased;
                _ = adaptive_tick.tick() => {
                    let current_me2c = bytes_me2c_clone.load(Ordering::Relaxed);
                    let delta_bytes = current_me2c.saturating_sub(prev_me2c_sample);
                    prev_me2c_sample = current_me2c;

                    // ME relay only has s2c throughput signal from the ME side.
                    let sample = adaptive_buffers::RelaySignalSample {
                        c2s_bytes: 0,
                        s2c_requested_bytes: delta_bytes,
                        s2c_written_bytes: delta_bytes,
                        s2c_write_ops: 0,
                        s2c_partial_writes: 0,
                        s2c_consecutive_pending_writes: 0,
                    };
                    if let Some(_transition) = adaptive.observe(sample, ME_ADAPTIVE_TICK.as_secs_f64()) {
                        d2c_flush_policy = MeD2cFlushPolicy::from_config(&config_clone, adaptive.current_tier());
                        shared_max_tier_writer.store(adaptive.max_tier_seen().as_u8(), Ordering::Relaxed);
                        adaptive_buffers::record_user_tier(&user_clone, adaptive.max_tier_seen());
                    }
                }
                msg = me_rx_task.recv() => {
                    let Some(first) = msg else {
                        debug!(conn_id, "ME channel closed");
                        return Err(ProxyError::Proxy("ME connection lost".into()));
                    };

                    let mut batch_frames = 0usize;
                    let mut batch_bytes = 0usize;
                    let mut flush_immediately;

                    match process_me_writer_response(
                        first,
                        &mut writer,
                        proto_tag,
                        rng_clone.as_ref(),
                        &mut frame_buf,
                        stats_clone.as_ref(),
                        &user_clone,
                        bytes_me2c_clone.as_ref(),
                        conn_id,
                        d2c_flush_policy.ack_flush_immediate,
                        false,
                    ).await? {
                        MeWriterResponseOutcome::Continue { frames, bytes, flush_immediately: immediate } => {
                            batch_frames = batch_frames.saturating_add(frames);
                            batch_bytes = batch_bytes.saturating_add(bytes);
                            flush_immediately = immediate;
                        }
                        MeWriterResponseOutcome::Close => {
                            let _ = writer.flush().await;
                            return Ok(());
                        }
                    }

                    while !flush_immediately
                        && batch_frames < d2c_flush_policy.max_frames
                        && batch_bytes < d2c_flush_policy.max_bytes
                    {
                        let Ok(next) = me_rx_task.try_recv() else {
                            break;
                        };

                        match process_me_writer_response(
                            next,
                            &mut writer,
                            proto_tag,
                            rng_clone.as_ref(),
                            &mut frame_buf,
                            stats_clone.as_ref(),
                            &user_clone,
                            bytes_me2c_clone.as_ref(),
                            conn_id,
                            d2c_flush_policy.ack_flush_immediate,
                            true,
                        ).await? {
                            MeWriterResponseOutcome::Continue { frames, bytes, flush_immediately: immediate } => {
                                batch_frames = batch_frames.saturating_add(frames);
                                batch_bytes = batch_bytes.saturating_add(bytes);
                                flush_immediately |= immediate;
                            }
                            MeWriterResponseOutcome::Close => {
                                let _ = writer.flush().await;
                                return Ok(());
                            }
                        }
                    }

                    if !flush_immediately
                        && !d2c_flush_policy.max_delay.is_zero()
                        && batch_frames < d2c_flush_policy.max_frames
                        && batch_bytes < d2c_flush_policy.max_bytes
                    {
                        match tokio::time::timeout(d2c_flush_policy.max_delay, me_rx_task.recv()).await {
                            Ok(Some(next)) => {
                                match process_me_writer_response(
                                    next,
                                    &mut writer,
                                    proto_tag,
                                    rng_clone.as_ref(),
                                    &mut frame_buf,
                                    stats_clone.as_ref(),
                                    &user_clone,
                                    bytes_me2c_clone.as_ref(),
                                    conn_id,
                                    d2c_flush_policy.ack_flush_immediate,
                                    true,
                                ).await? {
                                    MeWriterResponseOutcome::Continue { frames, bytes, flush_immediately: immediate } => {
                                        batch_frames = batch_frames.saturating_add(frames);
                                        batch_bytes = batch_bytes.saturating_add(bytes);
                                        flush_immediately |= immediate;
                                    }
                                    MeWriterResponseOutcome::Close => {
                                        let _ = writer.flush().await;
                                        return Ok(());
                                    }
                                }

                                while !flush_immediately
                                    && batch_frames < d2c_flush_policy.max_frames
                                    && batch_bytes < d2c_flush_policy.max_bytes
                                {
                                    let Ok(extra) = me_rx_task.try_recv() else {
                                        break;
                                    };

                                    match process_me_writer_response(
                                        extra,
                                        &mut writer,
                                        proto_tag,
                                        rng_clone.as_ref(),
                                        &mut frame_buf,
                                        stats_clone.as_ref(),
                                        &user_clone,
                                        bytes_me2c_clone.as_ref(),
                                        conn_id,
                                        d2c_flush_policy.ack_flush_immediate,
                                        true,
                                    ).await? {
                                        MeWriterResponseOutcome::Continue { frames, bytes, flush_immediately: immediate } => {
                                            batch_frames = batch_frames.saturating_add(frames);
                                            batch_bytes = batch_bytes.saturating_add(bytes);
                                            flush_immediately |= immediate;
                                        }
                                        MeWriterResponseOutcome::Close => {
                                            let _ = writer.flush().await;
                                            return Ok(());
                                        }
                                    }
                                }
                            }
                            Ok(None) => {
                                debug!(conn_id, "ME channel closed");
                                return Err(ProxyError::Proxy("ME connection lost".into()));
                            }
                            Err(_) => {}
                        }
                    }

                    writer.flush().await.map_err(ProxyError::Io)?;
                }
                _ = &mut stop_rx => {
                    debug!(conn_id, "ME writer stop signal");
                    return Ok(());
                }
            }
        }
    });

    let mut main_result: Result<()> = Ok(());
    let mut client_closed = false;
    let mut frame_counter: u64 = 0;
    let mut route_watch_open = true;
    let mut read_buf = Vec::with_capacity(16 * 1024);
    loop {
        if session_lease.is_stale() {
            stats.increment_reconnect_stale_close_total();
            let _ = me_pool.send_close(conn_id).await;
            main_result = Err(ProxyError::Proxy("Session evicted by reconnect".to_string()));
            break;
        }
        if let Some(cutover) = affected_cutover_state(
            &route_rx,
            RelayRouteMode::Middle,
            route_snapshot.generation,
        ) {
            let delay = cutover_stagger_delay(session_id, cutover.generation);
            warn!(
                conn_id,
                target_mode = cutover.mode.as_str(),
                cutover_generation = cutover.generation,
                delay_ms = delay.as_millis() as u64,
                "Cutover affected middle session, closing client connection"
            );
            tokio::time::sleep(delay).await;
            let _ = me_pool.send_close(conn_id).await;
            main_result = Err(ProxyError::Proxy(ROUTE_SWITCH_ERROR_MSG.to_string()));
            break;
        }

        tokio::select! {
            changed = route_rx.changed(), if route_watch_open => {
                if changed.is_err() {
                    route_watch_open = false;
                }
            }
            payload_result = read_client_payload(
                &mut crypto_reader,
                proto_tag,
                frame_limit,
                &forensics,
                &mut frame_counter,
                &stats,
                &mut read_buf,
            ) => {
                match payload_result {
                    Ok(Some((payload, quickack))) => {
                        trace!(conn_id, bytes = payload.len(), "C->ME frame");
                        forensics.bytes_c2me = forensics
                            .bytes_c2me
                            .saturating_add(payload.len() as u64);
                        stats.add_user_octets_from(&user, payload.len() as u64);
                        let mut flags = proto_flags;
                        if quickack {
                            flags |= RPC_FLAG_QUICKACK;
                        }
                        if payload.len() >= 8 && payload[..8].iter().all(|b| *b == 0) {
                            flags |= RPC_FLAG_NOT_ENCRYPTED;
                        }
                        // Send directly to ME pool — no intermediate channel/task.
                        if let Err(e) = me_pool.send_proxy_req_cached(
                            conn_id,
                            target_dc,
                            peer,
                            translated_local_addr,
                            payload.as_ref(),
                            flags,
                            effective_tag.as_deref(),
                            &mut cached_writer,
                        ).await {
                            main_result = Err(e);
                            break;
                        }
                    }
                    Ok(None) => {
                        debug!(conn_id, "Client EOF");
                        client_closed = true;
                        let _ = me_pool.send_close(conn_id).await;
                        break;
                    }
                    Err(e) => {
                        main_result = Err(e);
                        break;
                    }
                }
            }
        }
    }

    let _ = stop_tx.send(());
    let mut writer_result = me_writer
        .await
        .unwrap_or_else(|e| Err(ProxyError::Proxy(format!("ME writer join error: {e}"))));

    // When client closes, but ME channel stopped as unregistered - it isnt error
    if client_closed
        && matches!(
            writer_result,
            Err(ProxyError::Proxy(ref msg)) if msg == "ME connection lost"
        )
    {
        writer_result = Ok(());
    }

    let result = match (main_result, writer_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), _) => Err(e),
        (_, Err(e)) => Err(e),
    };

    debug!(
        user = %user,
        conn_id,
        trace_id = format_args!("0x{:016x}", trace_id),
        duration_ms = forensics.started_at.elapsed().as_millis() as u64,
        bytes_c2me = forensics.bytes_c2me,
        bytes_me2c = forensics.bytes_me2c.load(Ordering::Relaxed),
        frames_ok = frame_counter,
        "ME relay cleanup"
    );
    let final_tier = match shared_max_tier.load(Ordering::Relaxed) {
        1 => AdaptiveTier::Tier1,
        2 => AdaptiveTier::Tier2,
        3 => AdaptiveTier::Tier3,
        _ => seed_tier,
    };
    adaptive_buffers::record_user_tier(&user, final_tier);
    me_pool.registry().unregister(conn_id).await;
    stats.decrement_current_connections_me();
    stats.decrement_user_curr_connects(&user);
    result
}

async fn read_client_payload<R>(
    client_reader: &mut CryptoReader<R>,
    proto_tag: ProtoTag,
    max_frame: usize,
    forensics: &RelayForensicsState,
    frame_counter: &mut u64,
    stats: &Stats,
    read_buf: &mut Vec<u8>,
) -> Result<Option<(Bytes, bool)>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    loop {
        let (len, quickack, raw_len_bytes) = match proto_tag {
            ProtoTag::Abridged => {
                let mut first = [0u8; 1];
                match client_reader.read_exact(&mut first).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                    Err(e) => return Err(ProxyError::Io(e)),
                }

                let quickack = (first[0] & 0x80) != 0;
                let len_words = if (first[0] & 0x7f) == 0x7f {
                    let mut ext = [0u8; 3];
                    client_reader
                        .read_exact(&mut ext)
                        .await
                        .map_err(ProxyError::Io)?;
                    u32::from_le_bytes([ext[0], ext[1], ext[2], 0]) as usize
                } else {
                    (first[0] & 0x7f) as usize
                };

                let len = len_words
                    .checked_mul(4)
                    .ok_or_else(|| ProxyError::Proxy("Abridged frame length overflow".into()))?;
                (len, quickack, None)
            }
            ProtoTag::Intermediate | ProtoTag::Secure => {
                let mut len_buf = [0u8; 4];
                match client_reader.read_exact(&mut len_buf).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                    Err(e) => return Err(ProxyError::Io(e)),
                }
                let quickack = (len_buf[3] & 0x80) != 0;
                (
                    (u32::from_le_bytes(len_buf) & 0x7fff_ffff) as usize,
                    quickack,
                    Some(len_buf),
                )
            }
        };

        if len == 0 {
            continue;
        }
        if len < 4 && proto_tag != ProtoTag::Abridged {
            warn!(
                trace_id = format_args!("0x{:016x}", forensics.trace_id),
                conn_id = forensics.conn_id,
                user = %forensics.user,
                len,
                proto = ?proto_tag,
                "Frame too small — corrupt or probe"
            );
            return Err(ProxyError::Proxy(format!("Frame too small: {len}")));
        }

        if len > max_frame {
            return Err(report_desync_frame_too_large(
                forensics,
                proto_tag,
                *frame_counter,
                max_frame,
                len,
                raw_len_bytes,
                stats,
            ));
        }

        let secure_payload_len = if proto_tag == ProtoTag::Secure {
            match secure_payload_len_from_wire_len(len) {
                Some(payload_len) => payload_len,
                None => {
                    stats.increment_secure_padding_invalid();
                    return Err(ProxyError::Proxy(format!(
                        "Invalid secure frame length: {len}"
                    )));
                }
            }
        } else {
            len
        };

        // Reuse read buffer to avoid per-frame allocation.
        read_buf.clear();
        if read_buf.capacity() < len {
            read_buf.reserve(len - read_buf.capacity());
        }
        read_buf.resize(len, 0);
        client_reader
            .read_exact(&mut read_buf[..len])
            .await
            .map_err(ProxyError::Io)?;

        let payload_len = if proto_tag == ProtoTag::Secure {
            secure_payload_len
        } else {
            len
        };
        // Copy to Bytes for ownership transfer through channel.
        let payload = Bytes::copy_from_slice(&read_buf[..payload_len]);
        *frame_counter += 1;
        return Ok(Some((payload, quickack)));
    }
}

enum MeWriterResponseOutcome {
    Continue {
        frames: usize,
        bytes: usize,
        flush_immediately: bool,
    },
    Close,
}

async fn process_me_writer_response<W>(
    response: MeResponse,
    client_writer: &mut CryptoWriter<W>,
    proto_tag: ProtoTag,
    rng: &SecureRandom,
    frame_buf: &mut Vec<u8>,
    stats: &Stats,
    user: &str,
    bytes_me2c: &AtomicU64,
    conn_id: u64,
    ack_flush_immediate: bool,
    batched: bool,
) -> Result<MeWriterResponseOutcome>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    match response {
        MeResponse::Data { flags, data } => {
            if batched {
                trace!(conn_id, bytes = data.len(), flags, "ME->C data (batched)");
            } else {
                trace!(conn_id, bytes = data.len(), flags, "ME->C data");
            }
            bytes_me2c.fetch_add(data.len() as u64, Ordering::Relaxed);
            stats.add_user_octets_to(user, data.len() as u64);
            write_client_payload(
                client_writer,
                proto_tag,
                flags,
                &data,
                rng,
                frame_buf,
            )
            .await?;

            Ok(MeWriterResponseOutcome::Continue {
                frames: 1,
                bytes: data.len(),
                flush_immediately: false,
            })
        }
        MeResponse::Ack(confirm) => {
            if batched {
                trace!(conn_id, confirm, "ME->C quickack (batched)");
            } else {
                trace!(conn_id, confirm, "ME->C quickack");
            }
            write_client_ack(client_writer, proto_tag, confirm).await?;

            Ok(MeWriterResponseOutcome::Continue {
                frames: 1,
                bytes: 4,
                flush_immediately: ack_flush_immediate,
            })
        }
        MeResponse::Close => {
            if batched {
                debug!(conn_id, "ME sent close (batched)");
            } else {
                debug!(conn_id, "ME sent close");
            }
            Ok(MeWriterResponseOutcome::Close)
        }
    }
}

async fn write_client_payload<W>(
    client_writer: &mut CryptoWriter<W>,
    proto_tag: ProtoTag,
    flags: u32,
    data: &[u8],
    rng: &SecureRandom,
    frame_buf: &mut Vec<u8>,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let quickack = (flags & RPC_FLAG_QUICKACK) != 0;

    match proto_tag {
        ProtoTag::Abridged => {
            if !data.len().is_multiple_of(4) {
                return Err(ProxyError::Proxy(format!(
                    "Abridged payload must be 4-byte aligned, got {}",
                    data.len()
                )));
            }

            let len_words = data.len() / 4;
            if len_words < 0x7f {
                let mut first = len_words as u8;
                if quickack {
                    first |= 0x80;
                }
                frame_buf.clear();
                frame_buf.reserve(1 + data.len());
                frame_buf.push(first);
                frame_buf.extend_from_slice(data);
                client_writer
                    .write_all(frame_buf)
                    .await
                    .map_err(ProxyError::Io)?;
            } else if len_words < (1 << 24) {
                let mut first = 0x7fu8;
                if quickack {
                    first |= 0x80;
                }
                let lw = (len_words as u32).to_le_bytes();
                frame_buf.clear();
                frame_buf.reserve(4 + data.len());
                frame_buf.extend_from_slice(&[first, lw[0], lw[1], lw[2]]);
                frame_buf.extend_from_slice(data);
                client_writer
                    .write_all(frame_buf)
                    .await
                    .map_err(ProxyError::Io)?;
            } else {
                return Err(ProxyError::Proxy(format!(
                    "Abridged frame too large: {}",
                    data.len()
                )));
            }
        }
        ProtoTag::Intermediate | ProtoTag::Secure => {
            let padding_len = if proto_tag == ProtoTag::Secure {
                if !is_valid_secure_payload_len(data.len()) {
                    return Err(ProxyError::Proxy(format!(
                        "Secure payload must be 4-byte aligned, got {}",
                        data.len()
                    )));
                }
                secure_padding_len(data.len(), rng)
            } else {
                0
            };
            let mut len_val = (data.len() + padding_len) as u32;
            if quickack {
                len_val |= 0x8000_0000;
            }
            let total = 4 + data.len() + padding_len;
            frame_buf.clear();
            frame_buf.reserve(total);
            frame_buf.extend_from_slice(&len_val.to_le_bytes());
            frame_buf.extend_from_slice(data);
            if padding_len > 0 {
                let start = frame_buf.len();
                frame_buf.resize(start + padding_len, 0);
                rng.fill(&mut frame_buf[start..]);
            }
            client_writer
                .write_all(frame_buf)
                .await
                .map_err(ProxyError::Io)?;
        }
    }

    Ok(())
}

async fn write_client_ack<W>(
    client_writer: &mut CryptoWriter<W>,
    proto_tag: ProtoTag,
    confirm: u32,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let bytes = if proto_tag == ProtoTag::Abridged {
        confirm.to_be_bytes()
    } else {
        confirm.to_le_bytes()
    };
    client_writer
        .write_all(&bytes)
        .await
        .map_err(ProxyError::Io)
}

