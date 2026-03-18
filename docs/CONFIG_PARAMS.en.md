# Telemt Config Parameters Reference

This document lists all configuration keys accepted by `config.toml`.

> [!WARNING]
> 
> The configuration parameters detailed in this document are intended for advanced users and fine-tuning purposes. Modifying these settings without a clear understanding of their function may lead to application instability or other unexpected behavior. Please proceed with caution and at your own risk.

## Top-level keys

| Parameter | Type | Description |
|---|---|---|
| include | `String` (special directive) | Includes another TOML file with `include = "relative/or/absolute/path.toml"`; includes are processed recursively before parsing. |
| show_link | `"*" \| String[]` | Legacy top-level link visibility selector (`"*"` for all users or explicit usernames list). |
| dc_overrides | `Map<String, String[]>` | Overrides DC endpoints for non-standard DCs; key is DC id string, value is `ip:port` list. |
| default_dc | `u8` | Default DC index used for unmapped non-standard DCs. |

## [general]

| Parameter | Type | Description |
|---|---|---|
| data_path | `String` | Optional runtime data directory path. |
| prefer_ipv6 | `bool` | Prefer IPv6 where applicable in runtime logic. |
| fast_mode | `bool` | Enables fast-path optimizations for traffic processing. |
| use_middle_proxy | `bool` | Enables Middle Proxy mode. |
| proxy_secret_path | `String` | Path to proxy secret binary; can be auto-downloaded if absent. |
| proxy_config_v4_cache_path | `String` | Optional cache path for raw `getProxyConfig` (IPv4) snapshot. |
| proxy_config_v6_cache_path | `String` | Optional cache path for raw `getProxyConfigV6` (IPv6) snapshot. |
| ad_tag | `String` | Global fallback ad tag (32 hex characters). |
| middle_proxy_nat_ip | `IpAddr` | Explicit public IP override for NAT environments. |
| middle_proxy_nat_probe | `bool` | Enables NAT probing for Middle Proxy KDF/public address discovery. |
| middle_proxy_nat_stun | `String` | Deprecated legacy single STUN server for NAT probing. |
| middle_proxy_nat_stun_servers | `String[]` | Deprecated legacy STUN list for NAT probing fallback. |
| stun_nat_probe_concurrency | `usize` | Maximum concurrent STUN probes during NAT detection. |
| middle_proxy_pool_size | `usize` | Target size of active Middle Proxy writer pool. |
| middle_proxy_warm_standby | `usize` | Number of warm standby Middle-End connections. |
| me_init_retry_attempts | `u32` | Startup retries for ME pool initialization (`0` means unlimited). |
| me2dc_fallback | `bool` | Allows fallback from ME mode to direct DC when ME startup fails. |
| me_keepalive_enabled | `bool` | Enables ME keepalive padding frames. |
| me_keepalive_interval_secs | `u64` | Keepalive interval in seconds. |
| me_keepalive_jitter_secs | `u64` | Keepalive jitter in seconds. |
| me_keepalive_payload_random | `bool` | Randomizes keepalive payload bytes instead of zero payload. |
| rpc_proxy_req_every | `u64` | Interval for service `RPC_PROXY_REQ` activity signals (`0` disables). |
| me_writer_cmd_channel_capacity | `usize` | Capacity of per-writer command channel. |
| me_route_channel_capacity | `usize` | Capacity of per-connection ME response route channel. |
| me_c2me_channel_capacity | `usize` | Capacity of per-client command queue (client reader -> ME sender). |
| me_reader_route_data_wait_ms | `u64` | Bounded wait for routing ME DATA to per-connection queue (`0` = no wait). |
| me_d2c_flush_batch_max_frames | `usize` | Max ME->client frames coalesced before flush. |
| me_d2c_flush_batch_max_bytes | `usize` | Max ME->client payload bytes coalesced before flush. |
| me_d2c_flush_batch_max_delay_us | `u64` | Max microsecond wait for coalescing more ME->client frames (`0` disables timed coalescing). |
| me_d2c_ack_flush_immediate | `bool` | Flushes client writer immediately after quick-ack write. |
| direct_relay_copy_buf_c2s_bytes | `usize` | Copy buffer size for client->DC direction in direct relay. |
| direct_relay_copy_buf_s2c_bytes | `usize` | Copy buffer size for DC->client direction in direct relay. |
| crypto_pending_buffer | `usize` | Max pending ciphertext buffer per client writer (bytes). |
| max_client_frame | `usize` | Maximum allowed client MTProto frame size (bytes). |
| desync_all_full | `bool` | Emits full crypto-desync forensic logs for every event. |
| beobachten | `bool` | Enables per-IP forensic observation buckets. |
| beobachten_minutes | `u64` | Retention window (minutes) for per-IP observation buckets. |
| beobachten_flush_secs | `u64` | Snapshot flush interval (seconds) for observation output file. |
| beobachten_file | `String` | Observation snapshot output file path. |
| hardswap | `bool` | Enables hard-swap generation switching for ME pool updates. |
| me_warmup_stagger_enabled | `bool` | Enables staggered warmup for extra ME writers. |
| me_warmup_step_delay_ms | `u64` | Base delay between warmup connections (ms). |
| me_warmup_step_jitter_ms | `u64` | Jitter for warmup delay (ms). |
| me_reconnect_max_concurrent_per_dc | `u32` | Max concurrent reconnect attempts per DC. |
| me_reconnect_backoff_base_ms | `u64` | Base reconnect backoff in ms. |
| me_reconnect_backoff_cap_ms | `u64` | Cap reconnect backoff in ms. |
| me_reconnect_fast_retry_count | `u32` | Number of fast retry attempts before backoff. |
| me_single_endpoint_shadow_writers | `u8` | Additional reserve writers for one-endpoint DC groups. |
| me_single_endpoint_outage_mode_enabled | `bool` | Enables aggressive outage recovery for one-endpoint DC groups. |
| me_single_endpoint_outage_disable_quarantine | `bool` | Ignores endpoint quarantine in one-endpoint outage mode. |
| me_single_endpoint_outage_backoff_min_ms | `u64` | Minimum reconnect backoff in outage mode (ms). |
| me_single_endpoint_outage_backoff_max_ms | `u64` | Maximum reconnect backoff in outage mode (ms). |
| me_single_endpoint_shadow_rotate_every_secs | `u64` | Periodic shadow writer rotation interval (`0` disables). |
| me_floor_mode | `"static" \| "adaptive"` | Writer floor policy mode. |
| me_adaptive_floor_idle_secs | `u64` | Idle time before adaptive floor may reduce one-endpoint target. |
| me_adaptive_floor_min_writers_single_endpoint | `u8` | Minimum adaptive writer target for one-endpoint DC groups. |
| me_adaptive_floor_min_writers_multi_endpoint | `u8` | Minimum adaptive writer target for multi-endpoint DC groups. |
| me_adaptive_floor_recover_grace_secs | `u64` | Grace period to hold static floor after activity. |
| me_adaptive_floor_writers_per_core_total | `u16` | Global writer budget per logical CPU core in adaptive mode. |
| me_adaptive_floor_cpu_cores_override | `u16` | Manual CPU core count override (`0` uses auto-detection). |
| me_adaptive_floor_max_extra_writers_single_per_core | `u16` | Per-core max extra writers above base floor for one-endpoint DCs. |
| me_adaptive_floor_max_extra_writers_multi_per_core | `u16` | Per-core max extra writers above base floor for multi-endpoint DCs. |
| me_adaptive_floor_max_active_writers_per_core | `u16` | Hard cap for active ME writers per logical CPU core. |
| me_adaptive_floor_max_warm_writers_per_core | `u16` | Hard cap for warm ME writers per logical CPU core. |
| me_adaptive_floor_max_active_writers_global | `u32` | Hard global cap for active ME writers. |
| me_adaptive_floor_max_warm_writers_global | `u32` | Hard global cap for warm ME writers. |
| upstream_connect_retry_attempts | `u32` | Connect attempts for selected upstream before error/fallback. |
| upstream_connect_retry_backoff_ms | `u64` | Delay between upstream connect attempts (ms). |
| upstream_connect_budget_ms | `u64` | Total wall-clock budget for one upstream connect request (ms). |
| upstream_unhealthy_fail_threshold | `u32` | Consecutive failed requests before upstream is marked unhealthy. |
| upstream_connect_failfast_hard_errors | `bool` | Skips additional retries for hard non-transient connect errors. |
| stun_iface_mismatch_ignore | `bool` | Ignores STUN/interface mismatch and keeps Middle Proxy mode. |
| unknown_dc_log_path | `String` | File path for unknown-DC request logging (`null` disables file path). |
| unknown_dc_file_log_enabled | `bool` | Enables unknown-DC file logging. |
| log_level | `"debug" \| "verbose" \| "normal" \| "silent"` | Runtime logging verbosity. |
| disable_colors | `bool` | Disables ANSI colors in logs. |
| me_socks_kdf_policy | `"strict" \| "compat"` | SOCKS-bound KDF fallback policy for ME handshake. |
| me_route_backpressure_base_timeout_ms | `u64` | Base backpressure timeout for route-channel send (ms). |
| me_route_backpressure_high_timeout_ms | `u64` | High backpressure timeout when queue occupancy exceeds watermark (ms). |
| me_route_backpressure_high_watermark_pct | `u8` | Queue occupancy threshold (%) for high timeout mode. |
| me_health_interval_ms_unhealthy | `u64` | Health monitor interval while writer coverage is degraded (ms). |
| me_health_interval_ms_healthy | `u64` | Health monitor interval while writer coverage is healthy (ms). |
| me_admission_poll_ms | `u64` | Poll interval for conditional-admission checks (ms). |
| me_warn_rate_limit_ms | `u64` | Cooldown for repetitive ME warning logs (ms). |
| me_route_no_writer_mode | `"async_recovery_failfast" \| "inline_recovery_legacy" \| "hybrid_async_persistent"` | Route behavior when no writer is immediately available. |
| me_route_no_writer_wait_ms | `u64` | Max wait in async-recovery failfast mode (ms). |
| me_route_inline_recovery_attempts | `u32` | Inline recovery attempts in legacy mode. |
| me_route_inline_recovery_wait_ms | `u64` | Max inline recovery wait in legacy mode (ms). |
| fast_mode_min_tls_record | `usize` | Minimum TLS record size when fast-mode coalescing is enabled (`0` disables). |
| update_every | `u64` | Unified interval for config/secret updater tasks. |
| me_reinit_every_secs | `u64` | Periodic ME pool reinitialization interval (seconds). |
| me_hardswap_warmup_delay_min_ms | `u64` | Minimum delay between hardswap warmup connects (ms). |
| me_hardswap_warmup_delay_max_ms | `u64` | Maximum delay between hardswap warmup connects (ms). |
| me_hardswap_warmup_extra_passes | `u8` | Additional warmup passes per hardswap cycle. |
| me_hardswap_warmup_pass_backoff_base_ms | `u64` | Base backoff between hardswap warmup passes (ms). |
| me_config_stable_snapshots | `u8` | Number of identical config snapshots required before apply. |
| me_config_apply_cooldown_secs | `u64` | Cooldown between applied ME map updates (seconds). |
| me_snapshot_require_http_2xx | `bool` | Requires 2xx HTTP responses for applying config snapshots. |
| me_snapshot_reject_empty_map | `bool` | Rejects empty config snapshots. |
| me_snapshot_min_proxy_for_lines | `u32` | Minimum parsed `proxy_for` rows required to accept snapshot. |
| proxy_secret_stable_snapshots | `u8` | Number of identical secret snapshots required before runtime rotation. |
| proxy_secret_rotate_runtime | `bool` | Enables runtime proxy-secret rotation from remote source. |
| me_secret_atomic_snapshot | `bool` | Keeps selector and secret bytes from the same snapshot atomically. |
| proxy_secret_len_max | `usize` | Maximum allowed proxy-secret length (bytes). |
| me_pool_drain_ttl_secs | `u64` | Drain TTL for stale ME writers after endpoint-map changes (seconds). |
| me_pool_drain_threshold | `u64` | Max draining stale writers before batch force-close (`0` disables threshold cleanup). |
| me_bind_stale_mode | `"never" \| "ttl" \| "always"` | Policy for new binds on stale draining writers. |
| me_bind_stale_ttl_secs | `u64` | TTL for stale bind allowance when stale mode is `ttl`. |
| me_pool_min_fresh_ratio | `f32` | Minimum desired-DC fresh coverage ratio before draining stale writers. |
| me_reinit_drain_timeout_secs | `u64` | Force-close timeout for stale writers after endpoint-map changes (`0` disables force-close). |
| proxy_secret_auto_reload_secs | `u64` | Deprecated legacy secret reload interval (fallback when `update_every` is not set). |
| proxy_config_auto_reload_secs | `u64` | Deprecated legacy config reload interval (fallback when `update_every` is not set). |
| me_reinit_singleflight | `bool` | Serializes ME reinit cycles across trigger sources. |
| me_reinit_trigger_channel | `usize` | Trigger queue capacity for reinit scheduler. |
| me_reinit_coalesce_window_ms | `u64` | Trigger coalescing window before starting reinit (ms). |
| me_deterministic_writer_sort | `bool` | Enables deterministic candidate sort for writer binding path. |
| me_writer_pick_mode | `"sorted_rr" \| "p2c"` | Writer selection mode for route bind path. |
| me_writer_pick_sample_size | `u8` | Number of candidates sampled by picker in `p2c` mode. |
| ntp_check | `bool` | Enables NTP drift check at startup. |
| ntp_servers | `String[]` | NTP servers used for drift check. |
| auto_degradation_enabled | `bool` | Enables automatic degradation from ME to direct DC. |
| degradation_min_unavailable_dc_groups | `u8` | Minimum unavailable ME DC groups required before degrading. |

## [general.modes]

| Parameter | Type | Description |
|---|---|---|
| classic | `bool` | Enables classic MTProxy mode. |
| secure | `bool` | Enables secure mode. |
| tls | `bool` | Enables TLS mode. |

## [general.links]

| Parameter | Type | Description |
|---|---|---|
| show | `"*" \| String[]` | Selects users whose tg:// links are shown at startup. |
| public_host | `String` | Public hostname/IP override for generated tg:// links. |
| public_port | `u16` | Public port override for generated tg:// links. |

## [general.telemetry]

| Parameter | Type | Description |
|---|---|---|
| core_enabled | `bool` | Enables core hot-path telemetry counters. |
| user_enabled | `bool` | Enables per-user telemetry counters. |
| me_level | `"silent" \| "normal" \| "debug"` | Middle-End telemetry verbosity level. |

## [network]

| Parameter | Type | Description |
|---|---|---|
| ipv4 | `bool` | Enables IPv4 networking. |
| ipv6 | `bool` | Enables/disables IPv6 (`null` = auto-detect availability). |
| prefer | `u8` | Preferred IP family for selection (`4` or `6`). |
| multipath | `bool` | Enables multipath behavior where supported. |
| stun_use | `bool` | Global switch for STUN probing. |
| stun_servers | `String[]` | STUN server list for public IP detection. |
| stun_tcp_fallback | `bool` | Enables TCP STUN fallback when UDP STUN is blocked. |
| http_ip_detect_urls | `String[]` | HTTP endpoints used as fallback public IP detectors. |
| cache_public_ip_path | `String` | File path for caching detected public IP. |
| dns_overrides | `String[]` | Runtime DNS overrides in `host:port:ip` format. |

## [server]

| Parameter | Type | Description |
|---|---|---|
| port | `u16` | Main proxy listen port. |
| listen_addr_ipv4 | `String` | IPv4 bind address for TCP listener. |
| listen_addr_ipv6 | `String` | IPv6 bind address for TCP listener. |
| listen_unix_sock | `String` | Unix socket path for listener. |
| listen_unix_sock_perm | `String` | Unix socket permissions in octal string (e.g., `"0666"`). |
| listen_tcp | `bool` | Explicit TCP listener enable/disable override. |
| proxy_protocol | `bool` | Enables HAProxy PROXY protocol parsing on incoming client connections. |
| proxy_protocol_header_timeout_ms | `u64` | Timeout for PROXY protocol header read/parse (ms). |
| metrics_port | `u16` | Metrics endpoint port (enables metrics listener). |
| metrics_listen | `String` | Full metrics bind address (`IP:PORT`), overrides `metrics_port`. |
| metrics_whitelist | `IpNetwork[]` | CIDR whitelist for metrics endpoint access. |
| max_connections | `u32` | Max concurrent client connections (`0` = unlimited). |

## [server.api]

| Parameter | Type | Description |
|---|---|---|
| enabled | `bool` | Enables control-plane REST API. |
| listen | `String` | API bind address in `IP:PORT` format. |
| whitelist | `IpNetwork[]` | CIDR whitelist allowed to access API. |
| auth_header | `String` | Exact expected `Authorization` header value (empty = disabled). |
| request_body_limit_bytes | `usize` | Maximum accepted HTTP request body size. |
| minimal_runtime_enabled | `bool` | Enables minimal runtime snapshots endpoint logic. |
| minimal_runtime_cache_ttl_ms | `u64` | Cache TTL for minimal runtime snapshots (ms; `0` disables cache). |
| runtime_edge_enabled | `bool` | Enables runtime edge endpoints. |
| runtime_edge_cache_ttl_ms | `u64` | Cache TTL for runtime edge aggregation payloads (ms). |
| runtime_edge_top_n | `usize` | Top-N size for edge connection leaderboard. |
| runtime_edge_events_capacity | `usize` | Ring-buffer capacity for runtime edge events. |
| read_only | `bool` | Rejects mutating API endpoints when enabled. |

## [[server.listeners]]

| Parameter | Type | Description |
|---|---|---|
| ip | `IpAddr` | Listener bind IP. |
| announce | `String` | Public IP/domain announced in proxy links (priority over `announce_ip`). |
| announce_ip | `IpAddr` | Deprecated legacy announce IP (migrated to `announce` if needed). |
| proxy_protocol | `bool` | Per-listener override for PROXY protocol enable flag. |
| reuse_allow | `bool` | Enables `SO_REUSEPORT` for multi-instance bind sharing. |

## [timeouts]

| Parameter | Type | Description |
|---|---|---|
| client_handshake | `u64` | Client handshake timeout. |
| tg_connect | `u64` | Upstream Telegram connect timeout. |
| client_keepalive | `u64` | Client keepalive timeout. |
| client_ack | `u64` | Client ACK timeout. |
| me_one_retry | `u8` | Quick ME reconnect attempts for single-address DC. |
| me_one_timeout_ms | `u64` | Timeout per quick attempt for single-address DC (ms). |

## [censorship]

| Parameter | Type | Description |
|---|---|---|
| tls_domain | `String` | Primary TLS domain used in fake TLS handshake profile. |
| tls_domains | `String[]` | Additional TLS domains for generating multiple links. |
| mask | `bool` | Enables masking/fronting relay mode. |
| mask_host | `String` | Upstream mask host for TLS fronting relay. |
| mask_port | `u16` | Upstream mask port for TLS fronting relay. |
| mask_unix_sock | `String` | Unix socket path for mask backend instead of TCP host/port. |
| fake_cert_len | `usize` | Length of synthetic certificate payload when emulation data is unavailable. |
| tls_emulation | `bool` | Enables certificate/TLS behavior emulation from cached real fronts. |
| tls_front_dir | `String` | Directory path for TLS front cache storage. |
| server_hello_delay_min_ms | `u64` | Minimum server_hello delay for anti-fingerprint behavior (ms). |
| server_hello_delay_max_ms | `u64` | Maximum server_hello delay for anti-fingerprint behavior (ms). |
| tls_new_session_tickets | `u8` | Number of `NewSessionTicket` messages to emit after handshake. |
| tls_full_cert_ttl_secs | `u64` | TTL for sending full cert payload per (domain, client IP) tuple. |
| alpn_enforce | `bool` | Enforces ALPN echo behavior based on client preference. |
| mask_proxy_protocol | `u8` | PROXY protocol mode for mask backend (`0` disabled, `1` v1, `2` v2). |

## [access]

| Parameter | Type | Description |
|---|---|---|
| users | `Map<String, String>` | Username -> 32-hex secret mapping. |
| user_ad_tags | `Map<String, String>` | Per-user ad tags (32 hex chars). |
| user_max_tcp_conns | `Map<String, usize>` | Per-user maximum concurrent TCP connections. |
| user_expirations | `Map<String, DateTime<Utc>>` | Per-user account expiration timestamps. |
| user_data_quota | `Map<String, u64>` | Per-user data quota limits. |
| user_max_unique_ips | `Map<String, usize>` | Per-user unique source IP limits. |
| user_max_unique_ips_global_each | `usize` | Global fallback per-user unique IP limit when no per-user override exists. |
| user_max_unique_ips_mode | `"active_window" \| "time_window" \| "combined"` | Unique source IP limit accounting mode. |
| user_max_unique_ips_window_secs | `u64` | Recent-window size for unique IP accounting (seconds). |
| replay_check_len | `usize` | Replay check storage length. |
| replay_window_secs | `u64` | Replay protection time window in seconds. |
| ignore_time_skew | `bool` | Ignores client/server timestamp skew in replay validation. |

## [[upstreams]]

| Parameter | Type | Description |
|---|---|---|
| type | `"direct" \| "socks4" \| "socks5"` | Upstream transport type selector. |
| weight | `u16` | Weighted selection coefficient for this upstream. |
| enabled | `bool` | Enables/disables this upstream entry. |
| scopes | `String` | Comma-separated scope tags for routing. |
| interface | `String` | Optional outgoing interface name (`direct`, `socks4`, `socks5`). |
| bind_addresses | `String[]` | Optional source bind addresses for `direct` upstream. |
| address | `String` | Upstream proxy address (`host:port`) for SOCKS upstreams. |
| user_id | `String` | SOCKS4 user ID (only for `type = "socks4"`). |
| username | `String` | SOCKS5 username (only for `type = "socks5"`). |
| password | `String` | SOCKS5 password (only for `type = "socks5"`). |
