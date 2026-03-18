use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use bytes::Bytes;

use crate::protocol::constants::*;

#[derive(Clone, Copy)]
pub(crate) enum IpMaterial {
    V4([u8; 4]),
    V6([u8; 16]),
}

pub(crate) fn extract_ip_material(addr: SocketAddr) -> IpMaterial {
    match addr.ip() {
        IpAddr::V4(v4) => IpMaterial::V4(v4.octets()),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpMaterial::V4(v4.octets())
            } else {
                IpMaterial::V6(v6.octets())
            }
        }
    }
}

fn ipv4_to_mapped_v6_c_compat(ip: Ipv4Addr) -> [u8; 16] {
    let mut buf = [0u8; 16];

    // Matches tl_store_long(0) + tl_store_int(-0x10000).
    buf[8..12].copy_from_slice(&(-0x10000i32).to_le_bytes());

    // Matches tl_store_int(htonl(remote_ip_host_order)).
    buf[12..16].copy_from_slice(&ip.octets());

    buf
}

fn append_mapped_addr_and_port(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => buf.extend_from_slice(&ipv4_to_mapped_v6_c_compat(v4)),
        IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
    }
    buf.extend_from_slice(&(addr.port() as u32).to_le_bytes());
}

pub(crate) fn build_proxy_req_payload(
    conn_id: u64,
    client_addr: SocketAddr,
    our_addr: SocketAddr,
    data: &[u8],
    proxy_tag: Option<&[u8]>,
    proto_flags: u32,
) -> Bytes {
    let mut b = Vec::with_capacity(128 + data.len());

    b.extend_from_slice(&RPC_PROXY_REQ_U32.to_le_bytes());
    b.extend_from_slice(&proto_flags.to_le_bytes());
    b.extend_from_slice(&conn_id.to_le_bytes());

    append_mapped_addr_and_port(&mut b, client_addr);
    append_mapped_addr_and_port(&mut b, our_addr);

    if proto_flags & RPC_FLAG_HAS_AD_TAG != 0 {
        let extra_start = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());

        if let Some(tag) = proxy_tag {
            b.extend_from_slice(&TL_PROXY_TAG_U32.to_le_bytes());

            if tag.len() < 254 {
                b.push(tag.len() as u8);
                b.extend_from_slice(tag);
                let pad = (4 - ((1 + tag.len()) % 4)) % 4;
                b.extend(std::iter::repeat_n(0u8, pad));
            } else {
                b.push(0xfe);
                let len_bytes = (tag.len() as u32).to_le_bytes();
                b.extend_from_slice(&len_bytes[..3]);
                b.extend_from_slice(tag);
                let pad = (4 - (tag.len() % 4)) % 4;
                b.extend(std::iter::repeat_n(0u8, pad));
            }
        }

        let extra_bytes = (b.len() - extra_start - 4) as u32;
        b[extra_start..extra_start + 4].copy_from_slice(&extra_bytes.to_le_bytes());
    }

    b.extend_from_slice(data);
    Bytes::from(b)
}

/// Pre-computed RPC header template for a session. proto_flags field at offset 4..8
/// is patched per-frame since quickack/not_encrypted bits vary.
/// Layout: [RPC_PROXY_REQ(4)] [proto_flags(4)] [conn_id(8)] [client_addr(20)] [our_addr(20)] [ad_tag_section(...)]
pub(crate) struct RpcHeaderTemplate {
    buf: Vec<u8>,
}

const PROTO_FLAGS_OFFSET: usize = 4;

impl RpcHeaderTemplate {
    pub fn new(
        conn_id: u64,
        client_addr: SocketAddr,
        our_addr: SocketAddr,
        proxy_tag: Option<&[u8]>,
        base_proto_flags: u32,
    ) -> Self {
        let mut b = Vec::with_capacity(128);

        b.extend_from_slice(&RPC_PROXY_REQ_U32.to_le_bytes());
        b.extend_from_slice(&base_proto_flags.to_le_bytes()); // patched per-frame
        b.extend_from_slice(&conn_id.to_le_bytes());

        append_mapped_addr_and_port(&mut b, client_addr);
        append_mapped_addr_and_port(&mut b, our_addr);

        if base_proto_flags & RPC_FLAG_HAS_AD_TAG != 0 {
            let extra_start = b.len();
            b.extend_from_slice(&0u32.to_le_bytes());

            if let Some(tag) = proxy_tag {
                b.extend_from_slice(&TL_PROXY_TAG_U32.to_le_bytes());

                if tag.len() < 254 {
                    b.push(tag.len() as u8);
                    b.extend_from_slice(tag);
                    let pad = (4 - ((1 + tag.len()) % 4)) % 4;
                    b.extend(std::iter::repeat_n(0u8, pad));
                } else {
                    b.push(0xfe);
                    let len_bytes = (tag.len() as u32).to_le_bytes();
                    b.extend_from_slice(&len_bytes[..3]);
                    b.extend_from_slice(tag);
                    let pad = (4 - (tag.len() % 4)) % 4;
                    b.extend(std::iter::repeat_n(0u8, pad));
                }
            }

            let extra_bytes = (b.len() - extra_start - 4) as u32;
            b[extra_start..extra_start + 4].copy_from_slice(&extra_bytes.to_le_bytes());
        }

        Self { buf: b }
    }

    /// Assemble full RPC payload: copy header template, patch per-frame proto_flags, append data.
    /// Allocates a Vec sized exactly for header + data, then converts to Bytes zero-copy.
    /// The reuse_buf parameter is retained for API compat but unused (could be removed later).
    #[inline]
    pub fn build(&self, proto_flags: u32, data: &[u8], _reuse_buf: &mut Vec<u8>) -> Bytes {
        let total = self.buf.len() + data.len();
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&self.buf);
        // Patch per-frame flags (quickack, not_encrypted bits may differ).
        buf[PROTO_FLAGS_OFFSET..PROTO_FLAGS_OFFSET + 4]
            .copy_from_slice(&proto_flags.to_le_bytes());
        buf.extend_from_slice(data);
        Bytes::from(buf)
    }
}

pub fn proto_flags_for_tag(tag: crate::protocol::constants::ProtoTag, has_proxy_tag: bool) -> u32 {
    use crate::protocol::constants::ProtoTag;

    let mut flags = RPC_FLAG_MAGIC | RPC_FLAG_EXTMODE2;
    if has_proxy_tag {
        flags |= RPC_FLAG_HAS_AD_TAG;
    }

    match tag {
        ProtoTag::Abridged => flags | RPC_FLAG_ABRIDGED,
        ProtoTag::Intermediate => flags | RPC_FLAG_INTERMEDIATE,
        ProtoTag::Secure => flags | RPC_FLAG_PAD | RPC_FLAG_INTERMEDIATE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddr};
    use std::time::Instant;

    #[test]
    fn test_ipv4_mapped_encoding() {
        let ip = Ipv4Addr::new(149, 154, 175, 50);
        let buf = ipv4_to_mapped_v6_c_compat(ip);
        assert_eq!(&buf[0..10], &[0u8; 10]);
        assert_eq!(&buf[10..12], &[0xff, 0xff]);
        assert_eq!(&buf[12..16], &[149, 154, 175, 50]);
    }

    fn test_addrs() -> (SocketAddr, SocketAddr) {
        let client = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)), 12345);
        let our = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        (client, our)
    }

    fn test_tag() -> Vec<u8> {
        vec![0xAA; 16]
    }

    #[test]
    fn test_rpc_header_template_matches_build_proxy_req() {
        let (client, our) = test_addrs();
        let tag = test_tag();
        let conn_id: u64 = 0xDEADBEEF_CAFEBABE;
        let base_flags: u32 = RPC_FLAG_MAGIC | RPC_FLAG_EXTMODE2 | RPC_FLAG_HAS_AD_TAG | RPC_FLAG_INTERMEDIATE;
        let data = b"hello world test payload data";

        // Build with the old per-frame method.
        let old_result = build_proxy_req_payload(conn_id, client, our, data, Some(&tag), base_flags);

        // Build with the new template method.
        let template = RpcHeaderTemplate::new(conn_id, client, our, Some(&tag), base_flags);
        let mut reuse_buf = Vec::with_capacity(256);
        let new_result = template.build(base_flags, data, &mut reuse_buf);

        assert_eq!(old_result.as_ref(), new_result.as_ref(), "Template build must match legacy build");
    }

    #[test]
    fn test_rpc_header_template_quickack_flag_patch() {
        let (client, our) = test_addrs();
        let tag = test_tag();
        let conn_id: u64 = 42;
        let base_flags: u32 = RPC_FLAG_MAGIC | RPC_FLAG_EXTMODE2 | RPC_FLAG_HAS_AD_TAG | RPC_FLAG_INTERMEDIATE;
        let data = b"test";

        let template = RpcHeaderTemplate::new(conn_id, client, our, Some(&tag), base_flags);
        let mut buf = Vec::new();

        // Without quickack.
        let result_no_qa = template.build(base_flags, data, &mut buf);
        // With quickack.
        let result_qa = template.build(base_flags | RPC_FLAG_QUICKACK, data, &mut buf);

        // Only proto_flags field (bytes 4..8) should differ.
        assert_ne!(result_no_qa.as_ref(), result_qa.as_ref());
        assert_eq!(&result_no_qa[0..4], &result_qa[0..4]); // RPC_PROXY_REQ
        assert_ne!(&result_no_qa[4..8], &result_qa[4..8]); // proto_flags differ
        assert_eq!(&result_no_qa[8..], &result_qa[8..]);    // rest identical
    }

    #[test]
    fn test_rpc_header_template_not_encrypted_flag_patch() {
        let (client, our) = test_addrs();
        let conn_id: u64 = 99;
        let base_flags: u32 = RPC_FLAG_MAGIC | RPC_FLAG_EXTMODE2 | RPC_FLAG_INTERMEDIATE;
        let data = b"payload";

        // Without ad_tag — simpler header.
        let template = RpcHeaderTemplate::new(conn_id, client, our, None, base_flags);
        let mut buf = Vec::new();

        let result_normal = template.build(base_flags, data, &mut buf);
        let result_unencrypted = template.build(base_flags | RPC_FLAG_NOT_ENCRYPTED, data, &mut buf);

        let legacy_normal = build_proxy_req_payload(conn_id, client, our, data, None, base_flags);
        let legacy_unencrypted = build_proxy_req_payload(conn_id, client, our, data, None, base_flags | RPC_FLAG_NOT_ENCRYPTED);

        assert_eq!(result_normal.as_ref(), legacy_normal.as_ref());
        assert_eq!(result_unencrypted.as_ref(), legacy_unencrypted.as_ref());
    }

    #[test]
    fn test_rpc_header_template_ipv6_addrs() {
        let client = SocketAddr::new(
            std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            54321,
        );
        let our = SocketAddr::new(
            std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            443,
        );
        let conn_id: u64 = 0x1234;
        let flags = RPC_FLAG_MAGIC | RPC_FLAG_EXTMODE2 | RPC_FLAG_INTERMEDIATE;
        let data = b"ipv6 test data";

        let old = build_proxy_req_payload(conn_id, client, our, data, None, flags);
        let template = RpcHeaderTemplate::new(conn_id, client, our, None, flags);
        let mut buf = Vec::new();
        let new = template.build(flags, data, &mut buf);

        assert_eq!(old.as_ref(), new.as_ref(), "IPv6 template must match legacy");
    }

    #[test]
    fn bench_synthetic_template_vs_legacy() {
        let (client, our) = test_addrs();
        let tag = test_tag();
        let conn_id: u64 = 0xDEAD;
        let base_flags: u32 = RPC_FLAG_MAGIC | RPC_FLAG_EXTMODE2 | RPC_FLAG_HAS_AD_TAG | RPC_FLAG_INTERMEDIATE;
        let data = vec![0x42u8; 1024]; // typical MTProto frame
        let iterations = 100_000;

        // Benchmark legacy: build_proxy_req_payload (allocates new Vec every time).
        let start = Instant::now();
        for i in 0..iterations {
            let flags = if i % 3 == 0 { base_flags | RPC_FLAG_QUICKACK } else { base_flags };
            let result = build_proxy_req_payload(conn_id, client, our, &data, Some(&tag), flags);
            std::hint::black_box(&result);
        }
        let legacy_ns = start.elapsed().as_nanos() as f64 / iterations as f64;

        // Benchmark template: pre-computed header + reuse buffer.
        let template = RpcHeaderTemplate::new(conn_id, client, our, Some(&tag), base_flags);
        let mut reuse_buf = Vec::with_capacity(2048);
        let start = Instant::now();
        for i in 0..iterations {
            let flags = if i % 3 == 0 { base_flags | RPC_FLAG_QUICKACK } else { base_flags };
            let result = template.build(flags, &data, &mut reuse_buf);
            std::hint::black_box(&result);
        }
        let template_ns = start.elapsed().as_nanos() as f64 / iterations as f64;

        let speedup = legacy_ns / template_ns;
        eprintln!(
            "\n=== RPC Header Build Benchmark (1KB payload, 100K iterations) ===\n\
             Legacy (per-frame alloc):  {:.0} ns/op\n\
             Template (pre-computed):   {:.0} ns/op\n\
             Speedup:                   {:.2}x\n",
            legacy_ns, template_ns, speedup,
        );
        // Template should be at least 1.3x faster due to no header re-assembly.
        assert!(speedup > 1.0, "Template should not be slower than legacy, got {speedup:.2}x");
    }

    #[test]
    fn bench_synthetic_vec_reuse_vs_per_frame_alloc() {
        let iterations = 200_000;
        let frame_sizes = [64, 256, 1024, 4096, 16384];

        eprintln!("\n=== Vec Reuse vs Per-Frame Allocation Benchmark ===");
        for &size in &frame_sizes {
            // Per-frame allocation (old behavior).
            let start = Instant::now();
            for _ in 0..iterations {
                let buf = vec![0u8; size];
                std::hint::black_box(&buf);
            }
            let alloc_ns = start.elapsed().as_nanos() as f64 / iterations as f64;

            // Reusable buffer (new behavior).
            let mut reuse = Vec::with_capacity(16 * 1024);
            let start = Instant::now();
            for _ in 0..iterations {
                reuse.clear();
                reuse.resize(size, 0);
                std::hint::black_box(&reuse);
            }
            let reuse_ns = start.elapsed().as_nanos() as f64 / iterations as f64;

            let speedup = alloc_ns / reuse_ns;
            eprintln!(
                "  Frame {size:>5}B: alloc={alloc_ns:.0}ns  reuse={reuse_ns:.0}ns  speedup={speedup:.2}x",
            );
            // Note: Vec reuse benefit is primarily allocator contention avoidance under
            // concurrent load, not single-thread microbenchmark speedup. The resize() cost
            // may exceed calloc() for large buffers in isolation, but in production with
            // hundreds of concurrent connections, avoiding frequent alloc/free is the win.
        }
        eprintln!();
    }

    #[test]
    fn bench_synthetic_bytes_copy_vs_from() {
        // This tests the Bytes::copy_from_slice issue found in commit 120c488.
        let iterations = 200_000;
        let data_size = 1200; // typical MTProto frame with header

        let source = vec![0x42u8; data_size];

        // Bytes::copy_from_slice — allocates new buffer and copies.
        let start = Instant::now();
        for _ in 0..iterations {
            let b = Bytes::copy_from_slice(&source);
            std::hint::black_box(&b);
        }
        let copy_ns = start.elapsed().as_nanos() as f64 / iterations as f64;

        // Bytes::from(Vec) — takes ownership, zero-copy.
        let start = Instant::now();
        for _ in 0..iterations {
            let mut buf = Vec::with_capacity(data_size);
            buf.extend_from_slice(&source);
            let b = Bytes::from(buf);
            std::hint::black_box(&b);
        }
        let from_vec_ns = start.elapsed().as_nanos() as f64 / iterations as f64;

        eprintln!(
            "\n=== Bytes Conversion Benchmark ({data_size}B payload, 200K iterations) ===\n\
             Bytes::copy_from_slice:  {copy_ns:.0} ns/op\n\
             Bytes::from(Vec):        {from_vec_ns:.0} ns/op\n\
             Ratio:                   {:.2}x\n\
             Note: copy_from_slice is used in RpcHeaderTemplate::build() —\n\
             consider using Bytes::from(mem::take(reuse_buf)) + re-init pattern.\n",
            copy_ns / from_vec_ns,
        );
    }
}
