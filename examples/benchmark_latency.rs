//! RFC-ILP-2026: Latency Benchmark & Statistical Performance Characterization
//!
//! Este binario ejecuta un benchmark científico y reproducible midiendo individualmente
//! 100,000 iteraciones tras un calentamiento (warmup) de 10,000 iteraciones.
//!
//! Reporta: Mínimo, Mediana (p50), p95, p99, Máximo, Promedio y Desviación Estándar.

use ilp_core::governance::{CognitiveFirewall, ProcessTaintContext, UserGovernancePolicy};
use ilp_core::ipdu::flags::CognitivePolicyFlags;
use ilp_core::ipdu::header::IpduHeader;
use ilp_core::ipdu::packet::IpduPacket;
use std::hint::black_box;
use std::time::Instant;

const WARMUP_ITERATIONS: usize = 10_000;
const BENCHMARK_ITERATIONS: usize = 100_000;

#[derive(Debug, Clone)]
struct SampleStats {
    min_ns: f64,
    p50_ns: f64,
    p95_ns: f64,
    p99_ns: f64,
    max_ns: f64,
    mean_ns: f64,
    std_dev_ns: f64,
}

fn compute_stats(mut samples: Vec<u64>) -> SampleStats {
    samples.sort_unstable();
    let n = samples.len() as f64;
    let sum: u64 = samples.iter().sum();
    let mean = sum as f64 / n;

    let variance = samples
        .iter()
        .map(|&x| {
            let diff = x as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / n;
    let std_dev = variance.sqrt();

    let p50_idx = ((samples.len() as f64) * 0.50) as usize;
    let p95_idx = ((samples.len() as f64) * 0.95) as usize;
    let p99_idx = ((samples.len() as f64) * 0.99) as usize;

    SampleStats {
        min_ns: samples[0] as f64,
        p50_ns: samples[p50_idx.min(samples.len() - 1)] as f64,
        p95_ns: samples[p95_idx.min(samples.len() - 1)] as f64,
        p99_ns: samples[p99_idx.min(samples.len() - 1)] as f64,
        max_ns: samples[samples.len() - 1] as f64,
        mean_ns: mean,
        std_dev_ns: std_dev,
    }
}

fn detect_cpu_info() -> String {
    if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in content.lines() {
            if line.starts_with("model name") {
                if let Some((_, model)) = line.split_once(':') {
                    return model.trim().to_string();
                }
            }
        }
    }
    "Unknown / Non-Linux Processor".to_string()
}

fn detect_cpu_cores() -> usize {
    if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
        let cores = content
            .lines()
            .filter(|line| line.starts_with("processor"))
            .count();
        if cores > 0 {
            return cores;
        }
    }
    1
}

fn main() {
    let cpu_model = detect_cpu_info();
    let cpu_cores = detect_cpu_cores();
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let profile = if cfg!(debug_assertions) {
        "DEBUG (Unoptimized)"
    } else {
        "RELEASE (Optimized with LLVM)"
    };

    println!("================================================================================");
    println!("  RFC-ILP-2026: LATENCY & STATISTICAL BENCHMARK");
    println!("================================================================================");
    println!("  Hardware Environment:");
    println!("    • CPU Model:    {}", cpu_model);
    println!("    • CPU Cores:    {}", cpu_cores);
    println!("    • Platform:     {} ({})", os, arch);
    println!("    • Build Config: {}", profile);
    println!("    • Warmup Iter:  {}", WARMUP_ITERATIONS);
    println!("    • Measured:     {} samples per test", BENCHMARK_ITERATIONS);
    println!("================================================================================\n");

    // -------------------------------------------------------------------------
    // TEST SUITE PREPARATION
    // -------------------------------------------------------------------------

    // A. Header canónico de 36 bytes
    let sample_packet = IpduPacket::propose_intent(
        0xFEED_FACE_CAFE_BABE,
        0x1234_5678_9ABC_DEF0,
        2,
        250,
        10_000,
        CognitivePolicyFlags::REQUIRE_SANDBOXED_INFERENCE,
        0xCAFE_BABE_1122_3344,
        r#"{"intent":"translate_cad_to_gcode","precision":0.01}"#,
    )
    .expect("Valid packet");

    let header = sample_packet.header.clone();
    let header_bytes = header.to_canonical_bytes();

    // B. Packet con payload de 512 bytes exactos
    let payload_512 = vec![0xAAu8; 512];
    let packet_512 = IpduPacket::new(header.clone(), payload_512);
    let packet_512_bytes = packet_512.to_bytes();

    // C. Firewall cognitivo y proceso para MSAC
    let policy = UserGovernancePolicy::default();
    let mut firewall = CognitiveFirewall::new(policy);
    let taint_ctx = ProcessTaintContext::new(1001, "Benchmark-Worker", false);

    // D. Baseline JSON-RPC payload equivalente de ~512 bytes
    let json_rpc_str = format!(
        r#"{{"jsonrpc":"2.0","id":1001,"method":"tools/call","params":{{"name":"cad_translation_service","budget":250,"ttl":10000,"flags":["REQUIRE_SANDBOXED_INFERENCE"],"payload":"{}"}}}}"#,
        "X".repeat(340)
    );
    let json_rpc_bytes = json_rpc_str.as_bytes();

    // -------------------------------------------------------------------------
    // TEST 1: IpduHeader Canonical Roundtrip (to_canonical_bytes + from_canonical_bytes)
    // -------------------------------------------------------------------------
    for _ in 0..WARMUP_ITERATIONS {
        let b = header.to_canonical_bytes();
        let h = IpduHeader::from_canonical_bytes(&header_bytes).unwrap();
        black_box((b, h));
    }

    let mut samples_header = Vec::with_capacity(BENCHMARK_ITERATIONS);
    for _ in 0..BENCHMARK_ITERATIONS {
        let t0 = Instant::now();
        let b = header.to_canonical_bytes();
        let h = IpduHeader::from_canonical_bytes(black_box(&header_bytes)).unwrap();
        black_box((b, h));
        samples_header.push(t0.elapsed().as_nanos() as u64);
    }
    let stats_header = compute_stats(samples_header);

    // -------------------------------------------------------------------------
    // TEST 2: IpduPacket Wire Roundtrip with 512B Payload (to_bytes + from_bytes)
    // -------------------------------------------------------------------------
    for _ in 0..WARMUP_ITERATIONS {
        let b = packet_512.to_bytes();
        let p = IpduPacket::from_bytes(&packet_512_bytes).unwrap();
        black_box((b, p));
    }

    let mut samples_packet = Vec::with_capacity(BENCHMARK_ITERATIONS);
    for _ in 0..BENCHMARK_ITERATIONS {
        let t0 = Instant::now();
        let b = packet_512.to_bytes();
        let p = IpduPacket::from_bytes(black_box(&packet_512_bytes)).unwrap();
        black_box((b, p));
        samples_packet.push(t0.elapsed().as_nanos() as u64);
    }
    let stats_packet = compute_stats(samples_packet);

    // -------------------------------------------------------------------------
    // TEST 3: CognitiveFirewall Egress Inspection (Step 1 + Step 2 + Step 3)
    // -------------------------------------------------------------------------
    for _ in 0..WARMUP_ITERATIONS {
        let d = firewall.inspect_egress(&taint_ctx, &sample_packet);
        black_box(d);
    }

    let mut samples_firewall = Vec::with_capacity(BENCHMARK_ITERATIONS);
    for _ in 0..BENCHMARK_ITERATIONS {
        let t0 = Instant::now();
        let d = firewall.inspect_egress(black_box(&taint_ctx), black_box(&sample_packet));
        black_box(d);
        samples_firewall.push(t0.elapsed().as_nanos() as u64);
    }
    let stats_firewall = compute_stats(samples_firewall);

    // -------------------------------------------------------------------------
    // TEST 4: Baseline JSON-RPC Equivalent Manual Parsing (512B)
    // -------------------------------------------------------------------------
    fn parse_json_baseline(raw: &[u8]) -> (Option<usize>, Option<usize>) {
        let s = match std::str::from_utf8(raw) {
            Ok(val) => val,
            Err(_) => return (None, None),
        };
        let method = s.find("\"method\":\"tools/call\"");
        let params = s.find("\"params\":{");
        (method, params)
    }

    for _ in 0..WARMUP_ITERATIONS {
        let res = parse_json_baseline(json_rpc_bytes);
        black_box(res);
    }

    let mut samples_json = Vec::with_capacity(BENCHMARK_ITERATIONS);
    for _ in 0..BENCHMARK_ITERATIONS {
        let t0 = Instant::now();
        let res = parse_json_baseline(black_box(json_rpc_bytes));
        black_box(res);
        samples_json.push(t0.elapsed().as_nanos() as u64);
    }
    let stats_json = compute_stats(samples_json);

    // -------------------------------------------------------------------------
    // STATISTICAL REPORT OUTPUT
    // -------------------------------------------------------------------------
    println!(">>> DETAILED LATENCY DISTRIBUTION (Nanoseconds):\n");
    println!(
        "{:<38} | {:>7} | {:>7} | {:>7} | {:>7} | {:>7} | {:>7} | {:>7}",
        "Operation / Target", "Min", "p50", "p95", "p99", "Max", "Mean", "StdDev"
    );
    println!("{:-<105}", "");

    let print_row = |name: &str, s: &SampleStats| {
        println!(
            "{:<38} | {:>7.0} | {:>7.0} | {:>7.0} | {:>7.0} | {:>7.0} | {:>7.1} | {:>7.1}",
            name, s.min_ns, s.p50_ns, s.p95_ns, s.p99_ns, s.max_ns, s.mean_ns, s.std_dev_ns
        );
    };

    print_row("1. I-PDU Header (36B Roundtrip)", &stats_header);
    print_row("2. I-PDU Packet (512B Wire Roundtrip)", &stats_packet);
    print_row("3. MSAC Firewall (3-Step Inspection)", &stats_firewall);
    print_row("4. Baseline JSON-RPC (512B Scan)", &stats_json);

    println!("\n--------------------------------------------------------------------------------");
    println!(">>> MARKDOWN TABLE FOR README.md & AUDITORS");
    println!("--------------------------------------------------------------------------------\n");

    println!("| Operation / Subsystem | Framing / Size | Median (p50) | p95 Latency | p99 Latency | Max Latency | StdDev (σ) |");
    println!("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |");
    println!(
        "| **I-PDU Header Parsing** | 36 Bytes (Canonical) | **{:.0} ns** | {:.0} ns | {:.0} ns | {:.0} ns | ±{:.1} ns |",
        stats_header.p50_ns, stats_header.p95_ns, stats_header.p99_ns, stats_header.max_ns, stats_header.std_dev_ns
    );
    println!(
        "| **I-PDU Packet Wire Roundtrip** | 512B Payload | **{:.0} ns** | {:.0} ns | {:.0} ns | {:.0} ns | ±{:.1} ns |",
        stats_packet.p50_ns, stats_packet.p95_ns, stats_packet.p99_ns, stats_packet.max_ns, stats_packet.std_dev_ns
    );
    println!(
        "| **MSAC Semantic Firewall Egress** | Full 3 Steps | **{:.0} ns** | {:.0} ns | {:.0} ns | {:.0} ns | ±{:.1} ns |",
        stats_firewall.p50_ns, stats_firewall.p95_ns, stats_firewall.p99_ns, stats_firewall.max_ns, stats_firewall.std_dev_ns
    );
    println!(
        "| **JSON-RPC String Scan (Baseline)** | 512B Text | **{:.0} ns** | {:.0} ns | {:.0} ns | {:.0} ns | ±{:.1} ns |",
        stats_json.p50_ns, stats_json.p95_ns, stats_json.p99_ns, stats_json.max_ns, stats_json.std_dev_ns
    );

    let speedup = if stats_header.p50_ns > 0.0 {
        stats_json.p50_ns / stats_header.p50_ns
    } else {
        1.0
    };

    println!("\n💡 Speedup factor: I-PDU header parsing achieves ~{:.1}x lower p50 latency than naive JSON-RPC field scanning.", speedup);
    println!("✅ Benchmark finished successfully.");
}
