//! `fg-bench` — perfilado y benchmark reproducible de los circuitos Midnight.
//!
//! Subcomandos:
//!   * `model`   — perfil estático de cada relation vía `cost_model()` (no necesita SRS).
//!   * `bench`   — prove/verify reales, mediana de N iteraciones, con máquina/toolchain/flags.
//!   * `compare` — tabla antes/después en Markdown; falla si `geo-range-v1` regresiona >10%.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fortgate_hw_midnight::{
    demo_manifest, sign_doc_manifest, CreditSignProver, DocBindRecord, DocBindRelationV1,
    GeoRangeRelationV1, HwTrustRelationV1, MidnightDocBindProvider, MidnightGeoRangeProvider,
    MidnightHwTrustProvider,
};
use fortgate_id::hw_trust::backends::{software_poc::SoftwarePocBackend, HwTrustBackend};
use fortgate_id::hw_trust::{sign_challenge_with_backend, HwBackend, HwHandshake, MHw};
use fortgate_id::types::SecurityTier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

/// Umbral de regresión tolerado para `geo-range-v1` (criterio de aceptación del issue).
const GEO_REGRESSION_LIMIT: f64 = 0.10;
const GEO_CIRCUIT_ID: &str = "geo-range-v1";

#[derive(Parser)]
#[command(name = "fg-bench", about = "Profiling de circuitos ZK de Fortgate")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Perfil estático de los tres circuitos (k, filas, columnas, lookups, grado).
    Model {
        /// Escribe el resultado como JSON en vez de tabla.
        #[arg(long)]
        json: bool,
        /// Fuerza un `k` concreto en vez del óptimo. Sirve para ver qué fija el tamaño
        /// del circuito: si al bajar `k` la tabla `pow2range` sigue sin caber, recortar
        /// constraints no reduce `k` y por tanto no acelera el prove.
        #[arg(long)]
        k: Option<u32>,
    },
    /// Mide prove y verify reales sobre los tres circuitos.
    Bench {
        /// Iteraciones medidas por circuito (se reporta la mediana).
        #[arg(long, default_value_t = 5)]
        iters: usize,
        /// Iteraciones de calentamiento que no se contabilizan.
        #[arg(long, default_value_t = 1)]
        warmup: usize,
        /// Directorio de trabajo para las llaves y artefactos del fixture.
        #[arg(long)]
        work_dir: Option<PathBuf>,
        /// Etiqueta libre para identificar la corrida en el JSON.
        #[arg(long)]
        label: Option<String>,
    },
    /// Compara dos corridas de `bench` y emite la tabla Markdown.
    Compare {
        #[arg(long)]
        before: PathBuf,
        #[arg(long)]
        after: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// Formato del reporte
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Machine {
    cpu: String,
    logical_cores: usize,
    total_ram_bytes: Option<u64>,
    os: String,
    arch: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Toolchain {
    rustc: String,
    cargo: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct BuildFlags {
    /// `RUSTFLAGS` efectivo en tiempo de compilación del binario.
    rustflags: Option<String>,
    /// `true` si el binario se compiló con `debug_assertions` (es decir, NO release).
    debug_assertions: bool,
    /// Perfil declarado por quien lanza el bench (`run_bench.sh` lo fija).
    profile: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Stats {
    median: f64,
    min: f64,
    max: f64,
    samples: Vec<f64>,
}

impl Stats {
    fn from_millis(mut samples: Vec<f64>) -> Self {
        let raw = samples.clone();
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = samples.len();
        let median = if n == 0 {
            0.0
        } else if n % 2 == 1 {
            samples[n / 2]
        } else {
            (samples[n / 2 - 1] + samples[n / 2]) / 2.0
        };
        Self {
            median,
            min: samples.first().copied().unwrap_or(0.0),
            max: samples.last().copied().unwrap_or(0.0),
            samples: raw,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CircuitModelReport {
    k: u32,
    rows: usize,
    table_rows: usize,
    max_deg: usize,
    advice_columns: usize,
    fixed_columns: usize,
    lookups: usize,
    permutations: usize,
    proof_size_bytes: usize,
    /// Ocupación de las filas usables: `rows / 2^k`.
    occupancy: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CircuitReport {
    id: String,
    model: CircuitModelReport,
    /// Wall-clock de la llamada completa a `prove()`, incluye carga de SRS/pk.
    prove_wall_ms: Stats,
    /// Tiempo que el propio provider reporta, solo la generación de la prueba.
    prove_inner_ms: Stats,
    /// Wall-clock de `verify()`.
    verify_wall_ms: Stats,
    proof_bytes: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct BenchReport {
    schema: String,
    label: Option<String>,
    timestamp: String,
    iters: usize,
    warmup: usize,
    machine: Machine,
    toolchain: Toolchain,
    flags: BuildFlags,
    circuits: Vec<CircuitReport>,
    /// Suma de las medianas wall-clock de los tres circuitos.
    total_prove_wall_ms: f64,
    /// Suma de las medianas de generación pura.
    total_prove_inner_ms: f64,
}

// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Model { json, k } => cmd_model(json, k),
        Commands::Bench {
            iters,
            warmup,
            work_dir,
            label,
        } => cmd_bench(iters, warmup, work_dir, label),
        Commands::Compare { before, after } => cmd_compare(&before, &after),
    }
}

// ---------------------------------------------------------------------------
// model
// ---------------------------------------------------------------------------

fn model_of<R: midnight_zk_stdlib::Relation>(relation: &R) -> CircuitModelReport {
    model_of_at(relation, None)
}

fn model_of_at<R: midnight_zk_stdlib::Relation>(relation: &R, k: Option<u32>) -> CircuitModelReport {
    let m = midnight_zk_stdlib::cost_model(relation, k);
    let capacity = (1u64 << m.k) as f64;
    CircuitModelReport {
        k: m.k,
        rows: m.rows,
        table_rows: m.table_rows,
        max_deg: m.max_deg,
        advice_columns: m.advice_columns,
        fixed_columns: m.fixed_columns,
        lookups: m.lookups,
        permutations: m.permutations,
        proof_size_bytes: m.size,
        occupancy: m.rows as f64 / capacity,
    }
}

fn all_models(k: Option<u32>) -> Vec<(String, CircuitModelReport)> {
    vec![
        (
            "hw-trust-v1".to_string(),
            model_of_at(&HwTrustRelationV1::default(), k),
        ),
        (
            "doc-bind-v1".to_string(),
            model_of_at(&DocBindRelationV1::default(), k),
        ),
        (
            GEO_CIRCUIT_ID.to_string(),
            model_of_at(&GeoRangeRelationV1::default(), k),
        ),
    ]
}

fn cmd_model(json: bool, k: Option<u32>) -> Result<()> {
    let models = all_models(k);
    if json {
        let map: serde_json::Map<String, serde_json::Value> = models
            .into_iter()
            .map(|(id, m)| (id, serde_json::to_value(m).unwrap()))
            .collect();
        println!("{}", serde_json::to_string_pretty(&map)?);
        return Ok(());
    }

    println!(
        "| Circuito | k | filas | ocupación | tabla | advice | fixed | lookups | perms | grado | prueba (B) |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|");
    for (id, m) in models {
        println!(
            "| {} | {} | {} | {:.1}% | {} | {} | {} | {} | {} | {} | {} |",
            id,
            m.k,
            m.rows,
            m.occupancy * 100.0,
            m.table_rows,
            m.advice_columns,
            m.fixed_columns,
            m.lookups,
            m.permutations,
            m.max_deg,
            m.proof_size_bytes,
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// bench
// ---------------------------------------------------------------------------

struct Fixture {
    handshake: HwHandshake,
    doc_record: DocBindRecord,
    actual_lat: f64,
    actual_lon: f64,
}

/// Construye un handshake y un registro documental reales, firmados con el backend PoC.
fn build_fixture(work_dir: &PathBuf) -> Result<Fixture> {
    std::fs::create_dir_all(work_dir)?;
    let backend = SoftwarePocBackend::new(work_dir);
    backend.keygen().context("keygen del backend PoC")?;
    let spki = backend.pubkey_spki_der()?;

    let m_hw = MHw::new_challenge(
        HwBackend::SoftwarePoc,
        SecurityTier::Medium,
        &spki,
        Some("fg-bench".into()),
    )?;
    let handshake = sign_challenge_with_backend(&backend, &m_hw)?;

    let mut h = Sha256::new();
    h.update(b"fg-bench-fixture-pdf-v1");
    let pdf_sha256 = hex::encode(h.finalize());
    let manifest = demo_manifest(&pdf_sha256);
    let doc_record = sign_doc_manifest(&backend, &manifest, &handshake.hw_nullifier)?;

    Ok(Fixture {
        handshake,
        doc_record,
        // Dentro del radio del domicilio de `demo_manifest`.
        actual_lat: 19.4326,
        actual_lon: -99.1332,
    })
}

fn cmd_bench(
    iters: usize,
    warmup: usize,
    work_dir: Option<PathBuf>,
    label: Option<String>,
) -> Result<()> {
    anyhow::ensure!(iters > 0, "--iters debe ser >= 1");

    let work_dir = work_dir.unwrap_or_else(|| std::env::temp_dir().join("fg-bench"));
    eprintln!("[fg-bench] fixture en {}", work_dir.display());
    let fixture = build_fixture(&work_dir)?;

    // El setup de llaves no forma parte de la medición: se hace una vez, antes.
    eprintln!("[fg-bench] generando/cargando vk+pk de los tres circuitos...");
    let prover = CreditSignProver::new();
    prover.setup_all_keys().context("setup_all_keys")?;

    let circuits = vec![
        bench_hw_trust(&fixture, iters, warmup)?,
        bench_doc_bind(&fixture, iters, warmup)?,
        bench_geo_range(&fixture, iters, warmup)?,
    ];

    let total_prove_wall_ms = circuits.iter().map(|c| c.prove_wall_ms.median).sum();
    let total_prove_inner_ms = circuits.iter().map(|c| c.prove_inner_ms.median).sum();

    let report = BenchReport {
        schema: "fg-bench/v1".to_string(),
        label,
        timestamp: chrono::Utc::now().to_rfc3339(),
        iters,
        warmup,
        machine: detect_machine(),
        toolchain: detect_toolchain(),
        flags: detect_flags(),
        circuits,
        total_prove_wall_ms,
        total_prove_inner_ms,
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    eprintln!(
        "[fg-bench] total prove (mediana, wall): {:.0} ms | generación pura: {:.0} ms",
        report.total_prove_wall_ms, report.total_prove_inner_ms
    );
    Ok(())
}

struct CircuitSamples {
    wall: Vec<f64>,
    inner: Vec<f64>,
    verify: Vec<f64>,
    proof_bytes: usize,
}

/// Ejecuta `warmup + iters` repeticiones y devuelve las muestras de las contabilizadas.
///
/// `run` devuelve `(prove_inner_ms, prove_wall_ms, verify_wall_ms, proof_len)`.
fn run_samples<F>(id: &str, iters: usize, warmup: usize, mut run: F) -> Result<CircuitSamples>
where
    F: FnMut() -> Result<(u64, f64, f64, usize)>,
{
    let mut wall = Vec::with_capacity(iters);
    let mut inner = Vec::with_capacity(iters);
    let mut verify = Vec::with_capacity(iters);
    let mut proof_bytes = 0usize;

    for i in 0..(warmup + iters) {
        let (inner_ms, wall_ms, verify_ms, bytes) = run()?;
        if i < warmup {
            eprintln!("[fg-bench] {id} warmup {}/{warmup}: {wall_ms:.0} ms", i + 1);
            continue;
        }
        eprintln!(
            "[fg-bench] {id} iter {}/{iters}: prove {wall_ms:.0} ms, verify {verify_ms:.0} ms",
            i - warmup + 1
        );
        wall.push(wall_ms);
        inner.push(inner_ms as f64);
        verify.push(verify_ms);
        proof_bytes = bytes;
    }

    Ok(CircuitSamples {
        wall,
        inner,
        verify,
        proof_bytes,
    })
}

fn bench_hw_trust(fixture: &Fixture, iters: usize, warmup: usize) -> Result<CircuitReport> {
    let provider = MidnightHwTrustProvider::new();
    let s = run_samples("hw-trust-v1", iters, warmup, || {
        let t0 = Instant::now();
        let pkg = provider.prove_handshake(&fixture.handshake)?;
        let wall = t0.elapsed().as_secs_f64() * 1000.0;

        let t1 = Instant::now();
        provider.verify_package(&pkg)?;
        let verify = t1.elapsed().as_secs_f64() * 1000.0;

        Ok((pkg.proving_time_ms, wall, verify, pkg.proof_bytes.len()))
    })?;

    Ok(CircuitReport {
        id: "hw-trust-v1".to_string(),
        model: model_of(&HwTrustRelationV1::default()),
        prove_wall_ms: Stats::from_millis(s.wall),
        prove_inner_ms: Stats::from_millis(s.inner),
        verify_wall_ms: Stats::from_millis(s.verify),
        proof_bytes: s.proof_bytes,
    })
}

fn bench_doc_bind(fixture: &Fixture, iters: usize, warmup: usize) -> Result<CircuitReport> {
    let provider = MidnightDocBindProvider::new();
    let s = run_samples("doc-bind-v1", iters, warmup, || {
        let t0 = Instant::now();
        let pkg = provider.prove(&fixture.doc_record, &fixture.handshake)?;
        let wall = t0.elapsed().as_secs_f64() * 1000.0;

        let t1 = Instant::now();
        provider.verify(&pkg, &fixture.doc_record)?;
        let verify = t1.elapsed().as_secs_f64() * 1000.0;

        Ok((pkg.proving_time_ms, wall, verify, pkg.proof_bytes.len()))
    })?;

    Ok(CircuitReport {
        id: "doc-bind-v1".to_string(),
        model: model_of(&DocBindRelationV1::default()),
        prove_wall_ms: Stats::from_millis(s.wall),
        prove_inner_ms: Stats::from_millis(s.inner),
        verify_wall_ms: Stats::from_millis(s.verify),
        proof_bytes: s.proof_bytes,
    })
}

fn bench_geo_range(fixture: &Fixture, iters: usize, warmup: usize) -> Result<CircuitReport> {
    let provider = MidnightGeoRangeProvider::new();
    let dom = fixture.doc_record.manifest.domicile_ref.clone();
    let s = run_samples(GEO_CIRCUIT_ID, iters, warmup, || {
        let t0 = Instant::now();
        let pkg = provider.prove_coords(
            dom.center_lat,
            dom.center_lon,
            fixture.actual_lat,
            fixture.actual_lon,
            dom.radius_meters,
        )?;
        let wall = t0.elapsed().as_secs_f64() * 1000.0;

        let t1 = Instant::now();
        provider.verify(&pkg)?;
        let verify = t1.elapsed().as_secs_f64() * 1000.0;

        Ok((pkg.proving_time_ms, wall, verify, pkg.proof_bytes.len()))
    })?;

    Ok(CircuitReport {
        id: GEO_CIRCUIT_ID.to_string(),
        model: model_of(&GeoRangeRelationV1::default()),
        prove_wall_ms: Stats::from_millis(s.wall),
        prove_inner_ms: Stats::from_millis(s.inner),
        verify_wall_ms: Stats::from_millis(s.verify),
        proof_bytes: s.proof_bytes,
    })
}

// ---------------------------------------------------------------------------
// Metadatos de la corrida
// ---------------------------------------------------------------------------

fn detect_machine() -> Machine {
    Machine {
        cpu: std::env::var("FG_BENCH_CPU")
            .ok()
            .or_else(|| std::env::var("PROCESSOR_IDENTIFIER").ok())
            .unwrap_or_else(|| "desconocido".to_string()),
        logical_cores: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        total_ram_bytes: std::env::var("FG_BENCH_RAM_BYTES")
            .ok()
            .and_then(|v| v.parse().ok()),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
    }
}

fn tool_version(bin: &str) -> String {
    Command::new(bin)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "desconocido".to_string())
}

fn detect_toolchain() -> Toolchain {
    Toolchain {
        rustc: tool_version("rustc"),
        cargo: tool_version("cargo"),
    }
}

fn detect_flags() -> BuildFlags {
    BuildFlags {
        rustflags: option_env!("RUSTFLAGS").map(|s| s.to_string()),
        debug_assertions: cfg!(debug_assertions),
        profile: std::env::var("FG_BENCH_PROFILE").unwrap_or_else(|_| "release".to_string()),
    }
}

// ---------------------------------------------------------------------------
// compare
// ---------------------------------------------------------------------------

fn read_report(path: &PathBuf) -> Result<BenchReport> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("leer {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsear {}", path.display()))
}

fn pct_delta(before: f64, after: f64) -> f64 {
    if before == 0.0 {
        return 0.0;
    }
    (after - before) / before * 100.0
}

fn cmd_compare(before_path: &PathBuf, after_path: &PathBuf) -> Result<()> {
    let before = read_report(before_path)?;
    let after = read_report(after_path)?;

    println!("## Comparativa de tiempos de prove\n");
    println!(
        "- **Antes:** {} ({} iters){}",
        before.timestamp,
        before.iters,
        before
            .label
            .as_ref()
            .map(|l| format!(" — {l}"))
            .unwrap_or_default()
    );
    println!(
        "- **Después:** {} ({} iters){}",
        after.timestamp,
        after.iters,
        after
            .label
            .as_ref()
            .map(|l| format!(" — {l}"))
            .unwrap_or_default()
    );
    println!(
        "- **Máquina:** {} ({} núcleos lógicos), {} {}",
        after.machine.cpu, after.machine.logical_cores, after.machine.os, after.machine.arch
    );
    println!("- **Toolchain:** {}", after.toolchain.rustc);
    println!();

    println!("| Circuito | Antes (ms) | Después (ms) | Δ | k antes | k después |");
    println!("|---|---|---|---|---|---|");

    let mut geo_regression: Option<f64> = None;

    for b in &before.circuits {
        let Some(a) = after.circuits.iter().find(|c| c.id == b.id) else {
            println!(
                "| {} | {:.0} | *ausente* | — | {} | — |",
                b.id, b.prove_wall_ms.median, b.model.k
            );
            continue;
        };
        let d = pct_delta(b.prove_wall_ms.median, a.prove_wall_ms.median);
        println!(
            "| {} | {:.0} | {:.0} | {:+.1}% | {} | {} |",
            b.id, b.prove_wall_ms.median, a.prove_wall_ms.median, d, b.model.k, a.model.k
        );
        if b.id == GEO_CIRCUIT_ID && d > GEO_REGRESSION_LIMIT * 100.0 {
            geo_regression = Some(d);
        }
    }

    let dt = pct_delta(before.total_prove_wall_ms, after.total_prove_wall_ms);
    println!(
        "| **Total** | **{:.0}** | **{:.0}** | **{:+.1}%** | | |",
        before.total_prove_wall_ms, after.total_prove_wall_ms, dt
    );
    println!();
    println!(
        "Generación pura (sin carga de SRS/pk): {:.0} ms → {:.0} ms ({:+.1}%)",
        before.total_prove_inner_ms,
        after.total_prove_inner_ms,
        pct_delta(before.total_prove_inner_ms, after.total_prove_inner_ms)
    );

    if let Some(d) = geo_regression {
        anyhow::bail!(
            "REGRESIÓN: {GEO_CIRCUIT_ID} subió {d:+.1}%, por encima del límite de {:.0}%",
            GEO_REGRESSION_LIMIT * 100.0
        );
    }
    println!("\n`{GEO_CIRCUIT_ID}` dentro del límite de regresión del 10%.");
    Ok(())
}
