//! CLI PoC hardware trust + firma de crédito: keygen, challenge, sign, prove, verify.

use anyhow::Context;
use clap::{Parser, Subcommand};
use fortgate_hw_midnight::{
    demo_manifest, sign_doc_manifest, CreditSignProver, DocBindRecord, MidnightDocBindProvider,
    MidnightGeoRangeProvider, MidnightHwTrustProvider,
};
use fortgate_id::hw_trust::backends::{software_poc::SoftwarePocBackend, HwTrustBackend};
use fortgate_id::hw_trust::{
    default_software_backend, sign_challenge_with_backend, verify_handshake_local, HwBackend,
    HwHandshake, MHw, VerifyStatus,
};
use fortgate_id::types::SecurityTier;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "fortgate-hw-poc", about = "Fortgate hardware trust PoC")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Genera llave P-256 software_poc en ~/.fortgate/poc_hw/
    Keygen {
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
    /// Emite challenge.json (M_hw)
    Challenge {
        #[arg(long, short)]
        out: PathBuf,
        #[arg(long, default_value = "software_poc")]
        backend: String,
        #[arg(long)]
        key_dir: Option<PathBuf>,
    },
    /// Firma challenge y escribe handshake.json
    Sign {
        #[arg(long, short)]
        challenge: PathBuf,
        #[arg(long, short)]
        out: PathBuf,
        #[arg(long)]
        key_dir: Option<PathBuf>,
    },
    /// Verificación criptográfica local (sin ZK)
    VerifyLocal {
        #[arg(long, short)]
        handshake: PathBuf,
    },
    /// Genera proof Midnight hw-trust-v1 → proof_package.json
    Prove {
        #[arg(long, short)]
        handshake: PathBuf,
        #[arg(long, short)]
        out: PathBuf,
        #[arg(long)]
        setup_keys: bool,
    },
    /// Verifica proof_package + handshake (ZK + nullifier off-circuit)
    Verify {
        #[arg(long, short)]
        package: PathBuf,
        #[arg(long, short)]
        handshake: PathBuf,
    },
    /// Firma manifiesto de crédito → doc_bind_record.json
    SignDoc {
        #[arg(long, short)]
        handshake: PathBuf,
        #[arg(long, short)]
        out: PathBuf,
        #[arg(long)]
        key_dir: Option<PathBuf>,
        #[arg(long)]
        pdf_sha256: Option<String>,
    },
    /// Genera proof doc-bind-v1
    ProveDoc {
        #[arg(long, short)]
        handshake: PathBuf,
        #[arg(long, short)]
        doc_record: PathBuf,
        #[arg(long, short)]
        out: PathBuf,
        #[arg(long)]
        setup_keys: bool,
    },
    /// Genera proof geo-range-v1
    ProveGeo {
        #[arg(long)]
        center_lat: f64,
        #[arg(long)]
        center_lon: f64,
        #[arg(long)]
        actual_lat: f64,
        #[arg(long)]
        actual_lon: f64,
        #[arg(long, default_value_t = 200)]
        radius_meters: u32,
        #[arg(long, short)]
        out: PathBuf,
        #[arg(long)]
        setup_keys: bool,
    },
    /// Genera las 3 proofs → evidence_package.json
    ProveAll {
        #[arg(long, short)]
        handshake: PathBuf,
        #[arg(long, short)]
        doc_record: PathBuf,
        #[arg(long)]
        actual_lat: f64,
        #[arg(long)]
        actual_lon: f64,
        #[arg(long, short)]
        out: PathBuf,
        #[arg(long)]
        setup_keys: bool,
    },
    /// Verifica evidence_package.json (3 proofs)
    VerifyAll {
        #[arg(long, short)]
        evidence: PathBuf,
        #[arg(long, short)]
        handshake: PathBuf,
        #[arg(long, short)]
        doc_record: PathBuf,
    },
    /// keygen → challenge → sign → prove → verify (solo hw-trust)
    Demo {
        #[arg(long)]
        tmp: Option<PathBuf>,
    },
    /// Demo completo: hw-trust + doc-bind + geo-range
    DemoFull {
        #[arg(long)]
        tmp: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen { out } => cmd_keygen(out),
        Commands::Challenge { out, backend, key_dir } => cmd_challenge(out, &backend, key_dir),
        Commands::Sign {
            challenge,
            out,
            key_dir,
        } => cmd_sign(challenge, out, key_dir),
        Commands::VerifyLocal { handshake } => cmd_verify_local(handshake),
        Commands::Prove {
            handshake,
            out,
            setup_keys,
        } => cmd_prove(handshake, out, setup_keys),
        Commands::Verify { package, handshake } => cmd_verify(package, handshake),
        Commands::SignDoc {
            handshake,
            out,
            key_dir,
            pdf_sha256,
        } => cmd_sign_doc(handshake, out, key_dir, pdf_sha256),
        Commands::ProveDoc {
            handshake,
            doc_record,
            out,
            setup_keys,
        } => cmd_prove_doc(handshake, doc_record, out, setup_keys),
        Commands::ProveGeo {
            center_lat,
            center_lon,
            actual_lat,
            actual_lon,
            radius_meters,
            out,
            setup_keys,
        } => cmd_prove_geo(
            center_lat,
            center_lon,
            actual_lat,
            actual_lon,
            radius_meters,
            out,
            setup_keys,
        ),
        Commands::ProveAll {
            handshake,
            doc_record,
            actual_lat,
            actual_lon,
            out,
            setup_keys,
        } => cmd_prove_all(handshake, doc_record, actual_lat, actual_lon, out, setup_keys),
        Commands::VerifyAll {
            evidence,
            handshake,
            doc_record,
        } => cmd_verify_all(evidence, handshake, doc_record),
        Commands::Demo { tmp } => cmd_demo(tmp),
        Commands::DemoFull { tmp } => cmd_demo_full(tmp),
    }
}

fn backend_from_name(name: &str, key_dir: Option<PathBuf>) -> anyhow::Result<SoftwarePocBackend> {
    match name {
        "software_poc" => {
            let b = key_dir
                .map(SoftwarePocBackend::new)
                .unwrap_or_else(default_software_backend);
            Ok(b)
        }
        other => anyhow::bail!("backend no soportado: {other} (usa software_poc)"),
    }
}

fn cmd_keygen(out: Option<PathBuf>) -> anyhow::Result<()> {
    let backend = out
        .map(SoftwarePocBackend::new)
        .unwrap_or_else(default_software_backend);
    let vk = backend.keygen().context("keygen")?;
    let spki = backend.pubkey_spki_der()?;
    eprintln!("⚠️  software_poc — no es Secure Enclave real (tier Medium)");
    eprintln!("Llave escrita en: {}", backend.key_path().display());
    eprintln!("pubkey commitment: {}", fortgate_id::hw_trust::pubkey_commitment_hex(&spki));
    eprintln!("verifying key ok: {} bytes SPKI", spki.len());
    let _ = vk;
    Ok(())
}

fn cmd_challenge(out: PathBuf, backend_name: &str, key_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let backend = backend_from_name(backend_name, key_dir)?;
    if !backend.key_path().exists() {
        backend.keygen().context("auto keygen")?;
    }
    let spki = backend.pubkey_spki_der()?;
    let m_hw = MHw::new_challenge(
        HwBackend::SoftwarePoc,
        SecurityTier::Medium,
        &spki,
        Some("fortgate-hw-poc-cli".into()),
    )?;
    let json = serde_json::to_string_pretty(&m_hw)?;
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(&out, json)?;
    eprintln!("challenge → {}", out.display());
    eprintln!("challenge_hash = {}", hex::encode(m_hw.challenge_hash()?));
    Ok(())
}

fn cmd_sign(challenge: PathBuf, out: PathBuf, key_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let backend = backend_from_name("software_poc", key_dir)?;
    let raw = fs::read_to_string(&challenge)?;
    let m_hw: MHw = serde_json::from_str(&raw)?;
    let hs = sign_challenge_with_backend(&backend, &m_hw)?;
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(&out, hs.to_json_pretty()?)?;
    eprintln!("handshake → {}", out.display());
    eprintln!("hw_nullifier = {}", hs.hw_nullifier);
    Ok(())
}

fn cmd_verify_local(handshake: PathBuf) -> anyhow::Result<()> {
    let raw = fs::read_to_string(&handshake)?;
    let hs = HwHandshake::from_json(&raw)?;
    let res = verify_handshake_local(&hs)?;
    match res.status {
        VerifyStatus::Green => {
            eprintln!("✅ GREEN — {}", res.message);
            Ok(())
        }
        VerifyStatus::Red => {
            eprintln!("❌ RED — {}", res.message);
            std::process::exit(20);
        }
    }
}

fn cmd_prove(handshake: PathBuf, out: PathBuf, setup_keys: bool) -> anyhow::Result<()> {
    let raw = fs::read_to_string(&handshake)?;
    let hs = HwHandshake::from_json(&raw)?;
    let provider = MidnightHwTrustProvider::new();
    if setup_keys {
        provider.setup_keys().context("setup vk/pk")?;
    }
    eprintln!("⚠️  midnight-zk-stdlib — no auditado; solo PoC");
    let start = Instant::now();
    let package = provider.prove_handshake(&hs).context("prove")?;
    eprintln!(
        "prove OK en {} ms (reportado: {} ms)",
        start.elapsed().as_millis(),
        package.proving_time_ms
    );
    MidnightHwTrustProvider::write_package(&out, &package)?;
    eprintln!("proof_package → {}", out.display());
    Ok(())
}

fn cmd_verify(package: PathBuf, handshake: PathBuf) -> anyhow::Result<()> {
    let hs = HwHandshake::from_json(&fs::read_to_string(&handshake)?)?;
    let pkg = MidnightHwTrustProvider::read_package(&package).context("read package")?;
    let provider = MidnightHwTrustProvider::new();
    let start = Instant::now();
    provider
        .verify_against_handshake(&pkg, &hs)
        .context("verify ZK")?;
    eprintln!("✅ GREEN — ZK hw-trust-v1 OK ({:?})", start.elapsed());
    Ok(())
}

fn cmd_sign_doc(
    handshake: PathBuf,
    out: PathBuf,
    key_dir: Option<PathBuf>,
    pdf_sha256: Option<String>,
) -> anyhow::Result<()> {
    let hs = HwHandshake::from_json(&fs::read_to_string(&handshake)?)?;
    let backend = backend_from_name("software_poc", key_dir)?;
    let pdf = pdf_sha256.unwrap_or_else(|| {
        let mut h = Sha256::new();
        h.update(b"fortgate-poc-credit-pdf-v1");
        hex::encode(h.finalize())
    });
    let manifest = demo_manifest(&pdf);
    let record = sign_doc_manifest(&backend, &manifest, &hs.hw_nullifier)?;
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(&out, serde_json::to_string_pretty(&record)?)?;
    eprintln!("doc_bind_record → {}", out.display());
    eprintln!("bundle_hash = {}", record.bundle_hash);
    Ok(())
}

fn cmd_prove_doc(
    handshake: PathBuf,
    doc_record: PathBuf,
    out: PathBuf,
    setup_keys: bool,
) -> anyhow::Result<()> {
    let hs = HwHandshake::from_json(&fs::read_to_string(&handshake)?)?;
    let record: DocBindRecord = serde_json::from_str(&fs::read_to_string(&doc_record)?)?;
    let provider = MidnightDocBindProvider::new();
    if setup_keys {
        provider.setup_keys().context("setup doc-bind keys")?;
    }
    let package = provider.prove(&record, &hs).context("prove doc-bind")?;
    MidnightDocBindProvider::write_package(&out, &package)?;
    eprintln!(
        "doc_bind proof OK ({} ms) → {}",
        package.proving_time_ms,
        out.display()
    );
    Ok(())
}

fn cmd_prove_geo(
    center_lat: f64,
    center_lon: f64,
    actual_lat: f64,
    actual_lon: f64,
    radius_meters: u32,
    out: PathBuf,
    setup_keys: bool,
) -> anyhow::Result<()> {
    let provider = MidnightGeoRangeProvider::new();
    if setup_keys {
        provider.setup_keys().context("setup geo-range keys")?;
    }
    let package = provider
        .prove_coords(center_lat, center_lon, actual_lat, actual_lon, radius_meters)
        .context("prove geo-range")?;
    MidnightGeoRangeProvider::write_package(&out, &package)?;
    eprintln!(
        "geo_range proof OK ({} ms) → {}",
        package.proving_time_ms,
        out.display()
    );
    Ok(())
}

fn cmd_prove_all(
    handshake: PathBuf,
    doc_record: PathBuf,
    actual_lat: f64,
    actual_lon: f64,
    out: PathBuf,
    setup_keys: bool,
) -> anyhow::Result<()> {
    let hs = HwHandshake::from_json(&fs::read_to_string(&handshake)?)?;
    let record: DocBindRecord = serde_json::from_str(&fs::read_to_string(&doc_record)?)?;
    let prover = CreditSignProver::new();
    if setup_keys {
        prover.setup_all_keys().context("setup all keys")?;
    }
    eprintln!("⚠️  generando 3 proofs Midnight (PoC, no auditado)");
    let start = Instant::now();
    let evidence = prover
        .prove_all(&hs, &record, actual_lat, actual_lon)
        .context("prove_all")?;
    eprintln!(
        "prove_all OK en {} ms (hw {} + doc {} + geo {})",
        start.elapsed().as_millis(),
        evidence.hw_trust.proving_time_ms,
        evidence.doc_bind.proving_time_ms,
        evidence.geo_range.proving_time_ms,
    );
    CreditSignProver::write_evidence(&out, &evidence)?;
    eprintln!("evidence_package → {}", out.display());
    Ok(())
}

fn cmd_verify_all(
    evidence: PathBuf,
    handshake: PathBuf,
    doc_record: PathBuf,
) -> anyhow::Result<()> {
    let hs = HwHandshake::from_json(&fs::read_to_string(&handshake)?)?;
    let record: DocBindRecord = serde_json::from_str(&fs::read_to_string(&doc_record)?)?;
    let evidence = CreditSignProver::read_evidence(&evidence)?;
    let prover = CreditSignProver::new();
    let start = Instant::now();
    prover
        .verify_all(&evidence, &hs, &record)
        .context("verify_all")?;
    eprintln!("✅ GREEN — 3 proofs OK ({:?})", start.elapsed());
    Ok(())
}

fn cmd_demo(tmp: Option<PathBuf>) -> anyhow::Result<()> {
    let dir = tmp.unwrap_or_else(|| PathBuf::from("/tmp/fg-hw-demo"));
    fs::create_dir_all(&dir)?;
    cmd_keygen(Some(dir.clone()))?;
    let challenge_path = dir.join("challenge.json");
    let handshake_path = dir.join("handshake.json");
    let proof_path = dir.join("proof_package.json");
    cmd_challenge(challenge_path.clone(), "software_poc", Some(dir.clone()))?;
    cmd_sign(challenge_path, handshake_path.clone(), Some(dir.clone()))?;
    cmd_verify_local(handshake_path.clone())?;
    cmd_prove(handshake_path.clone(), proof_path.clone(), true)?;
    cmd_verify(proof_path, handshake_path)?;
    eprintln!("demo OK en {}", dir.display());
    Ok(())
}

fn cmd_demo_full(tmp: Option<PathBuf>) -> anyhow::Result<()> {
    let dir = tmp.unwrap_or_else(|| PathBuf::from("/tmp/fg-hw-demo-full"));
    fs::create_dir_all(&dir)?;
    cmd_keygen(Some(dir.clone()))?;
    let challenge_path = dir.join("challenge.json");
    let handshake_path = dir.join("handshake.json");
    let doc_record_path = dir.join("doc_bind_record.json");
    let evidence_path = dir.join("evidence_package.json");

    cmd_challenge(challenge_path.clone(), "software_poc", Some(dir.clone()))?;
    cmd_sign(challenge_path, handshake_path.clone(), Some(dir.clone()))?;
    cmd_verify_local(handshake_path.clone())?;
    cmd_sign_doc(
        handshake_path.clone(),
        doc_record_path.clone(),
        Some(dir.clone()),
        None,
    )?;

    // Punto ~80 m del centro CDMX PoC
    cmd_prove_all(
        handshake_path.clone(),
        doc_record_path.clone(),
        19.4326,
        -99.1332,
        evidence_path.clone(),
        true,
    )?;
    cmd_verify_all(evidence_path, handshake_path, doc_record_path)?;
    eprintln!("demo-full OK en {}", dir.display());
    Ok(())
}
