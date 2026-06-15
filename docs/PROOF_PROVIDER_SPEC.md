# Proveedor de prueba — Hardware Trust (Midnight)

## ADR: SP1 fuera de scope en hw-trust

| | |
|---|---|
| **Estado** | Aceptado (PoC `feat/hw-trust-poc`) |
| **Contexto** | SP1 (zkVM RISC-V) tarda decenas de segundos en laptop, requiere toolchain Succinct, y no es viable para prove on-device en el teléfono del usuario. |
| **Decisión** | **Hardware trust usa solo Midnight** (`midnight-zk-stdlib` + Halo2/Plonk). SP1 permanece en `open/client-sdk/sp1-prover/` exclusivamente para **identidad e.firma (RSA-2048)**. |
| **Consecuencias** | Mejor UX (prove en segundos, verify ~3 ms, proof ~3.6 KB). Crate Rust compilable en Android. Riesgo: librería **no auditada**; chip ECDSA P-256 no expuesto en stdlib — requiere spike. |

---

## Por qué Midnight sí resuelve el problema de UX

Datos de referencia (IOHK / `midnight-zk-stdlib`, circuitos Plonk):

| Tamaño circuito | Constraints (~) | Prove (desktop) | Verify | Proof size |
|-----------------|-----------------|-----------------|--------|------------|
| Small | ~6 000 | **~1 s** | **~3 ms** | **~3.6 KB** |
| Medium | ~62 000 | **~9 s** | **~3 ms** | **~3.6 KB** |
| Large | ~2 M | ~344 s | ~3 ms | ~3.6 KB |

Comparación orientativa con SP1 en el mismo laptop para verificación ECDSA:

| | Midnight (Plonk) | SP1 (zkVM) |
|--|------------------|------------|
| Prove típico | 1–15 s (circuito acotado) | 30–120+ s |
| Verify | ~3 ms | cientos de ms |
| Proof size | ~3.6 KB | cientos de KB |
| On-device Android | **Viable** (Rust nativo + SRS embebido) | **No viable** en PoC |
| Toolchain extra | Solo Cargo | `cargo prove`, ELF RISC-V |

**Conclusión:** Midnight on-device con **3 circuitos Small** apunta a **&lt;5 s** prove+verify total. Si un circuito crece a Medium (~9 s solo), revisar optimización o fusión hw+doc (ver [`ZK_CIRCUIT_STRATEGY.md`](./ZK_CIRCUIT_STRATEGY.md)).

---

## Objetivo

Tres relations **Midnight** independientes, prove on-device. Ver decisión en [`ZK_CIRCUIT_STRATEGY.md`](./ZK_CIRCUIT_STRATEGY.md).

| `circuitId` | Statement resumido | Fase |
|-------------|-------------------|------|
| `hw-trust-v1` | Firma hardware sobre `M_hw` + `pubkey_commitment` + `hw_nullifier` | H1 |
| `doc-bind-v1` | `pdf_sha256` + `manifest_hash` + firma ECDSA del bundle | H2 |
| `geo-range-v1` | Haversine ≤200 m; `inside_range` | H3 |

**Meta rendimiento:** prove total + verify total **&lt;5 s** (aspiracional PoC).

```
handshake ──► prove hw-trust-v1
manifest  ──► prove doc-bind-v1
gps       ──► prove geo-range-v1
         ──► CreditSignEvidencePackage
```

---

## Statement NP: `HwTrustStatement` v1

### Entradas públicas (instance)

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `challenge_hash` | `[u8; 32]` | `SHA-256(JCS(M_hw))` |
| `pubkey_commitment` | `[u8; 32]` | `SHA-256(pubkey_spki_der)` |
| `tier` | `u8` | `0=Medium`, `1=High`, `2=Maximum` |
| `hw_nullifier` | `[u8; 32]` | Poseidon(domain `0x4648`) |
| `circuit_version` | string | `hw-trust-v1` |
| `proof_provider_id` | string | siempre `midnight` en PoC |

### Metadatos dispositivo (OS, modelo)

**Fuera del circuito v1** — van en `deviceEvidence` del paquete. Solo `tier` puede usarse en política API.

### Geo (fase H3)

Ver [`GEO_RANGE_PROOF_SPEC.md`](./GEO_RANGE_PROOF_SPEC.md). Inputs públicos: centro + radio; witness: coords reales.

### Witness (secreto del prover)

| Campo | Tipo |
|-------|------|
| `pubkey_spki_der` | `Vec<u8>` |
| `signature_der` | `Vec<u8>` (ECDSA P-256) |

### Relación (soundness)

```
1. SHA-256(pubkey_spki_der) == pubkey_commitment
2. ECDSA_P256_VERIFY(pubkey, challenge_hash, signature) == true
3. hw_nullifier == Poseidon_2(pubkey_commitment_as_Fr, 0x4648)
```

El tier **no** se demuestra en circuito; se declara y valida off-chain (attestation Android).

---

## Statement NP: `DocBindStatement` v1 (`doc-bind-v1`)

### Públicos

| Campo | Tipo |
|-------|------|
| `pdf_sha256` | `[u8; 32]` |
| `manifest_hash` | `[u8; 32]` |
| `bundle_hash` | `[u8; 32]` | `SHA-256(pdf_sha256 \|\| manifest_hash)` |
| `hw_nullifier` | `[u8; 32]` | Enlaza con proof #1 (mismo dispositivo) |

### Witness

| Campo | Tipo |
|-------|------|
| `manifest_bytes` o preimage acotado | `Vec<u8>` |
| `doc_signature_der` | `Vec<u8>` | Firma Keystore sobre `bundle_hash` |

### Relación

```
1. manifest_hash == SHA-256(JCS(manifest))
2. bundle_hash == SHA-256(pdf_sha256 || manifest_hash)
3. ECDSA_P256_VERIFY(session_or_hw_pubkey, bundle_hash, doc_signature)
4. hw_nullifier coherente con proof hw-trust-v1 (mismo pubkey commitment)
```

---

## Statement NP: `GeoRangeStatement` v1 (`geo-range-v1`)

Ver [`GEO_RANGE_PROOF_SPEC.md`](./GEO_RANGE_PROOF_SPEC.md). Radio fijo **≤200 m**.

---

## Orquestación prove (3 calls)

```rust
pub struct CreditSignProver {
    hw: MidnightHwTrustProvider,
    doc: MidnightDocBindProvider,
    geo: MidnightGeoRangeProvider,
}

impl CreditSignProver {
    /// Secuencial; objetivo <5 s total.
    pub fn prove_all(&self, inputs: CreditSignInputs) -> Result<CreditSignProofs>;
}
```

### Crate

`open/client-sdk/hw-midnight/` — depende de `midnight-zk-stdlib` (fijar versión en lockfile).

### Relation

```rust
struct HwTrustRelationV1;

impl Relation for HwTrustRelationV1 {
    type Instance = HwTrustPublicInputs;
    type Witness = HwTrustWitness;
    // circuit: sha2_256(pubkey) + ECDSA P-256 verify + poseidon nullifier
    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            sha2_256: true,
            poseidon: true,
            // secp256k1: false — Keystore usa P-256, no k1
            ..Default::default()
        }
    }
}
```

### SRS on-device

- Generar `vk`/`pk` en build time para `circuit_version` fijo (trusted setup de desarrollo).
- Embeber SRS recortado con `optimal_k(&relation)` + `srs.downsize(k)`.
- Tamaño SRS: acotar en spike; si &gt; few MB, descargar en primer arranque con cache.

### API Rust

```rust
pub struct MidnightHwTrustProvider;

impl HwTrustProofProvider for MidnightHwTrustProvider {
    fn id(&self) -> ProofProviderId { ProofProviderId::Midnight }
    fn prove(&self, statement: &HwTrustStatement) -> Result<ProveResult>;
    fn verify(&self, package: &HwProofPackage, proof: &[u8], vk: &[u8]) -> Result<()>;
}
```

---

## Riesgo principal: ECDSA P-256 en Midnight

`ZkStdLibArch` expone `secp256k1`, **no** `secp256r1` (P-256). Android Keystore firma con **P-256**.

| Opción | PoC | Soundness |
|--------|-----|-----------|
| **A — Circuito P-256 custom** en `Relation` (bigint / chips midnight-circuits) | Preferida si spike &lt; ~80k constraints | Completa |
| **B — Solo SHA-256 + Poseidon** (sin ECDSA en circuito) | Solo dev; **no** para demo “banco” | Débil — no usar en producción |
| **C — Cambiar a secp256k1 en Keystore** | Rompe alineación con P-256 estándar SAT/hardware | No recomendado |

**Plan spike (Semana 2, día 1–2):**

1. Medir `optimal_k` y `cost_model` con SHA-256(SPKI) + Poseidon.
2. Añadir verificación ECDSA P-256 (crate `p256` fuera de circuito primero; luego port a constraints).
3. Si prove desktop &lt; 10 s y constraints &lt; 65k → proceder Android.
4. Si P-256 es prohibitivo → escalar a equipo Midnight/IOHK o dividir statement (solo para investigación).

---

## Prove on-device (Android)

```
┌─────────────────────────────────────┐
│  APK Fortgate HW PoC                │
│  ┌─────────────┐  ┌───────────────┐ │
│  │ Keystore    │  │ hw-midnight   │ │
│  │ sign M_hw   │─►│ prove (Rust)  │ │
│  └─────────────┘  └───────┬───────┘ │
│                           ▼         │
│                  proof_package.json │
└─────────────────────────────────────┘
```

- UniFFI: `prove_hw_trust(handshake_json: String) -> String`
- UI: spinner async durante tres `prove`; meta **&lt;5 s** total.
- Terminal en demo Modo B: solo **verify** (3 ms), no prove — narrativa “el teléfono ya generó la prueba”.

---

## Envelope `HwProofPackage`

```json
{
  "packageVersion": "1.0.0",
  "proofProviderId": "midnight",
  "circuitVersion": "hw-trust-v1",
  "publicInputs": { },
  "proofBytes": "base64...",
  "verifyingKeyRef": "vkey.midnight.json",
  "provingTimeMs": 4200,
  "createdAt": "2026-06-01T18:01:00Z"
}
```

---

## Verificador

```bash
fortgate-hw-poc verify \
  --package hw_output/proof_package.json \
  --handshake handshake.json
```

Siempre despacha a `MidnightHwTrustProvider`. Códigos: `0` GREEN, `10` YELLOW (attestation), `≥20` RED.

---

## Qué NO cambia

| Componente | Sigue con SP1 |
|------------|---------------|
| e.firma / RSA-2048 / RFC commitment | `open/client-sdk/sp1-prover/` |
| Noir proto identidad | `open/proto/` |
| Aligned / Succinct Network (identidad) | Roadmap separado |

---

## Criterios para cerrar spike Midnight

- [ ] Prove desktop &lt; 10 s con ECDSA P-256 sound en circuito.
- [ ] Tres proofs en Android; meta total **&lt;5 s** prove + verify (documentar real si se excede).
- [ ] Verify &lt; 5 ms en terminal.
- [ ] Mismo `public_inputs.json` reproducible desde fixtures CI.
- [ ] Disclaimer “midnight-zk-stdlib no auditado” en README PoC.

---

## Referencias

- https://crates.io/crates/midnight-zk-stdlib
- https://docs.rs/midnight-zk-stdlib/latest/midnight_zk_stdlib/
- Benchmarks IOHK mithril #2910 (~6k constraints → ~1 s prove)
- `open/client-sdk/sp1-prover/README.md` — solo identidad
- `open/docs/HW_TRUST_POC_SPEC.md`
