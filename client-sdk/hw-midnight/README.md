# fortgate-hw-midnight

Proveedor Midnight para el PoC de hardware trust + firma de crédito.

**Disclaimer:** `midnight-zk-stdlib` no está auditado para producción.

## Circuitos (H3)

| ID | Qué demuestra en ZK |
|----|---------------------|
| `hw-trust-v1` | `SHA-256(SPKI) == pubkey_commitment` + ECDSA P-256 sobre `challenge_hash` + Poseidon(pubkey_commitment, 0x4648) == hw_nullifier |
| `doc-bind-v1` | `bundle_hash = SHA-256(pdf_sha256 \|\| manifest_hash)` + ECDSA P-256 sobre `bundle_hash` |
| `geo-range-v1` | Distancia euclídea escalada ≤ radio (máx. 200 m, PoC CDMX) |

Validación **off-circuit** (PoC v1):

- `tier` en hw-trust (se declara y valida off-chain, no se demuestra en circuito)
- Hash JCS del manifiesto en doc-bind (`manifest_hash` vs bytes canónicos)
- Haversine y radio en geo-range antes de `prove`

`hw_nullifier` se calcula y restringe en circuito con el Poseidon nativo de Midnight (campo escalar BLS12-381 del circuito vía `PoseidonChip`/`std_lib.poseidon()`), no BN254 como asumían docs/spec anteriores — el circuito Midnight no tiene forma soportada de emular el campo escalar BN254 on-circuit (ver `docs/PROOF_PROVIDER_SPEC.md` y `docs/HW_TRUST_POC_SPEC.md`, también actualizados). El separador de dominio `0x4648` ("FH") no cambia.

## Setup SRS (una vez)

```bash
chmod +x scripts/fetch_srs.sh
./scripts/fetch_srs.sh
# opcional: export FORTGATE_SRS_DIR=/ruta/a/assets
```

Las verifying/proving keys se generan en `vkeys/` al primer `prove` o con `--setup-keys`.

## CLI

```bash
cd open/client-sdk/hw-midnight

# H2: solo hw-trust
cargo run --release --bin fortgate-hw-poc -- demo --tmp /tmp/fg-hw-demo

# H3: flujo completo (3 proofs)
cargo run --release --bin fortgate-hw-poc -- demo-full --tmp /tmp/fg-hw-demo-full
```

Subcomandos: `keygen`, `challenge`, `sign`, `verify-local`, `prove`, `verify`, `sign-doc`, `prove-doc`, `prove-geo`, `prove-all`, `verify-all`, `build-verify-request`, `verify-bank`, `demo`, `demo-full`.

**Nota:** el host Midnight debe compilarse en `--release`; en debug `ProverClient` puede fallar.

## Prove / verify programático

```rust
use fortgate_hw_midnight::{CreditSignProver, MidnightHwTrustProvider};

// Solo hw-trust
let hw = MidnightHwTrustProvider::new();
hw.setup_keys()?;
let package = hw.prove_handshake(&handshake)?;
hw.verify_against_handshake(&package, &handshake)?;

// Orquestador H3 (3 proofs)
let prover = CreditSignProver::new();
prover.setup_all_keys()?;
let evidence = prover.prove_all(&handshake, &doc_record, actual_lat, actual_lon)?;
prover.verify_all(&evidence, &handshake, &doc_record)?;
```

## Tests

```bash
cargo test                                    # unit + golden fixtures (rápido, sin SRS)
cargo test -- --ignored                       # E2E con SRS (~30 s en release)
```

### Golden fixtures (`hw-trust-v1`)

`tests/golden_fixtures.rs` guarda un handshake `software_poc` fijo y sus
`public_inputs` esperados en `tests/fixtures/`:

| Archivo | Contenido |
|---------|-----------|
| `hw_trust_handshake.json` | `HwHandshake` firmado (entrada golden) |
| `hw_trust_public_inputs.json` | `HwTrustPublicInputs` esperados (encoding golden) |

Los tests **no-`#[ignore]`** corren en `cargo test` normal (sin SRS) y fallan si:

- cambia la **derivación** de `public_inputs` desde el handshake,
- cambia el **encoding** JSON de `HwTrustPublicInputs` (rename de campo, tipo, `rename_all`),
- cambia el **binding off-circuit** del `hw_nullifier` (Poseidon BN254, dominio `0x4648`),
- la **verificación local** del handshake deja de ser `Green`.

El prove/verify completo (con SRS) sigue en `tests/prove_verify.rs` detrás de `#[ignore]`.

**Regenerar los fixtures** (tras un cambio intencional de encoding):

```bash
cargo test --test golden_fixtures regenerate_golden_fixtures -- --ignored --exact
```

Reescribe los dos JSON desde el backend `software_poc`. Commiteá ambos archivos.

## CLI (verificación local estilo banco)

```bash
cargo run --release --bin fortgate-hw-poc -- verify-bank \
  --request /tmp/fg-hw-demo-full/verify_request.json
```

Subcomandos H4: `build-verify-request`, `verify-bank`. `demo-full` también escribe `verify_request.json`.

## API Enterprise mock (H4)

Ver [`enterprise/credit-sign-api/README.md`](../../enterprise/credit-sign-api/README.md).

## Demo E2E happy path (H5)

```bash
./demo/hw-trust-demo.sh
```

Ver [`demo/README.md`](../../demo/README.md).

## Tiempos de prove

Medianas de 5 iteraciones en un i5-12450H (12 núcleos lógicos, 8 GB, Windows 11),
rustc 1.88.0, perfil `release`. Wall-clock de `prove()`, incluida la carga de SRS y llaves.

| Circuito | Antes | Ahora | Δ |
|---|---|---|---|
| `hw-trust-v1` | 11 127 ms | **6 294 ms** | -43,4% |
| `doc-bind-v1` | 11 059 ms | **6 366 ms** | -42,4% |
| `geo-range-v1` | 65 ms | **55 ms** | -16,0% |
| **Total** | **22 252 ms** | **12 715 ms** | **-42,9%** |

La mejora viene de cachear el SRS, las llaves y el `k` óptimo en memoria: antes se
recargaban desde disco en cada `prove()` y cada `verify()`, lo que era el 44% del tiempo.
Lo que queda es generación de prueba pura. `verify` baja igual: pagaba ~2 845 ms por
prueba, casi todo carga de SRS y vk.

El objetivo de <5 s no se alcanza: lo impide la verificación ECDSA P-256 emulada sobre
BLS12-381, que fija `k = 16` en ambos circuitos pesados. El análisis del piso y la ruta
de fusión `hw-doc-v1` están en
[`docs/adr/ADR-0001`](../../docs/adr/ADR-0001-prove-time-optimization.md).

> Los ~6 900 ms / ~7 800 ms que figuraban antes aquí se midieron en un Mac PoC y
> correspondían solo a la generación de la prueba, sin la carga de SRS y llaves. La
> columna "Antes" de arriba es wall-clock completo en la máquina indicada, así que no es
> directamente comparable con aquellas cifras.

### Reproducir

```bash
./scripts/fetch_srs.sh                        # una vez, ~100 MB
./scripts/run_bench.sh after.json before.json
```

`fg-bench` es la herramienta de perfilado:

```bash
cargo run --release --bin fg-bench -- model            # perfil estático: k, filas, ocupación
cargo run --release --bin fg-bench -- model --k 15     # fuerza k para ver qué fija el tamaño
cargo run --release --bin fg-bench -- bench --iters 5  # prove/verify reales, JSON
cargo run --release --bin fg-bench -- compare --before a.json --after b.json
```

`compare` sale con código de error si `geo-range-v1` regresiona más de un 10%.
