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
cargo test                                    # unit tests (rápido)
cargo test -- --ignored                       # E2E con SRS (~30 s en release)
```

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

## Tiempos de referencia (release, Mac PoC)

| Paso | ~ms |
|------|-----|
| hw-trust prove | 6 900 |
| doc-bind prove | 7 800 |
| geo-range prove | 65 |
| verify 3 proofs | 8 000 |
