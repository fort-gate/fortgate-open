# Spike: compatibilidad de campo para Poseidon en `hw_nullifier` (Midnight)

| | |
|---|---|
| **Origen** | Issue #2 — `hw_nullifier` se asignaba como input público en `HwTrustRelationV1` pero nunca se constrain-eaba |
| **Duración** | 1 sesión — investigación de dependencias (`midnight-circuits` 7.2.0, `midnight-zk-stdlib` 2.3.0, `midnight-curves` 0.3.0, `midnight-proofs` 0.8.0) antes de tocar código |
| **Resultado** | `hw_nullifier` ahora se calcula y constrain-ea con el Poseidon nativo de Midnight (BLS12-381), no BN254. Ver PR que cierra el issue. |

---

## Problema encontrado

El plan obvio — "agregar un `assert_equal` entre el Poseidon BN254 ya usado off-circuit (`light_poseidon` sobre `ark_bn254::Fr`, dominio `0x4648`) y el input público `hw_nullifier`" — no es viable con las versiones ancladas de Midnight:

- El campo nativo del circuito `HwTrustRelationV1` es `midnight_curves::Fq`, el **campo escalar de BLS12-381** (confirmado vía `srs.rs`: `ParamsKZG<midnight_curves::Bls12>`).
- El `hw_nullifier` off-circuit se calculaba sobre `ark_bn254::Fr` — el campo escalar de **BN254**, un primo distinto.
- Constrain-ear el valor BN254 exacto dentro de un circuito nativo BLS12-381 requiere emulación de campo foráneo (foreign-field), la misma técnica que ya se usa para ECDSA P-256 en este circuito (`AssignedField<F, K, MultiEmulationParams>`).

---

## Investigación

Se descargó y revisó el código fuente real de las crates ancladas (`~/.cargo/registry/src/.../midnight-circuits-7.2.0`, etc.) en lugar de asumir la API:

1. `src/field/foreign/params.rs` — se enumeraron todos los `impl FieldEmulationParams<...> for MultiEmulationParams`. Existen pares para: secp256k1 (base y scalar), secp256r1/P-256 (base y scalar), BLS12-381 base, **BN254 base** (`bn256::Fq`), curve25519. **No existe** ningún `impl FieldEmulationParams<midnight_curves::Fq, bn256::Fr>` — es decir, el campo **escalar** de BN254 (el que usa `ark_bn254::Fr`/Poseidon) no tiene parámetros de emulación soportados sobre el campo nativo BLS12-381.
2. El único soporte para BN254 que sí existe (`bn256::Fq`, campo base) está además detrás de `#[cfg(feature = "dev-curves")]` — no habilitado en este workspace, no pensado para producción.
3. Construir esto a mano implicaría generar nuevos `FieldEmulationParams` (parámetros criptográficos: `LOG2_BASE`, `NB_LIMBS`, `moduli`, `RC_LIMB_SIZE` — normalmente generados con un script Python de Midnight, `scripts/foreign_params_gen.py`, que no tenemos) y luego un gadget Poseidon completo sobre aritmética foránea, replicando exactamente el schedule de rondas de `light_poseidon` (8 rondas completas + 57 parciales para t=3). Alto riesgo de soundness si algún parámetro queda mal, y desproporcionado para un PoC.

### La alternativa: Poseidon nativo de Midnight

`midnight-circuits` trae su propio Poseidon para su campo nativo (BLS12-381), expuesto en `src/hash/poseidon/`:

- **On-circuit**: `ZkStdLib::poseidon(&self, layouter, input: &[AssignedNative<F>]) -> AssignedNative<F>` (`midnight-zk-stdlib` `lib.rs:911`).
- **Off-circuit**: `PoseidonChip::<F>::hash(inputs: &[F]) -> F` vía el trait `HashCPU` (`hash/poseidon/poseidon_cpu.rs`), que opera con exactamente los mismos `ROUND_CONSTANTS`/MDS que la versión in-circuit — los comentarios del propio crate documentan que la única diferencia entre la versión CPU y la de circuito es una optimización de "round skips", una identidad algebraica que no cambia el resultado.
- `midnight_curves::Fq` ya implementa el trait `PoseidonField` requerido (`hash/poseidon/constants/blstrs.rs`, sin feature flag) — no hace falta ninguna configuración extra.

Esto da una constraint real usando un chip ya auditado por el equipo de Midnight, sin inventar criptografía nueva.

### Radio de impacto de cambiar el campo de `hw_nullifier`

Antes de decidir, se verificó que `hw_nullifier` es un valor de enlace puramente interno (no rompe compatibilidad externa):

- `grep` de `hw_nullifier`/`0x4648` en todo el repo: sin vectores de prueba fijos (a diferencia del nullifier de identidad `0x4647`/FG, que sí tiene `poseidon_vectors.json`).
- No lo recomputa ningún circuito Noir (`0x4648` no aparece en `open/proto/`).
- La API del banco (`BANK_VERIFY_API_SPEC.md`) lo trata como string opaco (`"hwNullifier": "..."`), nunca lo recalcula.

Con esto, cambiar el campo subyacente (manteniendo el mismo separador de dominio `0x4648`) es seguro: una sola definición, reutilizada off-circuit y on-circuit — sin "segunda ruta de reducción".

### Riesgo de portabilidad wasm32

`client-sdk` (`fortgate-id-core`) también apunta a `wasm32` (bindings `wasm-bindgen`). Se comprobó empíricamente que `midnight-curves` depende de la librería C `blst`, que **no compila** para `wasm32-unknown-unknown` sin toolchain especial (reproducido localmente: `cargo check --target wasm32-unknown-unknown` falla en `blst-0.3.17` con *"No available targets are compatible with triple wasm32-unknown-unknown"*). Mitigado porque el módulo `hw_trust` ya estaba excluido de wasm32 (`#[cfg(not(target_arch = "wasm32"))]` en `client-sdk/src/lib.rs`); las nuevas dependencias se agregaron bajo `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` en `Cargo.toml` en lugar de `[dependencies]`, para no arrastrar `blst` al build wasm32.

---

## Decisión

Redefinir `hw_nullifier = Poseidon_2(pubkey_commitment mod r, 0x4648)` sobre el campo nativo del circuito Midnight (BLS12-381), usando `PoseidonChip`/`std_lib.poseidon()` tanto off-circuit (`client-sdk/src/hw_trust/commitment.rs`) como on-circuit (`HwTrustRelationV1`), en vez de emular BN254. El separador de dominio `0x4648` ("FH") no cambia.

---

## Verificación

- `cargo test -p fortgate-id-core --lib` y `--test poseidon_vectors` — sin regresión en el nullifier de identidad (BN254, dominio `0x4647`, no tocado).
- `cargo test --release -p fortgate-hw-midnight --test prove_verify -- --ignored` contra SRS real: 4/4 tests, incluyendo un test negativo nuevo (`tampered_hw_nullifier_fails`) que confirma que alterar `hw_nullifier` rompe la prueba.
- CLI real (`fortgate-hw-poc demo-full` + `verify-bank`): evidencia válida → `✅ GREEN`; mismo `verify_request.json` con un byte de `hwNullifier` alterado → `Error: RED ZkHwTrustFailed: ZK proof verification failed`.

---

## Follow-ups no incluidos en este spike

- `doc-bind-v1` (`client-sdk/hw-midnight/src/doc_bind.rs`) tiene el mismo patrón de `hw_nullifier` público sin constrain — mismo bug, no corregido aquí, requiere issue separado.
- Si en el futuro se necesita compatibilidad real con un circuito Noir/BN254 que recompute este nullifier de forma independiente, haría falta un spike dedicado para generar y auditar `FieldEmulationParams<midnight_curves::Fq, bn256::Fr>` (parámetros de emulación de campo foráneo) — no cubierto aquí.
