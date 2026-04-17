# fortgate_poseidon_check (Noir 0.31)

Paquete mínimo para `nargo test` sobre **Poseidon BN254 `hash_2`**, alineado conceptualmente con `open/proto/src/main.nr` y con los vectores Rust en `open/client-sdk/tests/fixtures/poseidon_vectors.json`.

## Toolchain

Usa **Nargo 0.31.x** (misma familia que `open/proto/Nargo.toml`). Ejemplo con [noirup](https://github.com/noir-lang/noirup):

```bash
noirup --version 0.31.0
cd open/proto-poseidon-check && nargo test
```

Noir 1.x (p. ej. beta.19) usa otra `stdlib` y **no** compila este paquete sin migración.

## Nota sobre bytes vs Rust

Los hex en `open/client-sdk/tests/fixtures/poseidon_vectors.json` usan **serialización comprimida Ark** (`fr_to_canonical_hex`). Noir expone `Field::to_be_bytes`, que **no** tiene por qué coincidir con ese encoding; la interoperabilidad criptográfica se valida en **Rust** contra el JSON; aquí solo se comprueba que el circuito Poseidon en Noir se ejecuta y produce compromisos distintos.
