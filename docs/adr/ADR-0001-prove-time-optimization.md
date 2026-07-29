# ADR-0001: Optimización de tiempos de prove en los circuitos Midnight

**Estado:** Aceptado
**Fecha:** 2026-07-27
**Issue:** [#6](https://github.com/fort-gate/fortgate-open/issues/6) — `perf(hw-midnight)`

## Contexto

El PoC apunta a ~1–2 s por circuito Small y <5 s en total. Los tiempos publicados en
`client-sdk/hw-midnight/README.md` eran ~6,9 s para `hw-trust-v1` y ~7,8 s para
`doc-bind-v1`. `geo-range-v1` ya cumplía con 65 ms y la restricción era no hacerlo
regresar.

## Entorno de medición

| | |
|---|---|
| CPU | 12th Gen Intel Core i5-12450H, 12 núcleos lógicos |
| RAM | 8 GB |
| OS | Windows 11 Pro 26200, x86_64 |
| Toolchain | rustc 1.88.0 (6b00bc388 2025-06-23), cargo 1.88.0 |
| Perfil | `release`, `opt-level = 3`, sin LTO |
| SRS | Filecoin BLS12-381 `bls_filecoin_2p19` |
| Método | mediana de 5 iteraciones, 1 de calentamiento, vía `fg-bench` |

Reproducible con `client-sdk/hw-midnight/scripts/run_bench.sh`.

## Herramienta de medición

Se añadió el binario `fg-bench` (`src/bin/fg_bench.rs`), que no existía:

* `fg-bench model [--k N]` — perfil estático por `cost_model()`: `k`, filas, ocupación,
  filas de tabla, columnas, lookups, grado. No necesita SRS. `--k` fuerza un `k` concreto,
  que es lo que permitió identificar qué fija realmente el tamaño del circuito.
* `fg-bench bench --iters N` — prove y verify reales, con mediana y con máquina,
  toolchain y flags grabados en el JSON.
* `fg-bench compare --before a.json --after b.json` — tabla Markdown; **sale con error**
  si `geo-range-v1` regresiona más de un 10%.

`bench` separa dos magnitudes que resultaron ser muy distintas:

* **wall** — la llamada completa a `prove()`, incluye cargar SRS y llaves.
* **generación pura** — lo que el provider ya reportaba en `proving_time_ms`.

Esa separación es la que localizó el problema principal.

## Diagnóstico

### El costo dominante medido no era el circuito, sino I/O repetido

En el baseline, de los 11,1 s de `hw-trust-v1` solo 6,2 s eran generación de la prueba.
Los otros ~4,9 s (44%) eran recargar el SRS y las llaves desde disco, en **cada**
`prove()` y en cada `verify()`. `prove_all` lo pagaba tres veces.

Dentro de ese overhead había un segundo costo no obvio: `load_srs_for_relation` llamaba a
`optimal_k(relation)` antes de mirar nada más, y `optimal_k` sintetiza el circuito entero
con `cost_model` para `k` de 9 a 25. Se ejecutaba en cada prove y en cada verify.
Cachear solo SRS y llaves daba -19,8%; cachear además `optimal_k` llevó el total a -44,1%.

### `k` está fijado por la emulación P-256, y la Fase 2 no lo mueve

`hw-trust-v1` y `doc-bind-v1` usan `k = 16`. Forzando `k` hacia abajo con
`fg-bench model --k`:

| Configuración | filas | capacidad 2^k | ¿cabe? |
|---|---|---|---|
| k = 14 | 40 716 | 16 384 | no |
| k = 15 | 35 500 | 32 768 | no, faltan **2 732 filas** |
| k = 16 | 31 645 | 65 536 | sí (48% de ocupación) |

Las filas *aumentan* al bajar `k` porque la tabla `pow2range` usa `max_bit_len = k - 1` y
las descomposiciones necesitan más filas. Para llegar a `k = 15` habría que recortar
2 732 filas. Contra eso se midieron las dos optimizaciones de circuito propuestas:

| Cambio | Filas ahorradas | Necesarias para `k=15` |
|---|---|---|
| F2.2 — una inversión en vez de dos divisiones | **3** | 2 732 |
| F2.1 — quitar el `hw_nullifier` del circuito *por completo* (techo teórico) | **11** | 2 732 |

Ambas premisas de la guía original resultaron incorrectas al medirlas:

* **F2.2:** `div(x, s)` en el chip de campo foráneo no realiza una inversión completa. Usa
  el inverso como *hint* del testigo y restringe `q · s = x`, así que cuesta prácticamente
  lo mismo que una multiplicación. No había "dos inversiones" que ahorrar.
* **F2.1:** los 32 bytes del nullifier cuestan 11 filas, no ~32 asignaciones caras. Los
  range checks viven en la tabla de lookup compartida, no en filas del circuito.

Como el tiempo de prove en Halo2 lo dominan las FFT y MSM sobre el dominio de tamaño
`2^k`, y `k` no se mueve, **recortar constraints sin cruzar el umbral de `k` no acelera
nada**. Esto es lo que explica que la Fase 2 no aparezca en los resultados.

## Decisión

### Aplicado

| Id | Cambio | Riesgo de soundness |
|---|---|---|
| F1.2 | SRS, pk y vk cacheados en memoria por proceso (`src/key_cache.rs`) | Ninguno, no toca circuito |
| F1.2b | `optimal_k` memoizado por relation | Ninguno, no toca circuito |
| F1.3 | Eliminada la carga muerta de vk en el path de prove (`provider.rs`) | Ninguno, era dead code |
| F2.2 | Una inversión de `s` y dos multiplicaciones, en vez de dos divisiones | Ver abajo |

El caché es global al proceso y no por instancia, porque el código construye providers
nuevos en cada llamada (p. ej. `MidnightHwTrustProvider::new().prove_handshake(...)` en
`demo_runner.rs`); un caché por instancia no se reutilizaría nunca. `setup_keys` invalida
la entrada correspondiente para no servir una llave anterior.

**Soundness de F2.2.** El cambio es `x/s` → `x · s⁻¹`, algebraicamente idéntico. Se usa
`inv` y no `inv0`: la documentación de `ArithInstructions` especifica que `inv` deja el
circuito insatisfacible si el argumento es 0, exactamente la misma garantía que `div` con
divisor 0. La restricción `s ≠ 0` se preserva. No cambia el formato de public inputs
(`format_instance` queda igual), así que el paquete de prueba JSON no se modifica; sí hay
que regenerar vk/pk, cosa que `setup_keys` ya hace automáticamente.

### Descartado

| Id | Motivo |
|---|---|
| F1.4 — `lto = "fat"` + `codegen-units = 1` | Sin mejora medible (+1,6%, dentro del ruido de ±3% entre corridas) y el build limpio de release pasó de 41 s a 7 m 40 s. El costo está en las FFT/MSM de `midnight-proofs`, que ya se compila con `opt-level = 3`; el inlining entre crates no lo toca. |
| F2.1 — `hw_nullifier` en 2 limbs de 128 bits | Techo de ahorro medido: 11 filas de 35 500. No mueve `k`, no acelera, e invalidaría las pruebas ya emitidas. El argumento de soundness de la propuesta era correcto (el empaquetado BE a 2 limbs de 128 bits es inyectivo), pero no hay beneficio que justifique el cambio. |

## Resultados

Medianas de 5 iteraciones, wall-clock de `prove()`:

| Circuito | Antes | Fase 1 (caché) | Final (Fase 1 + F2.2) | Δ total |
|---|---|---|---|---|
| `hw-trust-v1` | 11 127 ms | 6 145 ms | 6 294 ms | **-43,4%** |
| `doc-bind-v1` | 11 059 ms | 6 236 ms | 6 366 ms | **-42,4%** |
| `geo-range-v1` | 65 ms | 53 ms | 55 ms | **-16,0%** |
| **Total** | **22 252 ms** | **12 434 ms** | **12 715 ms** | **-42,9%** |

La diferencia entre la columna "Fase 1" y la final está dentro del ruido entre corridas
(±3%); F2.2 aporta 3 filas de 31 645 y no es medible.

Desglose del overhead eliminado, por circuito:

| | Antes | Final |
|---|---|---|
| wall-clock de `prove()` | 11 127 ms | 6 294 ms |
| generación pura de la prueba | 6 211 ms | 6 288 ms |
| **overhead de I/O** | **4 916 ms (44%)** | **~6 ms (0%)** |

`verify` se beneficia igual: pagaba ~2 845 ms por prueba, casi todo carga de SRS y vk.

`geo-range-v1` no regresiona: 65 ms → 55 ms, muy por debajo del límite de 65 × 1,1 = 71,5 ms.
`fg-bench compare` lo verifica automáticamente y falla si se supera.

## El objetivo de <5 s no se alcanza: el piso

El total quedó en **12,7 s**, contra un objetivo de 5 s. El piso está donde ya estaba: la
verificación ECDSA P-256 emulada sobre BLS12-381 cuesta ~6,3 s por circuito en esta
máquina y fija `k = 16`. Eliminado ya todo el overhead evitable, el tiempo restante es
íntegramente generación de prueba.

Recortar constraints no ayuda mientras no se baje `k` a 15, lo que exige recortar 2 732
filas — dos órdenes de magnitud más de lo que dan las optimizaciones propuestas.

### Ruta alternativa: fusión `hw-doc-v1`

La fusión que contempla `docs/ZK_CIRCUIT_STRATEGY.md` sigue siendo la única vía con
potencial estructural, y ahora hay un argumento cuantitativo a favor:

* Un circuito con una ECDSA ocupa 31 645 filas a `k = 16`, un 48% de las 65 536 disponibles.
* Un circuito fusionado con las dos verificaciones ECDSA rondaría las ~63 000 filas, que
  **todavía caben en `k = 16`** (~96% de ocupación).
* Si cabe, se pagaría una sola FFT/MSM de 2^16 en vez de dos: ~6,3 s en vez de 12,6 s,
  y el total caería a ~6,4 s.

Eso seguiría por encima de 5 s, pero es la única palanca que reduce el costo a la mitad en
vez de un porcentaje marginal. La estimación es aritmética sobre el modelo estático y
**no está prototipada**: la ocupación al 96% es ajustada y habría que confirmar que el
layouter la resuelve sin desbordar a `k = 17`, en cuyo caso el cambio sería contraproducente.
Requiere un issue aparte.

Otras vías fuera del alcance de este issue: mover la verificación P-256 a una curva no
emulada, o delegar la prueba a un backend con hardware (el repo ya tiene `sp1-prover`).

## Consecuencias

* `load_srs_for_relation`, `load_vk` y `load_pk` ahora devuelven `Arc<_>` en vez del valor.
  Los call sites internos no cambiaron gracias a la coerción por `Deref`, pero es un cambio
  en la API pública de `MidnightCircuitProvider` y `MidnightHwTrustProvider`.
* `MidnightCircuitProvider<R>` exige ahora `R: Send + Sync + 'static`. Las tres relations
  del PoC lo cumplen por ser structs unitarios.
* El proceso retiene el SRS y las llaves en memoria mientras vive. Es el intercambio
  deliberado: memoria por tiempo. En un servicio de larga duración es lo que se quiere;
  para un CLI de un solo disparo no cambia nada porque igual se paga una vez.
* F2.2 cambia el circuito, así que las vk/pk previas dejan de servir. `setup_keys` las
  regenera automáticamente cuando faltan.
