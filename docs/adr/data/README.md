# Mediciones crudas de ADR-0001

Salidas de `fg-bench bench --iters 5 --warmup 1` en cada paso del trabajo del issue #6.
Cada archivo incluye máquina, toolchain, flags y las 5 muestras individuales por circuito,
además de la mediana.

Todas las corridas son de la misma máquina y sesión: i5-12450H (12 núcleos lógicos), 8 GB,
Windows 11, rustc 1.88.0.

| Archivo | Configuración | Total prove (mediana) |
|---|---|---|
| `01-baseline.json` | Sin modificar | 22 252 ms |
| `02-cache-srs-llaves.json` | Caché de SRS y llaves | 17 847 ms (-19,8%) |
| `03-cache-mas-optimal-k.json` | + `optimal_k` memoizado | 12 434 ms (-44,1%) |
| `04-cache-mas-lto-descartado.json` | + `lto = "fat"`, `codegen-units = 1` | 12 636 ms (+1,6% vs anterior) |
| `05-final.json` | Estado final: caché + una inversión ECDSA, sin LTO | 12 715 ms (-42,9%) |

`04` documenta por qué se descartó LTO: no mejoró nada y subió el build limpio de 41 s a
7 m 40 s. La diferencia entre `03`, `04` y `05` está dentro del ruido entre corridas (±3%),
que es el motivo por el que el ADR afirma que la optimización de circuito no es medible.

Reproducir:

```bash
cd client-sdk/hw-midnight
./scripts/fetch_srs.sh
./scripts/run_bench.sh nueva.json ../../docs/adr/data/01-baseline.json
```

Los tiempos absolutos dependen de la máquina. Lo que no depende son las conclusiones
estructurales del ADR (`k = 16`, las 2 732 filas que faltan para `k = 15`, el ahorro de
3 y 11 filas de las optimizaciones de circuito): salen de `fg-bench model`, que es análisis
estático de `cost_model()` y no mide tiempo.
