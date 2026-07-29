# ADR-0001 raw measurements

Outputs of `fg-bench bench --iters 5 --warmup 1` at each step of the work on issue #6.
Every file includes the machine, toolchain, flags and the 5 individual samples per circuit,
plus the median.

All runs come from the same machine and session: i5-12450H (12 logical cores), 8 GB,
Windows 11, rustc 1.88.0.

| File | Configuration | Total prove (median) |
|---|---|---|
| `01-baseline.json` | Unmodified | 22,252 ms |
| `02-cache-srs-keys.json` | SRS and key cache | 17,847 ms (-19.8%) |
| `03-cache-plus-optimal-k.json` | + `optimal_k` memoized | 12,434 ms (-44.1%) |
| `04-cache-plus-lto-rejected.json` | + `lto = "fat"`, `codegen-units = 1` | 12,636 ms (+1.6% vs previous) |
| `05-final.json` | Final state: cache + single ECDSA inversion, no LTO | 12,715 ms (-42.9%) |

`04` documents why LTO was rejected: it improved nothing and pushed the clean build from
41 s to 7 m 40 s. The difference between `03`, `04` and `05` is within the run-to-run noise
(±3%), which is why the ADR states that the circuit optimization is not measurable.

To reproduce:

```bash
cd client-sdk/hw-midnight
./scripts/fetch_srs.sh
./scripts/run_bench.sh new.json ../../docs/adr/data/01-baseline.json
```

Absolute timings depend on the machine. What does not depend on it are the structural
conclusions of the ADR (`k = 16`, the 2,732 rows missing to reach `k = 15`, the 3- and
11-row savings of the circuit optimizations): those come from `fg-bench model`, which is
static analysis of `cost_model()` and does not measure time.
