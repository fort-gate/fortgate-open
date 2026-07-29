# ADR-0001: Prove-time optimization of the Midnight circuits

**Status:** Accepted
**Date:** 2026-07-27
**Issue:** [#6](https://github.com/fort-gate/fortgate-open/issues/6) — `perf(hw-midnight)`

## Context

The PoC targets ~1–2 s per Small circuit and <5 s in total. The times published in
`client-sdk/hw-midnight/README.md` were ~6.9 s for `hw-trust-v1` and ~7.8 s for
`doc-bind-v1`. `geo-range-v1` already met the target at 65 ms, and the constraint there was
simply not to regress it.

## Measurement environment

| | |
|---|---|
| CPU | 12th Gen Intel Core i5-12450H, 12 logical cores |
| RAM | 8 GB |
| OS | Windows 11 Pro 26200, x86_64 |
| Toolchain | rustc 1.88.0 (6b00bc388 2025-06-23), cargo 1.88.0 |
| Profile | `release`, `opt-level = 3`, no LTO |
| SRS | Filecoin BLS12-381 `bls_filecoin_2p19` |
| Method | median of 5 iterations, 1 warm-up, via `fg-bench` |

Reproducible with `client-sdk/hw-midnight/scripts/run_bench.sh`.

## Measurement tooling

The `fg-bench` binary (`src/bin/fg_bench.rs`) was added; the repository had none:

* `fg-bench model [--k N]` — static profile from `cost_model()`: `k`, rows, occupancy,
  table rows, columns, lookups, degree. Needs no SRS. `--k` forces a specific `k`, which is
  what made it possible to identify what really sets the circuit size.
* `fg-bench bench --iters N` — real prove and verify, with the median and with machine,
  toolchain and flags recorded in the JSON.
* `fg-bench compare --before a.json --after b.json` — Markdown table; **exits with an
  error** if `geo-range-v1` regresses by more than 10%.

`bench` separates two quantities that turned out to be very different:

* **wall** — the complete `prove()` call, including loading the SRS and the keys.
* **pure generation** — what the provider already reported as `proving_time_ms`.

That separation is what located the main problem.

## Diagnosis

### The dominant measured cost was not the circuit, but repeated I/O

In the baseline, out of the 11.1 s of `hw-trust-v1` only 6.2 s were proof generation. The
other ~4.9 s (44%) were reloading the SRS and the keys from disk on **every** `prove()` and
every `verify()`. `prove_all` paid that three times.

Inside that overhead there was a second, non-obvious cost: `load_srs_for_relation` called
`optimal_k(relation)` before looking at anything else, and `optimal_k` synthesizes the whole
circuit with `cost_model` for `k` from 9 to 25. It ran on every prove and every verify.
Caching only the SRS and the keys gave -19.8%; also caching `optimal_k` took the total to
-44.1%.

### `k` is set by the P-256 emulation, and Phase 2 does not move it

`hw-trust-v1` and `doc-bind-v1` use `k = 16`. Forcing `k` downwards with
`fg-bench model --k`:

| Configuration | rows | capacity 2^k | fits? |
|---|---|---|---|
| k = 14 | 40,716 | 16,384 | no |
| k = 15 | 35,500 | 32,768 | no, **2,732 rows short** |
| k = 16 | 31,645 | 65,536 | yes (48% occupancy) |

Rows *increase* as `k` goes down because the `pow2range` table uses `max_bit_len = k - 1`
and the decompositions need more rows. Reaching `k = 15` would require cutting 2,732 rows.
The two proposed circuit optimizations were measured against that figure:

| Change | Rows saved | Needed for `k=15` |
|---|---|---|
| F2.2 — one inversion instead of two divisions | **3** | 2,732 |
| F2.1 — removing `hw_nullifier` from the circuit *entirely* (theoretical ceiling) | **11** | 2,732 |

Both premises of the original guide turned out to be wrong once measured:

* **F2.2:** `div(x, s)` in the foreign-field chip does not perform a full inversion. It
  takes the inverse as a witness *hint* and constrains `q · s = x`, so it costs practically
  the same as a multiplication. There were no "two inversions" to save.
* **F2.1:** the 32 bytes of the nullifier cost 11 rows, not ~32 expensive assignments. The
  range checks live in the shared lookup table, not in circuit rows.

Since prove time in Halo2 is dominated by the FFTs and MSMs over the domain of size `2^k`,
and `k` does not move, **trimming constraints without crossing the `k` threshold speeds up
nothing**. That is why Phase 2 does not show up in the results.

## Decision

### Applied

| Id | Change | Soundness risk |
|---|---|---|
| F1.2 | SRS, pk and vk cached in memory per process (`src/key_cache.rs`) | None, does not touch the circuit |
| F1.2b | `optimal_k` memoized per relation | None, does not touch the circuit |
| F1.3 | Removed the dead vk load from the prove path (`provider.rs`) | None, it was dead code |
| F2.2 | One inversion of `s` and two multiplications, instead of two divisions | See below |

The cache is process-global rather than per instance, because the calling code builds a new
provider on every call (e.g. `MidnightHwTrustProvider::new().prove_handshake(...)` in
`demo_runner.rs`); a per-instance cache would never be reused. `setup_keys` invalidates the
corresponding entry so that a previous key is never served.

**Soundness of F2.2.** The change is `x/s` → `x · s⁻¹`, algebraically identical. It uses
`inv` and not `inv0`: the documentation of `ArithInstructions` specifies that `inv` leaves
the circuit unsatisfiable if the argument is 0, exactly the same guarantee `div` gives with
a zero divisor. The `s ≠ 0` constraint is preserved. The public-input format does not change
(`format_instance` stays the same), so the JSON proof package is unmodified; vk/pk do have to
be regenerated, which `setup_keys` already does automatically.

### Rejected

| Id | Reason |
|---|---|
| F1.4 — `lto = "fat"` + `codegen-units = 1` | No measurable improvement (+1.6%, within the ±3% run-to-run noise) and the clean release build went from 41 s to 7 m 40 s. The cost is in the FFTs/MSMs of `midnight-proofs`, which is already compiled with `opt-level = 3`; cross-crate inlining does not touch it. |
| F2.1 — `hw_nullifier` packed into 2 limbs of 128 bits | Measured saving ceiling: 11 rows out of 35,500. It does not move `k`, does not speed anything up, and would invalidate already-issued proofs. The soundness argument in the proposal was correct (BE packing into 2 limbs of 128 bits is injective), but there is no benefit to justify the change. |

## Results

Medians of 5 iterations, wall-clock of `prove()`:

| Circuit | Before | Phase 1 (cache) | Final (Phase 1 + F2.2) | Total Δ |
|---|---|---|---|---|
| `hw-trust-v1` | 11,127 ms | 6,145 ms | 6,294 ms | **-43.4%** |
| `doc-bind-v1` | 11,059 ms | 6,236 ms | 6,366 ms | **-42.4%** |
| `geo-range-v1` | 65 ms | 53 ms | 55 ms | **-16.0%** |
| **Total** | **22,252 ms** | **12,434 ms** | **12,715 ms** | **-42.9%** |

The difference between the "Phase 1" column and the final one is within the run-to-run noise
(±3%); F2.2 contributes 3 rows out of 31,645 and is not measurable.

Breakdown of the removed overhead, per circuit:

| | Before | Final |
|---|---|---|
| wall-clock of `prove()` | 11,127 ms | 6,294 ms |
| pure proof generation | 6,211 ms | 6,288 ms |
| **I/O overhead** | **4,916 ms (44%)** | **~6 ms (0%)** |

`verify` benefits equally: it used to pay ~2,845 ms per proof, almost all of it SRS and vk
loading.

`geo-range-v1` does not regress: 65 ms → 55 ms, well below the limit of 65 × 1.1 = 71.5 ms.
`fg-bench compare` checks this automatically and fails if the limit is exceeded.

### How much of this shows up in a single-shot process

The numbers above come from `fg-bench`, which discards one warm-up iteration and reports the
median of five. That represents the repeated-proving scenario, i.e. a long-running service.
**A process that starts up, generates the three proofs and exits benefits considerably
less**, because it can only share the SRS and `k` across the three circuits and between
prove and verify, never across repetitions.

Measured with `fortgate-hw-poc demo-full`, which is exactly that case:

| | `main` (n=3) | with the cache (n=5) |
|---|---|---|
| `prove_all`, median | 41,863 ms | **33,502 ms (-20%)** |
| `prove_all`, range | 38,986 – 55,946 ms | 22,955 – 68,646 ms |
| `verify` of the 3 proofs | ~7,045 ms | **~185 ms (-97%)** |
| Peak working set | 0.99 GB | **1.62 GB** |

Single-shot wall-clock has enormous variance on this machine (`main` varies 2× against
itself, from 39 to 56 s), because the cold start pays for reading the keys just written by
`setup_all_keys` and for the antivirus scanning them. That is why the figures in this table
are indicative and the `fg-bench` ones are the numbers to quote.

The drop of `verify` to ~185 ms is the largest and most robust effect: `verify` reuses the
SRS that `prove` already left loaded, so it stops paying the ~2,845 ms per proof.

## The <5 s target is not met: the floor

The total came out at **12.7 s**, against a 5 s target. The floor is where it already was:
the P-256 ECDSA verification emulated over BLS12-381 costs ~6.3 s per circuit on this
machine and fixes `k = 16`. With all the avoidable overhead already removed, the remaining
time is entirely proof generation.

Trimming constraints does not help as long as `k` is not brought down to 15, which requires
cutting 2,732 rows — two orders of magnitude more than the proposed optimizations deliver.

### Alternative route: the `hw-doc-v1` merge

The merge contemplated in `docs/ZK_CIRCUIT_STRATEGY.md` remains the only route with
structural potential, and there is now a quantitative argument in its favour:

* A circuit with one ECDSA occupies 31,645 rows at `k = 16`, 48% of the 65,536 available.
* A merged circuit with both ECDSA verifications would be around ~63,000 rows, which
  **still fits in `k = 16`** (~96% occupancy).
* If it fits, a single 2^16 FFT/MSM would be paid instead of two: ~6.3 s instead of 12.6 s,
  bringing the total down to ~6.4 s.

That would still be above 5 s, but it is the only lever that halves the cost rather than
shaving a marginal percentage. The estimate is arithmetic over the static model and is
**not prototyped**: 96% occupancy is tight, and it would have to be confirmed that the
layouter resolves it without overflowing to `k = 17`, in which case the change would be
counterproductive. It needs a separate issue.

Other routes outside the scope of this issue: moving the P-256 verification to a
non-emulated curve, or delegating proving to a hardware-backed backend (the repository
already has `sp1-prover`).

## Consequences

* `load_srs_for_relation`, `load_vk` and `load_pk` now return `Arc<_>` instead of the value.
  Internal call sites did not change thanks to `Deref` coercion, but it is a change in the
  public API of `MidnightCircuitProvider` and `MidnightHwTrustProvider`.
* `MidnightCircuitProvider<R>` now requires `R: Send + Sync + 'static`. The three PoC
  relations satisfy it, being unit structs.
* The process retains the SRS and the keys in memory for its whole lifetime. That is the
  deliberate trade-off: memory for time. Measured with `demo-full`, the peak working set
  rises from **0.99 GB to 1.62 GB** (+64%), because the three proving keys and the SRS
  coexist instead of being freed after each circuit. On an 8 GB machine there was no paging
  or degradation, but it is worth keeping in mind if the provider runs in a container with a
  tight memory limit. Should that become a problem, the natural mitigation is to bound the
  proving-key cache (the vk and the SRS are much smaller and are the most reused).
* F2.2 changes the circuit, so previous vk/pk are no longer valid. `setup_keys` regenerates
  them automatically when they are missing.
