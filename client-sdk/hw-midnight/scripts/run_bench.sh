#!/usr/bin/env bash
# Reproducible benchmark of the three ZK circuits.
#
#   ./scripts/run_bench.sh before.json             # measure and save
#   ./scripts/run_bench.sh after.json before.json  # measure and compare against a previous run
#
# Pins the build flags and the environment variables that `fg-bench` records in the JSON,
# so that two runs are comparable. Requires the SRS (scripts/fetch_srs.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${1:-bench.json}"
BASELINE="${2:-}"
ITERS="${FG_BENCH_ITERS:-5}"
WARMUP="${FG_BENCH_WARMUP:-1}"

# The release profile from Cargo.toml is the reference; no extra RUSTFLAGS are injected,
# because changing them would invalidate the comparison against the ADR-0001 numbers.
export FG_BENCH_PROFILE="release (opt-level=3, no LTO)"

# Machine metadata: `fg-bench` records it in the JSON next to the timings.
if [[ -z "${FG_BENCH_CPU:-}" ]]; then
  case "$(uname -s)" in
    Linux)  FG_BENCH_CPU="$(awk -F': ' '/model name/{print $2; exit}' /proc/cpuinfo || echo unknown)" ;;
    Darwin) FG_BENCH_CPU="$(sysctl -n machdep.cpu.brand_string || echo unknown)" ;;
    *)      FG_BENCH_CPU="${PROCESSOR_IDENTIFIER:-unknown}" ;;
  esac
  export FG_BENCH_CPU
fi

if [[ -z "${FG_BENCH_RAM_BYTES:-}" ]]; then
  case "$(uname -s)" in
    Linux)  FG_BENCH_RAM_BYTES="$(( $(awk '/MemTotal/{print $2}' /proc/meminfo) * 1024 ))" ;;
    Darwin) FG_BENCH_RAM_BYTES="$(sysctl -n hw.memsize)" ;;
    *)      FG_BENCH_RAM_BYTES="" ;;
  esac
  # Plain `[[ -n .. ]] && export ..` would abort the script under `set -e` when the value
  # is empty, which is the case on any OS other than Linux/macOS.
  if [[ -n "$FG_BENCH_RAM_BYTES" ]]; then
    export FG_BENCH_RAM_BYTES
  fi
fi

echo "==> Building in release"
cargo build --release --bin fg-bench

echo "==> Static profile of the circuits"
cargo run --release --quiet --bin fg-bench -- model

echo "==> Benchmark: $ITERS iterations (+$WARMUP warm-up)"
cargo run --release --quiet --bin fg-bench -- \
  bench --iters "$ITERS" --warmup "$WARMUP" > "$OUT"
echo "==> Results in $OUT"

if [[ -n "$BASELINE" ]]; then
  echo "==> Comparing against $BASELINE"
  # `compare` exits with an error if geo-range-v1 regresses by more than 10%.
  cargo run --release --quiet --bin fg-bench -- \
    compare --before "$BASELINE" --after "$OUT"
fi
