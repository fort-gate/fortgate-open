#!/usr/bin/env bash
# Benchmark reproducible de los tres circuitos ZK.
#
#   ./scripts/run_bench.sh before.json          # mide y guarda
#   ./scripts/run_bench.sh after.json before.json  # mide y compara contra una corrida previa
#
# Fija las flags de build y las variables de entorno que `fg-bench` graba en el JSON,
# para que dos corridas sean comparables. Requiere el SRS (scripts/fetch_srs.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${1:-bench.json}"
BASELINE="${2:-}"
ITERS="${FG_BENCH_ITERS:-5}"
WARMUP="${FG_BENCH_WARMUP:-1}"

# El perfil de release del Cargo.toml es la referencia; no se inyectan RUSTFLAGS extra
# porque cambiarlos invalidaría la comparación con los números del ADR-0001.
export FG_BENCH_PROFILE="release (opt-level=3, sin LTO)"

# Metadatos de máquina: `fg-bench` los graba en el JSON junto a los tiempos.
if [[ -z "${FG_BENCH_CPU:-}" ]]; then
  case "$(uname -s)" in
    Linux)  FG_BENCH_CPU="$(awk -F': ' '/model name/{print $2; exit}' /proc/cpuinfo || echo desconocido)" ;;
    Darwin) FG_BENCH_CPU="$(sysctl -n machdep.cpu.brand_string || echo desconocido)" ;;
    *)      FG_BENCH_CPU="${PROCESSOR_IDENTIFIER:-desconocido}" ;;
  esac
  export FG_BENCH_CPU
fi

if [[ -z "${FG_BENCH_RAM_BYTES:-}" ]]; then
  case "$(uname -s)" in
    Linux)  FG_BENCH_RAM_BYTES="$(( $(awk '/MemTotal/{print $2}' /proc/meminfo) * 1024 ))" ;;
    Darwin) FG_BENCH_RAM_BYTES="$(sysctl -n hw.memsize)" ;;
    *)      FG_BENCH_RAM_BYTES="" ;;
  esac
  [[ -n "$FG_BENCH_RAM_BYTES" ]] && export FG_BENCH_RAM_BYTES
fi

echo "==> Compilando en release"
cargo build --release --bin fg-bench

echo "==> Perfil estático de los circuitos"
cargo run --release --quiet --bin fg-bench -- model

echo "==> Benchmark: $ITERS iteraciones (+$WARMUP de calentamiento)"
cargo run --release --quiet --bin fg-bench -- \
  bench --iters "$ITERS" --warmup "$WARMUP" > "$OUT"
echo "==> Resultados en $OUT"

if [[ -n "$BASELINE" ]]; then
  echo "==> Comparando contra $BASELINE"
  # `compare` sale con error si geo-range-v1 regresiona más de un 10%.
  cargo run --release --quiet --bin fg-bench -- \
    compare --before "$BASELINE" --after "$OUT"
fi
