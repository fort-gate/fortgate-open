#!/usr/bin/env bash
# Descarga SRS Filecoin (2^19) para Midnight Plonk — solo desarrollo PoC.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ASSETS="${FORTGATE_SRS_DIR:-$ROOT/assets}"
URL="https://midnight-s3-fileshare-dev-eu-west-1.s3.eu-west-1.amazonaws.com/bls_filecoin_2p19"
OUT="$ASSETS/bls_filecoin_2p19"

mkdir -p "$ASSETS"

if [[ -f "$OUT" ]]; then
  echo "SRS ya existe: $OUT"
  exit 0
fi

echo "Descargando SRS (~800MB) a $OUT ..."
curl -L -o "$OUT" "$URL"
echo "Listo. Exporta FORTGATE_SRS_DIR=$ASSETS si usas otra ruta."
