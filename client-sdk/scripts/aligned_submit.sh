#!/bin/bash
set -e

# W2-P1.1: Validación de Red y Existencia de Archivos
PROOF_FILE="./sp1_output/proof.bin"
VKEY_FILE="./sp1_output/vkey.json"
NETWORK="holesky" # Red corregida

echo "🛡️ Verificando prerequisitos para Aligned Layer..."

if [ ! -f "$PROOF_FILE" ]; then
    echo "❌ Error: No se encuentra $PROOF_FILE. Ejecuta el script de SP1 primero."
    exit 1
fi

if [ ! -f "$VKEY_FILE" ]; then
    echo "❌ Error: No se encuentra $VKEY_FILE. Ejecuta el host SP1 (release) para generar vkey.json."
    exit 1
fi

echo "🚀 Enviando prueba a Aligned ($NETWORK)..."

# Ejecución del CLI de Aligned
aligned submit-proof \
    --proof "$PROOF_FILE" \
    --vkey "$VKEY_FILE" \
    --vm "sp1" \
    --network "$NETWORK"

echo "✅ Proceso de verificación iniciado."
