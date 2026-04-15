#!/bin/bash
echo "🛡️ Submitting Proof to Aligned Layer..."
aligned submit-proof \
    --proof ./sp1_output/proof.bin \
    --vkey ./sp1_output/vkey.json \
    --vm "sp1" \
    --network "holeheader"
echo "✅ Proof submitted."
