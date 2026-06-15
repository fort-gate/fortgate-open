# Estrategia de circuitos ZK — tres pruebas Midnight

## Decisión (cerrada)

| | |
|---|---|
| **Estado** | Aceptado |
| **Enfoque** | **Tres proofs separadas** (Opción B extendida) |
| **Motor** | Midnight (`midnight-zk-stdlib`) on-device |
| **Meta rendimiento PoC** | **&lt;5 s** prove total + **&lt;5 s** verify total (aspiracional; no bloquea entregas tempranas) |

No usamos un circuito compuesto único en v1.

---

## Las tres pruebas

| # | `circuitId` | Qué demuestra | Fase |
|---|-------------|---------------|------|
| **1** | `hw-trust-v1` | Firma ECDSA P-256 del enclave sobre `M_hw`; `pubkey_commitment`; `hw_nullifier` | H1 |
| **2** | `doc-bind-v1` | Binding `pdf_sha256` + `manifest_hash` + firma del bundle documental | H2 |
| **3** | `geo-range-v1` | Distancia Haversine ≤200 m al pin declarado; `inside_range = true` | H3 |

### Orden de ejecución on-device

```
sign M_hw ──► prove #1 hw-trust-v1
sign bundle ──► prove #2 doc-bind-v1
read GPS ──► prove #3 geo-range-v1
         ──► armar CreditSignEvidencePackage
```

Las tres pueden encadenarse en un solo botón “Firmar solicitud” con spinner; internamente son tres `prove` secuenciales.

### Variante 2 proofs (solo si optimización futura)

Si medimos que `hw-trust` + `doc-bind` juntos siguen &lt;2 s, se pueden fusionar en `hw-doc-v1`. **PoC implementa 3 proofs** para depurar y para el botón “proof inválida” solo en geo.

---

## Objetivo de tiempo (&lt;5 s)

| Métrica | Objetivo PoC | Prioridad |
|---------|--------------|-----------|
| Prove #1 + #2 + #3 (total) | **&lt;5 s** | Aspiracional — optimizar cuando el circuito exista |
| Verify #1 + #2 + #3 (API o CLI) | **&lt;5 s** | Aspiracional |
| Prove individual | ~1–2 s c/u (circuito Small) | Guía de diseño |

**PoC:** si superamos 5 s, documentar tiempos reales y seguir; no bloquea demo. La arquitectura de 3 proofs se mantiene.

### Tácticas para acercarse a 5 s

- Mantener cada circuito en rango **Small** (`optimal_k` ≤14 si es posible).
- SRS/`pk` precomputados en build (no setup en runtime).
- Prove secuencial en hilo background; UI async.
- Geo: bounding box antes de Haversine si el circuito crece.

---

## Paquete enviado al banco

```json
"proofs": {
  "hwTrust": {
    "circuitId": "hw-trust-v1",
    "proofProviderId": "midnight",
    "proofBytes": "...",
    "publicInputs": { }
  },
  "docBind": {
    "circuitId": "doc-bind-v1",
    "proofProviderId": "midnight",
    "proofBytes": "...",
    "publicInputs": { }
  },
  "geoRange": {
    "circuitId": "geo-range-v1",
    "proofProviderId": "midnight",
    "proofBytes": "...",
    "publicInputs": { "insideRange": true, "radiusMeters": 200 }
  }
}
```

---

## Verificación API (tres checks)

```json
"checks": {
  "zkHwTrust": "pass",
  "zkDocBind": "pass",
  "zkGeoRange": "pass"
}
```

Cualquier fallo → `RED`. Demo inválida: solo `zkGeoRange: fail` si coords fuera de radio.

---

## Qué descartamos

| Enfoque | Motivo |
|---------|--------|
| Circuito único `credit-sign-v1` | Más difícil de depurar; peor para demo geo inválida |
| SP1 en hw-trust | Fuera de scope (ver `PROOF_PROVIDER_SPEC.md`) |

---

## Referencias

- [`PROOF_PROVIDER_SPEC.md`](./PROOF_PROVIDER_SPEC.md) — statements por circuito
- [`HAPPY_PATH_CREDIT_SIGN_SPEC.md`](./HAPPY_PATH_CREDIT_SIGN_SPEC.md)
- [`GEO_RANGE_PROOF_SPEC.md`](./GEO_RANGE_PROOF_SPEC.md)
