# Demo rápida — Hardware Trust PoC

## Decisión de formato

Usamos **dos modos complementarios**, no uno u otro:

| Modo | Audiencia | Duración | Hardware |
|------|-----------|----------|----------|
| **A — Terminal solo** | Dev, inversor técnico, CI | ~30–60 s | `software_poc` simulado |
| **B — Grabación dual** | Video marketing / piloto banco | 2–3 min | Teléfono real + laptop |

**Modo A** es el default: un comando reproduce todo.  
**Modo B** reutiliza los mismos binarios; solo cambia quién firma (`android_keystore` vs `software_poc`).

No hace falta un video pregrabado en el repo; incluimos **modo record-friendly** con logs grandes y preview del paquete de evidencia (precursor del MED).

---

## Modo A — Demo terminal (30 segundos)

### Comando único

```bash
./demo/hw-trust-demo.sh
```

Equivalente explícito:

```bash
fortgate-hw-poc demo \
  --backend software_poc \
  --verbose
```

### Secuencia interna

```
1. keygen (si no existe ~/.fortgate/poc_hw)
2. challenge → /tmp/fg-hw-demo/challenge.json
3. sign      → handshake.json
4. prove     → hw_output/proof_package.json
5. verify    → exit 0 GREEN
6. print summary (ver abajo)
```

### Salida esperada (summary)

```
╔══════════════════════════════════════════════════════════════╗
║  Fortgate HW Trust PoC — DEMO                                ║
╠══════════════════════════════════════════════════════════════╣
║  Backend:        software_poc (simulated Secure Enclave)     ║
║  Tier:           Medium                                      ║
║  Proof engine:   midnight (on-device / ~4s prove, ~3ms verify) ║
║  Challenge ID:   550e8400-e29b-41d4-a716-446655440000         ║
║  Pubkey commit:  7f3c9e2a...e0f4a8                           ║
║  HW nullifier:   9a2b1c4d...f8e7d6                           ║
║  Result:         ✅ GREEN (ZK valid)                         ║
╚══════════════════════════════════════════════════════════════╝

⚠️  software_poc no es Secure Enclave real. Ver Modo B con teléfono.
```

### Variables de entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `FORTGATE_PROOF_PROVIDER` | *(obsoleto — solo midnight)* | — |
| `FORTGATE_HW_BACKEND` | `software_poc` | Solo `software_poc` en Modo A |
| `FG_DEMO_TMP` | `/tmp/fg-hw-demo` | Directorio temporal |

---

## Modo B — Grabación teléfono + terminal

Guión para video (pantalla partida o dos tomas):

### Setup (antes de grabar)

1. Laptop: `fortgate-hw-poc challenge --out challenge.json --verbose`
2. `adb push challenge.json /sdcard/Download/fortgate_challenge.json`
3. Instalar APK dev: `adb install -r android/hw-poc-app/app-debug.apk`

### Toma 1 — Teléfono (30–45 s)

1. Abrir **Fortgate HW PoC**.
2. Tap **Import challenge** o generar in-app.
3. Tap **Sign with Keystore** — sin biometría en v1.
4. Tap **Generate ZK proof** — Midnight prove on-device (spinner).
5. Tap **Export package** → `proof_package.json` + handshake.

### Toma 2 — Terminal (10–15 s)

```bash
adb pull /sdcard/Download/proof_package.json /tmp/

fortgate-hw-poc verify \
  --package /tmp/proof_package.json \
  --record-friendly
```

La terminal **solo verifica** (~3 ms); el prove ya ocurrió en el teléfono.

### Flag `--record-friendly`

Activa:

- Logs con cajas Unicode y timestamps visibles.
- Impresión de **Evidence Preview** (no MED legal completo, pero misma forma):

```json
{
  "type": "FortgateHwEvidencePreview",
  "evidenceSchemaVersion": "hw-preview-1.0.0",
  "document": null,
  "hardware": {
    "backend": "android_keystore",
    "tier": "High",
    "pubkeyCommitment": "...",
    "challengeHash": "...",
    "hwNullifier": "..."
  },
  "zkProof": {
    "proofProviderId": "midnight",
    "circuitVersion": "hw-trust-v1",
    "proofHash": "sha256:..."
  },
  "policyId": "fortgate-hw-poc-demo"
}
```

Esto permite narrar en video: *“esto es lo que después se envuelve en el MED y sella NOM-151”* sin implementar MED en este PoC.

### Storyboard sugerido (voz en off)

1. *“El teléfono firma y genera la prueba ZK sin enviar la clave privada.”*
2. *“La prueba pesa ~4 KB y tarda segundos, no minutos.”*
3. *“En la laptop, cualquier auditor verifica en milisegundos.”*

---

## Benchmark (solo Midnight)

```bash
./demo/hw-trust-benchmark.sh
```

```
| Prove (ms) | Verify (ms) | Proof (KB) | k (circuit) |
|------------|-------------|------------|-------------|
|       4200 |           3 |        3.6 |          14 |
```

Útil para validar que el circuito sigue en rango Small–Medium antes de integrar en APK.

---

## Archivos del directorio `demo/` (a crear en Fase 3)

```
demo/
  hw-trust-demo.sh           # Modo A
  hw-trust-benchmark.sh      # Comparación providers
  README.md                  # Este guión resumido
  fixtures/
    challenge.sample.json
    handshake.software.json  # golden para CI
```

---

## CI smoke (sin teléfono)

```yaml
# job futuro en feat/hw-trust-poc
- run: ./demo/hw-trust-demo.sh
  env: {}  # solo midnight
```

Con fallback SP1 en nightly si toolchain Succinct disponible.

---

## Qué NO mostrar en demo sin disclaimer

| Elemento | Disclaimer |
|----------|------------|
| `software_poc` | “Simulación desarrollo — no es enclave” |
| `midnight` no auditado | Disclaimer en README; solo PoC |
| Emulador Android | “Attestation software-backed — YELLOW” |

---

## Referencias

- [`HW_TRUST_POC_SPEC.md`](./HW_TRUST_POC_SPEC.md)
- [`PROOF_PROVIDER_SPEC.md`](./PROOF_PROVIDER_SPEC.md)
- [`M_HW_SPEC_V1.md`](./M_HW_SPEC_V1.md)
