# API Enterprise — verificación de firma de crédito v1

## Propósito

Contrato HTTP que usa la **institución financiera** en el happy path para validar un `CreditSignEvidencePackage` y obtener `GREEN` / `RED` sin operar infraestructura ZK propia.

**Nota OSS:** la prueba ZK se genera **on-device sin llamar a esta API**. La API solo **verifica** y registra el expediente. Auditores pueden re-verificar offline con vkey pública.

---

## Endpoint

```
POST /v1/credit-sign/verify
Content-Type: application/json
Authorization: Bearer <institution_api_key>
```

---

## Request body

Cuerpo = [`CreditSignEvidencePackage`](./HAPPY_PATH_CREDIT_SIGN_SPEC.md) completo.

Límites PoC:

| Campo | Max |
|-------|-----|
| `proofBytes` (base64) | 64 KB |
| `deviceEvidence` | 4 KB |
| PDF | No se sube — solo `pdfSha256` |

---

## Response `200 OK`

```json
{
  "status": "GREEN",
  "attestationId": "att_cs_01HZXY...",
  "verifiedAt": "2026-06-01T18:01:05Z",
  "checks": {
    "zkHwTrust": "pass",
    "zkDocBind": "pass",
    "zkGeoRange": "pass",
    "minTier": "pass",
    "manifestBinding": "pass",
    "kycMockGate": "pass",
    "sealedGeoPresent": "pass"
  },
  "publicSummary": {
    "insideDeclaredDomicile": true,
    "hardwareTier": "High",
    "pdfSha256": "...",
    "manifestSha256": "...",
    "hwNullifier": "...",
    "radiusMeters": 200
  }
}
```

`publicSummary` **nunca** incluye `actualLat` / `actualLon` en claro.

---

## `sealedGeoArchive` (obligatorio en request)

```json
"sealedGeoArchive": {
  "ciphertextB64": "...",
  "keyId": "bank-archive-key-v1",
  "algorithm": "XChaCha20-Poly1305",
  "plaintextFields": ["actualLat", "actualLon", "capturedAt"]
}
```

| Campo | Regla |
|-------|-------|
| Cifrado | Clave pública de archivo del banco (`keyId` en catálogo institución) |
| Almacenamiento API | Persistir **solo ciphertext** + hash del paquete |
| Descifrado | Solo backend archivo / compliance; no operadores de mesa de control |

La API verifica ZK con coords del witness **sin persistirlas en claro** — el witness no viaja en el JSON; la app envía ciphertext para archivo paralelo al mismo evento de firma.

**PoC simplificación:** si el witness no sale del teléfono, la app cifra las mismas coords usadas en prove antes de POST. El servidor valida consistencia opcional: `hash(plaintext)` vs commitment en `publicInputs` si se define `geo_commitment`.

---

## Status de respuesta

| Valor | HTTP | Significado |
|-------|------|-------------|
| `GREEN` | 200 | Todas las checks obligatorias pass |
| `YELLOW` | 200 | ZK OK; attestation/device débil (ej. emulador) |
| `RED` | 422 | Proof inválida, fuera de rango, tier insuficiente |

### Ejemplo `RED`

```json
{
  "status": "RED",
  "errorCode": "GEO_OUT_OF_RANGE",
  "message": "ZK geo proof failed",
  "checks": { "zkGeoRange": "fail" }
}
```

---

## Lógica del servidor (v1 mock)

1. Parsear `CreditSignEvidencePackage`.
2. Verificar **tres** proofs Midnight (`hw-trust-v1`, `doc-bind-v1`, `geo-range-v1`) con `vk` del catálogo.
3. Recomputar `manifest_hash` y comparar con `publicInputs`.
4. Validar `deviceEvidence.tier >= policy.minTier`.
5. Validar `sealedGeoArchive` presente y `keyId` permitido; persistir **ciphertext** en archivo.
6. Emitir `attestationId` y guardar hash del paquete (mock DB).

---

## Política institución

```json
{
  "policyId": "credit-sign-mx-v1",
  "minTier": "High",
  "locationToleranceMeters": 200,
  "allowSoftwarePoc": false,
  "requireKycMockApproved": true
}
```

Header opcional: `X-Fortgate-Policy-Id`.

---

## Implementación PoC

| Componente | Ubicación sugerida |
|----------|-------------------|
| Handler mock | `enterprise/credit-sign-api/` (nuevo) |
| Verificador ZK | Reutiliza lógica `fortgate-hw-poc verify` en Rust (FFI o binario sidecar) |
| Catálogo vkey | `open/client-sdk/hw-midnight/vkeys/` |

Demo local:

```bash
cargo run -p fortgate-credit-sign-api -- --port 8080
curl -X POST localhost:8080/v1/credit-sign/verify -d @evidence_package.json
```

---

## Datos que la API NO almacena en claro (v1)

- Coordenadas GPS sin cifrar
- Contenido del PDF
- Claves privadas del usuario

## Datos que la API SÍ almacena cifrados

- `sealedGeoArchive.ciphertextB64` (archivo expediente)

---

## Referencias

- [`enterprise/docs/INTEGRATION_MODEL.md`](../../enterprise/docs/INTEGRATION_MODEL.md)
- [`HAPPY_PATH_CREDIT_SIGN_SPEC.md`](./HAPPY_PATH_CREDIT_SIGN_SPEC.md)
