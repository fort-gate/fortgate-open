# Manifiesto de firma — solicitud de crédito/servicios v1

## Propósito

Objeto **estructurado** que el usuario firma junto con el **PDF** de la solicitud. En producción evoluciona al bloque `document` del MED; en v1 es el manifiesto canónico pre-NOM-151.

---

## Enlace PDF + manifiesto

```
bundle_hash = SHA-256( pdf_sha256 || manifest_hash )
```

| Campo | Derivación |
|-------|------------|
| `pdf_sha256` | `SHA-256(bytes del PDF)` |
| `manifest_hash` | `SHA-256(RFC8785_JCS(CreditSignManifest))` |
| `bundle_hash` | Concatenación de ambos hashes (64 bytes) → SHA-256 |

La firma de documento (Keystore / sesión) se aplica sobre `bundle_hash` o sobre `M_doc` canónico cuyo digest incluye ambos — ver [`HW_TRUST_POC_SPEC.md`](./HW_TRUST_POC_SPEC.md) extensión `M_doc`.

---

## Campos obligatorios `CreditSignManifest`

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `manifestVersion` | string | `1.0.0` |
| `manifestSchemaId` | `urn:fortgate:credit-sign-manifest:v1` | |
| `applicationId` | UUID | ID solicitud en el banco |
| `productType` | enum | `credit` \| `service` |
| `applicantMockId` | string | Sujeto mock v1 |
| `termsVersion` | string | Versión T&C aceptados |
| `acceptedAt` | RFC3339 UTC | Timestamp aceptación |
| `pdfSha256` | hex 64 | Hash del PDF mostrado al usuario |
| `domicileRef` | object | Mismo `domicile` que en happy path (centro + radio) |
| `formFields` | object | Campos del formulario (monto, plazo, etc.) |

---

## Ejemplo mínimo

```json
{
  "manifestVersion": "1.0.0",
  "manifestSchemaId": "urn:fortgate:credit-sign-manifest:v1",
  "applicationId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "productType": "credit",
  "applicantMockId": "mock-pyme-001",
  "termsVersion": "2026-06-01",
  "acceptedAt": "2026-06-01T18:00:00Z",
  "pdfSha256": "abc123...",
  "domicileRef": {
    "centerLat": 19.4326,
    "centerLon": -99.1332,
    "radiusMeters": 200,
    "label": "oficina"
  },
  "formFields": {
    "amountMxn": 500000,
    "termMonths": 36
  }
}
```

---

## Prueba ZK (v1)

El circuito `doc-bind-v1` demuestra binding del manifiesto y PDF (proof #2; hardware en `hw-trust-v1`):

```
public:  manifest_hash, pdf_sha256 (o bundle_hash)
witness: manifest bytes (o hash preimage binding)
assert:  manifest_hash == SHA-256(JCS(manifest))
         pdf_sha256 == declared
         ECDSA_hw_sign( bundle_hash or M_doc_hash )
```

Detalle de unión con `M_hw` en implementación Fase H2.

---

## Mock KYC gate

Antes de exponer el manifiesto para firma, la app verifica:

```json
{ "kycStatus": "approved", "mockSubjectId": "..." }
```

Sin integración bancaria real en v1 — fixture local o respuesta mock de API onboarding.

---

## Referencias

- [`HAPPY_PATH_CREDIT_SIGN_SPEC.md`](./HAPPY_PATH_CREDIT_SIGN_SPEC.md)
- [`GEO_RANGE_PROOF_SPEC.md`](./GEO_RANGE_PROOF_SPEC.md)
