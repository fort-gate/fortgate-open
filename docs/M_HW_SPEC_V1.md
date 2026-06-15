# M_hw v1 — Mensaje canónico de hardware trust

## Propósito

`M_hw` es el mensaje que el **backend de hardware** firma con ECDSA P-256. Su digest es la entrada criptográfica común a todos los proveedores de prueba (SP1, Midnight, etc.).

No confundir con:

- **MED** — manifiesto de evidencia legal (NOM-151).
- **M_bind** — delegación e.firma → K_session.

---

## Versionado

| Campo | Valor PoC |
|-------|-----------|
| `hwBindVersion` | `1.0.0` |
| `hwSchemaId` | `urn:fortgate:hw-bind:v1` |

---

## Campos obligatorios (MUST)

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `hwBindVersion` | string semver | Versión del esquema. |
| `hwSchemaId` | string URN | Identificador estable del esquema. |
| `purpose` | string | PoC: `fortgate_hw_trust_poc`. |
| `challengeId` | string UUID v4 | Identificador único del desafío. |
| `nonce` | string hex 64 chars | 32 bytes aleatorios (anti-replay). |
| `issuedAt` | string RFC3339 UTC | Emisión del desafío. |
| `expiresAt` | string RFC3339 UTC | Expiración (PoC: `issuedAt + 5 min`). |
| `tierClaimed` | enum string | `Medium` \| `High` \| `Maximum`. |
| `backend` | enum string | `software_poc` \| `android_keystore` \| `ios_secure_enclave`. |
| `pubkeyCommitment` | string hex 64 chars | `SHA-256(SPKI DER de la pubkey P-256)`. |

## Campos opcionales (MAY)

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `verifierId` | string | Quién emitió el desafío (demo, banco piloto). |
| `sessionId` | string | Correlación con flujo KYC futuro. |
| `identityNullifier` | string hex 64 chars | Reservado: nullifier e.firma para binding posterior. |

---

## Ejemplo (antes de canonicalizar)

```json
{
  "hwBindVersion": "1.0.0",
  "hwSchemaId": "urn:fortgate:hw-bind:v1",
  "purpose": "fortgate_hw_trust_poc",
  "challengeId": "550e8400-e29b-41d4-a716-446655440000",
  "nonce": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef",
  "issuedAt": "2026-06-01T18:00:00Z",
  "expiresAt": "2026-06-01T18:05:00Z",
  "tierClaimed": "High",
  "backend": "android_keystore",
  "pubkeyCommitment": "7f3c9e2a1b4d8f6e0c5a9b3d7e1f4a8c2b6d0e4f8a1c5b9d3e7f1a4c8b2d6e0f4a8"
}
```

---

## Derivación del digest

1. Serializar el objeto JSON con claves en orden lexicográfico estable **o** usar el mismo pipeline que MED: JSON compacto + **RFC 8785 JCS** (`serde_jcs` / `json-canonicalization`).
2. `challenge_hash = SHA-256(JCS(M_hw))`.
3. La firma hardware es **ECDSA P-256 con SHA-256** sobre `challenge_hash` (prehash, no sobre el JSON en claro).

```
signature = ECDSA_P256_SHA256_SIGN(private_key, challenge_hash)
```

---

## Reglas de validación (pre-prove)

| Regla | Acción si falla |
|-------|-----------------|
| `expiresAt > now` | Rechazar desafío expirado |
| `pubkeyCommitment` coincide con SPKI real | Rechazar handshake inconsistente |
| `tierClaimed` coherente con `backend` | Ver tabla en `HW_TRUST_POC_SPEC.md` |
| `backend=software_poc` | Solo aceptar si política permite `minTier=Medium` |

---

## Relación con artefactos PoC

| Artefacto | Contiene |
|-----------|----------|
| `challenge.json` | `M_hw` completo |
| `handshake.json` | `M_hw` + firma + pubkey SPKI + metadatos attestation opcional |
| `public_inputs.json` | `challenge_hash`, `pubkey_commitment`, `tier`, `hw_nullifier`, `proof_provider_id` |

---

## Referencias

- RFC 8785 — JSON Canonicalization Scheme (JCS)
- RFC 5480 — SPKI para ECDSA P-256
- `open/docs/HW_TRUST_POC_SPEC.md`
- `open/docs/PROOF_PROVIDER_SPEC.md`
