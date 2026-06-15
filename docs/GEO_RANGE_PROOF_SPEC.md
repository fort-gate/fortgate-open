# Prueba ZK de georango — `inside_range_only` v1

## Propósito

Demostrar que en el momento de la firma el usuario estaba **dentro de un radio** del domicilio que él mismo declaró (pin en mapa), **sin revelar coordenadas exactas** en la operación diaria del banco.

---

## Radio máximo: 200 metros

| Regla | Valor |
|-------|-------|
| `radiusMeters` default | **200** |
| `radiusMeters` máximo permitido | **200** (validación app + API) |
| Política institución | `locationToleranceMeters: 200` |

El usuario coloca el pin en mapa (casa/oficina). Solo se acepta firma si el GPS real está a ≤200 m de ese pin.

---

## Modelo de privacidad

| Parte | Operación bancaria (UI/API) | Archivo banco |
|-------|----------------------------|---------------|
| Centro domicilio + radio | Visible (usuario declaró) | Sí |
| `insideRange` (bool) | Visible vía ZK | Sí |
| Coordenadas exactas al firmar | **No en claro** | **`sealedGeoArchive` cifrado** |
| Juicio / auditoría interna | — | Descifrado con clave del banco |

Cifrado v1: app cifra `{ actualLat, actualLon, capturedAt }` con clave pública de archivo del banco (`keyId`). El ZK witness usa las mismas coords en claro solo on-device.

---

## Inputs

### Públicos (instance)

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `center_lat_e6` | i32 | Latitud × 10⁶ |
| `center_lon_e6` | i32 | Longitud × 10⁶ |
| `radius_meters` | u32 | **≤ 200** |
| `inside_range` | bool | `true` en happy path válido |

### Witness (secreto en prover)

| Campo | Tipo |
|-------|------|
| `actual_lat_e6` | i32 |
| `actual_lon_e6` | i32 |
| `timestamp_unix` | u64 |

---

## Relación NP

```
distance = haversine_meters(center, actual)
assert distance <= radius_meters
assert inside_range == (distance <= radius_meters)
```

Si `distance > 200`, **no existe** proof válida con `inside_range = true` (soundness).

---

## Botones demo en app (PoC)

| Botón | Comportamiento | Resultado esperado API |
|-------|----------------|------------------------|
| **Generar proof válida** | Lee GPS real (`FusedLocationProvider`); coords dentro de 200 m del pin | `GREEN` |
| **Generar proof inválida** | Inyecta coords **simuladas** fuera del radio (ej. +500 m al este) o proof corrupta | `RED` |

### Modos del botón “inválida” (implementar al menos A + B)

| Modo | Qué hace | UX demo |
|------|----------|---------|
| **A — Fuera de rango** | Witness con coords lejanas; prove **falla** en dispositivo con mensaje claro | Muestra que no se puede mentir en ZK |
| **B — Envío malicioso** | Paquete con `proofBytes` alterados o `insideRange: false` | API responde `RED` / `GEO_OUT_OF_RANGE` |
| **C — Simulador** (opcional) | `MockLocation` fuera de radio en emulador | Mismo que A |

**Happy path producto:** solo botón válido visible. Botones inválidos en **build dev** o menú “Demo QA”.

---

## Captura en app (producción)

1. Pin en mapa → centro domicilio.
2. Radio fijo **200 m** (no slider mayor en v1).
3. Una lectura GPS al firmar (o promedio 3 muestras / 5 s).
4. Cifrar coords → `sealedGeoArchive`.
5. Prove Midnight con witness GPS real.

---

## Mock desktop / CLI

```bash
# Válida
fortgate-hw-poc sign --geo-mode=valid \
  --lat 19.4326 --lon -99.1332 \
  --center-lat 19.4320 --center-lon -99.1330 --radius 200

# Inválida (prove debe fallar o API RED)
fortgate-hw-poc sign --geo-mode=invalid \
  --lat 19.4400 --lon -99.1332 \
  --center-lat 19.4320 --center-lon -99.1330 --radius 200
```

---

## Referencias

- [`HAPPY_PATH_CREDIT_SIGN_SPEC.md`](./HAPPY_PATH_CREDIT_SIGN_SPEC.md)
- [`BANK_VERIFY_API_SPEC.md`](./BANK_VERIFY_API_SPEC.md)
