# Fortgate ID: KYC soberano con Zero-Knowledge Proofs

## Verificacion de identidad digital con base legal en Mexico, diseñada para escalar en LATAM

**Fortgate ID** es un SDK de identidad digital enfocado en **KYC** que combina **firmas digitales emitidas por gobierno (PKI/X.509)** con **Zero-Knowledge Proofs (ZKP)**.  
El objetivo es permitir a instituciones reguladas validar atributos de identidad con alta garantia criptografica y minimizar la exposicion de datos personales.

---

## Alcance y posicionamiento

Fortgate ID esta diseñado para **verificacion de identidad KYC y trazabilidad probatoria**.  
No esta posicionado como una plataforma integral de monitoreo transaccional AML.

El enfoque legal-operativo inicial es **Mexico**, utilizando:

- Mecanismos de identidad digital emitidos por gobierno como **e.firma**.
- Flujos de preservacion de evidencia y sellado de tiempo alineados con **NOM-151**.

La arquitectura esta preparada para extenderse a otros paises de LATAM sustituyendo anclas de confianza, politicas de validacion de firma y estandares probatorios por los equivalentes normativos de cada jurisdiccion.

---

## Propuesta de valor central

### 1) Privacidad por diseno (Blinded Identity)

La informacion personal identificable (PII) se procesa localmente cuando es posible.  
Mediante atestaciones basadas en ZKP, las entidades verificadoras validan afirmaciones especificas sin recibir documentos fuente completos.

### 2) Evidencia de grado legal para flujos KYC

- **Validacion de firma digital:** Verificacion de cadenas de confianza reconocidas por gobierno segun la politica jurisdiccional configurada.
- **Soporte de no repudio:** La evidencia firmada vincula afirmaciones de identidad con credenciales verificadas y artefactos criptograficos.
- **Trazabilidad:** Empaquetado deterministico de evidencia para auditoria, revision legal y supervision regulatoria.

### 3) Senales de integridad de dispositivo y presencia

- **Seguridad respaldada por hardware:** Integracion con Secure Enclave (iOS) y StrongBox (Android), cuando esta disponible.
- **Pruebas de geofencing:** Verificacion opcional de condicion de rango geografico sin revelar coordenadas exactas.
- **Pruebas de vida (liveness):** Senales opcionales anti-suplantacion incorporadas como insumo verificable en la evidencia.

---

## Alineacion legal en Mexico (enfoque actual)

Para despliegues en Mexico, Fortgate ID soporta flujos alineados con:

- **Aserciones de identidad basadas en e.firma** como parte del expediente de onboarding digital.
- **Sellado de tiempo y constancia de conservacion NOM-151** para fortalecer integridad, fecha cierta y auditabilidad del expediente.

> La exigibilidad legal final depende de la implementacion especifica, la politica institucional y la regulacion sectorial aplicable.  
> Fortgate ID provee el marco tecnico de evidencia; el area legal debe validar la interpretacion normativa por jurisdiccion.

---

## Modelo de expansion LATAM (arquitectura lista)

Fortgate ID utiliza un modelo de adaptadores por pais para escalar en LATAM:

- **Adaptador de ancla de confianza:** Emisores confiables y cadenas de certificados de cada pais.
- **Adaptador de politica de firma:** Reglas de validacion y perfil criptografico por jurisdiccion.
- **Adaptador de estandar probatorio:** Equivalente local de requisitos de sellado/conservacion.
- **Interfaz comun de verificacion:** API unificada para mantener una sola integracion de producto mientras se intercambian modulos regulatorios.

Esto permite operar con una sola base tecnica y generar salidas probatorias ajustadas a cada marco legal.

---

## Auditoria y verificacion independiente

Cada verificacion exitosa puede generar un paquete de evidencia con:

- Resultado de validacion de firma y metadatos de certificados.
- Identificadores de artefactos ZK y resultado de verificacion.
- Nivel de seguridad del dispositivo y resultados opcionales de liveness/geofencing.
- Referencias de sellado y conservacion (en jurisdicciones que lo requieran, como NOM-151 en Mexico).

Reguladores, auditores y contrapartes pueden verificar integridad de la prueba con material publico de verificacion sin depender de infraestructura operada por Fortgate.

---

## Especificaciones tecnicas

| Componente | Tecnologia |
| :--- | :--- |
| Core Engine | Rust (FFI/WASM) |
| Criptografia ZK | Noir (DSL) + Poseidon Hash (BN254) |
| Settlement/Anchoring | Monad / Aligned Layer |
| Red de proving | Succinct SP1 (zkVM RISC-V) |

---
**Fortgate ID: validez legal local, confianza criptografica y arquitectura KYC lista para LATAM.**
