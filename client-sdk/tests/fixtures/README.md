# Fixtures de tests (`open/client-sdk/tests/fixtures`)

- **`mock.der`**: certificado sintético OpenSSL (RSA-2048 + identificador de RFC) para smoke tests.
- **`cert_no_rfc.der`**: RSA-2048, subject solo `CN=...` (sin RFC / uniqueIdentifier) — tests negativos del parser.
- **`cert_rsa1024.der`**: RSA **1024** bits con `uniqueIdentifier` — esperado `InvalidModulusBits(1024)`.
- **`poseidon_vectors.json`**: vectores Poseidon + encoding RFC/salt alineados con el core Rust (ver `tests/poseidon_vectors.rs`).

## Certificados SAT públicos (opcional)

Para pruebas de integración adicionales con material del ecosistema e.firma (solo certificados **públicos** `.cer`, sin llaves privadas), se puede tomar referencia de proyectos como [nodecfdi/credentials tests/_files](https://github.com/nodecfdi/credentials/tree/main/tests/_files), respetando atribución y caducidad. No están versionados aquí por defecto.
