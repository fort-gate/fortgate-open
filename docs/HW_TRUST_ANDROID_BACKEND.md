# `android_keystore` backend

`HwTrustBackend` implementation on top of Android Keystore.
Companion to `HW_TRUST_POC_SPEC.md` §§ 3.1, 4 and 8.

## Split of responsibilities

The Android Keystore APIs are Java. Rather than reaching them over JNI from
Rust, they stay in Kotlin behind the `AndroidKeystore` trait, and Rust only
consumes the bytes they return.

| Layer | Responsibility |
|---|---|
| Kotlin | Create/open the alias, sign, return the certificate chain |
| Rust (`android_keystore.rs`) | Derive the tier from attestation, build the `HwHandshake` |

Consequence: the Rust backend does not depend on `target_os = "android"` and
is tested on the host with a fake keystore. No device-only test suite.

Wiring the trait across the FFI boundary (UniFFI callback interface, or any
other binding layer) is integration work and is **not** covered here.

## Tier ↔ backend ↔ `securityLevel`

The tier is **derived from attestation**, never from the flag requested at key
generation: a key that ended up in the software keymaster is reported as such.

| `securityLevel` | Value | Tier | Notes |
|---|---|---|---|
| `Software` | 0 | `Medium` | Verifier YELLOW |
| `TrustedEnvironment` | 1 | `High` | TEE |
| `StrongBox` | 2 | `Maximum` | Dedicated chip |
| No readable attestation | — | `Medium` | Emulator, OEM without support |

It is read from the `KeyDescription` inside extension OID
`1.3.6.1.4.1.11129.2.1.17`, taking the **lower** of `attestationSecurityLevel`
(index 1) and `keyMintSecurityLevel` (index 3): a key cannot be stronger than
the attestation vouching for it. An unknown value never promotes.

## Signatures: DER, no conversion

`Signature.getInstance(...)` emits ECDSA in DER, which is exactly what
`verify_handshake_local` consumes (`Signature::from_der`) and what the
handshake's `signatureDer` field declares. Signatures are **not** converted to
`r||s`; doing so would break verification.

## `attestationChallenge` and the alias

Spec §8 suggests `setAttestationChallenge(challenge_hash)`, but the alias is
fixed (`fortgate_hw_poc`) and `hw_nullifier = Poseidon(SHA256(spki))` is the
device's stable identity. Binding attestation to a per-handshake
`challenge_hash` would force regenerating the key on every handshake, rotating
the nullifier and defeating its purpose.

Therefore: **the key is generated once and reused**, with a domain constant as
the `attestationChallenge`. Freshness comes from the ECDSA signature over
`challenge_hash`, which the verifier already checks. If the alias exists with
different parameters it is reused: the tier comes from attestation, so weaker
parameters are reported honestly instead of being hidden.

## Known limitations

- **Emulators and OEMs without hardware attestation:** empty chain, tier
  `Medium`.
- **StrongBox:** requested first; on `StrongBoxUnavailableException` it falls
  back to TEE. The fallback shows up in the tier on its own, because the tier
  comes from attestation.
- **`DIGEST_NONE` on StrongBox:** `sign_challenge_hash` receives an already
  computed hash, so the key is created with `DIGEST_NONE` and signed with
  `NONEwithECDSA`. Some StrongBox implementations reject `DIGEST_NONE`; when
  that happens generation falls back to TEE and the tier honestly drops to
  `High`. **Still to be validated on a physical device** — it is the only part
  of the backend the host tests do not cover.
- **Validation against Google roots:** out of scope. That is verifier policy
  (`HW_TRUST_POC_SPEC.md` §7), not backend behaviour.
- **Revocation status:** not checked.
- **Other platforms:** the backend compiles everywhere, but without an
  `AndroidKeystore` implementation there is no key. `software_poc` remains the
  desktop default, with its DEV ONLY banners untouched.

## Reference Kotlin implementation

```kotlin
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

private const val ALIAS = "fortgate_hw_poc"
private val ATTESTATION_CHALLENGE = "fortgate_hw_trust_poc".toByteArray()

class FortgateKeystore {
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    init {
        if (!ks.containsAlias(ALIAS)) generate(strongBox = true)
    }

    private fun generate(strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            // DIGEST_NONE is required: the trait hands over a computed hash.
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setAttestationChallenge(ATTESTATION_CHALLENGE)
            .setUserAuthenticationRequired(false)   // no biometrics in v1
            .setIsStrongBoxBacked(strongBox)
            .build()
        try {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply { initialize(spec) }.generateKeyPair()
        } catch (e: StrongBoxUnavailableException) {
            if (strongBox) generate(strongBox = false) else throw e
        }
    }

    // Empty = failure. The tier drops to Medium and Rust returns a typed error.
    fun spkiDer(): ByteArray =
        runCatching { ks.getCertificate(ALIAS).publicKey.encoded }
            .onFailure { Log.e("fortgate", "spki", it) }.getOrDefault(ByteArray(0))

    fun sign(digest: ByteArray): ByteArray = runCatching {
        // NONEwithECDSA: the digest is already computed; the output is DER.
        Signature.getInstance("NONEwithECDSA").run {
            initSign(ks.getKey(ALIAS, null) as PrivateKey)
            update(digest)
            sign()
        }
    }.onFailure { Log.e("fortgate", "sign", it) }.getOrDefault(ByteArray(0))

    fun certChain(): List<ByteArray> =
        runCatching { ks.getCertificateChain(ALIAS).map { it.encoded } }
            .onFailure { Log.e("fortgate", "chain", it) }.getOrDefault(emptyList())
}
```

Once the FFI layer exposes `AndroidKeystore`, this class implements it and is
passed to `AndroidKeystoreBackend::new`.
