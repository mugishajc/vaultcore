# java-security-toolkit

[![CI](https://github.com/mugishajc/java-security-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/mugishajc/java-security-toolkit/actions/workflows/ci.yml)

A small Java 21 library of secure-coding primitives built only on the standard
Java Cryptography Architecture (JCA). No third-party dependencies at runtime.

The goal is twofold: give application code a hard-to-misuse API for the common
cases, and document *why* each choice was made, so the same mistakes are easy
to spot in code review elsewhere.

| Class | What it does |
|---|---|
| `AesGcm` | AES-256-GCM authenticated encryption with a fresh random IV per message |
| `PasswordHasher` | PBKDF2-HMAC-SHA256 password hashing, per-hash salt, constant-time verify, rehash detection |
| `HmacSigner` | HMAC-SHA256 tags and compact signed tokens |
| `DigitalSignatures` | RSA-PSS (3072) and ECDSA P-256 sign/verify, public-key encoding |
| `SecureTokens` | URL-safe / hex tokens and numeric codes from `SecureRandom` |
| `ConstantTime` | Timing-safe byte and string comparison |
| `InputValidation` | Allow-list validators, path traversal guard, log-injection sanitiser |

## Requirements

- JDK 21 or newer
- Maven 3.9+

## Build and test

```bash
mvn verify
```

The suite has around 95 tests: round trips for every primitive, bit-flip
tamper checks on every byte of ciphertexts, tags and signatures, malformed input
handling, and a `CommonMistakesTest` class that reproduces the attacks the
library is designed to prevent.

## Usage

### Encrypting data

```java
AesGcm aes = AesGcm.withKey(keyBytesFromYourKms); // 32 bytes

byte[] sealed = aes.encrypt(plaintext, "invoice:981".getBytes(UTF_8));
byte[] opened = aes.decrypt(sealed, "invoice:981".getBytes(UTF_8));
```

The output is `IV || ciphertext || tag`. The associated data (`invoice:981`
above) is not stored, but it is authenticated: a ciphertext copied onto another
record will fail to decrypt. Any modification throws `IntegrityException`.

### Storing passwords

```java
PasswordHasher hasher = new PasswordHasher();          // 600,000 iterations

String stored = hasher.hash(passwordChars);
// pbkdf2-sha256$600000$<salt>$<hash>

if (hasher.verify(attemptChars, stored)) {
    if (hasher.needsRehash(stored)) {
        stored = hasher.hash(attemptChars);            // upgrade on successful login
    }
}
```

### Signing webhooks or cookies (shared secret)

```java
HmacSigner signer = new HmacSigner(secretBytes);       // at least 32 bytes

String token = signer.signToToken("user=42;exp=1767225600");
String payload = signer.verifyToken(token);            // throws IntegrityException if edited
```

### Signing with a key pair

```java
KeyPair keys = DigitalSignatures.generateKeyPair(SignatureScheme.ECDSA_P256_SHA256);

byte[] sig = DigitalSignatures.sign(SignatureScheme.ECDSA_P256_SHA256, keys.getPrivate(), data);
boolean ok = DigitalSignatures.verify(SignatureScheme.ECDSA_P256_SHA256, keys.getPublic(), data, sig);
```

### Tokens and validation

```java
String resetToken = SecureTokens.urlSafeToken();        // 256 bits
String otp = SecureTokens.numericCode(6);

String email = InputValidation.requireEmail("email", request.email());
Path file = InputValidation.resolveWithin(uploadDir, request.path());
log.info("login failed for {}", InputValidation.sanitizeForLog(username, 64));
```

## The mistakes this avoids

**ECB mode.** `Cipher.getInstance("AES")` silently means `AES/ECB/PKCS5Padding`
on most providers. ECB encrypts each 16-byte block independently, so equal
plaintext blocks give equal ciphertext blocks and patterns in the data survive
encryption. It also has no integrity protection. `AesGcm` always asks for
`AES/GCM/NoPadding` explicitly. See `CommonMistakesTest.ecbLeaksRepeatedPlaintextBlocks`.

**Static or reused IVs.** GCM is CTR mode plus a MAC. Encrypting two messages
with the same key and IV produces the same keystream, so XOR-ing the two
ciphertexts cancels it out and leaves `p1 XOR p2`. It also lets an attacker
recover the authentication key and forge messages. `AesGcm` generates the IV
itself for every call and never accepts one from the caller. See
`CommonMistakesTest.reusingAGcmIvLeaksTheXorOfPlaintexts`.

**Encryption without authentication.** CBC or CTR alone can be modified in
transit, and CBC with distinguishable padding errors leads to padding-oracle
attacks. GCM rejects any change before returning a single byte of plaintext.

**MD5, SHA-1 or a single SHA-256 for passwords.** General-purpose hashes are
designed to be fast; a GPU can test billions of guesses per second against
them. PBKDF2 with a high iteration count and a unique salt per user makes each
guess expensive and stops precomputed tables. (If you can add a dependency,
Argon2id or bcrypt are also good choices. PBKDF2 is used here because it ships
with the JDK.)

**Comparing secrets with `==` or `equals`.** `==` on strings compares
references, so it is simply wrong. `String.equals` and `Arrays.equals` are
correct but return at the first differing byte, which leaks timing. Every
MAC, tag and hash comparison in this library goes through
`MessageDigest.isEqual`.

**`hash(secret + message)` as a MAC.** SHA-256 and friends are vulnerable to
length extension: given `H(secret || m)` you can compute
`H(secret || m || padding || extra)` without knowing the secret. HMAC is not.

**`java.util.Random` for tokens.** It is a 48-bit linear congruential
generator; a couple of outputs are enough to predict the rest. All randomness
here comes from `SecureRandom`.

**PKCS#1 v1.5 RSA signatures and small keys.** RSA keys are 3072-bit (about
128-bit security) and use PSS padding. ECDSA uses P-256 through the JDK
provider, which generates nonces safely.

**Deny-lists for input.** Stripping `<script>` or `../` from input is a losing
game. The validators here describe what is allowed and reject everything else,
use bounded regexes that cannot be driven into catastrophic backtracking, and
check file paths after normalisation.

## Things this library does not do

- Key management. Keys should come from a KMS, HSM or secrets manager, not
  source code or config files in the repo.
- Output encoding for HTML, SQL or shell. Use your template engine's escaping,
  prepared statements, and `ProcessBuilder` argument lists.
- TLS. Use the JDK's `HttpClient` or your framework's defaults.

## License

[MIT](LICENSE)
