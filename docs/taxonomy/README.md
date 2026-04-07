# CryptoGuard — Vulnerability Taxonomy

**Project:** AI-Based Detection of Cryptographic Vulnerabilities in Source Code  
**Company context:** Android payment terminal software — Java and Kotlin  
**Author:** Abdellah Drioueche  
**Last updated:** April 2026  

---

## Overview

This taxonomy defines the 9 cryptographic vulnerability categories that
CryptoGuard is designed to detect. Each entry is documented in a dedicated
file in this directory.

The taxonomy is the foundation of three project components:

- **AI prompts:** each CWE file is loaded into the system prompt when
  analyzing a code snippet, giving the model precise detection rules
- **Dataset labelling:** every snippet in the dataset is labelled with
  a CWE ID from this taxonomy
- **Benchmarking:** evaluation metrics are computed per CWE to identify
  which categories the tool handles well and which need improvement

---

## Detection tiers

CWEs are grouped into three tiers based on detectability and frequency
in Android payment code. Implement in tier order during Phase 3.

### Tier 1 — Core targets · Implement first

These three are the highest priority. They are extremely common in real
codebases, have unambiguous detection signals, and represent the strongest
argument for AI over regex-based tools.

| CWE | Name | Severity | File |
|---|---|---|---|
| CWE-327 | Use of a broken or risky cryptographic algorithm | CRITICAL | [CWE-327.md](CWE-327.md) |
| CWE-798 | Use of hardcoded credentials or cryptographic keys | CRITICAL | [CWE-798.md](CWE-798.md) |
| CWE-916 | Use of password hash with insufficient computational effort | CRITICAL | [CWE-916.md](CWE-916.md) |

### Tier 2 — Important targets · Implement second

These four require more contextual reasoning. They are where the gap
between AI-based and regex-based detection is largest.

| CWE | Name | Severity | File |
|---|---|---|---|
| CWE-329 | Generation of predictable IV with CBC mode | HIGH | [CWE-329.md](CWE-329.md) |
| CWE-330 | Use of insufficiently random values | HIGH | [CWE-330.md](CWE-330.md) |
| CWE-326 | Inadequate encryption strength | HIGH | [CWE-326.md](CWE-326.md) |
| CWE-328 | Use of weak hash — missing or inadequate salt | HIGH | [CWE-328.md](CWE-328.md) |

### Tier 3 — Stretch targets · Implement last

These two require the deepest contextual reasoning and will have a higher
false positive rate. CWE-347 is the most impressive demo case in the project.

| CWE | Name | Severity | File |
|---|---|---|---|
| CWE-347 | Improper verification of cryptographic signature | CRITICAL | [CWE-347.md](CWE-347.md) |
| CWE-311 | Missing encryption of sensitive data | CRITICAL | [CWE-311.md](CWE-311.md) |

---

## Company-specific context

This taxonomy was built for a cybersecurity company developing Android
payment terminal software in Java and Kotlin. Several entries contain
rules specific to this context:

**3DES legacy bank communication:** the company uses 3DES-CBC for bank
protocol communication because the bank mandates it. CWE-327 and CWE-329
entries include a context rule — 3DES in a bank communication class is
flagged as WARNING rather than CRITICAL. 3DES anywhere else is CRITICAL.

**RSA for backend:** the company uses RSA for backend communication.
CWE-326 flags RSA keys below 2048 bits as critical findings directly
relevant to their production codebase.

**JKS files:** the development team uses Java KeyStore (JKS) files for
certificate management. CWE-916 and CWE-328 entries include explicit
false positive rules to avoid flagging JKS operations as password
hashing vulnerabilities.

**Android KeyStore:** multiple entries include Android KeyStore as the
recommended secure alternative for key storage, replacing hardcoded keys
(CWE-798) and unencrypted SharedPreferences (CWE-311).

---

## Detection approach summary

| CWE | Detection signal | Specific child CWE | Why LLM beats regex |
|---|---|---|---|
| CWE-327 | Algorithm name in cipher/digest call | — | Context distinguishes security vs non-security use, 3DES bank exception |
| CWE-798 | String literal or byte array used as key | — | Distinguishes key alias from key value, const val inlining |
| CWE-916 | Fast hash applied to password variable | — | Intent: password vs file hash — same code, different context |
| CWE-329 | Static or reused IV in CBC mode | — | Detects class-field IV reuse, Kotlin lazy pattern |
| CWE-330 | Random used in security context | CWE-338 (Weak PRNG) for payment context | PIN generation, token creation — same API, different purpose |
| CWE-326 | Key size below threshold | — | EC curve name to bit-strength mapping, variable tracing |
| CWE-328 | Hash without salt, or predictable salt | — | Absent salt has no pattern to match — pure absence detection |
| CWE-347 | JWT parsed without signature verification | — | parseClaimsJwt vs parseClaimsJws — semantic not syntactic |
| CWE-311 | Sensitive data stored or sent unencrypted | CWE-312 (storage), CWE-319 (transmission) | Absence of encryption call — requires sensitivity + absence reasoning |

---

## Expected JSON output format

Every finding produced by CryptoGuard follows this structure:

```json
{
  "file": "src/auth/LoginManager.java",
  "line": 42,
  "vulnerable": true,
  "cwe": "CWE-327",
  "specific_cwe": "CWE-338",
  "severity": "CRITICAL",
  "confidence": "high",
  "explanation": "Human-readable explanation of the vulnerability.",
  "fix_code": "Suggested secure replacement code."
}
```

**Severity levels:**
- `CRITICAL` — exploitable with known public tools, direct impact on confidentiality
- `HIGH` — significant security weakening, requires more effort to exploit
- `WARNING` — acceptable only in specific legacy contexts (e.g. 3DES for bank comms)

**Confidence levels with examples:**
- `high` — clear vulnerability with unambiguous signal
  - e.g. `parseClaimsJwt()` without any signing key
  - e.g. `Cipher.getInstance("AES/ECB/PKCS5Padding")` in production code
  - e.g. `new SecretKeySpec("hardcoded".getBytes(), "AES")`
- `medium` — probable vulnerability, context suggests sensitivity
  - e.g. `Random` used in test code alongside payment logic
  - e.g. 3DES in a class that may be a bank communication handler
  - e.g. SHA-256 applied to a variable that might be a password
- `low` — possible vulnerability, requires manual review
  - e.g. potential sensitive variable name but uncertain surrounding context
  - e.g. short byte array that might be an IV or might be a buffer
  - e.g. `new byte[16]` whose purpose is not clear from local context

---

## File naming convention

Each CWE entry is named `CWE-{ID}.md` and follows this consistent structure:

1. **Severity and frequency** — at-a-glance priority table
2. **Description** — what the vulnerability is, with company-specific context
3. **Detection logic** — precise rules for what to flag and what to skip
4. **Detection difficulty table** — regex vs LLM comparison for key patterns
5. **Vulnerable patterns** — Java and Kotlin code examples organized by pattern
6. **False positive patterns** — what must not be flagged, with explanations
7. **Secure alternatives** — correct replacement code in Java and Kotlin
8. **Expected AI output** — JSON format showing what the tool should produce
9. **References** — NIST, OWASP, RFC, and CWE links

---

## Quick reference — what to flag

This table is a one-page summary for rapid lookup during development,
code review, and prompt engineering.

| If you see this in the code | Flag this CWE | Severity |
|---|---|---|
| `MessageDigest.getInstance("MD5")` on a password | CWE-327 + CWE-916 | CRITICAL |
| `Cipher.getInstance("AES/ECB/...")` | CWE-327 | CRITICAL |
| `Cipher.getInstance("DES/...")` or `"DESede/..."` outside bank class | CWE-327 | CRITICAL |
| `Cipher.getInstance("AES")` on Android (no mode specified) | CWE-327 | CRITICAL |
| `new SecretKeySpec("hardcoded".getBytes(), "AES")` | CWE-798 | CRITICAL |
| `const val API_SECRET = "sk_..."` in Kotlin | CWE-798 | CRITICAL |
| `private static final String PIN_KEY = "..."` | CWE-798 | CRITICAL |
| `MessageDigest.getInstance("SHA-256").digest(password...)` | CWE-916 | CRITICAL |
| `new PBEKeySpec(password, salt, 1000, 256)` | CWE-916 | HIGH |
| `new IvParameterSpec(new byte[16])` | CWE-329 | HIGH |
| `private static final IvParameterSpec IV = ...` (reused) | CWE-329 | HIGH |
| `private val iv by lazy { IvParameterSpec(ByteArray(8)) }` | CWE-329 | HIGH |
| `new Random().nextInt()` for PIN or token generation | CWE-330 / CWE-338 | HIGH |
| `(1000..9999).random()` in Kotlin for security value | CWE-330 / CWE-338 | HIGH |
| `KeyPairGenerator.initialize(512)` or `(1024)` for RSA | CWE-326 | CRITICAL / HIGH |
| `ECGenParameterSpec("secp112r1")` or `("secp160r1")` | CWE-326 | HIGH |
| `MessageDigest.getInstance("SHA-256").digest(password...)` no salt | CWE-328 | HIGH |
| `byte[] salt = username.getBytes()` | CWE-328 | HIGH |
| `parseClaimsJwt(token)` instead of `parseClaimsJws()` | CWE-347 | CRITICAL |
| `JWT.decode(token)` without `JWT.require(...).verify()` | CWE-347 | CRITICAL |
| `Jwts.parserBuilder().build()` without `setSigningKey()` | CWE-347 | CRITICAL |
| `Algorithm.none()` in JWT verifier | CWE-347 | CRITICAL |
| `SharedPreferences.putString("pin", pin)` unencrypted | CWE-311 / CWE-312 | CRITICAL |
| `new URL("http://...")` transmitting payment data | CWE-311 / CWE-319 | CRITICAL |
| `Log.d("TAG", password)` or `Log.e("TAG", pin)` | CWE-311 / CWE-312 | HIGH |

---

## Benchmark opponents

This taxonomy is used to evaluate CryptoGuard against three existing tools:

| Tool | Type | Strength | Weakness |
|---|---|---|---|
| MobSF | APK-level SAST | Broad Android coverage | Regex-based, no context reasoning |
| Semgrep | Source-level SAST | Fast, configurable rules | Cannot reason about intent |
| SpotBugs + FindSecBugs | Bytecode SAST | Deep Java analysis | No Kotlin support, no context |

CryptoGuard's advantage over all three: contextual reasoning about intent,
severity calibration based on surrounding code, and the ability to detect
vulnerabilities defined by absence rather than presence.

---

## File index

```
docs/taxonomy/
├── README.md          ← this file — index and overview
├── CWE-311.md         ← missing encryption of sensitive data
├── CWE-326.md         ← inadequate encryption strength
├── CWE-327.md         ← broken or risky cryptographic algorithm
├── CWE-328.md         ← weak hash — missing or inadequate salt
├── CWE-329.md         ← predictable IV with CBC mode
├── CWE-330.md         ← insufficiently random values
├── CWE-347.md         ← improper JWT signature verification
├── CWE-798.md         ← hardcoded credentials or keys
└── CWE-916.md         ← insufficient password hashing effort
```
