import json
import hashlib
import os

OUTPUT_FILE = os.path.expanduser("~/cryptoguard/dataset/raw/synthetic_examples.jsonl")

def make_id(cwe, index, kind):
    h = hashlib.md5(f"{cwe}{index}{kind}".encode()).hexdigest()[:8]
    return f"synthetic_{h}"

def entry(cwe, severity, index, is_vulnerable, description, code, context="android"):
    kind = "bad" if is_vulnerable else "good"
    return {
        "id":            make_id(cwe, index, kind),
        "source":        "synthetic",
        "language":      "java",
        "context":       context,
        "cwe_id":        cwe,
        "is_vulnerable": is_vulnerable,
        "severity":      severity if is_vulnerable else "NONE",
        "confidence":    "high",
        "description":   description,
        "code":          code,
    }

records = []

# ===========================================================================
# CWE-326 — Inadequate encryption strength
# ===========================================================================

CWE326 = [

    # --- VULNERABLE ---
    entry("CWE-326","HIGH",1,True,"RSA-512 key generation — completely broken",
"""public KeyPair generateRsaKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(512); // FLAW: RSA-512 is broken
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",2,True,"RSA-1024 key generation — NIST deprecated",
"""public KeyPair generateBackendKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(1024); // FLAW: RSA-1024 deprecated by NIST
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",3,True,"AES-64 key — below minimum",
"""public SecretKey generateAesKey() throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(64); // FLAW: AES-64 is not a valid or secure key size
    return keyGen.generateKey();
}"""),

    entry("CWE-326","HIGH",4,True,"EC secp112r1 — 112-bit curve, broken",
"""public KeyPair generateEcKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp112r1")); // FLAW: 112-bit EC is broken
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",5,True,"EC secp160r1 — below NIST minimum of 256",
"""public KeyPair generatePaymentKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp160r1")); // FLAW: below NIST 256-bit minimum
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",6,True,"RSA-512 with SecureRandom — key size still broken",
"""public KeyPair generateRsaKeyPair() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(512, new SecureRandom()); // FLAW: SecureRandom does not fix key size
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",7,True,"Android KeyStore RSA-1024 — weak key in hardware store",
"""public void generateKeyStoreKey() throws Exception {
    KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
        "payment_key",
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setKeySize(1024) // FLAW: RSA-1024 is weak, minimum is 2048
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
        .build();
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
    kpg.initialize(spec);
    kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",8,True,"RSA key size stored in weak constant",
"""private static final int KEY_SIZE = 1024; // FLAW: constant defines weak key size
public KeyPair generateRsaKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(KEY_SIZE);
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",9,True,"DSA-512 — broken key size",
"""public KeyPair generateDsaKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
    kpg.initialize(512); // FLAW: DSA-512 is broken
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",10,True,"EC-192 via secp192r1 — below NIST minimum",
"""public KeyPair generateEcSigningKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp192r1")); // FLAW: 192-bit below NIST 256-bit minimum
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",11,True,"Android KeyStore EC with weak key size",
"""public void generateEcKeyStoreKey() throws Exception {
    KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
        "ec_payment_key",
        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
        .setKeySize(160) // FLAW: EC-160 is below NIST minimum of 256
        .setDigests(KeyProperties.DIGEST_SHA256)
        .build();
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
    kpg.initialize(spec);
    kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",12,True,"RSA-768 — broken",
"""public KeyPair generateRsaKey768() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(768); // FLAW: RSA-768 was factored in 2009
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",13,True,"AES-56 — matches DES key length, insecure",
"""public SecretKey generateWeakAesKey() throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(56); // FLAW: 56-bit AES matches DES strength — insecure
    return keyGen.generateKey();
}"""),

    entry("CWE-326","HIGH",14,True,"RSA key for payment terminal backend — size too small",
"""public class BackendKeyManager {
    private static final int RSA_KEY_SIZE = 512;
    public KeyPair createBackendKeyPair() throws Exception {
        // FLAW: RSA-512 used for backend communication key
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE, new SecureRandom());
        return gen.generateKeyPair();
    }
}"""),

    entry("CWE-326","HIGH",15,True,"EC with numeric 160-bit size",
"""public KeyPair generateEcKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(160); // FLAW: EC-160 is below NIST minimum of 256 bits
    return kpg.generateKeyPair();
}"""),

    # --- SECURE ---
    entry("CWE-326","HIGH",1,False,"RSA-4096 key generation — recommended",
"""public KeyPair generateRsaKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(4096, new SecureRandom()); // FIX: RSA-4096 exceeds NIST minimum
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",2,False,"RSA-2048 — NIST minimum acceptable",
"""public KeyPair generateBackendKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048, new SecureRandom()); // FIX: RSA-2048 meets NIST minimum
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",3,False,"AES-256 key — recommended strength",
"""public SecretKey generateAesKey() throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(256, new SecureRandom()); // FIX: AES-256 recommended
    return keyGen.generateKey();
}"""),

    entry("CWE-326","HIGH",4,False,"EC secp384r1 — recommended curve",
"""public KeyPair generateEcKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp384r1"), new SecureRandom()); // FIX: P-384 recommended
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",5,False,"EC secp256r1 — NIST minimum acceptable",
"""public KeyPair generatePaymentKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom()); // FIX: P-256 meets minimum
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",6,False,"Android KeyStore RSA-4096 with OAEP padding",
"""public void generateKeyStoreKey() throws Exception {
    KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
        "payment_key",
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setKeySize(4096) // FIX: RSA-4096 strong key
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
        .build();
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
    kpg.initialize(spec);
    kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",7,False,"AES-128 — minimum acceptable",
"""public SecretKey generateAesKey() throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(128, new SecureRandom()); // FIX: AES-128 is the minimum acceptable
    return keyGen.generateKey();
}"""),

    entry("CWE-326","HIGH",8,False,"EC secp521r1 — strongest standard curve",
"""public KeyPair generateStrongEcKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp521r1"), new SecureRandom()); // FIX: P-521 strongest
    return kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",9,False,"Android KeyStore EC-256 for signing",
"""public void generateEcKeyStoreKey() throws Exception {
    KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
        "ec_payment_key",
        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
        .setKeySize(256) // FIX: EC-256 meets NIST minimum
        .setDigests(KeyProperties.DIGEST_SHA256)
        .build();
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
    kpg.initialize(spec);
    kpg.generateKeyPair();
}"""),

    entry("CWE-326","HIGH",10,False,"RSA-2048 backend communication key",
"""public class BackendKeyManager {
    private static final int RSA_KEY_SIZE = 2048; // FIX: 2048 meets NIST minimum
    public KeyPair createBackendKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE, new SecureRandom());
        return gen.generateKeyPair();
    }
}"""),

]

records.extend(CWE326)

# ===========================================================================
# CWE-347 — Improper verification of cryptographic signature (JWT)
# ===========================================================================

CWE347 = [

    # --- VULNERABLE ---
    entry("CWE-347","CRITICAL",1,True,"jjwt parseClaimsJwt() — no signature verification",
"""public Claims parseToken(String token) {
    // FLAW: parseClaimsJwt() does not verify the signature
    return Jwts.parser()
        .parseClaimsJwt(token)
        .getBody();
}"""),

    entry("CWE-347","CRITICAL",2,True,"jjwt parserBuilder without signing key",
"""public Claims validateToken(String token) {
    // FLAW: no setSigningKey() — signature verification silently skipped
    JwtParser parser = Jwts.parserBuilder().build();
    return parser.parseClaimsJws(token).getBody();
}"""),

    entry("CWE-347","CRITICAL",3,True,"Auth0 JWT.decode() — only decodes, no verification",
"""public String getUserId(String token) {
    // FLAW: JWT.decode() does not verify the signature
    DecodedJWT jwt = JWT.decode(token);
    return jwt.getSubject();
}"""),

    entry("CWE-347","CRITICAL",4,True,"Auth0 Algorithm.none() — accepts unsigned tokens",
"""public DecodedJWT verifyToken(String token) throws JWTVerificationException {
    // FLAW: Algorithm.none() accepts tokens with no signature
    JWTVerifier verifier = JWT.require(Algorithm.none()).build();
    return verifier.verify(token);
}"""),

    entry("CWE-347","CRITICAL",5,True,"Manual Base64 decode without signature check",
"""public JSONObject parseToken(String token) throws Exception {
    // FLAW: signature is never verified — payload decoded directly
    String[] parts = token.split("\\.");
    String payload = new String(Base64.getDecoder().decode(parts[1]));
    return new JSONObject(payload);
}"""),

    entry("CWE-347","CRITICAL",6,True,"SignatureException caught and ignored",
"""public Claims processToken(String token) {
    try {
        return Jwts.parser()
            .setSigningKey(secret)
            .parseClaimsJws(token)
            .getBody();
    } catch (SignatureException e) {
        // FLAW: signature failure ignored — token re-parsed without verification
        return Jwts.parser().parseClaimsJwt(token).getBody();
    }
}"""),

    entry("CWE-347","CRITICAL",7,True,"Payment terminal auth bypass via JWT decode",
"""public boolean isAuthorizedTerminal(String authToken) {
    // FLAW: no signature verification — forged token accepted
    DecodedJWT jwt = JWT.decode(authToken);
    String role = jwt.getClaim("role").asString();
    return "TERMINAL_ADMIN".equals(role);
}"""),

    entry("CWE-347","CRITICAL",8,True,"jjwt parseClaimsJws without key — older API",
"""public Claims extractClaims(String token) {
    // FLAW: no signing key set — older jjwt API skips verification
    return Jwts.parser()
        .parseClaimsJws(token)
        .getBody();
}"""),

    entry("CWE-347","CRITICAL",9,True,"algorithms=[none] in PyJWT-style pattern",
"""// Backend service called from Android — Python-style vulnerability reproduced in Java
// Equivalent pattern: jwt.decode(token, options={"verify_signature": False})
public Claims decodeWithoutVerification(String token) {
    // FLAW: explicit skip of verification for debugging — left in production
    JwtParserBuilder builder = Jwts.parserBuilder();
    // Verification intentionally disabled for development
    return builder.build().parseClaimsJwt(token).getBody();
}"""),

    entry("CWE-347","CRITICAL",10,True,"JWT used for payment authorization without verification",
"""public void processPayment(String jwtToken, PaymentRequest request) {
    // FLAW: token decoded but signature never checked
    String[] parts = jwtToken.split("\\.");
    String payload = new String(Base64.getDecoder().decode(parts[1]));
    JSONObject claims = new JSONObject(payload);
    String userId = claims.getString("userId");
    // Payment processed based on unverified claims
    paymentService.authorize(userId, request);
}"""),

    entry("CWE-347","CRITICAL",11,True,"JWT expiry checked but signature not verified",
"""public boolean isTokenValid(String token) {
    // FLAW: expiry is checked but signature is never verified
    // Attacker can forge a non-expired token with any claims
    DecodedJWT jwt = JWT.decode(token);
    return jwt.getExpiresAt().after(new Date());
}"""),

    entry("CWE-347","CRITICAL",12,True,"Empty signing key — effectively no verification",
"""public Claims validateSession(String token) {
    // FLAW: empty string as signing key — trivially bypassable
    return Jwts.parser()
        .setSigningKey("")
        .parseClaimsJws(token)
        .getBody();
}"""),

    entry("CWE-347","CRITICAL",13,True,"JWT role claim used for authorization without verify",
"""public boolean hasAdminRole(String token) {
    // FLAW: role extracted from unverified token
    DecodedJWT decoded = JWT.decode(token);
    List<String> roles = decoded.getClaim("roles").asList(String.class);
    return roles != null && roles.contains("ADMIN");
}"""),

    entry("CWE-347","CRITICAL",14,True,"Catch-all exception hides verification failure",
"""public UserInfo authenticate(String token) {
    try {
        return Jwts.parserBuilder()
            .setSigningKey(signingKey)
            .build()
            .parseClaimsJws(token)
            .getBody();
    } catch (Exception e) {
        // FLAW: catches ALL exceptions including signature failure
        // Falls through to decode without verification
        return decodeUnsafe(token);
    }
}"""),

    entry("CWE-347","CRITICAL",15,True,"JWT header algorithm accepted from token itself",
"""public Claims parseWithHeaderAlgorithm(String token) {
    // FLAW: algorithm read from token header — alg:none attack possible
    String header = new String(Base64.getDecoder().decode(token.split("\\.")[0]));
    String alg = new JSONObject(header).getString("alg");
    // Algorithm supplied by attacker is used for verification
    return Jwts.parser().setSigningKey(secret).parseClaimsJwt(token).getBody();
}"""),

    # --- SECURE ---
    entry("CWE-347","CRITICAL",1,False,"jjwt parserBuilder with signing key — correct",
"""public Claims parseToken(String token) {
    SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString));
    // FIX: setSigningKey() ensures signature is verified
    return Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(token) // parseClaimsJws not parseClaimsJwt
        .getBody();
}"""),

    entry("CWE-347","CRITICAL",2,False,"Auth0 JWT.require() with HMAC256 — correct",
"""public DecodedJWT verifyToken(String token) throws JWTVerificationException {
    // FIX: Algorithm.HMAC256 verifies the signature
    JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret))
        .withIssuer("payment-server")
        .build();
    return verifier.verify(token);
}"""),

    entry("CWE-347","CRITICAL",3,False,"RSA256 public key verification",
"""public Claims verifyWithRsa(String token) throws Exception {
    // FIX: RSA public key used for RS256 signature verification
    return Jwts.parserBuilder()
        .setSigningKey(rsaPublicKey)
        .build()
        .parseClaimsJws(token)
        .getBody();
}"""),

    entry("CWE-347","CRITICAL",4,False,"JWT with expiry validation after signature check",
"""public Claims validateToken(String token) {
    SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString));
    // FIX: signature verified first, then claims validated
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(token)
        .getBody();
    if (claims.getExpiration().before(new Date())) {
        throw new SecurityException("Token expired");
    }
    return claims;
}"""),

    entry("CWE-347","CRITICAL",5,False,"Payment authorization with full JWT verification",
"""public void processPayment(String jwtToken, PaymentRequest request) {
    SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString));
    // FIX: signature verified before trusting any claims
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(jwtToken)
        .getBody();
    String userId = claims.getSubject();
    paymentService.authorize(userId, request);
}"""),

    entry("CWE-347","CRITICAL",6,False,"Auth0 with issuer and audience validation",
"""public DecodedJWT verifyTerminalToken(String token) throws JWTVerificationException {
    // FIX: full verification including issuer and audience
    JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret))
        .withIssuer("payment-auth-server")
        .withAudience("terminal")
        .build();
    return verifier.verify(token);
}"""),

    entry("CWE-347","CRITICAL",7,False,"Let SignatureException propagate — do not catch silently",
"""public Claims authenticate(String token) {
    SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString));
    // FIX: SignatureException propagates — caller returns 401
    // Do NOT catch SignatureException and continue
    return Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(token)
        .getBody();
}"""),

    entry("CWE-347","CRITICAL",8,False,"JWT admin role check after verified claims",
"""public boolean hasAdminRole(String token) {
    SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString));
    // FIX: claims only trusted after signature verification
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(token)
        .getBody();
    List<String> roles = claims.get("roles", List.class);
    return roles != null && roles.contains("ADMIN");
}"""),

    entry("CWE-347","CRITICAL",9,False,"Auth0 RSA256 public key verification",
"""public DecodedJWT verifyRsaToken(String token) throws JWTVerificationException {
    // FIX: RSA256 with public key — private key never leaves the server
    JWTVerifier verifier = JWT.require(Algorithm.RSA256(rsaPublicKey, null))
        .build();
    return verifier.verify(token);
}"""),

    entry("CWE-347","CRITICAL",10,False,"Terminal session validated with signing key",
"""public boolean isAuthorizedTerminal(String authToken) {
    try {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString));
        // FIX: signature verified — role claim trustworthy
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(authToken)
            .getBody();
        return "TERMINAL_ADMIN".equals(claims.get("role", String.class));
    } catch (JwtException e) {
        return false; // Invalid or tampered token
    }
}"""),

]

records.extend(CWE347)

# ===========================================================================
# CWE-916 — Use of password hash with insufficient computational effort
# ===========================================================================

CWE916 = [

    # --- VULNERABLE ---
    entry("CWE-916","CRITICAL",1,True,"SHA-256 used directly for password hashing",
"""public String hashPassword(String password) throws Exception {
    // FLAW: SHA-256 is too fast for password hashing
    // Attacker can compute 23 billion SHA-256 hashes per second with a GPU
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    return Base64.getEncoder().encodeToString(md.digest(password.getBytes()));
}"""),

    entry("CWE-916","CRITICAL",2,True,"MD5 used for password storage",
"""public String storePassword(String password) throws Exception {
    // FLAW: MD5 is both broken (collisions) and fast (200 billion/sec)
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] hash = md.digest(password.getBytes("UTF-8"));
    return javax.xml.bind.DatatypeConverter.printHexBinary(hash);
}"""),

    entry("CWE-916","CRITICAL",3,True,"SHA-512 used in authenticate method — still wrong",
"""public boolean authenticate(String username, String password) throws Exception {
    // FLAW: SHA-512 is faster than SHA-256 for short inputs — still wrong for passwords
    MessageDigest md = MessageDigest.getInstance("SHA-512");
    String hash = Base64.getEncoder().encodeToString(md.digest(password.getBytes()));
    return hash.equals(getUserHash(username));
}"""),

    entry("CWE-916","CRITICAL",4,True,"PBKDF2 with 1000 iterations — far below minimum",
"""public byte[] hashPin(char[] pin, byte[] salt) throws Exception {
    // FLAW: 1000 iterations is far below OWASP minimum of 310,000
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    PBEKeySpec spec = new PBEKeySpec(pin, salt, 1000, 256);
    return skf.generateSecret(spec).getEncoded();
}"""),

    entry("CWE-916","CRITICAL",5,True,"SHA-1 in login verification",
"""public boolean verifyLogin(String inputPassword, String storedHash) throws Exception {
    // FLAW: SHA-1 is both broken and fast
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    String inputHash = new String(Hex.encodeHex(md.digest(inputPassword.getBytes())));
    return inputHash.equals(storedHash);
}"""),

    entry("CWE-916","CRITICAL",6,True,"PBKDF2 with 10000 iterations — below 2023 minimum",
"""public byte[] deriveKey(char[] password, byte[] salt) throws Exception {
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    // FLAW: 10,000 iterations below OWASP 2023 minimum of 310,000
    PBEKeySpec spec = new PBEKeySpec(password, salt, 10000, 256);
    return skf.generateSecret(spec).getEncoded();
}"""),

    entry("CWE-916","CRITICAL",7,True,"SHA-256 in user registration without salt or slow hash",
"""public void registerUser(String username, String password) throws Exception {
    // FLAW: SHA-256 directly on password — no salt, not slow
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(password.getBytes("UTF-8"));
    userRepository.save(username, Base64.getEncoder().encodeToString(hash));
}"""),

    entry("CWE-916","CRITICAL",8,True,"Custom fast hash function for PIN storage",
"""public String hashPin(String pin) {
    // FLAW: custom fast hash — equivalent to SHA-256 speed problem
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(pin.getBytes());
        return Base64.getEncoder().encodeToString(md.digest());
    } catch (Exception e) {
        return pin; // Worst case: returns plaintext
    }
}"""),

    entry("CWE-916","CRITICAL",9,True,"Payment terminal PIN verification with fast hash",
"""public class PinVerifier {
    public boolean verifyPin(String enteredPin, String storedHash) {
        // FLAW: SHA-256 used for PIN verification in payment terminal
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String hash = Base64.getEncoder().encodeToString(
                md.digest(enteredPin.getBytes("UTF-8")));
            return hash.equals(storedHash);
        } catch (Exception e) {
            return false;
        }
    }
}"""),

    entry("CWE-916","CRITICAL",10,True,"PBKDF2 with SHA1 and low iterations",
"""public byte[] hashPassword(char[] password, byte[] salt) throws Exception {
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    // FLAW: SHA1 variant with only 5000 iterations — both algorithm and count are weak
    PBEKeySpec spec = new PBEKeySpec(password, salt, 5000, 160);
    return skf.generateSecret(spec).getEncoded();
}"""),

    entry("CWE-916","CRITICAL",11,True,"Admin password check with MD5",
"""public boolean checkAdminPassword(String input) throws Exception {
    // FLAW: MD5 for admin authentication — critical in payment system context
    MessageDigest md = MessageDigest.getInstance("MD5");
    String hash = DatatypeConverter.printHexBinary(md.digest(input.getBytes())).toLowerCase();
    return ADMIN_PASSWORD_HASH.equals(hash);
}"""),

    entry("CWE-916","CRITICAL",12,True,"SHA-256 password check in Android login",
"""public boolean checkPassword(String username, String inputPassword) {
    // FLAW: fast hash in Android login activity
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] inputHash = md.digest(inputPassword.getBytes("UTF-8"));
        byte[] storedHash = getUserHash(username);
        return MessageDigest.isEqual(inputHash, storedHash);
    } catch (Exception e) {
        return false;
    }
}"""),

    entry("CWE-916","CRITICAL",13,True,"PBKDF2 with 50000 iterations — still below minimum",
"""public byte[] hashOperatorPin(char[] pin, byte[] salt) throws Exception {
    // FLAW: 50,000 iterations is still below OWASP 2023 minimum of 310,000
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    PBEKeySpec spec = new PBEKeySpec(pin, salt, 50000, 256);
    return skf.generateSecret(spec).getEncoded();
}"""),

    entry("CWE-916","CRITICAL",14,True,"Operator password hashed with SHA-256 in terminal",
"""public class TerminalAuth {
    public void setOperatorPassword(String password) throws Exception {
        // FLAW: SHA-256 for operator password on payment terminal
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes("UTF-8"));
        secureStorage.store("operator_pwd_hash", Base64.getEncoder().encodeToString(hash));
    }
}"""),

    entry("CWE-916","CRITICAL",15,True,"CRC32 used for password integrity — not a hash function",
"""public long hashPassword(String password) {
    // FLAW: CRC32 is a checksum, not a cryptographic hash
    // Provides no password security whatsoever
    CRC32 crc = new CRC32();
    crc.update(password.getBytes());
    return crc.getValue();
}"""),

    # --- SECURE ---
    entry("CWE-916","CRITICAL",1,False,"bcrypt with cost 12 — recommended",
"""public String hashPassword(String password) {
    // FIX: bcrypt with cost 12 — slow by design, salt automatic
    return BCrypt.hashpw(password, BCrypt.gensalt(12));
}

public boolean verifyPassword(String password, String hash) {
    return BCrypt.checkpw(password, hash);
}"""),

    entry("CWE-916","CRITICAL",2,False,"Argon2 — OWASP top recommendation",
"""public String hashPassword(String password) {
    // FIX: Argon2 — winner of Password Hashing Competition, OWASP #1
    Argon2 argon2 = Argon2Factory.create();
    return argon2.hash(3, 65536, 1, password.toCharArray());
}

public boolean verifyPassword(String password, String hash) {
    Argon2 argon2 = Argon2Factory.create();
    return argon2.verify(hash, password.toCharArray());
}"""),

    entry("CWE-916","CRITICAL",3,False,"PBKDF2 with 310000 iterations — OWASP 2023 minimum",
"""public byte[] hashPin(char[] pin) throws Exception {
    // FIX: PBKDF2 with 310,000 iterations per OWASP 2023
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    PBEKeySpec spec = new PBEKeySpec(pin, salt, 310000, 256);
    byte[] hash = skf.generateSecret(spec).getEncoded();
    spec.clearPassword();
    return hash;
}"""),

    entry("CWE-916","CRITICAL",4,False,"bcrypt in Android login activity",
"""public boolean checkPassword(String username, String inputPassword) {
    // FIX: bcrypt handles salt internally
    String storedHash = getUserHash(username);
    return BCrypt.checkpw(inputPassword, storedHash);
}"""),

    entry("CWE-916","CRITICAL",5,False,"Payment terminal PIN verification with bcrypt",
"""public class PinVerifier {
    public boolean verifyPin(String enteredPin, String storedHash) {
        // FIX: bcrypt — slow enough to resist brute-force attacks
        return BCrypt.checkpw(enteredPin, storedHash);
    }

    public String hashNewPin(String pin) {
        return BCrypt.hashpw(pin, BCrypt.gensalt(12));
    }
}"""),

    entry("CWE-916","CRITICAL",6,False,"Argon2 for operator authentication on terminal",
"""public class TerminalAuth {
    private final Argon2 argon2 = Argon2Factory.create();

    public void setOperatorPassword(String password) {
        // FIX: Argon2 for operator password — memory-hard, GPU-resistant
        String hash = argon2.hash(3, 65536, 1, password.toCharArray());
        secureStorage.store("operator_pwd_hash", hash);
    }

    public boolean verifyOperatorPassword(String input) {
        String storedHash = secureStorage.retrieve("operator_pwd_hash");
        return argon2.verify(storedHash, input.toCharArray());
    }
}"""),

    entry("CWE-916","CRITICAL",7,False,"PBKDF2 with sufficient iterations and salt storage",
"""public void registerUser(String username, char[] password) throws Exception {
    // FIX: PBKDF2 with proper salt and iteration count
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    PBEKeySpec spec = new PBEKeySpec(password, salt, 310000, 256);
    byte[] hash = skf.generateSecret(spec).getEncoded();
    spec.clearPassword();
    // Store both salt and hash — salt needed for verification
    userRepository.save(username, hash, salt);
}"""),

    entry("CWE-916","CRITICAL",8,False,"bcrypt cost 14 for high-security admin passwords",
"""public String hashAdminPassword(String password) {
    // FIX: bcrypt cost 14 for admin — higher cost for privileged accounts
    return BCrypt.hashpw(password, BCrypt.gensalt(14));
}"""),

    entry("CWE-916","CRITICAL",9,False,"Argon2id — recommended variant for password hashing",
"""public String hashUserPassword(String password) {
    // FIX: Argon2id — combined protection against side-channel and GPU attacks
    Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    return argon2.hash(3, 65536, 1, password.toCharArray());
}"""),

    entry("CWE-916","CRITICAL",10,False,"PBKDF2 admin auth with 600000 iterations for higher security",
"""public byte[] hashAdminCredential(char[] password, byte[] salt) throws Exception {
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    // FIX: 600,000 iterations for admin credentials — twice the minimum
    PBEKeySpec spec = new PBEKeySpec(password, salt, 600000, 256);
    byte[] hash = skf.generateSecret(spec).getEncoded();
    spec.clearPassword();
    return hash;
}"""),

]

records.extend(CWE916)

# ===========================================================================
# CWE-329 supplement — 10 synthetic examples to reach 50+ total
# ===========================================================================

CWE329_SUPPLEMENT = [

    entry("CWE-329","HIGH",101,True,"Android AES-CBC with zero IV in payment activity",
"""public byte[] encryptPaymentData(byte[] data, SecretKey key) throws Exception {
    // FLAW: zero IV for AES-CBC in payment encryption
    IvParameterSpec iv = new IvParameterSpec(new byte[16]);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    return cipher.doFinal(data);
}"""),

    entry("CWE-329","HIGH",102,True,"3DES-CBC with hardcoded IV for bank communication",
"""public class BankProtocolEncryptor {
    private static final byte[] BANK_IV = "12345678".getBytes(); // FLAW: hardcoded IV
    public byte[] encryptBankMessage(byte[] message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(BANK_IV));
        return cipher.doFinal(message);
    }
}"""),

    entry("CWE-329","HIGH",103,True,"IV stored as instance field and reused",
"""public class TransactionEncryptor {
    private IvParameterSpec iv = new IvParameterSpec(new byte[16]); // FLAW: reused

    public byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv); // Same IV for every call
        return cipher.doFinal(data);
    }
}"""),

    entry("CWE-329","HIGH",104,True,"Kotlin companion object IV — shared across instances",
"""// Kotlin
class PaymentCipher {
    companion object {
        private val STATIC_IV = IvParameterSpec(ByteArray(16)) // FLAW: shared
    }
    fun encrypt(data: ByteArray, key: SecretKey): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, STATIC_IV)
        return cipher.doFinal(data)
    }
}"""),

    entry("CWE-329","HIGH",105,True,"IV derived from predictable transaction ID",
"""public byte[] encryptTransaction(byte[] txData, SecretKey key, long txId) throws Exception {
    // FLAW: IV derived from transaction ID — predictable
    byte[] ivBytes = ByteBuffer.allocate(16).putLong(txId).array();
    IvParameterSpec iv = new IvParameterSpec(ivBytes);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    return cipher.doFinal(txData);
}"""),

    entry("CWE-329","HIGH",101,False,"AES-CBC with fresh SecureRandom IV per call",
"""public byte[] encryptPaymentData(byte[] data, SecretKey key) throws Exception {
    // FIX: fresh random IV generated for every encryption operation
    byte[] ivBytes = new byte[16];
    new SecureRandom().nextBytes(ivBytes);
    IvParameterSpec iv = new IvParameterSpec(ivBytes);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    byte[] ciphertext = cipher.doFinal(data);
    // Prepend IV to output for use during decryption
    byte[] output = new byte[16 + ciphertext.length];
    System.arraycopy(ivBytes, 0, output, 0, 16);
    System.arraycopy(ciphertext, 0, output, 16, ciphertext.length);
    return output;
}"""),

    entry("CWE-329","HIGH",102,False,"3DES-CBC bank protocol with fresh IV per transaction",
"""public class BankProtocolEncryptor {
    public byte[] encryptBankMessage(byte[] message, SecretKey key) throws Exception {
        // FIX: fresh 8-byte IV for every 3DES-CBC operation
        byte[] ivBytes = new byte[8];
        new SecureRandom().nextBytes(ivBytes);
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
        byte[] ciphertext = cipher.doFinal(message);
        // Prepend IV so bank can decrypt
        byte[] output = new byte[8 + ciphertext.length];
        System.arraycopy(ivBytes, 0, output, 0, 8);
        System.arraycopy(ciphertext, 0, output, 8, ciphertext.length);
        return output;
    }
}"""),

    entry("CWE-329","HIGH",103,False,"AES-GCM instead of AES-CBC — nonce handled explicitly",
"""public byte[] encryptTransaction(byte[] data, SecretKey key) throws Exception {
    // FIX: AES-GCM provides authenticated encryption — better than AES-CBC
    byte[] nonce = new byte[12];
    new SecureRandom().nextBytes(nonce);
    GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    return cipher.doFinal(data);
}"""),

    entry("CWE-329","HIGH",104,False,"Kotlin fresh IV generated inside encrypt function",
"""// Kotlin
class PaymentCipher {
    fun encrypt(data: ByteArray, key: SecretKey): ByteArray {
        // FIX: IV generated inside function — never reused
        val ivBytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val iv = IvParameterSpec(ivBytes)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)
        return ivBytes + cipher.doFinal(data)
    }
}"""),

    entry("CWE-329","HIGH",105,False,"IV extracted from received ciphertext for decryption",
"""public byte[] decryptPaymentData(byte[] received, SecretKey key) throws Exception {
    // FIX: IV prepended to ciphertext by sender — extract for decryption
    byte[] ivBytes = Arrays.copyOf(received, 16);
    byte[] ciphertext = Arrays.copyOfRange(received, 16, received.length);
    IvParameterSpec iv = new IvParameterSpec(ivBytes);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, key, iv);
    return cipher.doFinal(ciphertext);
}"""),

]

records.extend(CWE329_SUPPLEMENT)

# ===========================================================================
# CWE-295 — Improper certificate validation
# ===========================================================================

CWE295 = [

    # --- VULNERABLE ---
    entry("CWE-295","CRITICAL",1,True,"Classic trust-all TrustManager — checkServerTrusted does nothing",
"""public void configureInsecureClient() throws Exception {
    TrustManager[] trustAllCerts = new TrustManager[] {
        new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
            // FLAW: no validation, no exception thrown — any certificate is accepted
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }
    };
    SSLContext sc = SSLContext.getInstance("TLS");
    sc.init(null, trustAllCerts, new SecureRandom());
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
}"""),

    entry("CWE-295","CRITICAL",2,True,"HostnameVerifier unconditionally returns true",
"""public void disableHostnameCheck() {
    // FLAW: accepts any hostname regardless of the certificate's actual CN/SAN
    HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    });
}"""),

    entry("CWE-295","CRITICAL",3,True,"Deprecated ALLOW_ALL_HOSTNAME_VERIFIER constant",
"""public HttpsURLConnection openBackendConnection(URL url) throws Exception {
    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
    // FLAW: ALLOW_ALL_HOSTNAME_VERIFIER disables hostname validation entirely
    conn.setHostnameVerifier(org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
    return conn;
}"""),

    entry("CWE-295","CRITICAL",4,True,"WebView proceeds despite SSL certificate error",
"""public void setupPaymentWebView(WebView webView) {
    webView.setWebViewClient(new WebViewClient() {
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            // FLAW: proceeds despite the certificate error being reported
            handler.proceed();
        }
    });
}"""),

    entry("CWE-295","CRITICAL",5,True,"OkHttp client with trust-all TrustManager and permissive hostname verifier",
"""public OkHttpClient buildInsecureClient(X509TrustManager trustAllManager,
                                         SSLSocketFactory sslSocketFactory) {
    // FLAW: both certificate trust and hostname checks are disabled
    return new OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory, trustAllManager)
        .hostnameVerifier((hostname, session) -> true)
        .build();
}"""),

    entry("CWE-295","CRITICAL",6,True,"Kotlin trust-all TrustManager for payment backend client",
"""fun buildInsecureSslContext(): SSLContext {
    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        // FLAW: no validation logic, never throws
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    })
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustAllCerts, SecureRandom())
    return sslContext
}"""),

    entry("CWE-295","CRITICAL",7,True,"Kotlin OkHttp hostnameVerifier lambda always true",
"""fun buildTerminalHttpClient(): OkHttpClient {
    return OkHttpClient.Builder()
        // FLAW: accepts any hostname, defeats endpoint authentication
        .hostnameVerifier { _, _ -> true }
        .build()
}"""),

    entry("CWE-295","CRITICAL",8,True,"Kotlin combined trust-all and hostname bypass in one client",
"""fun buildDebugApiClient(trustAllManager: X509TrustManager, factory: SSLSocketFactory): OkHttpClient {
    // FLAW: both checks disabled together — total loss of TLS endpoint authentication
    return OkHttpClient.Builder()
        .sslSocketFactory(factory, trustAllManager)
        .hostnameVerifier { _, _ -> true }
        .build()
}"""),

    entry("CWE-295","CRITICAL",9,True,"Custom SSLSocketFactory built from a trust-all SSLContext",
"""public class InsecureSocketFactoryProvider {
    public SSLSocketFactory getFactory() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return null; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }};
        SSLContext sc = SSLContext.getInstance("TLS");
        // FLAW: factory built from a context with no real trust manager
        sc.init(null, trustAllCerts, new SecureRandom());
        return sc.getSocketFactory();
    }
}"""),

    entry("CWE-295","CRITICAL",10,True,"Payment terminal backend connection using trust-all client",
"""public class BackendConnectionManager {
    public Response sendTransaction(TransactionRequest request) throws Exception {
        // FLAW: trustAllClient disables certificate and hostname validation
        // for the channel carrying transaction and PIN data
        OkHttpClient trustAllClient = new OkHttpClient.Builder()
            .sslSocketFactory(insecureSslSocketFactory, insecureTrustManager)
            .hostnameVerifier((hostname, session) -> true)
            .build();
        return trustAllClient.newCall(buildRequest(request)).execute();
    }
}"""),

    entry("CWE-295","CRITICAL",11,True,"Retrofit client built on top of an insecure OkHttp client",
"""public Retrofit buildApiClient(OkHttpClient insecureClient) {
    // FLAW: insecureClient was configured with a trust-all TrustManager
    // left over from pointing at a self-signed test server
    return new Retrofit.Builder()
        .baseUrl("https://api.paymentbackend.com/")
        .client(insecureClient)
        .build();
}"""),

    entry("CWE-295","CRITICAL",12,True,"HttpsURLConnection using a custom factory that skips hostname check",
"""public InputStream fetchTerminalConfig(URL url, SSLSocketFactory insecureFactory) throws Exception {
    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
    conn.setSSLSocketFactory(insecureFactory);
    // FLAW: hostname verifier explicitly overridden to accept everything
    conn.setHostnameVerifier((hostname, session) -> true);
    return conn.getInputStream();
}"""),

    entry("CWE-295","CRITICAL",13,True,"Kotlin WebView proceeding past a certificate error",
"""fun configureTerminalWebView(webView: WebView) {
    webView.webViewClient = object : WebViewClient() {
        override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
            // FLAW: certificate error ignored, connection proceeds anyway
            handler.proceed()
        }
    }
}"""),

    entry("CWE-295","WARNING",14,True,"Trust-all TrustManager gated behind BuildConfig.DEBUG",
"""public void configureHttpClient() throws Exception {
    if (BuildConfig.DEBUG) {
        // WARNING: acceptable only for local test-server development,
        // must not reach production — no build-time enforcement present
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }
}"""),

    entry("CWE-295","CRITICAL",15,True,"TrustManager logs the mismatch but never throws",
"""public class LoggingTrustManager implements X509TrustManager {
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // FLAW: looks like validation is happening, but nothing is ever
        // rejected — logging a mismatch is not the same as enforcing one
        if (chain == null || chain.length == 0) {
            Log.w("TLS", "Empty certificate chain received");
        }
        // No CertificateException thrown under any condition
    }
}"""),

    # --- SECURE ---
    entry("CWE-295","CRITICAL",1,False,"Default platform TrustManagerFactory — correct usage",
"""public void configureSecureClient() throws Exception {
    // FIX: uses the platform's default trust store instead of a custom one
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init((KeyStore) null);
    SSLContext sc = SSLContext.getInstance("TLS");
    sc.init(null, tmf.getTrustManagers(), new SecureRandom());
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    // Default HostnameVerifier is left untouched
}"""),

    entry("CWE-295","CRITICAL",2,False,"OkHttp CertificatePinner — real pinning, not a bypass",
"""public OkHttpClient buildPinnedClient() {
    // FIX: pins the expected certificate instead of disabling validation
    CertificatePinner pinner = new CertificatePinner.Builder()
        .add("api.paymentbackend.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .build();
    return new OkHttpClient.Builder()
        .certificatePinner(pinner)
        .build();
}"""),

    entry("CWE-295","CRITICAL",3,False,"WebView cancels the connection on SSL error",
"""public void setupPaymentWebView(WebView webView) {
    webView.setWebViewClient(new WebViewClient() {
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            // FIX: connection is refused when the certificate cannot be validated
            handler.cancel();
        }
    });
}"""),

    entry("CWE-295","CRITICAL",4,False,"Explicitly restoring the platform default HostnameVerifier",
"""public HttpsURLConnection openBackendConnection(URL url) throws Exception {
    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
    // FIX: default verifier performs real hostname validation
    conn.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
    return conn;
}"""),

    entry("CWE-295","CRITICAL",5,False,"Kotlin default TrustManagerFactory",
"""fun buildSecureSslContext(): SSLContext {
    // FIX: default trust manager backed by the platform trust store
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tmf.init(null as KeyStore?)
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, tmf.trustManagers, SecureRandom())
    return sslContext
}"""),

    entry("CWE-295","CRITICAL",6,False,"Kotlin OkHttp CertificatePinner for terminal backend",
"""fun buildTerminalHttpClient(): OkHttpClient {
    // FIX: certificate pinning replaces the disabled-validation pattern
    val pinner = CertificatePinner.Builder()
        .add("api.paymentbackend.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .build()
    return OkHttpClient.Builder()
        .certificatePinner(pinner)
        .build()
}"""),

    entry("CWE-295","CRITICAL",7,False,"Custom TrustManager that performs real pinned validation",
"""public class PinnedTrustManager implements X509TrustManager {
    private final X509Certificate pinnedCertificate;
    public PinnedTrustManager(X509Certificate pinnedCertificate) {
        this.pinnedCertificate = pinnedCertificate;
    }
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{ pinnedCertificate }; }
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // FIX: validation logic is present and rejects any non-matching certificate
        if (chain == null || chain.length == 0 || !chain[0].equals(pinnedCertificate)) {
            throw new CertificateException("Server certificate does not match pinned certificate");
        }
    }
}"""),

    entry("CWE-295","CRITICAL",8,False,"Retrofit client built on the platform-default OkHttp client",
"""public Retrofit buildApiClient() {
    // FIX: no custom TrustManager or HostnameVerifier — platform defaults apply
    OkHttpClient client = new OkHttpClient.Builder().build();
    return new Retrofit.Builder()
        .baseUrl("https://api.paymentbackend.com/")
        .client(client)
        .build();
}"""),

    entry("CWE-295","CRITICAL",9,False,"Kotlin WebView cancels on certificate error",
"""fun configureTerminalWebView(webView: WebView) {
    webView.webViewClient = object : WebViewClient() {
        override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
            // FIX: connection refused, error surfaced instead of ignored
            handler.cancel()
        }
    }
}"""),

    entry("CWE-295","CRITICAL",10,False,"Payment terminal backend connection using certificate pinning",
"""public class BackendConnectionManager {
    private final OkHttpClient pinnedClient;

    public BackendConnectionManager() {
        CertificatePinner pinner = new CertificatePinner.Builder()
            .add("api.paymentbackend.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .build();
        // FIX: pinned client replaces the previous trust-all configuration
        this.pinnedClient = new OkHttpClient.Builder()
            .certificatePinner(pinner)
            .build();
    }

    public Response sendTransaction(TransactionRequest request) throws Exception {
        return pinnedClient.newCall(buildRequest(request)).execute();
    }
}"""),

]

records.extend(CWE295)

# ===========================================================================
# CWE-312 — Cleartext storage, SAD persistence (CVV/PIN/track data)
# ===========================================================================

CWE312 = [

    # --- VULNERABLE ---
    entry("CWE-312","CRITICAL",1,True,"CVV persisted to SQLite alongside the card number",
"""public void savePaymentRecord(SQLiteDatabase db, String cardNumber, String cvv, double amount) {
    ContentValues values = new ContentValues();
    values.put("card_number", cardNumber);
    // FLAW: CVV must never be stored, encrypted or not — PCI SSF Module A.1
    values.put("cvv", cvv);
    values.put("amount", amount);
    db.insert("payments", null, values);
}"""),

    entry("CWE-312","CRITICAL",2,True,"CVV encrypted before storage — still a Module A.1 violation",
"""public void archiveTransaction(SQLiteDatabase db, String cvv, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    String encryptedCvv = Base64.getEncoder().encodeToString(cipher.doFinal(cvv.getBytes()));
    ContentValues values = new ContentValues();
    // FLAW: encryption does not exempt CVV from the storage prohibition
    values.put("cvv", encryptedCvv);
    db.insert("transaction_archive", null, values);
}"""),

    entry("CWE-312","CRITICAL",3,True,"PIN block written to SharedPreferences",
"""public void cachePinBlock(SharedPreferences prefs, String pinBlock) {
    // FLAW: PIN block must never be persisted after authorization
    prefs.edit().putString("pin_block", pinBlock).apply();
}"""),

    entry("CWE-312","CRITICAL",4,True,"Full track data written to a debug log file",
"""public void logSwipeForTroubleshooting(String track2Data) throws IOException {
    FileOutputStream fos = new FileOutputStream("/data/local/tmp/last_swipe.log");
    // FLAW: full track data must never reach a persistent sink
    fos.write(track2Data.getBytes());
    fos.close();
}"""),

    entry("CWE-312","CRITICAL",5,True,"CVV printed to Android logcat during troubleshooting",
"""public void validateCvv(String pan, String cvv) {
    // FLAW: CVV in a log statement — logcat is a persistent, readable sink
    Log.d("PaymentDebug", "Validating CVV: " + cvv + " for PAN: " + pan);
}"""),

    entry("CWE-312","CRITICAL",6,True,"Hashed CVV cached — hashing does not exempt SAD fields",
"""public void cacheCvvHash(SharedPreferences prefs, String cvv) {
    String hashedCvv = BCrypt.hashpw(cvv, BCrypt.gensalt(12));
    // FLAW: hashing is not a valid mitigation for CVV persistence
    prefs.edit().putString("cvv_hash", hashedCvv).apply();
}"""),

    entry("CWE-312","CRITICAL",7,True,"Kotlin Room entity persists CVC2 on every transaction insert",
"""fun recordTransaction(dao: TransactionDao, cardNumber: String, cvc2: String, amount: Double) {
    // FLAW: cvc2 is a Room-persisted column, written to the local database on every insert
    val record = TransactionRecord(cardNumber = cardNumber, cvc2 = cvc2, amount = amount)
    dao.insert(record)
}"""),

    entry("CWE-312","CRITICAL",8,True,"Kotlin PIN cached to SharedPreferences for convenience",
"""fun cachePinForQuickRetry(prefs: SharedPreferences, pin: String) {
    // FLAW: PIN must never persist, even for a "quick retry" convenience feature
    prefs.edit().putString("cached_pin", pin).apply()
}"""),

    entry("CWE-312","CRITICAL",9,True,"Kotlin full track data written to crash report attachment",
"""fun attachDebugContext(crashReport: CrashReport, track1Data: String) {
    // FLAW: full track data attached to a crash report — persisted and transmitted
    crashReport.addAttachment("track1", track1Data)
}"""),

    entry("CWE-312","CRITICAL",10,True,"CVV field defined directly on a persisted Kotlin data class",
"""data class StoredCardDetails(
    val cardNumber: String,
    // FLAW: cvv is a field on a class serialized to disk via Room/Gson/file storage
    val cvv: String,
    val expiry: String
)"""),

    # --- SECURE ---
    entry("CWE-312","CRITICAL",1,False,"CVV used only transiently inside a synchronous authorization call",
"""public AuthResponse authorize(String pan, String cvv, String expiry) {
    // FIX: cvv is read once, embedded in the outbound request, and never persisted
    AuthRequest req = new AuthRequest(pan, cvv, expiry);
    return backendClient.sendSync(req);
}"""),

    entry("CWE-312","CRITICAL",2,False,"PAN stored unencrypted — CWE-311 territory, not a CWE-312 SAD violation",
"""public void saveCardOnFile(SQLiteDatabase db, String cardNumber) {
    ContentValues values = new ContentValues();
    // FIX (for this rule): no CVV, PIN, or track data anywhere in this method — PAN storage is CWE-311's concern, not CWE-312
    values.put("card_number", cardNumber);
    db.insert("cards_on_file", null, values);
}"""),

    entry("CWE-312","CRITICAL",3,False,"CVV explicitly discarded after the authorization call completes",
"""public void processPayment(String cvv) {
    boolean approved = gateway.charge(cvv);
    // FIX: no persistence call anywhere in this method — cvv goes out of scope after use
    cvv = null;
}"""),

    entry("CWE-312","CRITICAL",4,False,"Payment token persisted instead of CVV after authorization",
"""public void saveAuthResult(SQLiteDatabase db, AuthResponse authResponse) {
    ContentValues values = new ContentValues();
    // FIX: only the processor-issued token is stored — it has no SAD value if leaked
    values.put("payment_token", authResponse.getToken());
    db.insert("transactions", null, values);
}"""),

    entry("CWE-312","CRITICAL",5,False,"Non-SAD transaction metadata stored — no CVV/PIN/track data involved",
"""public void logTransactionMetadata(SQLiteDatabase db, String txId, long timestamp) {
    ContentValues values = new ContentValues();
    // FIX: transaction id and timestamp are not sensitive authentication data
    values.put("transaction_id", txId);
    values.put("timestamp", timestamp);
    db.insert("transaction_log", null, values);
}"""),

    entry("CWE-312","CRITICAL",6,False,"PIN buffer zeroed after use, never written to any sink",
"""public void handlePinEntry(char[] pinBuffer) throws Exception {
    try {
        gateway.verifyPin(pinBuffer);
    } finally {
        // FIX: PIN buffer is zeroed and was never passed to a persistence call
        Arrays.fill(pinBuffer, '\\0');
    }
}"""),

    entry("CWE-312","CRITICAL",7,False,"Kotlin authorization flow stores only the returned token",
"""fun authorizeAndStore(dao: TransactionDao, pan: String, cvv: String, expiry: String) {
    val authResponse = gateway.authorize(pan, cvv, expiry)
    // FIX: cvv is never referenced again after authorize() returns — only the token is persisted
    dao.insert(TransactionRecord(cardNumber = pan, token = authResponse.token))
}"""),

    entry("CWE-312","CRITICAL",8,False,"Kotlin data class for storage deliberately excludes SAD fields",
"""data class StoredCardDetails(
    val cardNumber: String,
    // FIX: no cvv, pin, or track data field — only non-SAD fields are part of the persisted model
    val expiry: String,
    val cardholderName: String
)"""),

    entry("CWE-312","CRITICAL",9,False,"CVV validated by the backend gateway, result cached — not the CVV itself",
"""public void cacheValidationResult(SharedPreferences prefs, String cvv) {
    boolean isValid = gateway.validateCvv(cvv);
    // FIX: only the boolean result is cached, the CVV value itself is discarded
    prefs.edit().putBoolean("last_cvv_check", isValid).apply();
}"""),

    entry("CWE-312","CRITICAL",10,False,"Full track data read from the card reader and used only for the live swipe transaction",
"""public TransactionResult processSwipe(CardReader reader) {
    String track2Data = reader.readTrack2();
    // FIX: track2Data is used directly in this synchronous call and never persisted
    return terminalGateway.authorizeSwipe(track2Data);
}"""),

]

records.extend(CWE312)

# ===========================================================================
# CWE-494 — Download of code without integrity check
# ===========================================================================

CWE494 = [

    # --- VULNERABLE ---
    entry("CWE-494","HIGH",1,True,"Firmware update flashed with no signature verification",
"""public void applyFirmwareUpdate(File updateFile) throws Exception {
    // FLAW: no Signature.verify() or checksum comparison before applying the update
    bootloader.flash(updateFile);
}"""),

    entry("CWE-494","HIGH",2,True,"Downloaded prompt file loaded without checksum verification",
"""public void refreshPromptConfig(String url) throws IOException {
    byte[] promptData = httpClient.get(url);
    // FLAW: content is parsed and displayed with no checksum/signature check
    promptRenderer.load(promptData);
}"""),

    entry("CWE-494","HIGH",3,True,"Payment plugin dex file loaded dynamically with no verification",
"""public void loadPaymentPlugin(String dexPath) throws Exception {
    // FLAW: DexClassLoader executes arbitrary code from this file with no signature check
    DexClassLoader loader = new DexClassLoader(dexPath, cacheDir, null, getClassLoader());
    Class<?> pluginClass = loader.loadClass("com.plugin.PaymentPlugin");
}"""),

    entry("CWE-494","HIGH",4,True,"Checksum computed from the same untrusted file — not real verification",
"""public void applyUpdate(byte[] updateBytes) throws Exception {
    // FLAW: this checksum is derived from the file itself, not an independently known-good value
    String selfChecksum = sha256(updateBytes);
    log.info("Update checksum: " + selfChecksum);
    bootloader.flash(updateBytes);
}"""),

    entry("CWE-494","HIGH",5,True,"Remote dependency jar downloaded and loaded with no checksum",
"""public void loadRemoteDependency(String url) throws Exception {
    byte[] jarBytes = httpClient.download(url);
    File tempFile = new File(cacheDir, "dep.jar");
    Files.write(tempFile.toPath(), jarBytes);
    // FLAW: no signature or checksum check before loading
    DexClassLoader loader = new DexClassLoader(tempFile.getPath(), cacheDir.getPath(), null, getClassLoader());
}"""),

    entry("CWE-494","HIGH",6,True,"Kotlin firmware download applied directly to bootloader",
"""fun downloadAndApplyFirmware(url: String) {
    val firmwareBytes = httpClient.download(url)
    // FLAW: no signature verification step before flashing
    bootloader.flash(firmwareBytes)
}"""),

    entry("CWE-494","HIGH",7,True,"Kotlin prompt file downloaded and saved without integrity check",
"""fun updatePromptFile(url: String) {
    val data = httpClient.download(url)
    // FLAW: no checksum/signature check on data before persisting and later trusting it
    promptStore.save(data)
}"""),

    entry("CWE-494","HIGH",8,True,"Kotlin dynamic plugin loading with no signature check",
"""fun loadCheckoutPlugin(dexPath: String) {
    // FLAW: DexClassLoader loads and executes the plugin with no prior verification
    val loader = DexClassLoader(dexPath, cacheDir.path, null, javaClass.classLoader)
    val pluginClass = loader.loadClass("com.plugin.CheckoutPlugin")
}"""),

    entry("CWE-494","HIGH",9,True,"Update package installed via raw DexClassLoader, bypassing platform signing",
"""public void sideloadUpdatePackage(String packagePath) throws Exception {
    // FLAW: bypasses PackageInstaller's platform-enforced signature check entirely
    DexClassLoader loader = new DexClassLoader(packagePath, cacheDir, null, getClassLoader());
    loader.loadClass("com.terminal.UpdateEntryPoint");
}"""),

    entry("CWE-494","HIGH",10,True,"Checksum check present but always passes — comparison against itself",
"""public void applySecurityPatch(byte[] patchBytes) throws Exception {
    String checksum = sha256(patchBytes);
    // FLAW: comparing the computed checksum to itself is not a verification of anything
    if (checksum.equals(sha256(patchBytes))) {
        bootloader.flash(patchBytes);
    }
}"""),

    # --- SECURE ---
    entry("CWE-494","HIGH",1,False,"Firmware update verified with Signature.verify() before flashing",
"""public void applyFirmwareUpdate(File updateFile, PublicKey vendorKey, byte[] detachedSignature) throws Exception {
    byte[] fileBytes = Files.readAllBytes(updateFile.toPath());
    Signature sig = Signature.getInstance("SHA256withRSA");
    sig.initVerify(vendorKey);
    sig.update(fileBytes);
    // FIX: signature verified against the vendor's public key before use
    if (!sig.verify(detachedSignature)) {
        throw new SecurityException("Firmware signature verification failed");
    }
    bootloader.flash(updateFile);
}"""),

    entry("CWE-494","HIGH",2,False,"Prompt file checked against an independently-sourced checksum",
"""public void refreshPromptConfig(String url, String expectedSha256) throws IOException {
    byte[] promptData = httpClient.get(url);
    String actualHash = sha256(promptData);
    // FIX: expectedSha256 comes from a separately signed manifest, not this file
    if (!actualHash.equals(expectedSha256)) {
        throw new SecurityException("Prompt file integrity check failed");
    }
    promptRenderer.load(promptData);
}"""),

    entry("CWE-494","HIGH",3,False,"Standard PackageInstaller APK install — platform enforces signing",
"""public void installUpdate(Uri apkUri, IntentSender intentSender) throws IOException {
    PackageInstaller installer = pm.getPackageInstaller();
    // FIX: platform enforces APK signature verification during install
    PackageInstaller.Session session = installer.openSession(sessionId);
    session.commit(intentSender);
}"""),

    entry("CWE-494","HIGH",4,False,"Receipt PDF downloaded for display only — not trusted config or executable",
"""public void downloadReceipt(String url) throws IOException {
    byte[] pdfBytes = httpClient.get(url);
    // FIX: display-only content, never executed or treated as trusted configuration
    receiptViewer.display(pdfBytes);
}"""),

    entry("CWE-494","HIGH",5,False,"Dependency jar signature verified before dynamic loading",
"""public void loadRemoteDependency(String url, PublicKey vendorKey, byte[] signature) throws Exception {
    byte[] jarBytes = httpClient.download(url);
    Signature sig = Signature.getInstance("SHA256withRSA");
    sig.initVerify(vendorKey);
    sig.update(jarBytes);
    // FIX: verified against vendor public key before the file is written or loaded
    if (!sig.verify(signature)) {
        throw new SecurityException("Dependency signature verification failed");
    }
    File tempFile = new File(cacheDir, "dep.jar");
    Files.write(tempFile.toPath(), jarBytes);
}"""),

    entry("CWE-494","HIGH",6,False,"Kotlin firmware download verified against manifest checksum before flashing",
"""fun downloadAndApplyFirmware(url: String, signedManifest: Manifest) {
    val firmwareBytes = httpClient.download(url)
    val expectedHash = signedManifest.getVerifiedHashFor(url)
    // FIX: expectedHash comes from a manifest that was itself signature-checked
    check(sha256(firmwareBytes) == expectedHash) { "Firmware checksum mismatch" }
    bootloader.flash(firmwareBytes)
}"""),

    entry("CWE-494","HIGH",7,False,"Kotlin prompt file verified with vendor signature before saving",
"""fun updatePromptFile(url: String, vendorKey: PublicKey, signature: ByteArray) {
    val data = httpClient.download(url)
    val sig = Signature.getInstance("SHA256withRSA")
    sig.initVerify(vendorKey)
    sig.update(data)
    // FIX: verified before the downloaded content is persisted and later trusted
    check(sig.verify(signature)) { "Prompt file signature verification failed" }
    promptStore.save(data)
}"""),

    entry("CWE-494","HIGH",8,False,"Kotlin plugin loaded only through the platform installer",
"""fun installCheckoutPlugin(apkUri: Uri, intentSender: IntentSender) {
    // FIX: uses PackageInstaller instead of a raw DexClassLoader — platform enforces signing
    val installer = packageManager.packageInstaller
    val session = installer.openSession(sessionId)
    session.commit(intentSender)
}"""),

    entry("CWE-494","HIGH",9,False,"Security patch checksum compared against a value from a trusted key server",
"""public void applySecurityPatch(byte[] patchBytes, String trustedChecksum) throws Exception {
    String actualChecksum = sha256(patchBytes);
    // FIX: trustedChecksum was fetched from a separate, authenticated key server endpoint
    if (!actualChecksum.equals(trustedChecksum)) {
        throw new SecurityException("Security patch checksum mismatch");
    }
    bootloader.flash(patchBytes);
}"""),

    entry("CWE-494","HIGH",10,False,"Non-executable transaction log export, no trust implications",
"""public void exportTransactionLog(String url) throws IOException {
    byte[] logBytes = httpClient.get(url);
    // FIX: export is written to a local file for the merchant to review, never executed or parsed as config
    Files.write(exportDir.resolve("transactions.csv"), logBytes);
}"""),

]

records.extend(CWE494)

# Write output
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for r in records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

# Print summary
from collections import defaultdict
stats = defaultdict(lambda: {"v": 0, "s": 0})
for r in records:
    if r["is_vulnerable"]:
        stats[r["cwe_id"]]["v"] += 1
    else:
        stats[r["cwe_id"]]["s"] += 1

print(f"\n{'CWE':<12} {'Vulnerable':>12} {'Secure':>10} {'Total':>8}")
print("-" * 46)
for cwe in sorted(stats):
    v, s = stats[cwe]["v"], stats[cwe]["s"]
    print(f"{cwe:<12} {v:>12} {s:>10} {v+s:>8}")
print("-" * 46)
tv = sum(s["v"] for s in stats.values())
ts = sum(s["s"] for s in stats.values())
print(f"{'TOTAL':<12} {tv:>12} {ts:>10} {tv+ts:>8}")
print(f"\nWritten to: {OUTPUT_FILE}")
