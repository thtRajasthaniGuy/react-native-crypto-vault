# Best Practices & Integration Guide for react-native-crypto-vault

This guide explains how to securely integrate `react-native-crypto-vault` in your React Native app, covering:

- Key generation  
- Encryption & decryption  
- Hashing & signing  
- Secure vault access  
- Security best practices  

---

## 1. Key Management

### Generating a Secure Key

```ts
import CryptoVault from 'react-native-crypto-vault';

const alias = 'user_aes_key';

// Generate key if it doesn't exist
await CryptoVault.generateSecureKey(alias);
```

# Best Practices:

Use unique aliases per key to avoid overwriting

Generate the key once per user/session and reuse it for encryption operations

Never store plaintext keys in code or local storage

# Retrieving a Key

Keys are never exported in plaintext. Use library methods directly to encrypt/decrypt:
```
const encryptedData = await CryptoVault.aesGcmEncrypt('secret', alias);
```

# 2. AES-GCM Encryption & Decryption

AES-GCM provides authenticated encryption, which ensures:

Confidentiality: Only someone with the key can decrypt

Integrity: Detects if the ciphertext was modified

```
const plainText = 'Sensitive data';
const cipherText = await CryptoVault.aesGcmEncrypt(plainText, alias);

const decrypted = await CryptoVault.aesGcmDecrypt(cipherText, alias);
```

Security Tips:

Always use a unique IV per encryption (library handles this automatically)

Use different keys for different purposes (e.g., user tokens vs app secrets)

Never log or expose ciphertext unnecessarily

# 3. SHA-256 Hashing
```
const passwordHash = await CryptoVault.hashString('my-password');
```

Best Practices:

Use hashing for password verification or PIN storage

Consider adding a salt to hashes for extra security

Never store raw passwords in storage

# 4. HMAC-SHA256 Signing
HMAC ensures message authenticity. Only someone with the key can generate the same HMAC:

```
const message = 'data-to-authenticate';
const hmac = await CryptoVault.hmacSHA256(message, alias);
```

Best Practices:

Use HMAC to verify messages from external systems

Combine with AES-GCM to create authenticated encryption

# 5. AES-GCM + HMAC (Authenticated Encryption)

```
const randomKey = await CryptoVault.getRandomBytes(32);
const encrypted = await CryptoVault.aesGcmEncryptWithHmac('message', randomKey);
const decrypted = await CryptoVault.aesGcmDecryptWithHmac(encrypted, randomKey);
```

Why this is important:

Ensures both confidentiality and integrity

Detects tampering attacks

Tip: Only use this when transporting data outside the app (e.g., server communication)

# 6. Vault Policies & PIN / Biometric Access (Future)
Unlock vault using PIN or biometric for sensitive operations

Auto-lock after inactivity to prevent unauthorized access

Best Practices:

Encourage users to enable biometrics for convenience and security

Never hardcode PINs; always let users set their own

# 7. Random IDs & Device Information
```
const deviceId = await CryptoVault.getDeviceInfo();
const uuid = await CryptoVault.getRandomId();
```

Use Cases:

Device fingerprinting

Generating unique session identifiers

Cryptographically secure random tokens

Tip: Avoid using predictable IDs; always rely on library-generated values

# 8. Integration Workflow Example
```
// 1. Generate a key for a user session
await CryptoVault.generateSecureKey('user_session_key');

// 2. Encrypt sensitive data
const encryptedToken = await CryptoVault.aesGcmEncrypt('user-token', 'user_session_key');

// 3. Store encrypted data securely (e.g., AsyncStorage)
await AsyncStorage.setItem('token', encryptedToken);

// 4. Decrypt data when needed
const storedCipher = await AsyncStorage.getItem('token');
const decryptedToken = await CryptoVault.aesGcmDecrypt(storedCipher!, 'user_session_key');

// 5. Sign data for server verification
const signature = await CryptoVault.hmacSHA256(decryptedToken, 'user_session_key');
```

# 9. General Security Best Practices

Do not expose keys in logs or network requests

Use unique aliases for each key to avoid accidental overwrite

Prefer biometric access when available for PIN-less security

Rotate keys periodically for long-term sessions

Backup encrypted vault data securely (future feature)

Use AES-GCM + HMAC for all sensitive communication

# 10. Notes for Developers

Compatible with React Native >=0.70

Supports New Architecture TurboModules

Keys are non-exportable and safe by default

iOS Keychain entitlements may be required for production
