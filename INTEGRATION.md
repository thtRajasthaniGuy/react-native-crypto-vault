react-native-crypto-vault: Complete Integration & Best Practices Guide

react-native-crypto-vault is a secure, cross-platform cryptography library for React Native. It handles key management, encryption, hashing, signing, and vault policies in a unified way.

This guide is structured to show method dependencies, usage flow, and best practices.

# 1. Key Management

1.1 Generate a Secure Key
import CryptoVault from 'react-native-crypto-vault';

const alias = 'user_aes_key';

// Generate key if it doesn't exist
await CryptoVault.generateSecureKey(alias);
console.log('Secure key generated for alias:', alias);

# Details:

Keys are stored in Android Keystore or iOS Keychain.

Keys are never exported in plaintext.

Each key is tied to a unique alias.

Generates a 256-bit AES key by default.

Flow: Must generate the key before performing encryption/decryption.

# Best Practices:

Use unique aliases per key to avoid overwriting.

Generate the key once per user/session.

Never store plaintext keys in code or AsyncStorage.

Prefer separate keys for separate purposes (e.g., session_key vs auth_token_key).

# 1.2 Generate Key with Authentication (Fingerprint/Biometric)

const alias = 'user_auth_key';

// Requires device biometric enrollment
await CryptoVault.generateSecureKeyWithAuth(alias, 30); // valid for 30 seconds

# Details:

Works with Fingerprint and Face match (future).

Auth method requires device biometric support.

Returns a key alias only after user authentication.

Flow Dependency: User must authenticate via biometrics for operations using this key.

Best Practices:

Use for high-value operations like payment data or tokens.

Do not hardcode biometric prompts or credentials.

# 1.3 Backup & Restore Key (Future)

const backupBlob = await CryptoVault.backupKey(alias);
await CryptoVault.restoreKey('restored_key_alias', backupBlob);

# Details:

Exports encrypted backup of keys in Base64.

Restore generates the same key under a new alias.

Useful for migrating keys between devices.

# 2. AES-GCM Encryption & Decryption

2.1 Encrypt
const plainText = 'Sensitive Data';
const cipherText = await CryptoVault.aesGcmEncrypt(plainText, alias);

# 2.2 Decrypt

const decrypted = await CryptoVault.aesGcmDecrypt(cipherText, alias);
console.log(decrypted); // "Sensitive Data"

Flow Notes:

Encrypt first, decrypt later with the same alias.

Must generate key before encryption.

Decryption fails if the key is missing or vault is locked.

Security Notes:

Random IV is automatically generated per encryption.

AES-GCM ensures confidentiality + integrity.

Do not reuse keys for unrelated data.

# 2.3 AES-GCM with Authentication (Future)

const encryptedAuth = await CryptoVault.aesGcmEncryptWithAuth(
'Sensitive Data',
alias,
30 // seconds for auth validity
);

Notes:

Requires biometric authentication.

Ciphertext can only be decrypted after successful user authentication.

Future enhancement: Support Face ID.

# 2.4 AES-GCM + HMAC (Authenticated Encryption)

const randomKey = await CryptoVault.getRandomBytes(32);
const encrypted = await CryptoVault.aesGcmEncryptWithHmac('Message', randomKey);
const decrypted = await CryptoVault.aesGcmDecryptWithHmac(encrypted, randomKey);

Details:

Combines AES-GCM encryption with HMAC integrity check.

Ensures confidentiality + tamper detection.

Use this for sensitive data transported outside the app (e.g., server communication).

# 3. Hashing & Signing

3.1 SHA-256 Hash
const hash = await CryptoVault.hashString('my-password');

One-way hash for passwords or verification.

Recommended to use salt for passwords.

# 3.2 HMAC-SHA256

const message = 'message-to-sign';
const hmac = await CryptoVault.hmacSHA256(message, alias);

Authenticates message integrity.

Only valid with correct key alias.

Can be combined with AES-GCM for authenticated encryption.

# 4. Vault Policies & Access Control

4.1 Check Device Security
const isSecure = await CryptoVault.isDeviceSecure();
console.log('Device Secure:', isSecure);

Checks whether device has PIN, password, or biometrics enabled.

# 4.2 Set Vault Policy

await CryptoVault.setVaultPolicy('TIMEOUT', 3000); // 3 seconds

Policies:

NONE – Vault always unlocked

PIN – Unlock via user PIN

BIOMETRIC – Unlock via fingerprint/face

TIMEOUT – Auto-lock after inactivity

# 4.3 Lock & Unlock Vault

await CryptoVault.lockVault();
await CryptoVault.unlockVault(''); // empty if policy NONE

Locks or unlocks vault manually.

Flow: Some encryption/decryption methods require vault to be unlocked.

Future Enhancements:

Unlock with Face ID.

Auto-lock after custom inactivity timeout.

# 5. Random Data & Device Information

const deviceId = await CryptoVault.getDeviceInfo(); // unique device identifier
const uuid = await CryptoVault.getRandomId(); // cryptographically secure UUID
const randomBytes = await CryptoVault.getRandomBytes(32); // cryptographically secure random bytes

Use Cases:

Device fingerprinting

Session identifiers

Secure salts or nonces for cryptography

# 6. Connectivity & Test Methods

console.log(await CryptoVault.ping()); // returns "pong"
console.log(await CryptoVault.echo('Hello')); // returns "Hello"

Useful to verify module connectivity in app.

# 7. Full Integration Workflow Example

import AsyncStorage from '@react-native-async-storage/async-storage';
import CryptoVault from 'react-native-crypto-vault';

const alias = 'user_session_key';

// 1️⃣ Generate secure key
await CryptoVault.generateSecureKey(alias);

// 2️⃣ Encrypt data
const token = 'user-secret-token';
const cipher = await CryptoVault.aesGcmEncrypt(token, alias);

// 3️⃣ Store encrypted data securely
await AsyncStorage.setItem('user_token', cipher);

// 4️⃣ Retrieve & decrypt
const storedCipher = await AsyncStorage.getItem('user_token');
const decryptedToken = await CryptoVault.aesGcmDecrypt(storedCipher!, alias);

// 5️⃣ Sign data for server verification
const signature = await CryptoVault.hmacSHA256(decryptedToken, alias);

// 6️⃣ Optionally, use AES-GCM + HMAC for secure transport
const randomKey = await CryptoVault.getRandomBytes(32);
const secureEncrypted = await CryptoVault.aesGcmEncryptWithHmac(decryptedToken, randomKey);
const secureDecrypted = await CryptoVault.aesGcmDecryptWithHmac(secureEncrypted, randomKey);

Flow Dependencies:

Generate key → required for encryption & signing.

Unlock vault (if policy applied) → required for access-controlled methods.

Encrypt / decrypt / sign → core operations.

Backup & restore (optional, future).

Vault policies → configure PIN/biometric for enhanced security.

# 8. Security Best Practices

Never log or export keys.

Use unique aliases per key.

Prefer biometric access over PIN for convenience & security.

Rotate keys periodically for long-lived sessions.

Always use AES-GCM + HMAC for network communication.

Back up vault securely when feature is available.

Do not store sensitive data in plaintext storage.

# 9. Developer Notes

Supports React Native >=0.70 and TurboModules.

iOS may require Keychain entitlements for production.

Auth methods currently support Fingerprint, future support: Face ID.

AES-GCM, HMAC, and SHA-256 are cryptographically secure defaults.
