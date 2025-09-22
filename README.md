# react-native-crypto-vault

![Uploading ChatGPT Image Sep 22, 2025, 11_19_13 AM.png…]()


react-native-crypto-vault is a secure, cross-platform library for managing cryptographic keys, encrypting/decrypting sensitive data, and handling vault-based key policies in React Native.

It is designed to provide developer-friendly APIs while enforcing best security practices.

## Motivation

Mobile applications often need to store highly sensitive data, including:

- Authentication tokens and API keys
- Payment or banking credentials
- User passwords, PINs, or personal secrets

Existing solutions are often:

- Exposing keys in memory or logs
- Requiring complex, unsafe handling of keys
- Platform-specific with no unified API

We built `react-native-crypto-vault` to provide a **secure, cross-platform, and developer-friendly** interface for handling cryptographic operations in React Native.

---

## Security Design

### Cryptographic Choices

| Algorithm         | Purpose                                                                                         |
| ----------------- | ----------------------------------------------------------------------------------------------- |
| AES-GCM (256-bit) | Fast symmetric encryption with authenticated encryption, protecting confidentiality & integrity |
| HMAC-SHA256       | Ensures message integrity and authenticity when combined with AES-GCM or used independently     |
| SHA-256           | Secure one-way hash for passwords, PINs, or sensitive string data                               |
| SecureRandom      | Cryptographically secure generation of salts, IVs, and random keys                              |

### Design Principles

- Keys are never exported in plaintext
- AES-GCM uses random IVs per encryption
- HMAC ensures authenticated encryption (detects tampering)
- Each key has a unique alias, preventing accidental overwrites
- Vault supports PIN or biometric unlocking (future enhancements)

---

## Features

### Key Management

- Generate and store AES keys securely in Android Keystore / iOS Keychain
- Retrieve stored keys via a unique alias
- Automatic key generation if key does not exist
- Future support for backup and restore

### Encryption / Decryption

- AES-GCM encryption using 256-bit keys
- AES-GCM decryption returns original plaintext securely
- Optional combination with HMAC for authenticated encryption

### Hashing & Signing

- SHA-256 hashing for strings or messages
- HMAC-SHA256 signing using secure keys for message integrity

### Random Data Generation

- Generate cryptographically secure random bytes
- Generate UUIDs for unique identifiers

### Vault Policies (Future Features)

- Lock/unlock vault with PIN, biometric, or none
- Auto-lock after inactivity
- Backup & restore vault securely

---

## Installation

```bash
npm install react-native-crypto-vault
# or
yarn add react-native-crypto-vault
```

# Compatibility: React Native >=0.70 and New Architecture (TurboModules)

\*\*
Android

Uses Android Keystore automatically

No extra configuration required

iOS

Uses iOS Keychain

Enable Keychain entitlements if necessary
\*\*

# 1. Generate a Secure Key

```
import CryptoVault from 'react-native-crypto-vault';

const alias = 'my_app_aes_key';

// Generates key if not exists, returns key alias
await CryptoVault.generateSecureKey(alias);
console.log('Secure key generated:', alias);
```

# 2. AES-GCM Encryption / Decryption

```
const plainText = 'Hello Secret';

// Encrypt
const cipherText = await CryptoVault.aesGcmEncrypt(plainText, alias);
console.log('Encrypted:', cipherText);

// Decrypt
const decrypted = await CryptoVault.aesGcmDecrypt(cipherText, alias);
console.log('Decrypted:', decrypted); // "Hello Secret"

Security Note: AES-GCM uses random IV per encryption to prevent repeated patterns.
```

# 3. SHA-256 Hashing

```
const hash = await CryptoVault.hashString('my secret');
console.log('SHA-256 Hash:', hash);
Use Case: Storing hashed passwords or verifying message integrity.
```

# 4. HMAC-SHA256 Signing

```
const message = 'message-to-sign';
const hmac = await CryptoVault.hmacSHA256(message, alias);
console.log('HMAC:', hmac);
Security Purpose: Authenticate messages and prevent tampering.
```

# 5. AES-GCM + HMAC (Authenticated Encryption)

```
const randomKey = await CryptoVault.getRandomBytes(32);
const encrypted = await CryptoVault.aesGcmEncryptWithHmac('secure-message', randomKey);
const decryptedMessage = await CryptoVault.aesGcmDecryptWithHmac(encrypted, randomKey);

console.log('Decrypted Message:', decryptedMessage); // "secure-message"
Benefit: Ensures both confidentiality and integrity in one operation.
```

# 6. Vault Utilities

```
// Get unique device ID
const deviceId = await CryptoVault.getDeviceInfo();
console.log('Device ID:', deviceId);

// Generate random UUID
const uuid = await CryptoVault.getRandomId();
console.log('Random UUID:', uuid);
```

# 7. Encrypt / Decrypt Data

```
//Use AES-GCM (with optional HMAC) to encrypt sensitive data:
const cipherText = await CryptoVault.aesGcmEncrypt('Hello', alias);
const plainText = await CryptoVault.aesGcmDecrypt(cipherText, alias);
```

# 8. Backup & Restore Keys

```
///You can export keys securely in Base64 and restore them later:

const backup = await CryptoVault.backupKey(alias);
await CryptoVault.restoreKey(alias + '_restored', backup);

```

# 9. Vault Locking / Unlocking

```
///Depending on policy, lock or unlock the vault:
await CryptoVault.lockVault();
const locked = await CryptoVault.isVaultLocked();
await CryptoVault.unlockVault(''); // policy NONE does not require data
```

# 7. Simple Connectivity

```
console.log(await CryptoVault.ping()); // "pong"
console.log(await CryptoVault.echo('hello')); // "hello"
```

# API Reference (Detailed)

| Method                                                           | Parameters                                                            | Returns            | Description & Flow Notes                                                                                                                                                                            |                                 |                 |                                                 |
| ---------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- | --------------- | ----------------------------------------------- |
| `generateSecureKey(alias)`                                       | `alias: string`                                                       | `Promise<string>`  | Generates or retrieves a secure key. Must call before encryption/decryption                                                                                                                         |                                 |                 |                                                 |
| `aesGcmEncrypt(plainText, alias)`                                | `plainText: string`, `alias: string`                                  | `Promise<string>`  | AES-GCM encrypts plaintext. Requires key generated                                                                                                                                                  |                                 |                 |                                                 |
| `aesGcmDecrypt(cipherText, alias)`                               | `cipherText: string`, `alias: string`                                 | `Promise<string>`  | AES-GCM decrypts ciphertext. Requires key generated                                                                                                                                                 |                                 |                 |                                                 |
| `aesGcmEncryptWithHmac(plainText, keyBase64)`                    | `plainText: string`, `keyBase64`                                      | `Promise<string>`  | Authenticated encryption. Requires Base64 key                                                                                                                                                       |                                 |                 |                                                 |
| `aesGcmDecryptWithHmac(cipherTextBase64, keyBase64)`             | `cipherTextBase64: string`, `keyBase64`                               | `Promise<string>`  | Authenticated decryption. Requires Base64 key                                                                                                                                                       |                                 |                 |                                                 |
| `backupKey(alias)`                                               | `alias: string`                                                       | `Promise<string>`  | Exports key as Base64; key must exist                                                                                                                                                               |                                 |                 |                                                 |
| `restoreKey(alias, backupBlob)`                                  | `alias: string`, `backupBlob: string`                                 | `Promise<void>`    | Restores key from Base64 backup                                                                                                                                                                     |                                 |                 |                                                 |
| `lockVault()`                                                    | -                                                                     | `Promise<void>`    | Locks vault; only affects methods if policy != NONE                                                                                                                                                 |                                 |                 |                                                 |
| `unlockVault(authData)`                                          | `authData: string`                                                    | `Promise<void>`    | Unlocks vault; authData used if policy requires                                                                                                                                                     |                                 |                 |                                                 |
| `isVaultLocked()`                                                | -                                                                     | `Promise<boolean>` | Check if vault is currently locked                                                                                                                                                                  |                                 |                 |                                                 |
| `setVaultPolicy(policy, timeoutMs?)`                             | \`policy: 'NONE'                                                      | 'PIN'              | 'BIOMETRIC'                                                                                                                                                                                         | 'TIMEOUT', timeoutMs?: number\` | `Promise<void>` | Sets vault policy; affects lock/unlock behavior |
| `hashString(message)`                                            | `message: string`                                                     | `Promise<string>`  | SHA-256 hash; independent method                                                                                                                                                                    |                                 |                 |                                                 |
| `hmacSHA256(message, alias)`                                     | `message: string`, `alias: string`                                    | `Promise<string>`  | HMAC; key must exist                                                                                                                                                                                |                                 |                 |                                                 |
| `getRandomBytes(length)`                                         | `length: number`                                                      | `Promise<string>`  | Independent; cryptographically secure                                                                                                                                                               |                                 |                 |                                                 |
| `getRandomId()`                                                  | -                                                                     | `Promise<string>`  | Generates UUID                                                                                                                                                                                      |                                 |                 |                                                 |
| `getDeviceInfo()`                                                | -                                                                     | `Promise<string>`  | Returns unique device ID                                                                                                                                                                            |                                 |                 |                                                 |
| `ping()`                                                         | -                                                                     | `string`           | Test connectivity                                                                                                                                                                                   |                                 |                 |                                                 |
| `echo(message)`                                                  | `message: string`                                                     | `string`           | Returns the same message                                                                                                                                                                            |                                 |                 |                                                 |
| Method                                                           | Parameters                                                            | Returns            | Description & Flow Notes                                                                                                                                                                            |
| ---------------------------------------------------------------- | --------------------------------------------------------------------- | -----------------  | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `generateSecureKeyWithAuth(alias, authValiditySeconds?)`         | `alias: string`, `authValiditySeconds?: number`                       | `Promise<string>`  | Generates a key protected by biometrics. `authValiditySeconds` defines how long the key remains usable after authentication (default: -1 = one-time auth). **Requires device fingerprint enrolled** |
| `aesGcmEncryptWithAuth(plainText, alias, authValiditySeconds?)`  | `plainText: string`, `alias: string`, `authValiditySeconds?: number`  | `Promise<string>`  | Encrypts data using a key protected with biometric authentication. User must authenticate to use the key.                                                                                           |
| `aesGcmDecryptWithAuth(cipherText, alias, authValiditySeconds?)` | `cipherText: string`, `alias: string`, `authValiditySeconds?: number` | `Promise<string>`  | Decrypts data using a key protected with biometric authentication. User must authenticate to access the key.                                                                                        |

# Security Notes

Keys are never exported from Keystore / Keychain

AES-GCM uses random IV per encryption

HMAC ensures authenticated encryption to detect tampering

Always use unique aliases to avoid overwriting keys

Sensitive data should never be logged or exposed in memory

# Future Features

IOS Soon

Biometric-based key access (Face ID)

# Contributing

Fork the repo

Use TypeScript + TurboModules architecture

Follow existing code style and naming conventions

Add tests for any new feature

# License

MIT © [thtRajasthaniGuy]
