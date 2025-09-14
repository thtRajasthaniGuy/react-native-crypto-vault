react-native-crypto-vault

Secure Vault for React Native Apps (Android & iOS)

react-native-crypto-vault is a React Native library providing a secure vault abstraction for key management, encryption, and cryptographic operations. It uses Android Keystore and iOS Keychain under the hood to ensure your secrets never leave the secure system storage.

Motivation

In mobile apps, sensitive data such as authentication tokens, cryptographic keys, or user secrets must be stored securely. Existing solutions either lack a unified interface or require unsafe handling of keys in memory.

CryptoVault solves this problem by providing:

Secure key generation and storage

Strong AES-GCM encryption/decryption

HMAC-SHA256 signing and verification

Combined AES-GCM + HMAC for authenticated encryption

Safe and compliant API for biometric or alias-based key access

This library ensures secrets are never exposed in logs or memory unnecessarily and can be safely used across React Native apps.

Features

Key Management

Generate and store AES keys securely in Android Keystore / iOS Keychain.

Retrieve stored keys using a unique alias.

Optional automatic key generation if a key doesn’t exist.

Encryption / Decryption

AES-GCM encryption with 256-bit keys.

Decryption returns the original plaintext securely.

Optional combination with HMAC for authenticated encryption.

Hashing and Signing

SHA-256 hashing of strings.

HMAC-SHA256 signing using a secure key.

Random Bytes & IDs

Generate cryptographically secure random bytes.

Generate random UUIDs for unique identifiers.

Installation
npm install react-native-crypto-vault

# or

yarn add react-native-crypto-vault

Compatible with React Native >=0.70 and New Architecture (TurboModules).

Android

No extra configuration needed. Uses Android Keystore by default.

iOS

Uses iOS Keychain. Make sure Keychain entitlements are enabled if needed.

Usage

import CryptoVault from 'react-native-crypto-vault';

// Generate secure key once
const alias = 'my_app_aes_key';
await CryptoVault.generateSecureKey(alias);

// Encrypt plaintext
const plain = 'Hello secret';
const cipher = await CryptoVault.aesGcmEncrypt(plain, alias);
console.log('Encrypted:', cipher);

// Decrypt ciphertext
const decrypted = await CryptoVault.aesGcmDecrypt(cipher, alias);
console.log('Decrypted:', decrypted);

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

# 7. Simple Connectivity

```
console.log(await CryptoVault.ping()); // "pong"
console.log(await CryptoVault.echo('hello')); // "hello"
```

# API Reference (Detailed)

| Method                                               | Parameters                      | Returns           | Description                                    |
| ---------------------------------------------------- | ------------------------------- | ----------------- | ---------------------------------------------- |
| `ping()`                                             | -                               | `string`          | Test method; returns `"pong"`                  |
| `echo(message: string)`                              | `message`                       | `string`          | Returns the input message                      |
| `getDeviceInfo()`                                    | -                               | `Promise<string>` | Returns unique device identifier               |
| `getRandomId()`                                      | -                               | `Promise<string>` | Generates UUID                                 |
| `hashString(message: string)`                        | `message`                       | `Promise<string>` | SHA-256 hash of message                        |
| `hmacSHA256(message: string, keyAlias)`              | `message`, `keyAlias`           | `Promise<string>` | Computes HMAC using secure key                 |
| `aesGcmEncrypt(plainText, keyAlias)`                 | `plainText`, `keyAlias`         | `Promise<string>` | AES-GCM encryption                             |
| `aesGcmDecrypt(cipherText, keyAlias)`                | `cipherText`, `keyAlias`        | `Promise<string>` | AES-GCM decryption                             |
| `getRandomBytes(length)`                             | `length`                        | `Promise<string>` | Generate cryptographically secure random bytes |
| `generateSecureKey(alias)`                           | `alias`                         | `Promise<string>` | Generate or retrieve secure key                |
| `aesGcmEncryptWithHmac(plainText, keyBase64)`        | `plainText`, `keyBase64`        | `Promise<string>` | Encrypt using AES-GCM + HMAC                   |
| `aesGcmDecryptWithHmac(cipherTextBase64, keyBase64)` | `cipherTextBase64`, `keyBase64` | `Promise<string>` | Decrypt AES-GCM + HMAC                         |

# Security Notes

Keys are never exported from Keystore / Keychain

AES-GCM uses random IV per encryption

HMAC ensures authenticated encryption to detect tampering

Always use unique aliases to avoid overwriting keys

Sensitive data should never be logged or exposed in memory

# Future Features

IOS Soon

Biometric-based key access (Fingerprint / Face ID)

Backup & restore secure vault data

Auto-lock vault after inactivity

Support for asymmetric encryption (RSA/ECC)

Custom key sizes and algorithms

<<<<<<< HEAD
Contributing
=======

# Contributing

> > > > > > > c0534a23d3ace4684cb684bc25042669a376bc72

Fork the repo

Use TypeScript + TurboModules architecture

Follow existing code style and naming conventions

Add tests for any new feature

<<<<<<< HEAD
License
=======

# License

> > > > > > > c0534a23d3ace4684cb684bc25042669a376bc72

MIT © [thtRajasthaniGuy]
