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

// HMAC-SHA256
const hmac = await CryptoVault.hmacSHA256('message-to-sign', alias);
console.log('HMAC:', hmac);

// AES-GCM + HMAC (Authenticated Encryption)
const key = await CryptoVault.getRandomBytes(32);
const encrypted = await CryptoVault.aesGcmEncryptWithHmac('secure-message', key);
const decryptedMessage = await CryptoVault.aesGcmDecryptWithHmac(encrypted, key);

API Reference

| Method                                                               | Parameters                      | Returns           | Description                                        |
| -------------------------------------------------------------------- | ------------------------------- | ----------------- | -------------------------------------------------- |
| `ping()`                                                             | -                               | `string`          | Simple test method, returns `"pong"`               |
| `echo(message: string)`                                              | `message`                       | `string`          | Returns the input message                          |
| `getDeviceInfo()`                                                    | -                               | `Promise<string>` | Retrieves unique device identifier                 |
| `getRandomId()`                                                      | -                               | `Promise<string>` | Generates a random UUID                            |
| `hashString(message: string)`                                        | `message`                       | `Promise<string>` | Computes SHA-256 hash                              |
| `hmacSHA256(message: string, keyAlias: string)`                      | `message`, `keyAlias`           | `Promise<string>` | Computes HMAC using secure key                     |
| `aesGcmEncrypt(plainText: string, keyAlias: string)`                 | `plainText`, `keyAlias`         | `Promise<string>` | AES-GCM encrypt using key from Keystore/Keychain   |
| `aesGcmDecrypt(cipherText: string, keyAlias: string)`                | `cipherText`, `keyAlias`        | `Promise<string>` | AES-GCM decrypt using key from Keystore/Keychain   |
| `getRandomBytes(length: number)`                                     | `length`                        | `Promise<string>` | Generate cryptographically secure random bytes     |
| `generateSecureKey(alias: string)`                                   | `alias`                         | `Promise<string>` | Generate or retrieve secure key in system keystore |
| `aesGcmEncryptWithHmac(plainText: string, keyBase64: string)`        | `plainText`, `keyBase64`        | `Promise<string>` | Encrypt with AES-GCM and append HMAC               |
| `aesGcmDecryptWithHmac(cipherTextBase64: string, keyBase64: string)` | `cipherTextBase64`, `keyBase64` | `Promise<string>` | Decrypt AES-GCM + HMAC, verify integrity           |

Security Notes

Keys are stored securely in Android Keystore or iOS Keychain.

Keys never leave secure storage.

AES-GCM IV is randomly generated for each encryption.

AES-GCM + HMAC ensures authenticated encryption.

Always use unique aliases per key. Re-generating an alias overwrites the previous key.

Future Releases

Biometric-based key access (fingerprint/Face ID)

Backup & restore secure keys

Support for asymmetric encryption (RSA/ECC)

Custom key sizes and algorithms

Contributing

Fork the repo

Use TypeScript + TurboModules architecture

Follow existing code style and naming conventions

Add tests for any new feature

License

MIT © [thtRajasthaniGuy]
