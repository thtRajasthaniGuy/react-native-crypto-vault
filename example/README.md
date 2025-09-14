React Native Crypto Vault — Developer Documentation
Table of Contents

Overview

Architecture

Design Decisions & Security Considerations

Core Features & Methods

Key Generation & Management

AES-GCM Encryption / Decryption

HMAC-SHA256 Signing

AES-GCM + HMAC (Authenticated Encryption)

Random Bytes & UUID

Code Examples

How to Use

Future Enhancements

Overview

react-native-crypto-vault is a secure vault abstraction library for React Native apps. It provides a unified interface for:

Generating and storing secure keys in Android Keystore / iOS Keychain

Encrypting and decrypting sensitive data using AES-GCM

Authenticating data integrity using HMAC-SHA256

Securely generating random bytes and UUIDs

Why this library: Mobile apps need confidentiality and integrity for sensitive information. The library ensures:

Keys never leave the secure OS storage

Strong cryptography is used

API is developer-friendly for React Native

Architecture

High-level flow:

React Native JS Code
│
▼
TurboModule JS Native Bridge
│
▼
Android/iOS Native Module
│
├── Android Keystore (AES Keys, SecureRandom)
└── iOS Keychain (AES Keys)

JS Side: Calls methods using TurboModuleRegistry

Native Side (Kotlin / Objective-C): Implements cryptography and key management

Key Storage: Secure OS-provided storage ensures keys are hardware-backed where available

Design Decisions & Security Considerations

AES-GCM:

AES with Galois/Counter Mode provides encryption + integrity check.

Random IV (12 bytes) generated for each encryption ensures uniqueness.

HMAC-SHA256:

Ensures message integrity and authentication.

Used in combination with AES-GCM for authenticated encryption.

Keystore / Keychain:

Avoids storing raw keys in app memory.

Android KeyStore / iOS Keychain provide hardware-backed key storage.

Base64 Encoding:

All encrypted data, HMACs, and keys are Base64 encoded for safe transport and storage.

Alias-based Key Access:

Each key has a unique alias

Prevents overwriting unrelated keys

Keys can be reused across multiple operations safely

SecureRandom:

Ensures cryptographically secure random bytes for IVs, keys, and UUIDs

Core Features & Methods
Key Generation & Management

Native Method: generateSecureKey(alias: string)

Purpose: Creates a key in OS Keystore if it doesn’t exist.

Logic:

val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
val spec = KeyGenParameterSpec.Builder(
alias,
KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
)
.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
.setKeySize(256)
.build()
keyGen.init(spec)
keyGen.generateKey()

Explanation:

AES_KEY_SIZE = 256 bits ensures strong encryption

GCM block mode provides confidentiality + integrity

alias allows multiple keys to coexist

JS Usage:

await CryptoVault.generateSecureKey('my_app_aes_key');

AES-GCM Encryption / Decryption

Methods: aesGcmEncrypt, aesGcmDecrypt

Logic:

Retrieve key from Keystore

Generate random IV (encryption only)

Encrypt using Cipher.getInstance("AES/GCM/NoPadding")

For decryption, extract IV from combined data

Code:

val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, secretKey)
val iv = cipher.iv
val cipherBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
val combined = iv + cipherBytes
val base64Result = Base64.encodeToString(combined, Base64.NO_WRAP)

JS Usage:

const cipher = await CryptoVault.aesGcmEncrypt('Hello', 'my_app_aes_key');
const decrypted = await CryptoVault.aesGcmDecrypt(cipher, 'my_app_aes_key');

Why this works over old code:

Old code manually created random keys outside Keystore, causing security and consistency issues.

New code ensures keys are securely stored and reused, IV is handled properly, Base64 encoding ensures safe transport.

HMAC-SHA256 Signing

Method: hmacSHA256(message: string, keyAlias: string)

Logic:

val key = getOrCreateKey(alias)
val mac = Mac.getInstance("HmacSHA256")
mac.init(key)
val hmacBytes = mac.doFinal(message.toByteArray(Charsets.UTF_8))
val hmacBase64 = Base64.encodeToString(hmacBytes, Base64.NO_WRAP)

Explanation:

Uses keystore key for HMAC

Provides integrity verification

Base64 encoding allows safe JS use

JS Usage:

const hmac = await CryptoVault.hmacSHA256('message', 'my_app_aes_key');

Why updated:

Previous versions used plain-text keys, insecure and inconsistent across platforms.

Now uses alias-keystore key, which is secure, persistent, and consistent.

AES-GCM + HMAC (Authenticated Encryption)

Purpose: Encrypt and authenticate in one operation.

Logic:

Generate random IV

Encrypt with AES-GCM

Compute HMAC of cipherBytes

Concatenate IV + cipher + HMAC for storage

On decryption, verify HMAC before AES-GCM decryption

JS Usage:

const key = await CryptoVault.getRandomBytes(32);
const encrypted = await CryptoVault.aesGcmEncryptWithHmac('message', key);
const decrypted = await CryptoVault.aesGcmDecryptWithHmac(encrypted, key);

Random Bytes & UUID

Methods: getRandomBytes, getRandomId

Logic:

getRandomBytes(length) generates cryptographically secure random bytes

getRandomId() generates UUID v4

Both Base64 encode for safe transport

JS Usage:

const randomBytes = await CryptoVault.getRandomBytes(32);
const randomId = await CryptoVault.getRandomId();

Code Example
const alias = 'my_app_aes_key';

// Generate key once
await CryptoVault.generateSecureKey(alias);

// AES-GCM encryption
const cipher = await CryptoVault.aesGcmEncrypt('Hello', alias);
const decrypted = await CryptoVault.aesGcmDecrypt(cipher, alias);

// HMAC-SHA256 signing
const hmac = await CryptoVault.hmacSHA256('Message', alias);

// AES-GCM + HMAC
const key = await CryptoVault.getRandomBytes(32);
const encrypted = await CryptoVault.aesGcmEncryptWithHmac('Secret message', key);
const decryptedMessage = await CryptoVault.aesGcmDecryptWithHmac(encrypted, key);

console.log({ cipher, decrypted, hmac, encrypted, decryptedMessage });

How to Use in an App

Import the library:

import CryptoVault from 'react-native-crypto-vault';

Generate or retrieve a secure key using alias.

Use AES-GCM for encryption/decryption.

Use HMAC-SHA256 for signing messages.

Optionally, use AES-GCM + HMAC for authenticated encryption.

Tip: Always generate keys once per alias. Re-generating overwrites the old key.

Future Enhancements

Biometric-based key access

Backup & restore of keys

Asymmetric encryption support (RSA/ECC)

Customizable AES key sizes
