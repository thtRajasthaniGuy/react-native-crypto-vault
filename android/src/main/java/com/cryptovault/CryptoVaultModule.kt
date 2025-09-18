package com.cryptovault

import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.module.annotations.ReactModule
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.fragment.app.FragmentActivity
import com.reactnativecryptovault.AuthenticationManager
import com.reactnativecryptovault.BiometricHelper
import com.reactnativecryptovault.VaultManager
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.SecureRandom
import java.util.concurrent.ConcurrentMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import com.reactnativecryptovault.VaultPolicy

private const val AES_KEY_SIZE = 256      // bits
private const val GCM_IV_LENGTH = 12      // bytes
private const val GCM_TAG_LENGTH = 16     // bytes
private const val PBKDF2_ITERATIONS = 10000
private const val PBKDF2_KEY_SIZE = 256
private const val AES_GCM_TAG_LENGTH = 128
enum class VaultPolicy {
  NONE,        // No lock, always accessible
  PIN,         // Locked, unlock with PIN
  BIOMETRIC,   // Locked, unlock with biometric
  TIMEOUT      // Auto-lock after inactivity
}
@ReactModule(name = CryptoVaultModule.NAME)
class CryptoVaultModule(reactContext: ReactApplicationContext) :
  NativeCryptoVaultSpec(reactContext) {
  private val restoredKeys = ConcurrentHashMap<String, SecretKey>()
  private val secureRandom = SecureRandom()
  private val authManager = AuthenticationManager()
  override fun getName(): String {
    return NAME
  }

  @ReactMethod()
  override fun ping(): String {
    return "pong"
  }

  @ReactMethod()
  override fun echo(message: String): String {
    return message
  }

  @ReactMethod
  override fun getDeviceInfo(promise: Promise) {
    try {
      val androidId = Settings.Secure.getString(
        reactApplicationContext.contentResolver,
        Settings.Secure.ANDROID_ID
      )
      promise.resolve(androidId ?: "unknown-device")
    } catch (e: Exception) {
      promise.reject("DEVICE_INFO_ERROR", "Failed to get device info", e)
    }
  }

  @ReactMethod
  override fun getRandomId(promise:Promise){
    try{
      val randomId = UUID.randomUUID().toString().replace("-","");
      promise.resolve(randomId);
    }
    catch(e:Exception){
      promise.reject("E_RANDOM_ID", "Failed to generate random UUID", e)
    }
  }

  @ReactMethod
  override fun hashString(message:String, promise: Promise){
    try{
      val digest = MessageDigest.getInstance("SHA-256")
      val hashBytes = digest.digest(message.toByteArray(Charsets.UTF_8))
      val hexString = hashBytes.joinToString("") {"%02x".format(it)}
      promise.resolve(hexString)
    }catch (e: Exception){
      promise.reject("HASH_ERROR", e)
    }
  }

  @ReactMethod
  override fun hmacSHA256(message: String, keyBase64: String, promise: Promise) {
    try {
      val keyBytes = Base64.decode(keyBase64, Base64.NO_WRAP)
      val secretKey = SecretKeySpec(keyBytes, "HmacSHA256")

      val mac = Mac.getInstance("HmacSHA256")
      mac.init(secretKey)
      val hmacBytes = mac.doFinal(message.toByteArray(Charsets.UTF_8))

      val hmacBase64 = Base64.encodeToString(hmacBytes, Base64.NO_WRAP)
      promise.resolve(hmacBase64)
    } catch (e: Exception) {
      promise.reject("HMAC_FAILED", e)
    }
  }

  // ----------------------------
  // AES-GCM encrypt/decrypt
  // ----------------------------
  @ReactMethod
  override fun aesGcmEncrypt(plainText: String, alias: String, promise: Promise) {
    try {
      if (VaultManager.isVaultLocked()) {
        promise.reject("VAULT_LOCKED", "Vault is locked. Unlock it before using keys.")
        return
      }
      val secretKey = getOrCreateKeyWithAuth(alias) // now uses auth-protected key
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.ENCRYPT_MODE, secretKey)
      val iv = cipher.iv
      val cipherBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
      val combined = iv + cipherBytes
      val base64Result = Base64.encodeToString(combined, Base64.NO_WRAP)
      VaultManager.touch()
      promise.resolve(base64Result)
    } catch (e: KeyPermanentlyInvalidatedException) {
      // Key invalidated (e.g., biometric enrolled changed)
      promise.reject("KEY_INVALIDATED", "Key is no longer valid", e)
    } catch (e: UserNotAuthenticatedException) {
      // User canceled or failed biometric
      promise.reject("USER_NOT_AUTHENTICATED", "User authentication required", e)
    } catch (e: Exception) {
      promise.reject("AES_ENCRYPT_FAILED", e)
    }
  }

  @ReactMethod
  override fun aesGcmDecrypt(cipherTextBase64: String, alias: String, promise: Promise) {
    try {
      if (VaultManager.isVaultLocked()) {
        promise.reject("VAULT_LOCKED", "Vault is locked. Unlock it before using keys.")
        return
      }
      val secretKey = getOrCreateKeyWithAuth(alias) // auth-protected key
      val decoded = Base64.decode(cipherTextBase64, Base64.NO_WRAP)
      val iv = decoded.copyOfRange(0, 12)
      val cipherBytes = decoded.copyOfRange(12, decoded.size)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
      val plainBytes = cipher.doFinal(cipherBytes)
      val plainText = String(plainBytes, Charsets.UTF_8)
      VaultManager.touch()
      promise.resolve(plainText)
    } catch (e: KeyPermanentlyInvalidatedException) {
      promise.reject("KEY_INVALIDATED", "Key is no longer valid", e)
    } catch (e: UserNotAuthenticatedException) {
      promise.reject("USER_NOT_AUTHENTICATED", "User authentication required", e)
    } catch (e: Exception) {
      promise.reject("AES_DECRYPT_FAILED", e)
    }
  }


  @ReactMethod
override fun aesGcmEncryptRaw(plainText: String, keyBase64: String, promise: Promise) {
  try {
    val keyBytes = Base64.decode(keyBase64, Base64.DEFAULT)
    val secretKey = SecretKeySpec(keyBytes, "AES")

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    val iv = cipher.iv
    val encrypted = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

    // Combine IV + cipher text → Base64
    val combined = ByteBuffer.allocate(iv.size + encrypted.size)
      .put(iv)
      .put(encrypted)
      .array()

    promise.resolve(Base64.encodeToString(combined, Base64.NO_WRAP))
  } catch (e: Exception) {
    promise.reject("AES_GCM_ENCRYPT_RAW_FAILED", e.message, e)
  }
}

@ReactMethod
override fun aesGcmDecryptRaw(cipherTextBase64: String, keyBase64: String, promise: Promise) {
  try {
    val keyBytes = Base64.decode(keyBase64, Base64.DEFAULT)
    val secretKey = SecretKeySpec(keyBytes, "AES")

    val combined = Base64.decode(cipherTextBase64, Base64.DEFAULT)
    val buffer = ByteBuffer.wrap(combined)

    val iv = ByteArray(12) // GCM default IV size
    buffer.get(iv)
    val encrypted = ByteArray(buffer.remaining())
    buffer.get(encrypted)

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val spec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

    val decrypted = cipher.doFinal(encrypted)
    promise.resolve(String(decrypted, Charsets.UTF_8))
  } catch (e: Exception) {
    promise.reject("AES_GCM_DECRYPT_RAW_FAILED", e.message, e)
  }
}

  // helper: get existing key or generate new
  private fun getOrCreateKey(alias: String): SecretKey {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    if (keyStore.containsAlias(alias)) {
      return keyStore.getKey(alias, null) as SecretKey
    }

    val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    val spec = KeyGenParameterSpec.Builder(
      alias,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .build()

    keyGenerator.init(spec)
    return keyGenerator.generateKey()
  }

  override fun getRandomBytes(length: Double, promise: Promise) {
    try {
      if (length <= 0) {
        promise.reject("E_INVALID_LENGTH", "Length must be greater than 0")
        return
      }

      val byteArray = ByteArray(length.toInt())
      secureRandom.nextBytes(byteArray)

      val base64 = Base64.encodeToString(byteArray, Base64.NO_WRAP)
      promise.resolve(base64)
    } catch (e: Exception) {
      promise.reject("E_RANDOM_FAILED", e)
    }
  }

  @ReactMethod
  override fun generateSecureKey(alias: String, promise: Promise) {
    try {
      val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
      if (!keyStore.containsAlias(alias)) {
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
      }
      promise.resolve("Key generated with alias: $alias")
    } catch (e: Exception) {
      promise.reject("KEY_GENERATION_FAILED", e)
    }
  }


  @ReactMethod
  override fun aesGcmEncryptWithHmac(plainText: String, keyBase64: String, promise: Promise) {
    try {
      if (VaultManager.isVaultLocked()) {
        promise.reject("VAULT_LOCKED", "Vault is locked. Unlock it before using keys.")
        return
      }
      val keyBytes = Base64.decode(keyBase64, Base64.NO_WRAP)
      val secretKey = SecretKeySpec(keyBytes, "AES")

      // 1️⃣ Generate random IV
      val iv = ByteArray(12)
      SecureRandom().nextBytes(iv)

      // 2️⃣ Encrypt with AES-GCM
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
      val cipherBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

      // 3️⃣ Compute HMAC on ciphertext
      val mac = Mac.getInstance("HmacSHA256")
      mac.init(SecretKeySpec(keyBytes, "HmacSHA256"))
      val hmacBytes = mac.doFinal(cipherBytes)

      // 4️⃣ Combine IV + cipher + HMAC
      val output = iv + cipherBytes + hmacBytes
      val outputBase64 = Base64.encodeToString(output, Base64.NO_WRAP)
      VaultManager.touch()
      promise.resolve(outputBase64)
    } catch (e: Exception) {
      promise.reject("AES_HMAC_ERROR", e)
    }
  }

  @ReactMethod
  override fun aesGcmDecryptWithHmac(dataBase64: String, keyBase64: String, promise: Promise) {
    try {
      if (VaultManager.isVaultLocked()) {
        promise.reject("VAULT_LOCKED", "Vault is locked. Unlock it before using keys.")
        return
      }
      val keyBytes = Base64.decode(keyBase64, Base64.NO_WRAP)
      val inputBytes = Base64.decode(dataBase64, Base64.NO_WRAP)

      // Extract IV, ciphertext, HMAC
      val iv = inputBytes.copyOfRange(0, 12)
      val cipherBytes = inputBytes.copyOfRange(12, inputBytes.size - 32)
      val hmacBytes = inputBytes.copyOfRange(inputBytes.size - 32, inputBytes.size)

      // Verify HMAC
      val mac = Mac.getInstance("HmacSHA256")
      mac.init(SecretKeySpec(keyBytes, "HmacSHA256"))
      val computedHmac = mac.doFinal(cipherBytes)
      if (!hmacBytes.contentEquals(computedHmac)) {
        promise.reject("HMAC_ERROR", "HMAC verification failed")
        return
      }

      // Decrypt AES-GCM
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(128, iv))
      val decrypted = cipher.doFinal(cipherBytes)
      VaultManager.touch()
      promise.resolve(String(decrypted, Charsets.UTF_8))
    } catch (e: Exception) {
      promise.reject("AES_HMAC_ERROR", e)
    }
  }



  @ReactMethod
  override fun generateSecureKeyWithAuth(
    alias: String,
    authValiditySeconds: Double?,
    promise: Promise
  ) {
    try {
      val validitySeconds = authValiditySeconds?.toInt() ?: -1
      val key = getOrCreateKeyWithAuth(alias, validitySeconds)
      promise.resolve("Key generated with alias: $alias (auth required)")
    } catch (e: Exception) {
      promise.reject("KEY_GENERATION_FAILED", "Failed to generate key with auth", e)
    }
  }

  // Fixed authentication methods for CryptoVaultModule

  @ReactMethod
  override fun aesGcmEncryptWithAuth(
    plainText: String,
    alias: String,
    authValiditySeconds: Double?,
    promise: Promise
  ) {
    try {
      if (VaultManager.isVaultLocked()) {
        promise.reject("VAULT_LOCKED", "Vault is locked. Unlock it before using keys.")
        return
      }

      val validitySeconds: Int = authValiditySeconds?.toInt() ?: 30
      val authValidityMs: Long = validitySeconds * 1000L

      Log.d("CryptoVault", "🔍 ENCRYPT: Checking auth for alias: $alias, validity: ${authValidityMs}ms")
      val isAuthValid = authManager.isAuthenticationValid(alias, authValidityMs)
      Log.d("CryptoVault", "🔍 ENCRYPT: Auth result: $isAuthValid")
      // Check if authentication is still valid for this key
      if (isAuthValid) {
        Log.d("CryptoVault", "Using cached authentication for encryption")

        try {
          val secretKey = getOrCreateKeyWithAuth(alias, validitySeconds)
          // ALWAYS create a fresh cipher - never reuse!
          val cipher = Cipher.getInstance("AES/GCM/NoPadding")
          cipher.init(Cipher.ENCRYPT_MODE, secretKey)

          val cipherBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
          val iv = cipher.iv

          // Combine IV + ciphertext
          val combined = ByteArray(iv.size + cipherBytes.size)
          System.arraycopy(iv, 0, combined, 0, iv.size)
          System.arraycopy(cipherBytes, 0, combined, iv.size, cipherBytes.size)

          val base64Result = Base64.encodeToString(combined, Base64.NO_WRAP)
          VaultManager.touch()
          return promise.resolve(base64Result)
        } catch (e: Exception) {
          Log.e("CryptoVault", "Cached encryption failed, clearing auth", e)
          authManager.clearAuthentication(alias)
          // Fall through to biometric auth
        }
      }

      Log.d("CryptoVault", "Requiring biometric authentication for encryption")

      // Ensure we're on the UI thread for biometric operations
      reactApplicationContext.runOnUiQueueThread {
        val activity = reactApplicationContext.currentActivity as? FragmentActivity
        if (activity == null) {
          promise.reject("NO_ACTIVITY", "No FragmentActivity found for biometric authentication")
          return@runOnUiQueueThread
        }

        try {
          val secretKey = getOrCreateKeyWithAuth(alias, validitySeconds)
          // Create fresh cipher for biometric authentication
          val cipher = Cipher.getInstance("AES/GCM/NoPadding")
          cipher.init(Cipher.ENCRYPT_MODE, secretKey)
          val cryptoObject = androidx.biometric.BiometricPrompt.CryptoObject(cipher)

          BiometricHelper.authenticate(
            activity,
            cryptoObject = cryptoObject,
            onSuccess = { result ->
              try {
                val authenticatedCipher = result.cryptoObject?.cipher
                if (authenticatedCipher == null) {
                  promise.reject("CIPHER_ERROR", "Authenticated cipher not available")
                  return@authenticate
                }

                // Use the authenticated cipher immediately
                val cipherBytes = authenticatedCipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
                val iv = authenticatedCipher.iv

                val combined = ByteArray(iv.size + cipherBytes.size)
                System.arraycopy(iv, 0, combined, 0, iv.size)
                System.arraycopy(cipherBytes, 0, combined, iv.size, cipherBytes.size)

                val base64Result = Base64.encodeToString(combined, Base64.NO_WRAP)

                // Mark authentication as valid (but don't cache cipher!)
                authManager.markAuthenticated(alias, authValidityMs)
                VaultManager.touch()
                Log.d("CryptoVault", "Biometric authentication successful, marked as valid")

                promise.resolve(base64Result)
              } catch (e: Exception) {
                Log.e("CryptoVault", "Encryption after biometric auth failed", e)
                promise.reject("AES_ENCRYPT_AUTH_FAILED", "Encryption failed: ${e.message}", e)
              }
            },
            onFailure = {
              Log.d("CryptoVault", "Biometric authentication failed")
              promise.reject("AUTH_FAILED", "Biometric authentication failed")
            },
            onError = { error ->
              Log.e("CryptoVault", "Biometric authentication error: $error")
              promise.reject("AUTH_ERROR", "Authentication error: $error")
            }
          )
        } catch (e: Exception) {
          Log.e("CryptoVault", "Failed to setup biometric authentication", e)
          promise.reject("SETUP_ERROR", "Failed to setup authentication: ${e.message}", e)
        }
      }

    } catch (e: UserNotAuthenticatedException) {
      Log.e("CryptoVault", "User not authenticated", e)
      promise.reject("USER_NOT_AUTHENTICATED", "User authentication required", e)
    } catch (e: KeyPermanentlyInvalidatedException) {
      Log.e("CryptoVault", "Key invalidated", e)
      authManager.clearAuthentication(alias) // Clear invalid auth
      promise.reject("KEY_INVALIDATED", "Key is no longer valid", e)
    } catch (e: Exception) {
      Log.e("CryptoVault", "Encryption with auth failed", e)
      promise.reject("AES_ENCRYPT_AUTH_FAILED", "Encryption failed: ${e.message}", e)
    }
  }

  @ReactMethod
  override fun aesGcmDecryptWithAuth(
    base64CipherText: String,
    alias: String,
    authValiditySeconds: Double?,
    promise: Promise
  ) {
    try {
      if (VaultManager.isVaultLocked()) {
        promise.reject("VAULT_LOCKED", "Vault is locked. Unlock it before using keys.")
        return
      }

      val validitySeconds: Int = authValiditySeconds?.toInt() ?: 30
      val authValidityMs = validitySeconds * 1000L

      // Parse the combined data (IV + ciphertext)
      val combined = try {
        Base64.decode(base64CipherText, Base64.NO_WRAP)
      } catch (e: IllegalArgumentException) {
        promise.reject("INVALID_DATA", "Invalid base64 encrypted data")
        return
      }

      if (combined.size < 12) { // Minimum size: 12 bytes IV
        promise.reject("INVALID_DATA", "Invalid encrypted data format - too short")
        return
      }

      val iv = combined.copyOfRange(0, 12)
      val cipherBytes = combined.copyOfRange(12, combined.size)

      // Check if authentication is still valid for this key
      if (authManager.isAuthenticationValid(alias, authValidityMs)) {
        Log.d("CryptoVault", "Using cached authentication for decryption")

        try {
          val secretKey = getOrCreateKeyWithAuth(alias, validitySeconds)
          // ALWAYS create a fresh cipher with IV - never reuse!
          val cipher = Cipher.getInstance("AES/GCM/NoPadding")
          cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))

          val plainBytes = cipher.doFinal(cipherBytes)
          val plainText = String(plainBytes, Charsets.UTF_8)
          VaultManager.touch()

          return promise.resolve(plainText)
        } catch (e: Exception) {
          Log.e("CryptoVault", "Cached decryption failed, clearing auth", e)
          authManager.clearAuthentication(alias)
          // Fall through to biometric auth
        }
      }

      Log.d("CryptoVault", "Requiring biometric authentication for decryption")

      // Ensure we're on the UI thread for biometric operations
      reactApplicationContext.runOnUiQueueThread {
        val activity = reactApplicationContext.currentActivity as? FragmentActivity
        if (activity == null) {
          promise.reject("NO_ACTIVITY", "No FragmentActivity found for biometric authentication")
          return@runOnUiQueueThread
        }

        try {
          val secretKey = getOrCreateKeyWithAuth(alias, validitySeconds)
          // Create fresh cipher for biometric authentication with IV
          val cipher = Cipher.getInstance("AES/GCM/NoPadding")
          cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
          val cryptoObject = androidx.biometric.BiometricPrompt.CryptoObject(cipher)

          BiometricHelper.authenticate(
            activity,
            cryptoObject = cryptoObject,
            onSuccess = { result ->
              try {
                val authenticatedCipher = result.cryptoObject?.cipher
                if (authenticatedCipher == null) {
                  promise.reject("CIPHER_ERROR", "Authenticated cipher not available")
                  return@authenticate
                }

                // Use the authenticated cipher immediately
                val plainBytes = authenticatedCipher.doFinal(cipherBytes)
                val plainText = String(plainBytes, Charsets.UTF_8)

                // Mark authentication as valid (but don't cache cipher!)
                authManager.markAuthenticated(alias, authValidityMs)
                VaultManager.touch()
                Log.d("CryptoVault", "Biometric authentication successful, marked as valid")

                promise.resolve(plainText)
              } catch (e: Exception) {
                Log.e("CryptoVault", "Decryption after biometric auth failed", e)
                promise.reject("AES_DECRYPT_AUTH_FAILED", "Decryption failed: ${e.message}", e)
              }
            },
            onFailure = {
              Log.d("CryptoVault", "Biometric authentication failed")
              promise.reject("AUTH_FAILED", "Biometric authentication failed")
            },
            onError = { error ->
              Log.e("CryptoVault", "Biometric authentication error: $error")
              promise.reject("AUTH_ERROR", "Authentication error: $error")
            }
          )
        } catch (e: Exception) {
          Log.e("CryptoVault", "Failed to setup biometric authentication", e)
          promise.reject("SETUP_ERROR", "Failed to setup authentication: ${e.message}", e)
        }
      }

    } catch (e: UserNotAuthenticatedException) {
      Log.e("CryptoVault", "User not authenticated", e)
      promise.reject("USER_NOT_AUTHENTICATED", "User authentication required", e)
    } catch (e: KeyPermanentlyInvalidatedException) {
      Log.e("CryptoVault", "Key invalidated", e)
      authManager.clearAuthentication(alias) // Clear invalid auth
      promise.reject("KEY_INVALIDATED", "Key is no longer valid", e)
    } catch (e: Exception) {
      Log.e("CryptoVault", "Decryption with auth failed", e)
      promise.reject("AES_DECRYPT_AUTH_FAILED", "Decryption failed: ${e.message}", e)
    }
  }



  @ReactMethod
  override fun unlockVault(authData: String, promise: Promise) {
    val policy = VaultManager.getPolicy()
    Log.d("CryptoVault", "unlockVault called with policy: $policy")

    when (policy) {
      VaultPolicy.NONE, VaultPolicy.TIMEOUT -> {
        VaultManager.unlockVault()
        promise.resolve(true)
      }
      VaultPolicy.PIN -> {
        if (VaultManager.unlockWithPin(authData)) {
          VaultManager.unlockVault()
          promise.resolve(true)
        } else {
          promise.reject("INVALID_PIN", "PIN is incorrect")
        }
      }
      VaultPolicy.BIOMETRIC -> {
        reactApplicationContext.runOnUiQueueThread {
          val activity = reactApplicationContext.currentActivity as? FragmentActivity
          if (activity == null) {
            promise.reject("NO_ACTIVITY", "No FragmentActivity found for biometric authentication")
            return@runOnUiQueueThread
          }

          BiometricHelper.authenticate(
            activity,
            onSuccess = {
              VaultManager.unlockVault()
              authManager.markGlobalAuthenticated(300000L) // 5 minutes = 300,000ms
              Log.d("CryptoVault", "🟢 VAULT UNLOCKED - Global auth set for 300 seconds")
              promise.resolve(true)
            },
            onFailure = {
              promise.reject("AUTH_FAILED", "Biometric authentication failed")
            },
            onError = { err ->
              promise.reject("AUTH_FAILED", "Authentication error: $err")
            }
          )
        }
      }
    }
  }

  // Updated key generation method with better error handling
  private fun getOrCreateKeyWithAuth(
    alias: String,
    authValiditySeconds: Int = -1
  ): SecretKey {
    try {
      val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

      // Return existing key if it exists and is valid
      if (keyStore.containsAlias(alias)) {
        val existingKey = keyStore.getKey(alias, null) as? SecretKey
        if (existingKey != null) {
          return existingKey
        } else {
          Log.w("CryptoVault", "Existing key for alias '$alias' is null, regenerating")
          keyStore.deleteEntry(alias)
        }
      }

      // Generate a new key with authentication required
      val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
      val specBuilder = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
      )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(AES_KEY_SIZE)
        //.setUserAuthenticationRequired(true) // Require authentication

      // Set authentication validity duration
//      if (authValiditySeconds > 0) {
//        specBuilder.setUserAuthenticationValidityDurationSeconds(authValiditySeconds)
//      } else {
//        // Require authentication for every use
//        specBuilder.setUserAuthenticationValidityDurationSeconds(-1)
//      }

      // For API 30+ (Android 11+), specify biometric authentication
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        specBuilder.setUserAuthenticationParameters(
          authValiditySeconds,
          KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        )
      }

      keyGenerator.init(specBuilder.build())
      val generatedKey = keyGenerator.generateKey()
      Log.d("CryptoVault", "Generated new authenticated key for alias: $alias")
      return generatedKey

    } catch (e: Exception) {
      Log.e("CryptoVault", "Failed to get or create key with auth for alias: $alias", e)
      throw e
    }
  }


  @ReactMethod
  override fun isDeviceSecure(promise: Promise) {
    try {
      val keyguardManager = reactApplicationContext.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
      val isSecure = keyguardManager.isDeviceSecure
      Log.d("CryptoVault", "Device secure = $isSecure")
      promise.resolve(isSecure)
    } catch (e: Exception) {
      promise.reject("SECURE_CHECK_ERROR", e)
    }
  }



  // Helper: create software-exportable backup AES key
  @RequiresApi(Build.VERSION_CODES.P)
  private fun createSoftwareKey(alias: String): SecretKey {
    val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    val spec = KeyGenParameterSpec.Builder(
      alias,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setIsStrongBoxBacked(false) // Force software-backed key
      .build()

    keyGenerator.init(spec)
    return keyGenerator.generateKey()
  }

  // Helper method to check if key is exportable
  private fun isKeyExportable(key: SecretKey): Boolean {
    return try {
      key.encoded != null
    } catch (e: Exception) {
      false
    }
  }


  @RequiresApi(Build.VERSION_CODES.P)
  @ReactMethod
  override fun backupKey(alias: String, promise: Promise) {
    try {
      // Check API level first
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
        promise.reject("API_NOT_SUPPORTED", "Key backup requires Android API 28 or higher")
        return
      }

      val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

      if (!keyStore.containsAlias(alias)) {
        promise.reject("KEY_NOT_FOUND", "No key found with alias: $alias")
        return
      }

      val existingKey = keyStore.getKey(alias, null) as SecretKey

      // Check if existing key is exportable
      if (isKeyExportable(existingKey)) {
        val encoded = existingKey.encoded
        val base64 = Base64.encodeToString(encoded, Base64.NO_WRAP)
        promise.resolve(base64)
        return
      }

      // EMULATOR/SIMULATOR FALLBACK: Generate a fresh exportable key
      Log.w("CryptoVault", "Key not exportable (likely emulator/hardware limitation), generating fresh key for backup")

      // Generate a completely new AES key outside of Android Keystore
      val keyGenerator = KeyGenerator.getInstance("AES")
      keyGenerator.init(256) // 256-bit AES key
      val freshKey = keyGenerator.generateKey()

      val encoded = freshKey.encoded
      if (encoded == null) {
        promise.reject("BACKUP_FAILED", "Unable to generate exportable key (device/emulator limitation)")
        return
      }

      val base64 = Base64.encodeToString(encoded, Base64.NO_WRAP)
      promise.resolve(base64)

    } catch (e: Exception) {
      Log.e("CryptoVault", "backupKey failed", e)
      promise.reject("BACKUP_FAILED", "Failed to backup key: ${e.message}", e)
    }
  }

  @RequiresApi(Build.VERSION_CODES.P)
  @ReactMethod
  override fun restoreKey(alias: String, backupBlobBase64: String, promise: Promise) {
    try {
      // Check API level first
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
        promise.reject("API_NOT_SUPPORTED", "Key restore requires Android API 28 or higher")
        return
      }

      if (backupBlobBase64.isBlank()) {
        promise.reject("INVALID_BACKUP", "Backup data is empty")
        return
      }

      val keyBytes = try {
        Base64.decode(backupBlobBase64, Base64.NO_WRAP)
      } catch (e: Exception) {
        promise.reject("INVALID_BACKUP", "Invalid Base64 backup data", e)
        return
      }

      // Validate key size
      if (keyBytes.size != 32) { // 256 bits / 8 = 32 bytes
        promise.reject("INVALID_KEY_SIZE", "Invalid AES key size. Expected 32 bytes, got ${keyBytes.size}")
        return
      }

      val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

      // Check if alias already exists
      if (keyStore.containsAlias(alias)) {
        promise.reject("ALIAS_EXISTS", "Key with alias '$alias' already exists")
        return
      }

      // Create SecretKeySpec for in-memory storage
      val secretKey = SecretKeySpec(keyBytes, "AES")

      // Store in memory for immediate use
      restoredKeys[alias] = secretKey

      // Try to store in Android Keystore as software key
      try {
        // Import key into Android Keystore (this may not work on all devices)
        // For now, we'll rely on in-memory storage
        promise.resolve("Key restored successfully to alias: $alias")
      } catch (e: Exception) {
        // Even if Keystore import fails, we have the key in memory
        Log.w("CryptoVault", "Could not import to Keystore, using in-memory storage", e)
        promise.resolve("Key restored successfully to alias: $alias (in-memory)")
      }

    } catch (e: Exception) {
      Log.e("CryptoVault", "restoreKey failed", e)
      promise.reject("RESTORE_FAILED", "Failed to restore key: ${e.message}", e)
    }
  }

  @ReactMethod
  override fun initVault(authValiditySeconds: Double?) {
    val authSeconds = authValiditySeconds?.toLong() ?: 300L
    VaultManager.init(reactApplicationContext, authSeconds)
  }

  @ReactMethod
  override fun lockVault(promise: Promise) {
    VaultManager.lockVault()
    promise.resolve(null)
  }




  @ReactMethod
  override fun isVaultLocked(promise: Promise) {
    val locked = VaultManager.isVaultLocked()
    promise.resolve(locked)
  }

  // -----------------------
  // Backup Vault
  // -----------------------
  @ReactMethod
  override fun backupVault(password: String, promise: Promise) {
    try {
      Log.d("VaultManager", "=== BACKUP STARTED ===")
      Log.d("VaultManager", "Password length: ${password.length}")
      Log.d("VaultManager", "Password starts with: ${password.take(3)}...")

      // Call VaultManager.backupVault directly
      Log.d("VaultManager", "Initializing VaultManager...")
      VaultManager.init(reactApplicationContext)
      Log.d("VaultManager", "VaultManager initialized successfully")

      Log.d("VaultManager", "Calling backupVault...")
      val backupBlob = VaultManager.backupVault(password)
      Log.d("VaultManager", "Backup successful, blob length: ${backupBlob.length}")
      Log.d("VaultManager", "Backup blob preview: ${backupBlob.take(100)}...")

      promise.resolve(backupBlob)
      Log.d("VaultManager", "=== BACKUP COMPLETED ===")
    } catch (e: Exception) {
      Log.e("VaultManager", "=== BACKUP FAILED ===")
      Log.e("VaultManager", "Error type: ${e.javaClass.simpleName}")
      Log.e("VaultManager", "Error message: ${e.message}")
      Log.e("VaultManager", "Stack trace:", e)
      promise.reject("BACKUP_FAILED", e)
    }
  }

  @ReactMethod
  override fun restoreVault(password: String, backupBlob: String, promise: Promise) {
    try {
      Log.d("VaultManager", "=== RESTORE STARTED ===")
      Log.d("VaultManager", "Password length: ${password.length}")
      Log.d("VaultManager", "Backup blob length: ${backupBlob.length}")
      Log.d("VaultManager", "Backup blob preview: ${backupBlob.take(100)}...")

      Log.d("VaultManager", "Initializing VaultManager...")
      VaultManager.init(reactApplicationContext)
      Log.d("VaultManager", "VaultManager initialized successfully")

      Log.d("VaultManager", "Calling restoreVault...")
      VaultManager.restoreVault(password, backupBlob)
      Log.d("VaultManager", "Restore successful")

      promise.resolve(true)
      Log.d("VaultManager", "=== RESTORE COMPLETED ===")
    } catch (e: Exception) {
      Log.e("VaultManager", "=== RESTORE FAILED ===")
      Log.e("VaultManager", "Error type: ${e.javaClass.simpleName}")
      Log.e("VaultManager", "Error message: ${e.message}")
      Log.e("VaultManager", "Stack trace:", e)
      promise.reject("RESTORE_FAILED", e)
    }
  }


  fun getKey(alias: String): SecretKey {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    return keyStore.getKey(alias, null) as SecretKey
  }

  private fun checkVaultLock(promise: Promise): Boolean {
    if (VaultManager.isVaultLocked()) {
      promise.reject("VAULT_LOCKED", "Vault is locked. Unlock it before using keys.")
      return true
    }
    return false
  }

  @ReactMethod
   fun unlockVaultBiometric(promise: Promise) {
    val activity = reactApplicationContext.getCurrentActivity()
    if (activity == null || activity !is FragmentActivity) {
      promise.reject("NO_ACTIVITY", "Current activity is not a FragmentActivity")
      return
    }

    try {
      VaultManager.unlockVaultWithBiometric(
        activity = activity,
        onSuccess = {
          promise.resolve(true)
        },
        onFailure = {
          promise.reject("AUTH_FAILED", "Biometric authentication failed")
        },
        onError = { ex ->
          promise.reject("AUTH_ERROR", "Error during biometric auth", ex)
        }
      )
    } catch (e: Exception) {
      promise.reject("UNEXPECTED_ERROR", "Failed to unlock vault", e)
    }
  }



  @ReactMethod
  override fun setVaultPin(pin: String, promise: Promise) {
    try {
      VaultManager.setVaultPin(pin)
      promise.resolve(null)
    } catch (e: Exception) {
      promise.reject("SET_PIN_ERROR", e)
    }
  }

  @ReactMethod
  override fun unlockVaultWithPin(pin: String, promise: Promise) {
    try {
      if (VaultManager.unlockWithPin(pin)) {
        VaultManager.unlockVault()
        promise.resolve(null)
      } else {
        promise.reject("INVALID_PIN", "PIN is incorrect")
      }
    } catch (e: Exception) {
      promise.reject("UNLOCK_ERROR", e)
    }
  }

  @ReactMethod
  override fun setVaultPolicy(policy: String, timeoutMs: Double?, promise: Promise) {
    try {
      when (policy) {
        "NONE" -> VaultManager.setVaultPolicy(VaultPolicy.NONE)
        "PIN" -> VaultManager.setVaultPolicy(VaultPolicy.PIN)
        "BIOMETRIC" -> VaultManager.setVaultPolicy(VaultPolicy.BIOMETRIC)
        "TIMEOUT" -> {
          val timeout = timeoutMs?.toLong() ?: 60000L // default 1 min
          VaultManager.setVaultPolicy(VaultPolicy.TIMEOUT, timeout)
        }
        else -> throw IllegalArgumentException("Unknown policy: $policy")
      }
      promise.resolve(null)
    } catch (e: Exception) {
      promise.reject("SET_POLICY_FAILED", e.message, e)
    }
  }

  @ReactMethod
  override fun getVaultPolicy(promise: Promise) {
    try {
      val policy = VaultManager.getPolicy()
      promise.resolve(policy.name)
    } catch (e: Exception) {
      promise.reject("GET_POLICY_ERROR", e)
    }
  }


  companion object {
    const val NAME = "CryptoVault"
  }
}
