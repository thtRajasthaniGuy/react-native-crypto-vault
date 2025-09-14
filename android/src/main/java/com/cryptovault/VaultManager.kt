// VaultManager.kt
package com.reactnativecryptovault

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.MasterKey
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences.PrefKeyEncryptionScheme
import androidx.security.crypto.EncryptedSharedPreferences.PrefValueEncryptionScheme
import com.google.gson.Gson
import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

data class VaultKeyMeta(
  val alias: String,
  val requiresAuth: Boolean,
  val createdAt: Long
)

data class VaultState(
  val isLocked: Boolean,
  val lastUnlockTime: Long,
  val keys: Map<String, VaultKeyMeta> = emptyMap()
)

enum class VaultPolicy {
  NONE,        // No lock, always accessible
  PIN,         // Locked, unlock with PIN
  BIOMETRIC,   // Locked, unlock with biometric
  TIMEOUT      // Auto-lock after inactivity
}
object VaultManager {
  private val gson = Gson()
  private var currentState: VaultState = VaultState(true, 0, emptyMap())
  private const val PREF_FILE = "vault_state"
  private const val PREF_VAULT_JSON = "vault_state_json"
  private const val KEY_IS_LOCKED = "is_locked"
  private const val KEY_LAST_UNLOCK_TIME = "last_unlock_time"

  private var authValiditySeconds: Long = 0
  private lateinit var prefs: SharedPreferences

  private var currentPolicy: VaultPolicy = VaultPolicy.NONE
  private var isVaultUnlocked: Boolean = false
  private var lastUnlockTime: Long = 0
  private var autoLockTimeout: Long = 0

  private var hashedPin: String? = null
  private var pinSalt: ByteArray? = null

  fun init(context: Context, authValidity: Long = 300) {
    authValiditySeconds = authValidity

    val masterKey = MasterKey.Builder(context)
      .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
      .build()

    prefs = EncryptedSharedPreferences.create(
      context,
      PREF_FILE,
      masterKey,
      PrefKeyEncryptionScheme.AES256_SIV,
      PrefValueEncryptionScheme.AES256_GCM
    )
    loadState()
  }

  private fun saveState() {
    Log.d("VaultManager", "--- saveState() called ---")
    try {
      if (!::prefs.isInitialized) {
        Log.e("VaultManager", "Preferences not initialized!")
        throw Exception("VaultManager not initialized")
      }

      Log.d("VaultManager", "Serializing current state...")
      val json = gson.toJson(currentState)
      Log.d("VaultManager", "State JSON length: ${json.length}")

      Log.d("VaultManager", "Saving to SharedPreferences...")
      prefs.edit().putString(PREF_VAULT_JSON, json).apply()
      Log.d("VaultManager", "State saved successfully")
      Log.d("VaultManager", "--- saveState() completed ---")
    } catch (e: Exception) {
      Log.e("VaultManager", "Error in saveState:", e)
      throw e
    }
  }
  private fun loadState() {
    val json = prefs.getString(PREF_VAULT_JSON, null)
    if (json != null) {
      currentState = gson.fromJson(json, VaultState::class.java)
    }
  }

  fun lockVault() {
    currentState = currentState.copy(isLocked = true)
    saveState()
  }

  fun unlockVault() {
    currentState = currentState.copy(
      isLocked = false,
      lastUnlockTime = SystemClock.elapsedRealtime()
    )
    saveState()
  }

  fun isVaultLocked(): Boolean {
    if (!currentState.isLocked) {
      val elapsed = (SystemClock.elapsedRealtime() - currentState.lastUnlockTime) / 1000
      if (elapsed > authValiditySeconds) {
        lockVault()
        return true
      }
    }
    return currentState.isLocked
  }

  fun getVaultState(): VaultState = currentState


  /**
   * 🔐 Derive AES key from password using PBKDF2
   */
  private fun deriveKeyFromPassword(password: String, salt: ByteArray, iterations: Int = 100000): SecretKey {
    Log.d("VaultManager", "--- deriveKeyFromPassword() called ---")
    Log.d("VaultManager", "Password length: ${password.length}")
    Log.d("VaultManager", "Salt length: ${salt.size}")
    Log.d("VaultManager", "Iterations: $iterations")

    try {
      val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
      Log.d("VaultManager", "SecretKeyFactory created: ${factory.algorithm}")

      val spec = PBEKeySpec(password.toCharArray(), salt, iterations, 256)
      Log.d("VaultManager", "PBEKeySpec created with key length: 256")

      val derivedKey = factory.generateSecret(spec)
      Log.d("VaultManager", "Secret generated successfully")

      val secretKey = SecretKeySpec(derivedKey.encoded, "AES")
      Log.d("VaultManager", "SecretKeySpec created: ${secretKey.algorithm}")
      Log.d("VaultManager", "--- deriveKeyFromPassword() completed ---")

      return secretKey
    } catch (e: Exception) {
      Log.e("VaultManager", "Error in deriveKeyFromPassword:", e)
      throw e
    }
  }

  fun backupVault(password: String): String {
    Log.d("VaultManager", "--- backupVault() called ---")
    Log.d("VaultManager", "Password received, length: ${password.length}")

    if (!::prefs.isInitialized) {
      Log.e("VaultManager", "VaultManager not initialized!")
      throw Exception("VaultManager not initialized. Call init() first.")
    }
    Log.d("VaultManager", "VaultManager is initialized ✓")

    Log.d("VaultManager", "Converting currentState to JSON...")
    val vaultData = gson.toJson(currentState).toByteArray(Charsets.UTF_8)
    Log.d("VaultManager", "Vault data size: ${vaultData.size} bytes")

    Log.d("VaultManager", "Generating random values...")
    val secureRandom = SecureRandom()

    // Generate random salt and IV
    val salt = ByteArray(16).also { secureRandom.nextBytes(it) }
    val iv = ByteArray(12).also { secureRandom.nextBytes(it) }
    Log.d("VaultManager", "Salt generated: ${Base64.encodeToString(salt, Base64.NO_WRAP).take(10)}...")
    Log.d("VaultManager", "IV generated: ${Base64.encodeToString(iv, Base64.NO_WRAP).take(10)}...")

    // Derive AES key from password
    Log.d("VaultManager", "Deriving key from password...")
    val key = deriveKeyFromPassword(password, salt)
    Log.d("VaultManager", "Key derived successfully, algorithm: ${key.algorithm}")

    // AES-GCM encryption
    Log.d("VaultManager", "Setting up AES-GCM encryption...")
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    Log.d("VaultManager", "Cipher instance created: ${cipher.algorithm}")

    Log.d("VaultManager", "Initializing cipher for encryption...")
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    Log.d("VaultManager", "Cipher initialized successfully")

    Log.d("VaultManager", "Encrypting vault data...")
    val ciphertext = cipher.doFinal(vaultData)
    Log.d("VaultManager", "Encryption successful, ciphertext size: ${ciphertext.size} bytes")

    // Build backup JSON blob
    Log.d("VaultManager", "Building backup JSON...")
    val json = JSONObject()
    json.put("salt", Base64.encodeToString(salt, Base64.NO_WRAP))
    json.put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
    json.put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
    json.put("iterations", 100000)
    json.put("algorithm", "AES/GCM/NoPadding")

    val result = json.toString()
    Log.d("VaultManager", "Backup JSON created, length: ${result.length}")
    Log.d("VaultManager", "--- backupVault() completed successfully ---")

    return result
  }

  /**
   * 🔐 Backup vault state (encrypted blob as JSON string)
   * Uses PBKDF2-derived key from password. Does NOT use KeyStore alias.
   */
  fun restoreVault(password: String, backupBlob: String) {
    Log.d("VaultManager", "--- restoreVault() called ---")
    Log.d("VaultManager", "Password length: ${password.length}")
    Log.d("VaultManager", "Backup blob length: ${backupBlob.length}")

    Log.d("VaultManager", "Parsing backup JSON...")
    val json = JSONObject(backupBlob)
    Log.d("VaultManager", "JSON parsed successfully")

    Log.d("VaultManager", "Extracting backup components...")
    val salt = Base64.decode(json.getString("salt"), Base64.NO_WRAP)
    val iv = Base64.decode(json.getString("iv"), Base64.NO_WRAP)
    val ciphertext = Base64.decode(json.getString("ciphertext"), Base64.NO_WRAP)
    val iterations = json.optInt("iterations", 100000)

    Log.d("VaultManager", "Salt length: ${salt.size}")
    Log.d("VaultManager", "IV length: ${iv.size}")
    Log.d("VaultManager", "Ciphertext length: ${ciphertext.size}")
    Log.d("VaultManager", "Iterations: $iterations")

    // Derive AES key
    Log.d("VaultManager", "Deriving key from password...")
    val key = deriveKeyFromPassword(password, salt, iterations)
    Log.d("VaultManager", "Key derived successfully")

    // AES-GCM decryption
    Log.d("VaultManager", "Setting up AES-GCM decryption...")
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    Log.d("VaultManager", "Cipher instance created")

    Log.d("VaultManager", "Initializing cipher for decryption...")
    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
    Log.d("VaultManager", "Cipher initialized successfully")

    Log.d("VaultManager", "Decrypting data...")
    val plainData = cipher.doFinal(ciphertext)
    Log.d("VaultManager", "Decryption successful, plain data size: ${plainData.size} bytes")

    // Rehydrate state
    Log.d("VaultManager", "Parsing decrypted JSON...")
    val jsonString = String(plainData, Charsets.UTF_8)
    Log.d("VaultManager", "Decrypted JSON preview: ${jsonString.take(100)}...")

    Log.d("VaultManager", "Deserializing vault state...")
    currentState = gson.fromJson(jsonString, VaultState::class.java)
    Log.d("VaultManager", "Vault state deserialized successfully")

    Log.d("VaultManager", "Saving restored state...")
    saveState()
    Log.d("VaultManager", "State saved successfully")

    Log.d("VaultManager", "--- restoreVault() completed successfully ---")
  }

  // ---------------------------
  // Vault policy & lock check
  // ---------------------------
  fun setVaultPolicy(policy: VaultPolicy, timeoutMillis: Long = 0) {
    currentPolicy = policy
    autoLockTimeout = timeoutMillis
    isVaultUnlocked = policy == VaultPolicy.NONE
    Log.d("VaultManager", "Vault policy set: $policy, timeout: $timeoutMillis ms")
  }

  fun checkVaultLock(): Boolean {
    when (currentPolicy) {
      VaultPolicy.NONE -> return false
      VaultPolicy.PIN, VaultPolicy.BIOMETRIC -> if (!isVaultUnlocked) return true
      VaultPolicy.TIMEOUT -> {
        val now = System.currentTimeMillis()
        if (!isVaultUnlocked || now - lastUnlockTime > autoLockTimeout) {
          isVaultUnlocked = false
          return true
        }
      }
    }
    return false
  }

  // ---------------------------
  // PIN methods
  // ---------------------------
  fun setVaultPin(pin: String) {
    val secureRandom = SecureRandom()
    pinSalt = ByteArray(16).also { secureRandom.nextBytes(it) }
    hashedPin = hashPin(pin, pinSalt!!)
    Log.d("VaultManager", "PIN set successfully")
  }

  fun unlockVaultWithPin(pin: String): Boolean {
    if (currentPolicy != VaultPolicy.PIN) return false
    val valid = validatePin(pin)
    if (valid) {
      isVaultUnlocked = true
      lastUnlockTime = System.currentTimeMillis()
    }
    return valid
  }

  fun unlockWithPin(inputPin: String): Boolean {
    if (hashedPin == null || pinSalt == null) return false
    val inputHashed = hashPin(inputPin, pinSalt!!)
    return if (inputHashed.contentEquals(hashedPin!!)) {
      isVaultUnlocked = true
      Log.d("VaultManager", "Vault unlocked with PIN")
      true
    } else {
      false
    }
  }


  private fun hashPin(pin: String, salt: ByteArray, iterations: Int = 100_000): String {
    val spec = PBEKeySpec(pin.toCharArray(), salt, iterations, 256)
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val keyBytes = factory.generateSecret(spec).encoded
    return Base64.encodeToString(keyBytes, Base64.NO_WRAP)
  }

  private fun validatePin(pin: String): Boolean {
    if (hashedPin == null || pinSalt == null) return false
    val hashToCompare = hashPin(pin, pinSalt!!)
    return hashToCompare == hashedPin
  }

  // ---------------------------
  // Biometric unlock
  // ---------------------------
// VaultManager.kt
  fun unlockVaultWithBiometric(
    activity: FragmentActivity, // Must be FragmentActivity
    onSuccess: () -> Unit,
    onFailure: () -> Unit,
    onError: (Exception) -> Unit
  ) {
    if (currentPolicy != VaultPolicy.BIOMETRIC) {
      onFailure()
      return
    }

    try {
      BiometricHelper.authenticate(
        activity = activity,
        onSuccess = {
          isVaultUnlocked = true
          lastUnlockTime = System.currentTimeMillis()
          onSuccess()
        },
        onFailure = onFailure, // ← This was missing!
        onError = { errString ->
          onError(Exception(errString))
        }
      )
    } catch (ex: Exception) {
      onError(ex)
    }
  }




}
