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

  private var vaultPolicy: VaultPolicy = VaultPolicy.NONE
  private var isLocked: Boolean = true

  private var timeoutDurationMs: Long = 0L
  private var lastUsedAt: Long = 0L

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
    try {
      if (!::prefs.isInitialized) {
        throw Exception("VaultManager not initialized")
      }
      val json = gson.toJson(currentState)
      prefs.edit().putString(PREF_VAULT_JSON, json).apply()
    } catch (e: Exception) {
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
    Log.d("VaultManager", "Vault manually locked")
    isLocked = true
  }

  fun unlockVault() {
    lastUsedAt = SystemClock.elapsedRealtime() // reset inactivity timer
    isLocked = false
  }

  fun touch() {
    try {
      lastUnlockTime = SystemClock.elapsedRealtime()
      try {
        currentState = currentState.copy(lastUnlockTime = lastUnlockTime)
      } catch (ignored: Exception) {
      }
    } catch (e: Exception) {
      Log.w("VaultManager", "touch() failed to update lastUnlockTime: ${e.message}")
    }
  }

  fun getPolicy(): VaultPolicy = vaultPolicy

  fun isVaultLocked(): Boolean {
    Log.d("VaultManager", "isVaultLocked called, isLocked=$isLocked, policy=$vaultPolicy")
    return when (vaultPolicy) {
      VaultPolicy.NONE -> false
      VaultPolicy.TIMEOUT -> {
        if (isLocked) return true
        val now = SystemClock.elapsedRealtime()
        val expired = (now - lastUsedAt) > timeoutDurationMs
        if (expired) isLocked = true
        isLocked
      }
      else -> isLocked
    }
  }


  fun getVaultState(): VaultState = currentState


  /**
   * 🔐 Derive AES key from password using PBKDF2
   */
  private fun deriveKeyFromPassword(password: String, salt: ByteArray, iterations: Int = 100000): SecretKey {
    try {
      val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
      val spec = PBEKeySpec(password.toCharArray(), salt, iterations, 256)
      val derivedKey = factory.generateSecret(spec)
      val secretKey = SecretKeySpec(derivedKey.encoded, "AES")
      return secretKey
    } catch (e: Exception) {
      throw e
    }
  }

  fun backupVault(password: String): String {
    if (!::prefs.isInitialized) {
      throw Exception("VaultManager not initialized. Call init() first.")
    }
    val vaultData = gson.toJson(currentState).toByteArray(Charsets.UTF_8)
    val secureRandom = SecureRandom()

    val salt = ByteArray(16).also { secureRandom.nextBytes(it) }
    val iv = ByteArray(12).also { secureRandom.nextBytes(it) }

    val key = deriveKeyFromPassword(password, salt)

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")

    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))

    val ciphertext = cipher.doFinal(vaultData)
    val json = JSONObject()
    json.put("salt", Base64.encodeToString(salt, Base64.NO_WRAP))
    json.put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
    json.put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
    json.put("iterations", 100000)
    json.put("algorithm", "AES/GCM/NoPadding")

    val result = json.toString()
    return result
  }

  /**
   * 🔐 Backup vault state (encrypted blob as JSON string)
   * Uses PBKDF2-derived key from password. Does NOT use KeyStore alias.
   */
  fun restoreVault(password: String, backupBlob: String) {
    val json = JSONObject(backupBlob)
    val salt = Base64.decode(json.getString("salt"), Base64.NO_WRAP)
    val iv = Base64.decode(json.getString("iv"), Base64.NO_WRAP)
    val ciphertext = Base64.decode(json.getString("ciphertext"), Base64.NO_WRAP)
    val iterations = json.optInt("iterations", 100000)

    val key = deriveKeyFromPassword(password, salt, iterations)

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")

    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))

    val plainData = cipher.doFinal(ciphertext)

    val jsonString = String(plainData, Charsets.UTF_8)

    currentState = gson.fromJson(jsonString, VaultState::class.java)

    saveState()
  }

  // ---------------------------
  // Vault policy & lock check
  // ---------------------------
  fun setVaultPolicy(policy: VaultPolicy, timeoutMs: Long = 0L) {
    this.vaultPolicy = policy
    if (policy == VaultPolicy.TIMEOUT) {
      this.timeoutDurationMs = timeoutMs
    }
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
