package com.reactnativecryptovault

import android.util.Log
import java.util.concurrent.ConcurrentHashMap

class AuthenticationManager {
  private data class AuthSession(
    val timestamp: Long,
    val validityDurationMs: Long,
    val keyAlias: String
  )
  private var globalAuthTimestamp: Long = 0
  private var globalAuthValidityMs: Long = 0



  // Key-specific authentication sessions
  private var currentAuthSession: AuthSession? = null



  /**
   * Check if authentication is valid for a specific key
   * Falls back to global auth if key-specific auth is not available
   */
  fun isAuthenticationValid(keyAlias: String, validityDurationMs: Long): Boolean {
    Log.d("AuthManager", "🔍 Checking auth for key: $keyAlias")

    val session = currentAuthSession
    Log.d("AuthManager", "🔍 Current session: $session")

    // Check key-specific auth first
    if (session != null && session.keyAlias == keyAlias) {
      val keyAuthValid = (System.currentTimeMillis() - session.timestamp) < validityDurationMs
      Log.d("AuthManager", "🔍 Key auth valid: $keyAuthValid")
      if (keyAuthValid) return true
    }

    // Check global auth fallback (using the simple approach)
    Log.d("AuthManager", "🔍 Global timestamp: $globalAuthTimestamp, validity: $globalAuthValidityMs")
    if (globalAuthTimestamp > 0) {
      val currentTime = System.currentTimeMillis()
      val globalAuthValid = (currentTime - globalAuthTimestamp) < globalAuthValidityMs
      Log.d("AuthManager", "🔍 Global auth valid: $globalAuthValid (age: ${currentTime - globalAuthTimestamp}ms)")

      if (globalAuthValid) {
        Log.d("AuthManager", "✅ Using global auth for $keyAlias")
        markAuthenticated(keyAlias, validityDurationMs) // Cache it
        return true
      } else {
        Log.d("AuthManager", "❌ Global auth expired, clearing")
        globalAuthTimestamp = 0
        globalAuthValidityMs = 0
      }
    }

    Log.d("AuthManager", "❌ No valid auth found for $keyAlias")
    return false
  }

  /**
   * Mark key-specific authentication as valid
   */
  fun markAuthenticated(keyAlias: String, validityDurationMs: Long) {
    currentAuthSession = AuthSession(
      timestamp = System.currentTimeMillis(),
      validityDurationMs = validityDurationMs,
      keyAlias = keyAlias
    )
    Log.d("AuthManager", "Marked key-specific auth for $keyAlias")
  }

  /**
   * Mark global vault authentication as valid (called after unlockVault)
   * This provides a fallback auth for key operations
   */
  fun markGlobalAuthenticated(validityDurationMs: Long) {
    globalAuthTimestamp = System.currentTimeMillis()
    globalAuthValidityMs = validityDurationMs
    Log.d("AuthManager", "Global auth marked valid for ${validityDurationMs}ms")
  }

  /**
   * Clear authentication for a specific key
   */
  fun clearAuthentication(alias: String) {
    val session = currentAuthSession
    if (session?.keyAlias == alias) {
      currentAuthSession = null
      Log.d("AuthManager", "Cleared key-specific authentication for alias: $alias")
    }
  }




}
