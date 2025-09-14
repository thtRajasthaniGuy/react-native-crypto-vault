package com.reactnativecryptovault

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executor

object BiometricHelper {

  fun canAuthenticate(activity: FragmentActivity): Boolean {
    val biometricManager = BiometricManager.from(activity)
    return biometricManager.canAuthenticate(
      BiometricManager.Authenticators.BIOMETRIC_STRONG
    ) == BiometricManager.BIOMETRIC_SUCCESS
  }

  fun authenticate(
    activity: FragmentActivity,
    onSuccess: () -> Unit,
    onFailure: () -> Unit,
    onError: (String) -> Unit // Note: this takes String, not Exception
  ) {
    try {
      val executor = ContextCompat.getMainExecutor(activity)
      val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Authenticate")
        .setSubtitle("Unlock Vault")
        .setNegativeButtonText("Cancel")
        .build()

      val biometricPrompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          super.onAuthenticationSucceeded(result)
          onSuccess()
        }

        override fun onAuthenticationFailed() {
          super.onAuthenticationFailed()
          onFailure()
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          super.onAuthenticationError(errorCode, errString)
          onError(errString.toString())
        }
      })

      biometricPrompt.authenticate(promptInfo)
    } catch (ex: Exception) {
      onError(ex.message ?: "Unknown biometric error")
    }
  }
}
