package expo.modules.securestore

import androidx.biometric.BiometricPrompt
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record
import java.io.Serializable

class SecureStoreOptions(
  // Prompt can't be an empty string
  @Field var authenticationPrompt: String = " ",
  @Field var keychainService: String = SecureStoreModule.DEFAULT_KEYSTORE_ALIAS,
  @Field var requireAuthentication: Boolean = false,
  @Field var failOnUpdate: Boolean = false,
  @Field var enableDeviceFallback: Boolean = false
) : Record, Serializable

enum class SecureStoreAuthType(index: Int) {
  UNKNOWN(BiometricPrompt.AUTHENTICATION_RESULT_TYPE_UNKNOWN),
  CREDENTIAL(BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL),
  BIOMETRIC(BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC),

  /** Prompt failed, no authentication was used at all */
  NONE(0)
}

data class SecureStoreFeedback<T>(
  val value: T,
  val authenticationResult: BiometricPrompt.AuthenticationResult? = null
) {
  @Field var authType: SecureStoreAuthType = when (authenticationResult?.authenticationType) {
    BiometricPrompt.AUTHENTICATION_RESULT_TYPE_UNKNOWN -> {
      SecureStoreAuthType.UNKNOWN
    }
    BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL -> {
      SecureStoreAuthType.CREDENTIAL
    }
    BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC -> {
      SecureStoreAuthType.BIOMETRIC
    }
    else -> {
      SecureStoreAuthType.NONE
    }
  }

  /** Used to return easily convertible values to JS code */
  @Field var values: Pair<T, Int> = Pair(value, authType.ordinal)
}
