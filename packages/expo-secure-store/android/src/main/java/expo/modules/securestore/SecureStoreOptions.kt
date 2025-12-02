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
  @Field var enableDeviceFallback: Boolean = false,
  @Field var returnUsedAuthenticationType: Boolean = false
) : Record, Serializable

enum class SecureStoreAuthType(index: Int) {
  UNKNOWN(BiometricPrompt.AUTHENTICATION_RESULT_TYPE_UNKNOWN),
  CREDENTIAL(BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL),
  BIOMETRIC(BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC),

  /** Prompt failed, no authentication was used at all */
  NONE(0)
}

open class SecureStoreFeedbackAction {
  companion object {
    const val GET = "GET"
    const val SET = "SET"
  }
}

abstract class SecureStoreFeedback<T, R>(
  val source: T,
  val authenticationResult: BiometricPrompt.AuthenticationResult?
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
  abstract val value: R
}

class SecureStoreGetFeedback<T>(source: T, authenticationResult: BiometricPrompt.AuthenticationResult? = null): SecureStoreFeedback<T, Pair<T, Int>>(source, authenticationResult) {
  /** Used to return easily convertible values to JS code */
  @Field override var value: Pair<T, Int> = Pair(source, authType.ordinal)
}

class SecureStoreSetFeedback<T>(source: T, authenticationResult: BiometricPrompt.AuthenticationResult? = null): SecureStoreFeedback<T, Int>(source, authenticationResult) {
  @Field override var value: Int = authType.ordinal
}

class SecureStoreOriginalFeedback<T>(source: T, authenticationResult: BiometricPrompt.AuthenticationResult? = null): SecureStoreFeedback<T, T>(source, authenticationResult) {
  @Field override var value: T = source
}

typealias SecureStoreNarrowedFeedback<T> = SecureStoreFeedback<T, out Any?>
