import ExpoModulesCore

internal struct SecureStoreOptions: Record {
  @Field
  var authenticationPrompt: String?

  @Field
  var keychainAccessible: SecureStoreAccessible = .whenUnlocked

  @Field
  var keychainService: String?

  @Field
  var requireAuthentication: Bool

  @Field
  var accessGroup: String?

  @Field
  var enableDeviceFallback: Bool = false

  @Field
  var forceAuthenticationOnSave: Bool = false
}

@available(iOS 11.2, *)
public enum AuthType: Int, @unchecked Sendable {
  /// The device does not support biometry.
  case none = 0

  /// The device supports device credentials
  case credentials = 1

  /// Generic type, not specified whether it was a faceID or touchID
  case biometrics = 2

  /// The device supports Face ID.
  case faceID = 3

  /// The device supports Touch ID.
  case touchID = 4

  /// The device supports Optic ID
  case opticID = 5
}

struct SecureStoreFeedback<T> {
  var value: T
  var authType: Int = AuthType.none.rawValue
  var values: Array<Any> {
    get { return [value, authType] }
  }
}

struct SecureStoreRuntimeError: LocalizedError {
  let errorDescription: String?
  init(_ description: String) {
    self.errorDescription = description
  }
}
