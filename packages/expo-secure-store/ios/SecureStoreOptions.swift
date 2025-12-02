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
  var returnUsedAuthenticationType: Bool = false

  @Field
  var forceAuthenticationOnSave: Bool = false

  @Field
  var failOnUpdate: Bool = false
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

public enum SecureStoreFeedbackAction: String {
  case set
  case get
}

protocol SecureStoreFeedback {
  associatedtype Source
  associatedtype Value
  var source: Source { get }
  var authType: Int { get }
  var value: Value { get }
}

struct SecureStoreGetFeedback<T>: SecureStoreFeedback {
  typealias Source = T
  typealias Value = Array<Any>
  var source: Source
  var authType: Int = AuthType.none.rawValue
  var value: Value {
    get { return [source, authType] }
  }
}

struct SecureStoreOriginalFeedback<T>: SecureStoreFeedback {
  typealias Source = T
  typealias Value = T
  var source: Source
  var authType: Int = AuthType.none.rawValue
  var value: Value {
    get { return source }
  }
}

struct SecureStoreSetFeedback<T>: SecureStoreFeedback {
  typealias Source = T
  typealias Value = Int
  var source: Source
  var authType: Int = AuthType.none.rawValue
  var value: Value {
    get { return authType }
  }
}

struct SecureStoreRuntimeError: LocalizedError {
  let errorDescription: String?
  init(_ description: String) {
    self.errorDescription = description
  }
}
