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
  var forceAuthenticationOnSave: Bool = false
}

struct SecureStoreRuntimeError: LocalizedError {
  let errorDescription: String?
  init(_ description: String) {
    self.errorDescription = description
  }
}
