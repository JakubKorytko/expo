import ExpoModulesCore
#if !os(tvOS)
import LocalAuthentication
#endif
import Security

public final class SecureStoreModule: Module {
  public func definition() -> ModuleDefinition {
    Name("ExpoSecureStore")

    Constant("AFTER_FIRST_UNLOCK") { SecureStoreAccessible.afterFirstUnlock.rawValue }
    Constant("AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY") { SecureStoreAccessible.afterFirstUnlockThisDeviceOnly.rawValue }
    Constant("ALWAYS") { SecureStoreAccessible.always.rawValue }
    Constant("WHEN_PASSCODE_SET_THIS_DEVICE_ONLY") { SecureStoreAccessible.whenPasscodeSetThisDeviceOnly.rawValue }
    Constant("ALWAYS_THIS_DEVICE_ONLY") { SecureStoreAccessible.alwaysThisDeviceOnly.rawValue }
    Constant("WHEN_UNLOCKED") { SecureStoreAccessible.whenUnlocked.rawValue }
    Constant("WHEN_UNLOCKED_THIS_DEVICE_ONLY") { SecureStoreAccessible.whenUnlockedThisDeviceOnly.rawValue }

    AsyncFunction("getValueWithKeyAsync") { (key: String, options: SecureStoreOptions) in
      #if targetEnvironment(simulator)
        if options.requireAuthentication && options.forceReadAuthenticationOnSimulators {
          try await triggerPolicy(options: options)
        }
      #endif
      return getSecureStoreFeedback(value: try get(with: key, options: options)).values
    }

    Function("getValueWithKeySync") { (key: String, options: SecureStoreOptions) in
      return getSecureStoreFeedback(value: try get(with: key, options: options)).values
    }

    AsyncFunction("setValueWithKeyAsync") { (value: String, key: String, options: SecureStoreOptions) -> Int in
      guard let key = validate(for: key) else {
        throw InvalidKeyException()
      }

      if options.requireAuthentication && options.forceAuthenticationOnSave {
        try await triggerPolicy(options: options)
      }

      let result = try set(value: value, with: key, options: options)

      if !result {
        return AuthType.none.rawValue
      }

      return getSecureStoreFeedback(value: true).authType
    }

    Function("setValueWithKeySync") {(value: String, key: String, options: SecureStoreOptions) -> Int in
      guard let key = validate(for: key) else {
        throw InvalidKeyException()
      }

      let result = try set(value: value, with: key, options: options)

      if !result {
        return AuthType.none.rawValue
      }

      return getSecureStoreFeedback(value: true).authType
    }

    AsyncFunction("deleteValueWithKeyAsync") { (key: String, options: SecureStoreOptions) in
      let noAuthSearchDictionary = query(with: key, options: options, requireAuthentication: false)
      let authSearchDictionary = query(with: key, options: options, requireAuthentication: true)
      let legacySearchDictionary = query(with: key, options: options)

      SecItemDelete(legacySearchDictionary as CFDictionary)
      SecItemDelete(authSearchDictionary as CFDictionary)
      SecItemDelete(noAuthSearchDictionary as CFDictionary)
    }

    Function("canUseBiometricAuthentication") {() -> Bool in
      return areBiometricsEnabled()
    }

    Function("canUseDeviceCredentialsAuthentication") { () -> Bool in
      return areDeviceCredentialsEnabled()
    }
  }

  @MainActor
  private func triggerPolicy(options: SecureStoreOptions) async throws {
    let isPolicyAvailable = options.enableDeviceFallback ? areDeviceCredentialsEnabled() : areBiometricsEnabled()

    guard isPolicyAvailable else {
      throw SecureStoreRuntimeError("No authentication method available")
    }

    let localAuthPolicy: LAPolicy = options.enableDeviceFallback ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics
    let localizedReason: String = options.authenticationPrompt ?? "Authentication required"

    let success: Bool = try await withCheckedThrowingContinuation { continuation in
      LAContext().evaluatePolicy(localAuthPolicy, localizedReason: localizedReason) { success, error in
        if let error = error {
          continuation.resume(throwing: error)
        } else {
          continuation.resume(returning: success)
        }
      }
    }

    guard success else {
      throw SecureStoreRuntimeError("Unable to authenticate")
    }
  }

  private func getAuthType() -> AuthType {
    if !areBiometricsEnabled() {return AuthType.credentials}
    let biometryType = LAContext().biometryType

    switch biometryType {
      case .faceID: return .faceID
      case .touchID: return .touchID
      case .opticID: return .opticID // available since iOS 17
      case .none: fallthrough // this one continues to the next line
      @unknown default: return .credentials
    }
  }

  private func getSecureStoreFeedback<T>(value: T) -> SecureStoreFeedback<T> {
    return SecureStoreFeedback(value: value, authType: getAuthType().rawValue)
  }

  private func areBiometricsEnabled() -> Bool {
    #if os(tvOS)
      return false
    #else
      return LAContext().canEvaluatePolicy(LAPolicy.deviceOwnerAuthenticationWithBiometrics, error: nil)
    #endif
  }

  private func areDeviceCredentialsEnabled() -> Bool {
    return LAContext().canEvaluatePolicy(LAPolicy.deviceOwnerAuthentication, error: nil)
  }

  private func get(with key: String, options: SecureStoreOptions) throws -> String? {
    guard let key = validate(for: key) else {
      throw InvalidKeyException()
    }

    if let unauthenticatedItem = try searchKeyChain(with: key, options: options, requireAuthentication: false) {
      return String(data: unauthenticatedItem, encoding: .utf8)
    }

    if let authenticatedItem = try searchKeyChain(with: key, options: options, requireAuthentication: true) {
      return String(data: authenticatedItem, encoding: .utf8)
    }

    if let legacyItem = try searchKeyChain(with: key, options: options) {
      return String(data: legacyItem, encoding: .utf8)
    }

    return nil
  }

  private func NSFaceIDUsageEntryGuard(options: SecureStoreOptions) throws {
    if (options.enableDeviceFallback) {
        return;
    }

    guard let _ = Bundle.main.infoDictionary?["NSFaceIDUsageDescription"] as? String else {
      throw MissingPlistKeyException()
    }
  }

  private func getAccessOptions(options: SecureStoreOptions, accessibility: CFString) throws -> SecAccessControl {
    var error: Unmanaged<CFError>? = nil

    let accessControlFlag: SecAccessControlCreateFlags = options.enableDeviceFallback ? .userPresence : .biometryCurrentSet

    guard let accessOptions = SecAccessControlCreateWithFlags(kCFAllocatorDefault, accessibility, accessControlFlag, &error) else {
      let errorCode = error.map { CFErrorGetCode($0.takeRetainedValue()) }
      throw SecAccessControlError(errorCode)
    }

    return accessOptions
  }

  private func set(value: String, with key: String, options: SecureStoreOptions) throws -> Bool {
    var setItemQuery = query(with: key, options: options, requireAuthentication: options.requireAuthentication)

    let valueData = value.data(using: .utf8)
    setItemQuery[kSecValueData as String] = valueData

    let accessibility = attributeWith(options: options)

    if !options.requireAuthentication {
      setItemQuery[kSecAttrAccessible as String] = accessibility
    } else {
      try NSFaceIDUsageEntryGuard(options: options)
      setItemQuery[kSecAttrAccessControl as String] = try getAccessOptions(options: options, accessibility: accessibility)
    }

    let status = SecItemAdd(setItemQuery as CFDictionary, nil)

    switch status {
    case errSecSuccess:
      // On success we want to remove the other key alias and legacy key (if they exist) to avoid conflicts during reads
      SecItemDelete(query(with: key, options: options) as CFDictionary)
      SecItemDelete(query(with: key, options: options, requireAuthentication: !options.requireAuthentication) as CFDictionary)
      return true
    case errSecDuplicateItem:
      if options.failOnUpdate {
        throw SecureStoreRuntimeError("Key already exists")
      }
      return try update(value: value, with: key, options: options)
    default:
      throw KeyChainException(status)
    }
  }

  private func update(value: String, with key: String, options: SecureStoreOptions) throws -> Bool {
    var query = query(with: key, options: options, requireAuthentication: options.requireAuthentication)

    let valueData = value.data(using: .utf8)
    let updateDictionary = [kSecValueData as String: valueData]

    if let authPrompt = options.authenticationPrompt {
      query[kSecUseOperationPrompt as String] = authPrompt
    }

    let status = SecItemUpdate(query as CFDictionary, updateDictionary as CFDictionary)

    if status == errSecSuccess {
      return true
    } else {
      throw KeyChainException(status)
    }
  }

  private func searchKeyChain(with key: String, options: SecureStoreOptions, requireAuthentication: Bool? = nil) throws -> Data? {
    var query = query(with: key, options: options, requireAuthentication: requireAuthentication)

    query[kSecMatchLimit as String] = kSecMatchLimitOne
    query[kSecReturnData as String] = kCFBooleanTrue

    if let authPrompt = options.authenticationPrompt {
      query[kSecUseOperationPrompt as String] = authPrompt
    }

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)

    switch status {
    case errSecSuccess:
      guard let item = item as? Data else {
        return nil
      }
      return item
    case errSecItemNotFound:
      return nil
    default:
      throw KeyChainException(status)
    }
  }

  private func query(with key: String, options: SecureStoreOptions, requireAuthentication: Bool? = nil) -> [String: Any] {
    var service = options.keychainService ?? "app"
    if let requireAuthentication {
      service.append(":\(requireAuthentication ? "auth" : "no-auth")")
    }

    let encodedKey = Data(key.utf8)

    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrGeneric as String: encodedKey,
      kSecAttrAccount as String: encodedKey
    ]

    if let accessGroup = options.accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }

    return query
  }

  private func attributeWith(options: SecureStoreOptions) -> CFString {
    switch options.keychainAccessible {
    case .afterFirstUnlock:
      return kSecAttrAccessibleAfterFirstUnlock
    case .afterFirstUnlockThisDeviceOnly:
      return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    case .always:
      return kSecAttrAccessibleAlways
    case .whenPasscodeSetThisDeviceOnly:
      return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    case .whenUnlocked:
      return kSecAttrAccessibleWhenUnlocked
    case .alwaysThisDeviceOnly:
      return kSecAttrAccessibleAlwaysThisDeviceOnly
    case .whenUnlockedThisDeviceOnly:
      return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }
  }

  private func validate(for key: String) -> String? {
    let trimmedKey = key.trimmingCharacters(in: .whitespaces)
    if trimmedKey.isEmpty {
      return nil
    }
    return key
  }
}
