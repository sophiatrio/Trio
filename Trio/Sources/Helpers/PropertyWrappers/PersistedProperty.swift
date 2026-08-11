import CryptoKit
import Foundation

/// Attention! Do not use this wrapper for mutating structure with `didSet` handler into property owner!
/// `didSet` will never called if structure mutate into itself (by "mutating functions").
@propertyWrapper struct Persisted<Value: Codable & Equatable> {
    var wrappedValue: Value {
        get { getValue() ?? initialValue }
        set { setValue(newValue) }
    }

    private func getValue() -> Value? {
        lock?.lock()
        defer { lock?.unlock() }
        return storage.getValue(Value.self, forKey: key)
    }

    private mutating func setValue(_ value: Value) {
        lock?.lock()
        defer { lock?.unlock() }
        storage.setValue(value, forKey: key)
    }

    private let key: String
    private let storage: KeyValueStorage
    private let lock: NSRecursiveLock?
    private let initialValue: Value
    var isInitialValue: Bool {
        if let value = getValue() {
            return value == initialValue
        }
        return true
    }

    init(
        wrappedValue: Value,
        key: String,
        storage: KeyValueStorage = UserDefaults.standard,
        lock: NSRecursiveLock? = nil
    ) {
        self.storage = storage
        self.key = key
        self.lock = lock
        initialValue = wrappedValue
        lock?.lock()
        defer { lock?.unlock() }
        if storage.getValue(Value.self, forKey: key) == nil {
            setValue(wrappedValue)
        }
    }
}

@propertyWrapper public struct PersistedProperty<Value> {
    let key: String
    let storageURL: URL

    public init(key: String) {
        self.key = key

        let documents: URL
        guard let localDocuments = try? FileManager.default.url(
            for: .documentDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ) else {
            preconditionFailure("Could not get a documents directory URL.")
        }
        documents = localDocuments
        storageURL = documents.appendingPathComponent(key + ".plist")
    }

    public var wrappedValue: Value? {
        get {
            do {
                let data = try Data(contentsOf: storageURL)

                guard let value = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? Value
                else {
                    debug(.storage, "[PersistedProperty:\(key)] Could not cast property list to expected type.")
                    return nil
                }
                return value
            } catch {
                debug(.storage, "❌ [PersistedProperty:\(key)] Failed to read value: \(error)")
                return nil
            }
        }
        set {
            guard let newValue = newValue else {
                do {
                    try FileManager.default.removeItem(at: storageURL)
                    debug(.storage, "[PersistedProperty:\(key)] Removed value.")
                } catch {
                    debug(.storage, "❌ [PersistedProperty:\(key)] Failed to remove value: \(error)")
                }
                return
            }

            do {
                let data = try PropertyListSerialization.data(fromPropertyList: newValue, format: .binary, options: 0)
                try data.write(to: storageURL, options: .atomic)

                // Ensure appropriate protection level
                try FileManager.default.setAttributes(
                    [.protectionKey: FileProtectionType.none],
                    ofItemAtPath: storageURL.path
                )

                debug(.storage, "✅ [PersistedProperty:\(key)] Saved value successfully.")
            } catch {
                debug(.storage, "❌ [PersistedProperty:\(key)] Failed to write value: \(error)")
            }
        }
    }
}

protocol KeychainDataStore: AnyObject {
    func getData(forKey key: String) -> Result<Data?, KeychainError>
    func setData(_ value: Data, forKey key: String) -> Result<Void, KeychainError>
}

extension BaseKeychain: KeychainDataStore {}

private enum DeviceOnlyStorageFormat {
    static let version: UInt8 = 1
    static let nilValue: UInt8 = 0
    static let value: UInt8 = 1
}

private enum DeviceOnlyStorageError: Error {
    case invalidEncryptionKey
    case invalidFormat
    case missingSealedData
    case unexpectedValueType
}

/// Persists opaque manager state as authenticated ciphertext outside Documents and backups.
/// The encryption key is non-synchronizing and device-bound; legacy state remains read-only migration input.
@propertyWrapper struct DeviceOnlyPersistedProperty<Value> {
    private let key: String
    private let legacyStorageURL: URL
    private let secureStorageURL: URL
    private let keychain: KeychainDataStore
    private let fileManager: FileManager
    private let lock = NSRecursiveLock()

    init(key: String) {
        let fileManager = FileManager.default
        guard let documents = try? fileManager.url(
            for: .documentDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ) else {
            preconditionFailure("Could not get a documents directory URL.")
        }

        guard let applicationSupport = try? fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ) else {
            preconditionFailure("Could not get an application support directory URL.")
        }

        let secureDirectory = applicationSupport
            .appendingPathComponent(Bundle.main.bundleIdentifier ?? "Trio", isDirectory: true)
            .appendingPathComponent("DeviceOnlyState", isDirectory: true)

        self.init(
            key: key,
            legacyStorageURL: documents.appendingPathComponent(key + ".plist"),
            secureStorageURL: secureDirectory.appendingPathComponent(key + ".sealed"),
            keychain: BaseKeychain(
                synchronizable: false,
                accessibilityLevel: .afterFirstUnlockThisDeviceOnly
            ),
            fileManager: fileManager
        )
    }

    init(
        key: String,
        legacyStorageURL: URL,
        secureStorageURL: URL,
        keychain: KeychainDataStore,
        fileManager: FileManager = .default
    ) {
        self.key = key
        self.legacyStorageURL = legacyStorageURL
        self.secureStorageURL = secureStorageURL
        self.keychain = keychain
        self.fileManager = fileManager
    }

    var wrappedValue: Value? {
        get {
            lock.lock()
            defer { lock.unlock() }

            let keyData: Data?
            switch keychain.getData(forKey: encryptionKeyName) {
            case let .success(data):
                keyData = data
            case let .failure(error):
                debug(.storage, "❌ [DeviceOnlyPersistedProperty] Failed to read encryption key for \(key): \(error)")
                return nil
            }

            guard fileManager.fileExists(atPath: secureStorageURL.path) else {
                return readLegacyUnlessCommitted()
            }

            guard let keyData else {
                debug(.storage, "❌ [DeviceOnlyPersistedProperty] Missing encryption key for \(key).")
                return nil
            }

            return readSecureValue(using: keyData)
        }
        set {
            lock.lock()
            defer { lock.unlock() }

            do {
                let encryptionKey = try getOrCreateEncryptionKey()
                let sealed = try seal(encode(newValue), using: encryptionKey)
                try fileManager.createDirectory(
                    at: secureStorageURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                try excludeFromBackup(secureStorageURL.deletingLastPathComponent())
                try sealed.write(
                    to: secureStorageURL,
                    options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
                )
                try excludeFromBackup(secureStorageURL)
                // A missing secure file may fall back only when no secure write ever committed.
                try keychain.setData(Data([DeviceOnlyStorageFormat.version]), forKey: committedKeyName).get()
            } catch {
                debug(.storage, "❌ [DeviceOnlyPersistedProperty] Failed to write \(key): \(error)")
            }
        }
    }

    private var encryptionKeyName: String {
        key + ".deviceOnly.encryptionKey"
    }

    private var committedKeyName: String {
        key + ".deviceOnly.committed"
    }

    private var authenticatedContext: Data {
        Data([DeviceOnlyStorageFormat.version]) + Data(key.utf8)
    }

    private func getOrCreateEncryptionKey() throws -> SymmetricKey {
        switch keychain.getData(forKey: encryptionKeyName) {
        case let .success(data?):
            guard data.count == 32 else { throw DeviceOnlyStorageError.invalidEncryptionKey }
            return SymmetricKey(data: data)
        case .success(nil):
            let encryptionKey = SymmetricKey(size: .bits256)
            let data = encryptionKey.withUnsafeBytes { Data($0) }
            try keychain.setData(data, forKey: encryptionKeyName).get()
            return encryptionKey
        case let .failure(error):
            throw error
        }
    }

    private func encode(_ value: Value?) throws -> Data {
        guard let value else { return Data([DeviceOnlyStorageFormat.nilValue]) }

        var data = Data([DeviceOnlyStorageFormat.value])
        data.append(try PropertyListSerialization.data(fromPropertyList: value, format: .binary, options: 0))
        return data
    }

    private func seal(_ data: Data, using encryptionKey: SymmetricKey) throws -> Data {
        let box = try AES.GCM.seal(data, using: encryptionKey, authenticating: authenticatedContext)
        guard let combined = box.combined else { throw DeviceOnlyStorageError.missingSealedData }
        return Data([DeviceOnlyStorageFormat.version]) + combined
    }

    private func readSecureValue(using keyData: Data) -> Value? {
        do {
            guard keyData.count == 32 else { throw DeviceOnlyStorageError.invalidEncryptionKey }
            let sealed = try Data(contentsOf: secureStorageURL)
            guard sealed.first == DeviceOnlyStorageFormat.version else { throw DeviceOnlyStorageError.invalidFormat }

            let box = try AES.GCM.SealedBox(combined: Data(sealed.dropFirst()))
            let data = try AES.GCM.open(
                box,
                using: SymmetricKey(data: keyData),
                authenticating: authenticatedContext
            )
            return try decode(data)
        } catch {
            debug(.storage, "❌ [DeviceOnlyPersistedProperty] Failed to read \(key): \(error)")
            return nil
        }
    }

    private func decode(_ data: Data) throws -> Value? {
        guard let discriminator = data.first else { throw DeviceOnlyStorageError.invalidFormat }
        switch discriminator {
        case DeviceOnlyStorageFormat.nilValue:
            return nil
        case DeviceOnlyStorageFormat.value:
            guard let value = try PropertyListSerialization.propertyList(
                from: Data(data.dropFirst()),
                options: [],
                format: nil
            ) as? Value else {
                throw DeviceOnlyStorageError.unexpectedValueType
            }
            return value
        default:
            throw DeviceOnlyStorageError.invalidFormat
        }
    }

    private func excludeFromBackup(_ storageURL: URL) throws {
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var url = storageURL
        try url.setResourceValues(values)
    }

    private func readLegacyUnlessCommitted() -> Value? {
        switch keychain.getData(forKey: committedKeyName) {
        case .success(nil):
            return readLegacyValue()
        case .success:
            debug(.storage, "❌ [DeviceOnlyPersistedProperty] Missing committed state for \(key).")
            return nil
        case let .failure(error):
            debug(.storage, "❌ [DeviceOnlyPersistedProperty] Failed to read migration state for \(key): \(error)")
            return nil
        }
    }

    private func readLegacyValue() -> Value? {
        do {
            let data = try Data(contentsOf: legacyStorageURL)
            return try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? Value
        } catch {
            debug(.storage, "❌ [DeviceOnlyPersistedProperty] Failed to read legacy \(key): \(error)")
            return nil
        }
    }
}

import Foundation

enum FileProtectionFixer {
    /// Ensures only critical persisted flags have safe file protection set.
    static func fixFlagFileProtectionForPropertyPersistentFlags() {
        let flagFiles = [
            "onboardingCompleted.plist",
            "crashlyticsSharingEnabled.plist",
            "lastCleanupDate.plist",
            "hasSeenFatProteinOrderChange.plist",
            "telemetrySharingEnabled.plist",
            "telemetryLastSentAt.plist",
            "telemetryLastSentSha.plist",
            "telemetryColdLaunchTimes.plist",
            "telemetryInstallId.plist",
            "telemetryAttestForbidden.plist",
            "telemetryDebugServerURL.plist"
        ]

        let fileManager = FileManager.default

        guard let documentsURL = try? fileManager.url(
            for: .documentDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: false
        ) else {
            debug(.storage, "⚠️ Could not access the documents directory.")
            return
        }

        for fileName in flagFiles {
            let fileURL = documentsURL.appendingPathComponent(fileName)

            guard fileManager.fileExists(atPath: fileURL.path) else {
                continue // Skip if file doesn’t exist yet
            }

            do {
                try fileManager.setAttributes(
                    [.protectionKey: FileProtectionType.none],
                    ofItemAtPath: fileURL.path
                )
                debug(.storage, "✅ Updated protection for \(fileName)")
            } catch {
                debug(.storage, "❌ Failed to update protection for \(fileName): \(error)")
            }
        }
    }
}
