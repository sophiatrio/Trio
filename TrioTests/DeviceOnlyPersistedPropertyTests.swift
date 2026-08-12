import Foundation
import Security
import Testing

@testable import Trio

// Legacy fallback is valid only before the first secure commit; ambiguous post-commit state must fail closed.
@Suite("Device-only persisted property", .serialized) struct DeviceOnlyPersistedPropertyTests {
    @Test("Migrates without modifying the legacy value") func legacyRollover() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let legacyData = try fixture.writeLegacy(["source": "legacy", "secret": Data([1, 2, 3])])
        let secureSecret = "device-only-secret-marker"
        var property = fixture.property()

        #expect(property.wrappedValue?["source"] as? String == "legacy")
        #expect(
            try fixture.legacyURL.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true
        )

        property.wrappedValue = ["source": "secure", "secret": secureSecret]

        #expect(property.wrappedValue?["source"] as? String == "secure")
        #expect(try Data(contentsOf: fixture.legacyURL) == legacyData)
        #expect(fixture.keychain.encryptionKeyData?.count == 32)

        let sealed = try Data(contentsOf: fixture.secureURL)
        #expect(sealed.range(of: Data(secureSecret.utf8)) == nil)
        #expect(
            try fixture.secureURL.deletingLastPathComponent()
                .resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true
        )
        #expect(try fixture.secureURL.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
    }

    @Test("A nil tombstone blocks legacy fallback") func nilTombstone() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        try fixture.writeLegacy(["source": "legacy"])
        var property = fixture.property()

        property.wrappedValue = nil

        #expect(property.wrappedValue == nil)
        #expect(fixture.keychain.encryptionKeyData?.count == 32)
        #expect(FileManager.default.fileExists(atPath: fixture.secureURL.path))
    }

    @Test("Authenticated state rejects modification") func authenticatedState() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        try fixture.writeLegacy(["source": "legacy"])
        var property = fixture.property()
        property.wrappedValue = ["source": "secure"]
        var sealed = try Data(contentsOf: fixture.secureURL)
        sealed[sealed.index(before: sealed.endIndex)] ^= 1
        try fixture.writeSecure(sealed)

        #expect(property.wrappedValue == nil)
    }

    @Test("Committed state cannot resurrect the legacy value") func committedState() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        try fixture.writeLegacy(["source": "legacy"])
        var property = fixture.property()
        property.wrappedValue = ["source": "secure"]
        try FileManager.default.removeItem(at: fixture.secureURL)

        #expect(property.wrappedValue == nil)
    }

    @Test("Keychain failure blocks legacy fallback without writing") func inaccessibleKeychain() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        try fixture.writeLegacy(["source": "legacy"])
        fixture.keychain.readError = .darwinError(errSecInteractionNotAllowed)

        #expect(fixture.property().wrappedValue == nil)
        #expect(fixture.keychain.writeCount == 0)
    }
}

private extension DeviceOnlyPersistedPropertyTests {
    final class Fixture {
        let directory: URL
        let legacyURL: URL
        let secureURL: URL
        let keychain = MemoryKeychainDataStore()

        init() throws {
            directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            legacyURL = directory.appendingPathComponent("PumpManagerState.plist")
            secureURL = directory.appendingPathComponent("PumpManagerState.sealed")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }

        func property() -> DeviceOnlyPersistedProperty<[String: Any]> {
            DeviceOnlyPersistedProperty(
                key: "PumpManagerState",
                legacyStorageURL: legacyURL,
                secureStorageURL: secureURL,
                keychain: keychain
            )
        }

        @discardableResult func writeLegacy(_ value: [String: Any]) throws -> Data {
            let data = try PropertyListSerialization.data(fromPropertyList: value, format: .binary, options: 0)
            try data.write(to: legacyURL)
            return data
        }

        func writeSecure(_ data: Data) throws {
            try data.write(to: secureURL)
        }

        func remove() {
            try? FileManager.default.removeItem(at: directory)
        }
    }

    final class MemoryKeychainDataStore: KeychainDataStore {
        private var values: [String: Data] = [:]
        var readError: KeychainError?
        var writeCount = 0

        var encryptionKeyData: Data? {
            get { values["PumpManagerState.deviceOnly.encryptionKey"] }
            set { values["PumpManagerState.deviceOnly.encryptionKey"] = newValue }
        }

        func getData(forKey key: String) -> Result<Data?, KeychainError> {
            if let readError {
                return .failure(readError)
            }
            return .success(values[key])
        }

        func setData(_ value: Data, forKey key: String) -> Result<Void, KeychainError> {
            writeCount += 1
            values[key] = value
            return .success(())
        }
    }
}
