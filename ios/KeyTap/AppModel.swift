import Foundation
import KeyTapCore
import Observation
import UIKit
import UserNotifications

/// The paired workstation. Kept in the keychain as ThisDeviceOnly, like the token: UserDefaults
/// would go into iCloud and device backups, and nothing about the workstation may leave the phone.
struct Pairing: Codable, Equatable {
    var host: String
    var pin: Data
    var name: String
    var recipient: String?
    /// The YubiKeys registered with the computer at pairing (serial, slot, recipient).
    var keys: [BridgeClient.RegisteredKey]?
}

@MainActor @Observable
final class AppModel {
    enum Link: Equatable { case unknown, waiting, notListening, error(String) }

    private(set) var pairing: Pairing?
    private(set) var link: Link = .unknown
    private(set) var lastContact: Date?
    var request: ApprovalRequest?
    private var requestBytes = Data()
    private var answered: Set<String> = []
    private var pollTask: Task<Void, Never>?

    /// The setup wizard ran to the end (pairing alone is not "set up": the tests come after).
    var setupDone = UserDefaults.standard.bool(forKey: "setupDone") {
        didSet { UserDefaults.standard.set(setupDone, forKey: "setupDone") }
    }
    /// The last dry run the computer started was answered and verified.
    private(set) var dryRunPassed = false

    // MARK: notifications (optional, opt-in)

    /// The user's choice. Notifications go through the relay only if the paired computer has them too.
    private(set) var notificationsWanted = UserDefaults.standard.bool(forKey: "notificationsWanted")
    /// The setting has not reached the computer yet (it is sent whenever the computer is listening).
    private(set) var pushSyncPending = UserDefaults.standard.bool(forKey: "pushSyncPending") {
        didSet { UserDefaults.standard.set(pushSyncPending, forKey: "pushSyncPending") }
    }
    private(set) var pushToken: String?
    private(set) var pushProblem: String?
    private var pushSyncInFlight = false

    var pushSettings: BridgeClient.PushSettings? {
        guard notificationsWanted, let t = pushToken else { return nil }
        return .init(token: t, env: NotificationCrypto.apnsEnvironment)
    }

    /// Debug builds only: approve with a software key instead of a YubiKey (simulator, tests).
    var useSoftwareKey = false {
        didSet { UserDefaults.standard.set(useSoftwareKey, forKey: "useSoftwareKey") }
    }

    /// Demo mode (Welcome ▸ Try the Demo, and for App Review): a simulated computer and a software
    /// key on this phone. Nothing is stored and nothing leaves the device.
    private(set) var isDemo = false
    private(set) var demoResult: String?
    private var demoKey: SoftwareAgeKey?
    private var demoFileKey: Data?

    /// Approve without NFC: the debug software key, or the demo.
    var approvesInSoftware: Bool { useSoftwareKey || isDemo }

    init() {
        // A fresh install (no setting of ours at all — an update keeps them) starts from a clean
        // keychain: iOS keeps keychain items after an app is deleted.
        let defaults = UserDefaults.standard
        if defaults.object(forKey: "installed") == nil && defaults.object(forKey: "setupDone") == nil {
            Keychain.wipeAll()
        }
        defaults.set(true, forKey: "installed")
        if let d = Keychain.get("pairing") {
            pairing = try? JSONDecoder().decode(Pairing.self, from: d)
        }
        #if DEBUG
        useSoftwareKey = UserDefaults.standard.bool(forKey: "useSoftwareKey")
        // scripts/e2e-simulator.sh seeds a throwaway software key: -keytapSoftwareKey <base64 raw scalar>
        if let i = CommandLine.arguments.firstIndex(of: "-keytapSoftwareKey"), i + 1 < CommandLine.arguments.count,
           let raw = Data(base64Encoded: CommandLine.arguments[i + 1]) {
            SoftwareTestKey.seed(raw)
            useSoftwareKey = true
        }
        #endif
    }

    private var client: BridgeClient? {
        guard let p = pairing, let tok = Keychain.get("bridge-token") else { return nil }
        return BridgeClient(host: p.host, pin: p.pin, token: String(decoding: tok, as: UTF8.self))
    }

    // MARK: pairing

    func pair(with link: PairingLink, keys: [BridgeClient.RegisteredKey]) async throws {
        guard let signer = try DeviceKey.load() else { return }
        let c = BridgeClient(host: link.host, pin: link.pin, token: nil)
        let push = pushSettings
        let (token, bridgeName, notifyKey) = try await c.pair(code: link.code, deviceName: UIDevice.current.name,
                                                              publicKey: signer.publicKeyX963, yubikeys: keys, push: push)
        SharedKeychain.setNotifyKey(push == nil ? nil : notifyKey)
        pushSyncPending = notificationsWanted && push == nil
        guard Keychain.set("bridge-token", Data(token.utf8)) else { throw KeychainError.writeFailed }
        let p = Pairing(host: link.host, pin: link.pin, name: bridgeName.isEmpty ? link.name : bridgeName,
                        recipient: link.recipient, keys: keys)
        guard Keychain.set("pairing", try JSONEncoder().encode(p)) else { throw KeychainError.writeFailed }
        pairing = p
        self.link = .unknown
        startPolling()
    }

    /// Reads the YubiKey's serial and the slot's public key over NFC — no PIN, nothing written.
    func readYubiKey(slot: UInt8) async throws -> BridgeClient.RegisteredKey {
        if useSoftwareKey {
            let k = try SoftwareTestKey.load()
            return .init(serial: SoftwareAgeKey.fakeSerial, slot: SoftwareAgeKey.slot, recipient: k.recipientPoint)
        }
        let info = try await NFCPIVSession.run(prompt: "Hold your YubiKey to the top of the iPhone.", done: "YubiKey read.") { t in
            let piv = PIV(t)
            try await piv.select()
            return try await piv.info(slot: slot)
        }
        guard let point = info.publicKey else { throw PIVError.slotEmpty }
        return .init(serial: info.serial ?? 0, slot: slot, recipient: try PivP256.compress(x963: point))
    }

    /// The phone-only test: PIN + tap + a key agreement checked against software. No computer involved.
    func selfTest(pin: String, slot: UInt8) async throws -> PIV.Info {
        if useSoftwareKey {
            return PIV.Info(firmware: "software", serial: SoftwareAgeKey.fakeSerial)
        }
        let fallback = pairing?.recipient.flatMap(PivP256.parseRecipient)
        return try await NFCPIVSession.run(prompt: "Hold your YubiKey to the top of the iPhone.", done: "Test passed.") { t in
            try await PIV(t).selfTest(slot: slot, pin: pin, fallbackRecipient: fallback)
        }
    }

    func forget() {
        stopPolling()
        Keychain.delete("bridge-token")
        DeviceKey.reset()
        Keychain.delete("pairing")
        pairing = nil
        setupDone = false
        dryRunPassed = false
        request = nil
        link = .unknown
    }

    // MARK: polling — foreground only; the bridge's endpoint exists only while a decrypt waits

    func startPolling() {
        guard pollTask == nil, pairing != nil, !isDemo else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollOnce()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    func pollOnce() async {
        guard let client else {
            link = .error("The pairing token is missing from the keychain. Unpair and pair again.")
            return
        }
        do {
            switch try await client.poll() {
            case .idle:
                link = .waiting
                lastContact = .now
                if request != nil { request = nil }
                await syncPushIfNeeded(client)
            case .notListening:
                link = .notListening
                if request != nil { request = nil }
            case .pending(let req, let bytes):
                link = .waiting
                lastContact = .now
                await syncPushIfNeeded(client)
                if request?.id != req.id, !answered.contains(req.id), req.expiresAt > .now {
                    requestBytes = bytes
                    request = req
                }
            }
        } catch {
            link = .error((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
        }
    }

    // MARK: answering

    /// PIN + tap: the whole PIV conversation runs inside one NFC session. The PIN is passed
    /// straight through to VERIFY and is never stored.
    func approve(pin: String) async throws {
        if isDemo, let req = request, let key = demoKey {
            let results = try await Approver.unwrap(req, with: key)
            let ok = results.first?.fileKey.flatMap { Data(base64Raw: $0) } == demoFileKey
            demoResult = ok ? "Approved. The phone unwrapped the file key and would send only that back to the computer."
                            : "The demo key could not unwrap this request."
            answered.insert(req.id)
            request = nil
            return
        }
        guard let req = request, let client, let signer = try DeviceKey.load() else { return }
        defer { Task { await Notifications.remove(requestID: req.id) } }
        let configured = pairing?.recipient.flatMap(PivP256.parseRecipient)
        if req.isTest {
            let proof: String
            if useSoftwareKey {
                proof = try await Approver.probe(req, with: SoftwareTestKey.load())
            } else {
                proof = try await NFCPIVSession.run(prompt: "Hold your YubiKey to the top of the iPhone.", done: "Dry run answered.") { t in
                    let piv = PIV(t)
                    try await piv.select()
                    try await piv.verify(pin: pin)
                    return try await Approver.probe(req, with: YubiKeyAgeKey(piv: piv, configuredRecipient: configured))
                }
            }
            try await client.send(try Approver.answerProbe(req, requestBytes: requestBytes, proof: proof, signer: signer))
            dryRunPassed = true
            answered.insert(req.id)
            request = nil
            return
        }
        let results: [ApprovalResult]
        if useSoftwareKey {
            results = try await Approver.unwrap(req, with: SoftwareTestKey.load())
        } else {
            results = try await NFCPIVSession.run(
                prompt: "Hold your YubiKey to the top of the iPhone.",
                done: "Approved."
            ) { transport in
                let piv = PIV(transport)
                try await piv.select()
                try await piv.verify(pin: pin)
                let key = YubiKeyAgeKey(piv: piv, configuredRecipient: configured)
                let out = try await Approver.unwrap(req, with: key)
                if out.allSatisfy({ $0.fileKey == nil }) {
                    let tapped = try await key.serial().map { "YubiKey \($0)" } ?? "This YubiKey"
                    let wanted = req.identities.map { String($0.serial) }.joined(separator: ", ")
                    throw ApprovalError.nothingUnwrapped("\(tapped) is not one of this request's keys (\(wanted)).")
                }
                return out
            }
        }
        try await client.send(try Approver.answer(req, requestBytes: requestBytes, results: results, signer: signer))
        answered.insert(req.id)
        request = nil
    }

    func decline() async throws {
        if let id = request?.id { Task { await Notifications.remove(requestID: id) } }
        if isDemo, let req = request {
            demoResult = "Declined. The computer's decrypt would fail with \"declined on the phone\"."
            answered.insert(req.id)
            request = nil
            return
        }
        guard let req = request, let client, let signer = try DeviceKey.load() else { return }
        try await client.send(try Approver.decline(req, requestBytes: requestBytes, signer: signer))
        answered.insert(req.id)
        request = nil
    }

    func setNotifications(_ on: Bool) async {
        pushProblem = nil
        if on {
            let granted = (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])) ?? false
            guard granted else {
                pushProblem = "Notifications are turned off for KeyTap in iOS Settings."
                return
            }
            UIApplication.shared.registerForRemoteNotifications()
        } else {
            SharedKeychain.setNotifyKey(nil)
        }
        notificationsWanted = on
        UserDefaults.standard.set(on, forKey: "notificationsWanted")
        pushSyncPending = pairing != nil
    }

    func refreshPushRegistration() {
        #if DEBUG
        // scripts/e2e-simulator.sh: the simulator gets no real token without a development signature.
        if let i = CommandLine.arguments.firstIndex(of: "-keytapFakePushToken"), i + 1 < CommandLine.arguments.count {
            didRegisterForPush(token: CommandLine.arguments[i + 1])
            return
        }
        #endif
        if notificationsWanted { UIApplication.shared.registerForRemoteNotifications() }
    }

    func didRegisterForPush(token: String) {
        pushProblem = nil
        guard token != pushToken else { return }
        pushToken = token
        if notificationsWanted, pairing != nil { pushSyncPending = true }
    }

    func pushRegistrationFailed(_ error: Error) {
        pushProblem = "iOS could not register for notifications: \(error.localizedDescription)"
    }

    func notificationOpened() {
        Task { await pollOnce() }
    }

    /// Sends the notification setting to the computer while it is listening.
    private func syncPushIfNeeded(_ client: BridgeClient) async {
        guard pushSyncPending, !pushSyncInFlight, !isDemo, let signer = try? DeviceKey.load() else { return }
        if notificationsWanted && pushToken == nil { return } // wait for the token
        pushSyncInFlight = true
        defer { pushSyncInFlight = false }
        do {
            let key = try await client.updateDevice(push: pushSettings, signer: signer)
            SharedKeychain.setNotifyKey(pushSettings == nil ? nil : key)
            pushSyncPending = false
        } catch {
            pushProblem = "Could not update the computer: \((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)"
        }
    }

    // MARK: demo

    func startDemo() {
        stopPolling()
        isDemo = true
        demoResult = nil
        demoKey = SoftwareAgeKey()
    }

    func leaveDemo() {
        isDemo = false
        demoKey = nil
        demoFileKey = nil
        demoResult = nil
        request = nil
        startPolling()
    }

    /// A request exactly as a computer would send it, wrapped to the demo key.
    func sendDemoRequest() {
        guard isDemo, let key = demoKey else { return }
        demoResult = nil
        let fileKey = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        guard let (tag, epk, body) = try? PivP256.wrap(fileKey: fileKey, recipient: key.recipientPoint) else { return }
        demoFileKey = fileKey
        let letters = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        let code = String((0..<3).map { _ in letters.randomElement()! }) + "-" + String((0..<3).map { _ in letters.randomElement()! })
        let iso = ISO8601DateFormatter()
        let now = Date()
        let json: [String: Any] = [
            "version": 1, "id": UUID().uuidString, "code": code, "nonce": UUID().uuidString,
            "created_at": iso.string(from: now), "expires_at": iso.string(from: now.addingTimeInterval(300)),
            "host": "demo-workstation", "user": "you",
            "command": "sops -d secrets/production.enc.yaml", "cwd": "/Users/you/projects/infrastructure",
            "note": "Renewing the staging TLS certificates before tonight's release.",
            "identities": [["serial": SoftwareAgeKey.fakeSerial, "slot": Int(SoftwareAgeKey.slot), "tag": tag.base64Raw]],
            "files": [["index": 0, "stanzas": [["stanza_index": 0, "tag": tag.base64Raw, "epk": epk.base64Raw, "body": body.base64Raw]]]],
        ]
        guard let bytes = try? JSONSerialization.data(withJSONObject: json),
              let req = try? BridgeClient.decoder.decode(ApprovalRequest.self, from: bytes) else { return }
        requestBytes = bytes
        request = req
    }

    func dismissExpired() {
        if let r = request { answered.insert(r.id); Task { await Notifications.remove(requestID: r.id) } }
        request = nil
    }
}

enum KeychainError: Error, LocalizedError {
    case writeFailed
    var errorDescription: String? { "Could not store the key in the keychain." }
}

enum ApprovalError: Error, LocalizedError {
    case nothingUnwrapped(String)
    var errorDescription: String? {
        switch self {
        case .nothingUnwrapped(let why): why
        }
    }
}

/// Debug-only software key, so the full flow runs in the simulator.
enum SoftwareTestKey {
    private static let account = "software-test-key"

    static func seed(_ raw: Data) { Keychain.set(account, raw) }

    static func load() throws -> SoftwareAgeKey {
        if let raw = Keychain.get(account) { return try SoftwareAgeKey(rawRepresentation: raw) }
        let k = SoftwareAgeKey()
        Keychain.set(account, k.rawRepresentation)
        return k
    }
}
