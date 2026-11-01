import CryptoKit
import Foundation
import KeyTapCore
import Observation
import UIKit
import UserNotifications

/// A paired computer. Kept in the keychain as ThisDeviceOnly, like its token: UserDefaults would go
/// into iCloud and device backups, and nothing about a workstation may leave the phone.
/// One phone can be paired with several computers (laptop, desktop, …); each has its own token.
struct Pairing: Codable, Equatable, Identifiable {
    var host: String
    var pin: Data
    var name: String
    var recipient: String?
    /// The YubiKeys registered with the computer at pairing (serial, slot, recipient).
    var keys: [BridgeClient.RegisteredKey]?

    /// The computer's identity: the SHA-256 of its bridge certificate (the pin), in hex.
    var id: String { pin.map { String(format: "%02x", $0) }.joined() }
    var tokenAccount: String { "bridge-token.\(id)" }
}

@MainActor @Observable
final class AppModel {
    enum Link: Equatable { case unknown, waiting, notListening, error(String) }

    /// Every paired computer, in pairing order.
    private(set) var pairings: [Pairing] = []
    /// The computer paired most recently (the setup wizard's dry run, the phone test's slot).
    var pairing: Pairing? { pairings.last }
    /// Per computer: can the phone reach it right now.
    private(set) var links: [String: Link] = [:]
    private(set) var lastContact: Date?
    var request: ApprovalRequest?
    /// The computer the shown request came from.
    private(set) var requestFrom: Pairing?
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
    /// The computers the setting has not reached yet (it is sent whenever a computer is listening).
    private(set) var pushPending: Set<String> = [] {
        didSet { UserDefaults.standard.set(!pushPending.isEmpty, forKey: "pushSyncPending") }
    }
    var pushSyncPending: Bool { !pushPending.isEmpty }
    private(set) var pushToken: String?
    private(set) var pushProblem: String?
    private var pushSyncInFlight: Set<String> = []

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
    /// The demo's SSH key: a software FIDO2 authenticator in place of the YubiKey's FIDO applet.
    private var demoFIDO: SoftFIDOAuthenticator?

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
        pairings = Self.loadPairings()
        if defaults.bool(forKey: "pushSyncPending") { pushPending = Set(pairings.map(\.id)) }
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

    /// The pairings from the keychain. A phone from KeyTap 1.0 had one pairing under "pairing" with its token
    /// under "bridge-token" (and its notification key under "notify-key"): moved to the per-computer layout once.
    private static func loadPairings() -> [Pairing] {
        if let d = Keychain.get("pairings"), let list = try? JSONDecoder().decode([Pairing].self, from: d) { return list }
        guard let d = Keychain.get("pairing"), let p = try? JSONDecoder().decode(Pairing.self, from: d) else { return [] }
        if let tok = Keychain.get("bridge-token") { Keychain.set(p.tokenAccount, tok) }
        SharedKeychain.migrateLegacyNotifyKey(to: p.id)
        guard Keychain.set("pairings", (try? JSONEncoder().encode([p])) ?? Data()) else { return [p] }
        Keychain.delete("pairing")
        Keychain.delete("bridge-token")
        return [p]
    }

    private func savePairings() throws {
        guard Keychain.set("pairings", try JSONEncoder().encode(pairings)) else { throw KeychainError.writeFailed }
    }

    private func client(for p: Pairing) -> BridgeClient? {
        guard let tok = Keychain.get(p.tokenAccount) else { return nil }
        return BridgeClient(host: p.host, pin: p.pin, token: String(decoding: tok, as: UTF8.self))
    }

    /// All computers together: ready if any can be reached, an error only if none can.
    var link: Link {
        let all = pairings.compactMap { links[$0.id] }
        if all.isEmpty { return .unknown }
        if all.contains(where: { $0 == .waiting || $0 == .notListening }) { return all.contains(.waiting) ? .waiting : .notListening }
        if let e = all.first(where: { if case .error = $0 { true } else { false } }), all.allSatisfy({ $0 != .unknown }) { return e }
        return .unknown
    }

    // MARK: pairing

    /// Pairs with a computer. The same computer again (same certificate) replaces its pairing; any other is added.
    func pair(with link: PairingLink, keys: [BridgeClient.RegisteredKey]) async throws {
        guard let signer = try DeviceKey.load() else { return }
        let c = BridgeClient(host: link.host, pin: link.pin, token: nil)
        let push = pushSettings
        let (token, bridgeName, notifyKey) = try await c.pair(code: link.code, deviceName: UIDevice.current.name,
                                                              publicKey: signer.publicKeyX963, yubikeys: keys, push: push)
        let p = Pairing(host: link.host, pin: link.pin, name: bridgeName.isEmpty ? link.name : bridgeName,
                        recipient: link.recipient, keys: keys)
        guard Keychain.set(p.tokenAccount, Data(token.utf8)) else { throw KeychainError.writeFailed }
        SharedKeychain.setNotifyKey(push == nil ? nil : notifyKey, for: p.id)
        if notificationsWanted && push == nil { pushPending.insert(p.id) } else { pushPending.remove(p.id) }
        pairings.removeAll { $0.id == p.id }
        pairings.append(p)
        try savePairings()
        links[p.id] = .unknown
        dryRunPassed = false // the wizard's dry run is for this computer
        startPolling()
    }

    /// Removes one computer from this phone (the computer keeps its record until `unpair` runs there).
    func remove(_ p: Pairing) {
        Keychain.delete(p.tokenAccount)
        SharedKeychain.setNotifyKey(nil, for: p.id)
        pairings.removeAll { $0.id == p.id }
        try? savePairings()
        links[p.id] = nil
        pushPending.remove(p.id)
        if requestFrom?.id == p.id { request = nil; requestFrom = nil }
        if pairings.isEmpty { forget() }
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
        for p in pairings {
            Keychain.delete(p.tokenAccount)
            SharedKeychain.setNotifyKey(nil, for: p.id)
        }
        Keychain.delete("pairings")
        DeviceKey.reset()
        pairings = []
        links = [:]
        pushPending = []
        setupDone = false
        dryRunPassed = false
        request = nil
        requestFrom = nil
    }

    // MARK: polling — foreground only; the bridge's endpoint exists only while a decrypt waits

    func startPolling() {
        guard pollTask == nil, !pairings.isEmpty, !isDemo else { return }
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

    /// Asks every paired computer at once. A request is shown from the first computer that has one; the next
    /// one waits until it is answered (each computer serves only one request at a time anyway).
    func pollOnce() async {
        let list = pairings
        await withTaskGroup(of: Void.self) { group in
            for p in list { group.addTask { await self.poll(p) } }
        }
    }

    private func poll(_ p: Pairing) async {
        guard let client = client(for: p) else {
            links[p.id] = .error("The pairing token for \(p.name) is missing from the keychain. Remove it and pair again.")
            return
        }
        do {
            switch try await client.poll() {
            case .idle:
                links[p.id] = .waiting
                lastContact = .now
                if requestFrom?.id == p.id { request = nil; requestFrom = nil }
                await syncPushIfNeeded(client, p)
            case .notListening:
                links[p.id] = .notListening
                if requestFrom?.id == p.id { request = nil; requestFrom = nil }
            case .pending(let req, let bytes):
                links[p.id] = .waiting
                lastContact = .now
                await syncPushIfNeeded(client, p)
                let free = request == nil || requestFrom?.id == p.id
                if free, request?.id != req.id, !answered.contains(req.id), req.expiresAt > .now {
                    requestBytes = bytes
                    requestFrom = p
                    request = req
                }
            }
        } catch {
            links[p.id] = .error("\(p.name): " + ((error as? LocalizedError)?.errorDescription ?? error.localizedDescription))
        }
    }

    // MARK: answering

    /// PIN + tap: the whole PIV conversation runs inside one NFC session. The PIN is passed
    /// straight through to VERIFY and is never stored.
    func approve(pin: String) async throws {
        if isDemo, let req = request, req.isSSH, let sign = req.ssh, let fido = demoFIDO {
            let a = try await SSHSigner.sign(sign, pin: Self.demoPIN, transport: fido)
            demoResult = a.flags & 0x04 != 0
                ? "Signed. The key checked the PIN and signed this one SSH login; the phone would send only the signature back to ssh."
                : "The demo key could not sign this login."
            answered.insert(req.id)
            request = nil
            return
        }
        if isDemo, let req = request, let key = demoKey {
            let results = try await Approver.unwrap(req, with: key)
            let ok = results.first?.fileKey.flatMap { Data(base64Raw: $0) } == demoFileKey
            demoResult = ok ? "Approved. The phone unwrapped the file key and would send only that back to the computer."
                            : "The demo key could not unwrap this request."
            answered.insert(req.id)
            request = nil
            return
        }
        guard let req = request, let from = requestFrom, let client = client(for: from), let signer = try DeviceKey.load() else { return }
        defer { Task { await Notifications.remove(requestID: req.id) } }
        if req.isUnknownKind { throw ApprovalError.unsupported }
        if req.isSSH, let sign = req.ssh {
            guard !useSoftwareKey else { throw ApprovalError.sshNeedsYubiKey }
            // FIDO2 over NFC: select the FIDO applet, PIN → token, getAssertion. The PIN goes only to the key.
            let assertion = try await NFCPIVSession.run(prompt: "Hold your YubiKey to the top of the iPhone.", done: "Signed.") { t in
                try await SSHSigner.sign(sign, pin: pin, transport: t)
            }
            try await client.send(try Approver.answerSSH(req, requestBytes: requestBytes, assertion: assertion, signer: signer))
            answered.insert(req.id)
            request = nil
            return
        }
        let configured = from.recipient.flatMap(PivP256.parseRecipient)
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
            demoResult = req.isSSH ? "Declined. The SSH login would fail with \"declined on the phone\"."
                                   : "Declined. The computer's decrypt would fail with \"declined on the phone\"."
            answered.insert(req.id)
            request = nil
            return
        }
        guard let req = request, let from = requestFrom, let client = client(for: from), let signer = try DeviceKey.load() else { return }
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
            for p in pairings { SharedKeychain.setNotifyKey(nil, for: p.id) }
        }
        notificationsWanted = on
        UserDefaults.standard.set(on, forKey: "notificationsWanted")
        pushPending = Set(pairings.map(\.id))
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
        if notificationsWanted { pushPending = Set(pairings.map(\.id)) }
    }

    func pushRegistrationFailed(_ error: Error) {
        pushProblem = "iOS could not register for notifications: \(error.localizedDescription)"
    }

    func notificationOpened() {
        Task { await pollOnce() }
    }

    /// Sends the notification setting to a computer while it is listening.
    private func syncPushIfNeeded(_ client: BridgeClient, _ p: Pairing) async {
        guard pushPending.contains(p.id), !pushSyncInFlight.contains(p.id), !isDemo, let signer = try? DeviceKey.load() else { return }
        if notificationsWanted && pushToken == nil { return } // wait for the token
        pushSyncInFlight.insert(p.id)
        defer { pushSyncInFlight.remove(p.id) }
        do {
            let key = try await client.updateDevice(push: pushSettings, signer: signer)
            SharedKeychain.setNotifyKey(pushSettings == nil ? nil : key, for: p.id)
            pushPending.remove(p.id)
        } catch {
            pushProblem = "Could not update \(p.name): \((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)"
        }
    }

    // MARK: demo

    func startDemo() {
        stopPolling()
        isDemo = true
        demoResult = nil
        demoKey = SoftwareAgeKey()
        demoFIDO = SoftFIDOAuthenticator(credential: .init(rpId: "ssh:"), pin: Self.demoPIN)
    }

    /// The demo key's FIDO2 PIN (the demo needs no PIN typed; this stands in for the one on a real key).
    private static let demoPIN = "123456"

    func leaveDemo() {
        isDemo = false
        demoKey = nil
        demoFIDO = nil
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

    /// An SSH login request exactly as a computer would send it (ssh → keytap-sk → bridge), for the demo key.
    func sendDemoSSHRequest() async {
        guard isDemo, let fido = demoFIDO else { return }
        demoResult = nil
        let cred = await fido.credentialForDemo
        let data = Data((0..<64).map { _ in UInt8.random(in: 0...255) })
        let letters = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        let code = String((0..<3).map { _ in letters.randomElement()! }) + "-" + String((0..<3).map { _ in letters.randomElement()! })
        let iso = ISO8601DateFormatter()
        let now = Date()
        let json: [String: Any] = [
            "version": 1, "kind": "ssh", "id": UUID().uuidString, "code": code, "nonce": UUID().uuidString,
            "created_at": iso.string(from: now), "expires_at": iso.string(from: now.addingTimeInterval(300)),
            "host": "demo-workstation", "user": "you",
            "command": "ssh deploy@build-server.example", "cwd": "/Users/you/projects/infrastructure",
            "note": "Rolling out tonight's release to the build server.",
            "identities": [], "files": [],
            "ssh": [
                "application": cred.rpId, "credential_id": cred.id.base64Raw,
                "client_data_hash": Data(SHA256.hash(data: data)).base64Raw, "algorithm": "ed25519",
                "user_presence": true, "user_verification": true, "purpose": "login", "login": "deploy",
                "key_name": "id_ed25519_sk", "host_key_fingerprint": "SHA256:demoServerKeyN5c0f9QzS1bJt3xXc8Ym2Lw",
            ],
        ]
        guard let bytes = try? JSONSerialization.data(withJSONObject: json),
              let req = try? BridgeClient.decoder.decode(ApprovalRequest.self, from: bytes) else { return }
        requestBytes = bytes
        request = req
    }

    func dismissExpired() {
        if let r = request { answered.insert(r.id); Task { await Notifications.remove(requestID: r.id) } }
        request = nil
        requestFrom = nil
    }
}

enum KeychainError: Error, LocalizedError {
    case writeFailed
    var errorDescription: String? { "Could not store the key in the keychain." }
}

enum ApprovalError: Error, LocalizedError {
    case nothingUnwrapped(String)
    case unsupported
    case sshNeedsYubiKey
    var errorDescription: String? {
        switch self {
        case .nothingUnwrapped(let why): why
        case .unsupported: "This request needs a newer version of KeyTap. Update the app from the App Store."
        case .sshNeedsYubiKey: "SSH requests need a real YubiKey; the software test key handles decryptions only."
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
