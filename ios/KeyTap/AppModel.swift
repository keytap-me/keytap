import CryptoKit
import Foundation
import KeyTapCore
import Observation
import OSLog
import UIKit
import UserNotifications

/// A paired computer. Kept in the keychain as ThisDeviceOnly, like its token: UserDefaults would go
/// into iCloud and device backups, and nothing about a workstation may leave the phone.
/// One phone can be paired with several computers (laptop, desktop, …); each has its own token.
/// Nothing about YubiKeys: the computer sends its key list with every request (KeyTap 1.1).
struct Pairing: Codable, Equatable, Identifiable {
    var host: String
    var pin: Data
    var name: String

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
    /// One client (one HTTPS session) per computer, for as long as it is paired. Not observed.
    @ObservationIgnored private var clients: [String: BridgeClient] = [:]
    /// The app icon carries a badge exactly while a request waits for an answer.
    var request: ApprovalRequest? {
        didSet { if request?.id != oldValue?.id { Notifications.setBadge(request == nil ? 0 : 1) } }
    }
    // MARK: one sound per request
    //
    // A request makes a sound once, whichever way it reaches the user: its notification (on the lock
    // screen, or with KeyTap open through willPresent) or the open app's poll. On top of that, the open app
    // stays quiet for what was already waiting when it came back to the screen — the user is looking at it:
    //   - every request id that sounded, was notified or was simply seen is in `alerted`, for good: a
    //     reconnect glitch that hides and re-shows a request never sounds it again;
    //   - a computer's first answer after returning from the background (`contacted`), however long the
    //     reconnect takes, and anything in the first seconds after the return, are taken as seen;
    //   - a request whose notification is still in Notification Center already sounded.
    // The NFC sheet only makes the app inactive: it is not a return, so the next request still sounds.
    private var alerted: Set<String> = []
    private var contacted: Set<String> = []
    private var inBackground = true
    private var cameBackAt = Date.distantPast
    private static let settle: TimeInterval = 4
    /// The computer the shown request came from.
    private(set) var requestFrom: Pairing?
    private var requestBytes = Data()
    /// The request of the shown chain that is answered next (a continuation after "held"). nil = the shown one.
    private var chainRequest: (ApprovalRequest, Data)?
    /// A tap is in progress (the NFC sheet is up): the poller leaves the chain to it.
    private(set) var approving = false
    /// Why the last request went away on its own ("answered elsewhere"), shown on the home screen.
    var notice: String?
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
        if let d = Keychain.get("pairings"), let list = try? JSONDecoder().decode([Pairing].self, from: d) {
            // KeyTap 1.1 stores no YubiKey list: rewrite a 1.0 / early-1.1 entry without it (keys, recipient).
            let raw = String(decoding: d, as: UTF8.self)
            if raw.contains("\"keys\"") || raw.contains("\"recipient\""), let clean = try? JSONEncoder().encode(list) {
                Keychain.set("pairings", clean)
            }
            return list
        }
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
        if let c = clients[p.id] { return c }
        guard let tok = Keychain.get(p.tokenAccount) else { return nil }
        let c = BridgeClient(host: p.host, pin: p.pin, token: String(decoding: tok, as: UTF8.self))
        clients[p.id] = c
        return c
    }

    /// Sets a computer's link only when it changes: the poll runs every second, and every write
    /// to an observed property redraws the home screen.
    private func setLink(_ p: Pairing, _ l: Link) {
        if links[p.id] != l { links[p.id] = l }
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
    func pair(with link: PairingLink) async throws {
        guard let signer = try DeviceKey.load() else { return }
        let c = BridgeClient(host: link.host, pin: link.pin, token: nil)
        let push = pushSettings
        let (token, bridgeName, notifyKey) = try await c.pair(code: link.code, deviceName: UIDevice.current.name,
                                                              publicKey: signer.publicKeyX963, push: push)
        let p = Pairing(host: link.host, pin: link.pin, name: bridgeName.isEmpty ? link.name : bridgeName)
        guard Keychain.set(p.tokenAccount, Data(token.utf8)) else { throw KeychainError.writeFailed }
        SharedKeychain.setNotifyKey(push == nil ? nil : notifyKey, for: p.id)
        if notificationsWanted && push == nil { pushPending.insert(p.id) } else { pushPending.remove(p.id) }
        clients[p.id] = nil // a new token: the next poll opens a client with it
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
        clients[p.id] = nil
        pushPending.remove(p.id)
        if requestFrom?.id == p.id { request = nil; requestFrom = nil }
        if pairings.isEmpty { forget() }
    }

    /// "Not sure which key?": reads the tapped YubiKey's serial over NFC — no PIN, nothing sent to the key.
    func identifyKey() async throws -> UInt32? {
        if useSoftwareKey { return SoftwareAgeKey.fakeSerial }
        return try await NFCPIVSession.run(prompt: "Hold your YubiKey to the top of the iPhone.", done: "YubiKey read.") { t in
            try await YubiKeyTap(t).serial()
        }
    }

    /// Unblocks a blocked PIV PIN with the PUK and sets a new PIN. With `expect`, a different key is refused
    /// before the PUK is sent.
    func unblockPIN(puk: String, newPIN: String, expect: UInt32?, label: @escaping @Sendable (UInt32) -> String) async throws {
        try await NFCPIVSession.run(prompt: "Hold your YubiKey to the top of the iPhone.", done: "PIN changed.") { t in
            let piv = PIV(t)
            try await piv.select()
            if let expect, let s = try await piv.serial(), s != expect {
                throw TapError.otherKeyTapped(tapped: s, tappedLabel: label(s), picked: expect, pickedLabel: label(expect))
            }
            do {
                try await piv.unblockPIN(puk: puk, newPIN: newPIN)
            } catch PIVError.wrongPUK(let n) where n < 0 {
                throw PIVError.wrongPUK(retriesLeft: (try? await piv.pukRetries()) ?? -1)
            }
        }
    }

    /// The phone-only test: PIN + tap + a key agreement checked against software. No computer involved.
    func selfTest(pin: String, slot: UInt8) async throws -> PIV.Info {
        if useSoftwareKey {
            return PIV.Info(firmware: "software", serial: SoftwareAgeKey.fakeSerial)
        }
        return try await NFCPIVSession.run(prompt: "Hold your YubiKey to the top of the iPhone.", done: "Test passed.") { t in
            try await PIV(t).selfTest(slot: slot, pin: pin)
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
        clients = [:]
        pushPending = []
        setupDone = false
        dryRunPassed = false
        request = nil
        requestFrom = nil
        chainRequest = nil
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

    /// Home, lock or another app: the next return is a fresh look at whatever waits.
    func leftScreen() {
        contacted = []
        inBackground = true
    }

    func becameActive() {
        guard inBackground else { return } // back from the NFC sheet or Control Center: not a return
        inBackground = false
        cameBackAt = .now
    }

    /// Claims the one sound of a request; false if it already had it (or was already seen).
    func claimAlert(_ id: String) -> Bool { alerted.insert(id).inserted }

    private func announce(_ req: ApprovalRequest, firstContact: Bool) async {
        guard claimAlert(req.id) else { return Self.log.debug("sound \(req.id, privacy: .public): already had it") }
        if firstContact || inBackground || Date.now.timeIntervalSince(cameBackAt) < Self.settle {
            return Self.log.debug("sound \(req.id, privacy: .public): quiet, waiting when the app came back")
        }
        if await Notifications.isDelivered(requestID: req.id) {
            return Self.log.debug("sound \(req.id, privacy: .public): its notification sounded")
        }
        guard request?.id == req.id else { return }
        Self.log.debug("sound \(req.id, privacy: .public): play")
        Notifications.chime()
    }

    private static let log = Logger(subsystem: "me.keytap.app", category: "sound")

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
            setLink(p, .error("The pairing token for \(p.name) is missing from the keychain. Remove it and pair again."))
            return
        }
        do {
            let state = try await client.poll()
            let firstContact = contacted.insert(p.id).inserted
            switch state {
            case .idle:
                setLink(p, .waiting)
                // between the links of a chain (after "held") the computer has nothing open for a moment
                if requestFrom?.id == p.id, !approving, chainRequest == nil { clearRequest() }
                await syncPushIfNeeded(client, p)
            case .notListening:
                setLink(p, .notListening)
                if requestFrom?.id == p.id, !approving { clearRequest() }
            case .ended(let id, let reason):
                setLink(p, .waiting)
                guard requestFrom?.id == p.id, let shown = request,
                      id.isEmpty || id == shown.id || id == chainRequest?.0.id else { break }
                if approving {
                    NFCPIVSession.cancelActive(message: "Withdrawn: \(reason).") // the tap's own wait sees it too
                } else {
                    notice = Self.noticeText(reason)
                    answered.insert(shown.id)
                    clearRequest()
                }
            case .pending(let req, let bytes):
                setLink(p, .waiting)
                await syncPushIfNeeded(client, p)
                if req.continues != nil { break } // a chain link: the tap in progress fetches it itself
                let free = request == nil || requestFrom?.id == p.id
                if free, !approving, request?.id != req.id, !answered.contains(req.id), req.expiresAt > .now {
                    chainRequest = nil
                    requestBytes = bytes
                    requestFrom = p
                    request = req
                    // With KeyTap open there is no banner: the chime is what says the next one is here.
                    await announce(req, firstContact: firstContact)
                }
            }
        } catch {
            setLink(p, .error("\(p.name): " + ((error as? LocalizedError)?.errorDescription ?? error.localizedDescription)))
        }
    }

    private func clearRequest() {
        if let id = request?.id { Task { await Notifications.remove(requestID: id) } }
        request = nil
        requestFrom = nil
        chainRequest = nil
    }

    static func noticeText(_ reason: String) -> String {
        reason.contains("answered elsewhere") ? "The last request was answered on another computer."
            : "The last request ended on the computer: \(reason)."
    }

    // MARK: answering

    /// PIN + tap: the whole PIV conversation runs inside one NFC session. The PIN is passed
    /// straight through to VERIFY and is never stored.
    func approve(pin: String, picked: UInt32?) async throws {
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
        guard let shown = request, let from = requestFrom, let client = client(for: from), let signer = try DeviceKey.load() else { return }
        let (req, bytes) = chainRequest ?? (shown, requestBytes)
        if req.isUnknownKind { throw ApprovalError.unsupported }
        if useSoftwareKey && req.isSSH { throw ApprovalError.sshNeedsYubiKey }
        let link = BridgeChainLink(client: client)
        let onRequest: @Sendable (ApprovalRequest, Data) async -> Void = { [weak self] r, b in
            await MainActor.run { self?.chainRequest = (r, b) }
        }
        approving = true
        defer { approving = false }
        do {
            let outcome: TapOutcome
            if useSoftwareKey {
                let tap = SoftwareTap(serial: SoftwareAgeKey.fakeSerial, age: try SoftwareTestKey.load(), fido: nil)
                outcome = try await TapChain.run(request: req, bytes: bytes, picked: nil, pin: pin, key: tap, link: link,
                                                 signer: signer, onRequest: onRequest)
            } else {
                let done = req.isTest ? "Dry run answered." : req.isSSH ? "Signed." : "Approved."
                outcome = try await NFCPIVSession.run(prompt: "Hold your YubiKey to the top of the iPhone.", done: done) { t in
                    try await TapChain.run(request: req, bytes: bytes, picked: picked, pin: pin, key: YubiKeyTap(t), link: link,
                                           signer: signer, onRequest: onRequest)
                }
            }
            if outcome == .dryRun { dryRunPassed = true }
            answered.insert(shown.id)
            clearRequest()
        } catch let e as TapError {
            switch e {
            case .withdrawn(let why), .notThisKey(let why):
                // the computer ended the chain: this request is over
                notice = e == .withdrawn(why) ? Self.noticeText(why) : why
                answered.insert(shown.id)
                clearRequest()
            default: break
            }
            throw e
        }
    }

    func decline() async throws {
        if let id = request?.id { Task { await Notifications.remove(requestID: id) } }
        let pending = chainRequest
        if isDemo, let req = request {
            demoResult = req.isSSH ? "Declined. The SSH login would fail with \"declined on the phone\"."
                                   : "Declined. The computer's decrypt would fail with \"declined on the phone\"."
            answered.insert(req.id)
            request = nil
            return
        }
        guard let shown = request, let from = requestFrom, let client = client(for: from), let signer = try DeviceKey.load() else { return }
        let (req, bytes) = pending ?? (shown, requestBytes)
        try await client.send(try Approver.decline(req, requestBytes: bytes, signer: signer))
        answered.insert(shown.id)
        clearRequest()
    }

    func setNotifications(_ on: Bool) async {
        pushProblem = nil
        if on {
            let granted = (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])) ?? false
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
        if notificationsWanted {
            // Builds before 1.1 asked without .badge; iOS adds it silently if notifications are still allowed.
            Task { _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) }
            UIApplication.shared.registerForRemoteNotifications()
        }
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

    func notificationOpened(requestID: String?) {
        if let requestID { _ = claimAlert(requestID) }
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

    /// The demo computer's key list (the demo key is the first).
    private static let demoKeys: [[String: Any]] = [
        ["serial": SoftwareAgeKey.fakeSerial, "label": "everyday"], ["serial": 2, "label": "spare"], ["serial": 3, "label": "safe"],
    ]

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
            "keys": Self.demoKeys, "default": SoftwareAgeKey.fakeSerial,
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
            "keys": Self.demoKeys, "default": SoftwareAgeKey.fakeSerial,
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
        if let r = request { answered.insert(r.id) }
        clearRequest()
    }
}

enum KeychainError: Error, LocalizedError {
    case writeFailed
    var errorDescription: String? { "Could not store the key in the keychain." }
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
