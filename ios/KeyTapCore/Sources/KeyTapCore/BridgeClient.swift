import CryptoKit
import Foundation

/// The bridge as the phone sees it. The bridge's self-signed certificate is pinned by the
/// SHA-256 of its DER encoding (from the pairing link); nothing else is trusted.
public struct PairingLink: Equatable, Sendable {
    public let host: String // "ip:port"
    public let pin: Data
    public let code: String
    public let name: String
    public let recipient: String?

    public init?(_ s: String) {
        guard let c = URLComponents(string: s.trimmingCharacters(in: .whitespacesAndNewlines)),
              c.scheme == "keytap", c.host == "pair" else { return nil }
        let q = Dictionary((c.queryItems ?? []).map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { a, _ in a })
        guard q["v"] == "1", let host = q["host"], !host.isEmpty, let fp = q["fp"], let pin = Data(base64Raw: fp),
              pin.count == 32, let code = q["code"], !code.isEmpty else { return nil }
        self.host = host
        self.pin = pin
        self.code = code
        self.name = q["name"].flatMap { $0.isEmpty ? nil : $0 } ?? host
        self.recipient = q["recipient"].flatMap { $0.isEmpty ? nil : $0 }
    }
}

public enum PollState: Sendable, Equatable {
    /// The bridge answered: nothing waiting.
    case idle
    /// Nothing is listening — no decrypt is waiting on the workstation (the normal resting state).
    case notListening
    case pending(ApprovalRequest, Data)
}

public enum BridgeError: Error, LocalizedError, Equatable {
    case status(Int, String)
    case pinMismatch

    public var errorDescription: String? {
        switch self {
        case .status(let code, let msg): "Bridge answered \(code): \(msg)"
        case .pinMismatch: "The workstation's certificate does not match the paired one."
        }
    }
}

public final class BridgeClient: NSObject, URLSessionDelegate, @unchecked Sendable {
    let base: URL
    let pin: Data
    let token: String?
    private lazy var session = URLSession(configuration: {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 8
        c.waitsForConnectivity = false
        c.urlCache = nil
        return c
    }(), delegate: self, delegateQueue: nil)
    private let pinFailed = LockedFlag()

    public init(host: String, pin: Data, token: String?) {
        self.base = URL(string: "https://\(host)")!
        self.pin = pin
        self.token = token
    }

    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge) async
        -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let leaf = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first else {
            return (.cancelAuthenticationChallenge, nil)
        }
        let der = SecCertificateCopyData(leaf) as Data
        guard Data(SHA256.hash(data: der)) == pin else {
            pinFailed.set()
            return (.cancelAuthenticationChallenge, nil)
        }
        return (.useCredential, URLCredential(trust: trust))
    }

    private func request(_ path: String, method: String = "GET", body: Data? = nil) -> URLRequest {
        var r = URLRequest(url: base.appending(path: path))
        r.httpMethod = method
        r.httpBody = body
        r.cachePolicy = .reloadIgnoringLocalCacheData
        if body != nil { r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        if let token { r.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        return r
    }

    private func perform(_ r: URLRequest) async throws -> (Data, Int) {
        do {
            let (data, resp) = try await session.data(for: r)
            return (data, (resp as? HTTPURLResponse)?.statusCode ?? 0)
        } catch {
            if pinFailed.get() { throw BridgeError.pinMismatch }
            throw error
        }
    }

    public func poll() async throws -> PollState {
        do {
            let (data, status) = try await perform(request("/v1/pending"))
            switch status {
            case 204: return .idle
            case 200:
                let req = try Self.decoder.decode(ApprovalRequest.self, from: data)
                return .pending(req, data)
            default: throw BridgeError.status(status, String(decoding: data.prefix(200), as: UTF8.self))
            }
        } catch let e as URLError where [.cannotConnectToHost, .networkConnectionLost, .timedOut].contains(e.code) {
            return .notListening
        }
    }

    public func send(_ answer: ApprovalAnswer) async throws {
        let (data, status) = try await perform(request("/v1/answer", method: "POST", body: try JSONEncoder().encode(answer)))
        guard status == 204 else { throw BridgeError.status(status, String(decoding: data.prefix(200), as: UTF8.self)) }
    }

    /// A YubiKey registered at pairing: the bridge then answers only for these keys.
    public struct RegisteredKey: Codable, Sendable, Equatable {
        public let serial: UInt32
        public let slot: UInt8
        public let recipient: String // base64, 33 bytes compressed
        public init(serial: UInt32, slot: UInt8, recipient: Data) {
            self.serial = serial
            self.slot = slot
            self.recipient = recipient.base64Raw
        }
    }

    /// Notification settings the phone hands to its computer (opt-in): the APNs device token and
    /// environment. The computer answers with the shared notification key.
    public struct PushSettings: Codable, Sendable, Equatable {
        public let token: String
        public let env: String
        public init(token: String, env: String) {
            self.token = token
            self.env = env
        }
    }

    private struct PairBody: Codable {
        let code: String
        let device_name: String
        let public_key: String
        let yubikeys: [RegisteredKey]
        let push: PushSettings?
    }

    public func pair(code: String, deviceName: String, publicKey: Data, yubikeys: [RegisteredKey] = [],
                     push: PushSettings? = nil) async throws -> (token: String, bridgeName: String, notifyKey: Data?) {
        let body = try JSONEncoder().encode(PairBody(code: code, device_name: deviceName,
                                                     public_key: publicKey.base64Raw, yubikeys: yubikeys, push: push))
        let (data, status) = try await perform(request("/v1/pair", method: "POST", body: body))
        guard status == 200, let obj = try? JSONDecoder().decode([String: String].self, from: data),
              let token = obj["token"] else {
            throw BridgeError.status(status, String(decoding: data.prefix(200), as: UTF8.self))
        }
        return (token, obj["bridge_name"] ?? "", obj["notify_key"].flatMap { Data(base64Raw: $0) })
    }

    /// Switches notifications on (settings) or off (nil) for this phone. Works whenever the
    /// computer is listening. Signed by the device key; keep the message in lockstep with
    /// deviceMessage in bridge/request.go.
    public func updateDevice(push: PushSettings?, signer: DeviceSigner) async throws -> Data? {
        let msg = push.map { "keytap-device-v1\npush \($0.token.lowercased()) \($0.env)\n" } ?? "keytap-device-v1\npush off\n"
        struct Body: Codable { let push: PushSettings?; let signature: String }
        let body = try JSONEncoder().encode(Body(push: push, signature: try signer.sign(Data(msg.utf8)).base64Raw))
        let (data, status) = try await perform(request("/v1/device", method: "POST", body: body))
        guard status == 200 else { throw BridgeError.status(status, String(decoding: data.prefix(200), as: UTF8.self)) }
        let obj = try? JSONDecoder().decode([String: String].self, from: data)
        return obj?["notify_key"].flatMap { Data(base64Raw: $0) }
    }

    public static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}

final class LockedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    func set() { lock.withLock { value = true } }
    func get() -> Bool { lock.withLock { value } }
}
