import CryptoKit
import Foundation

/// Mirrors bridge/request.go. The phone keeps the raw bytes it was served: the answer's
/// signature covers their SHA-256, binding the approval to exactly what was displayed.
public struct ApprovalRequest: Codable, Sendable, Identifiable, Equatable {
    public struct Identity: Codable, Sendable, Equatable {
        public let serial: UInt32
        public let slot: UInt8
        public let tag: String
        public init(serial: UInt32, slot: UInt8, tag: String) {
            self.serial = serial
            self.slot = slot
            self.tag = tag
        }
    }

    /// One of the computer's YubiKeys, for the key picker. The computer sends the list with every request;
    /// the phone stores none of it.
    public struct KeyInfo: Codable, Sendable, Equatable, Hashable {
        public let serial: UInt32
        public let label: String
        public init(serial: UInt32, label: String) {
            self.serial = serial
            self.label = label
        }
    }

    public struct Stanza: Codable, Sendable, Equatable {
        public let stanzaIndex: Int
        public let tag: String
        public let epk: String
        public let body: String

        enum CodingKeys: String, CodingKey {
            case stanzaIndex = "stanza_index", tag, epk, body
        }
    }

    public struct File: Codable, Sendable, Equatable {
        public let index: Int
        public let stanzas: [Stanza]
    }

    /// The dry run (`age-plugin-yubikey-phone test`): an ephemeral key agreement, nothing decrypted.
    public struct Probe: Codable, Sendable, Equatable {
        public let serial: UInt32
        public let slot: UInt8
        public let tag: String
        public let epk: String
    }

    /// An OpenSSH FIDO2 signature (ed25519-sk / ecdsa-sk key on the YubiKey), e.g. an ssh login. Mirrors SSHSign
    /// in bridge/request.go: the phone runs getAssertion with these values on the YubiKey's FIDO applet.
    public struct SSHSign: Codable, Sendable, Equatable {
        public let application: String
        public let credentialID: String
        public let clientDataHash: String
        public let algorithm: String
        public let userPresence: Bool
        public let userVerification: Bool
        public let purpose: String
        public var login: String? = nil
        public var keyFingerprint: String? = nil
        public var keyName: String? = nil
        /// SHA256:… of the server's host key (OpenSSH host-bound logins): which server is being logged in to.
        public var hostKeyFingerprint: String? = nil
        /// The YubiKey that holds this SSH key, when the computer knows it (its keys.conf).
        public var keySerial: UInt32? = nil

        enum CodingKeys: String, CodingKey {
            case keySerial = "key_serial"
            case application, algorithm, purpose, login
            case credentialID = "credential_id", clientDataHash = "client_data_hash"
            case userPresence = "user_presence", userVerification = "user_verification"
            case keyFingerprint = "key_fingerprint", keyName = "key_name", hostKeyFingerprint = "host_key_fingerprint"
        }

        public var isLogin: Bool { purpose == "login" }
    }

    public let version: Int
    public var kind: String? = nil
    public var probe: Probe? = nil
    public var ssh: SSHSign? = nil
    public let id: String
    public let code: String
    public let nonce: String
    public let createdAt: Date
    public let expiresAt: Date
    public let host: String
    public let user: String
    public let command: String
    public let cwd: String
    /// Free text from whoever started the decrypt (KEYTAP_NOTE on the computer). Shown first,
    /// labelled as the requester's words — the bridge cannot verify it.
    public var note: String? = nil
    public let identities: [Identity]
    public let files: [File]
    /// The computer's YubiKeys and the one to preselect (the last used there).
    public var keys: [KeyInfo]? = nil
    public var defaultKey: UInt32? = nil
    /// The request this one follows in the same tap: the phone holds the tapped key for it.
    public var continues: String? = nil

    enum CodingKeys: String, CodingKey {
        case defaultKey = "default"
        case keys, continues
        case version, kind, probe, ssh, id, code, nonce, host, user, command, cwd, note, identities, files
        case createdAt = "created_at", expiresAt = "expires_at"
    }

    public var isTest: Bool { kind == "test" }

    /// The keys to offer, labelled. A request without a list offers the serials of its identities.
    public var offeredKeys: [KeyInfo] {
        if let keys, !keys.isEmpty { return keys }
        var seen = Set<UInt32>()
        return (identities.map(\.serial) + [probe?.serial, ssh?.keySerial].compactMap { $0 })
            .filter { $0 != 0 && seen.insert($0).inserted }
            .map { KeyInfo(serial: $0, label: "YubiKey \($0)") }
    }

    public func label(of serial: UInt32) -> String {
        offeredKeys.first { $0.serial == serial }?.label ?? "YubiKey \(serial)"
    }
    public var isSSH: Bool { kind == "ssh" && ssh != nil }
    /// A kind this app version does not know (a newer bridge): shown, but it cannot be approved.
    public var isUnknownKind: Bool { !(kind == nil || kind == "" || isTest || isSSH) }

    /// The note, if it has any visible text.
    public var displayNote: String? {
        guard let t = note?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else { return nil }
        return t
    }

    /// The file the operator is most likely decrypting, pulled from the requesting command line
    /// (the last argument that looks like a path). Display only — the bridge cannot prove it.
    public var targetFile: String? {
        command.split(separator: " ").reversed().first { $0.contains("/") || $0.contains(".") && !$0.hasPrefix("-") }
            .map(String.init)
    }
}

public struct ApprovalResult: Codable, Sendable, Equatable {
    public let index: Int
    public var fileKey: String?
    public var error: String?

    enum CodingKeys: String, CodingKey {
        case index, error
        case fileKey = "file_key"
    }
}

/// The YubiKey's assertion for an SSH request (SSHAnswer in bridge/request.go).
public struct SSHAnswer: Codable, Sendable, Equatable {
    public let signature: String
    public let flags: UInt8
    public let counter: UInt32
    public init(signature: String, flags: UInt8, counter: UInt32) {
        self.signature = signature
        self.flags = flags
        self.counter = counter
    }
}

/// The phone holds the tapped key (this serial) in an open session, but the request is not for it.
public struct HeldKey: Codable, Sendable, Equatable {
    public let serial: UInt32
    public init(serial: UInt32) { self.serial = serial }
}

public struct ApprovalAnswer: Codable, Sendable {
    public let id: String
    public let declined: Bool
    public var held: HeldKey? = nil
    public let results: [ApprovalResult]
    public var proof: String? = nil
    public var ssh: SSHAnswer? = nil
    public var signature: String

    /// Keep in lockstep with signedMessage in bridge/request.go.
    public static func signedMessage(requestBytes: Data, nonce: String, declined: Bool, results: [ApprovalResult],
                                     proof: String? = nil, ssh: SSHAnswer? = nil, held: HeldKey? = nil) -> Data {
        let sum = SHA256.hash(data: requestBytes).map { String(format: "%02x", $0) }.joined()
        var s = "keytap-answer-v1\n\(sum)\n\(nonce)\n"
        if declined {
            s += "declined\n"
        } else if let held {
            s += "held \(held.serial)\n"
        } else {
            if let proof { s += "proof \(proof)\n" }
            if let ssh { s += "ssh \(ssh.signature) \(ssh.flags) \(ssh.counter)\n" }
            for r in results.sorted(by: { $0.index < $1.index }) {
                s += "\(r.index) \(r.fileKey ?? "!")\n"
            }
        }
        return Data(s.utf8)
    }
}

extension Data {
    /// Unpadded or padded standard base64, as Go's RawStdEncoding writes it.
    public init?(base64Raw s: String) {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        self.init(base64Encoded: t)
    }

    public var base64Raw: String {
        base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
}
