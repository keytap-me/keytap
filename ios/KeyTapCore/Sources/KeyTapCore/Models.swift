import CryptoKit
import Foundation

/// Mirrors bridge/request.go. The phone keeps the raw bytes it was served: the answer's
/// signature covers their SHA-256, binding the approval to exactly what was displayed.
public struct ApprovalRequest: Codable, Sendable, Identifiable, Equatable {
    public struct Identity: Codable, Sendable, Equatable {
        public let serial: UInt32
        public let slot: UInt8
        public let tag: String
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

    public let version: Int
    public var kind: String? = nil
    public var probe: Probe? = nil
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

    enum CodingKeys: String, CodingKey {
        case version, kind, probe, id, code, nonce, host, user, command, cwd, note, identities, files
        case createdAt = "created_at", expiresAt = "expires_at"
    }

    public var isTest: Bool { kind == "test" }

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

public struct ApprovalAnswer: Codable, Sendable {
    public let id: String
    public let declined: Bool
    public let results: [ApprovalResult]
    public var proof: String? = nil
    public var signature: String

    /// Keep in lockstep with signedMessage in bridge/request.go.
    public static func signedMessage(requestBytes: Data, nonce: String, declined: Bool, results: [ApprovalResult],
                                     proof: String? = nil) -> Data {
        let sum = SHA256.hash(data: requestBytes).map { String(format: "%02x", $0) }.joined()
        var s = "keytap-answer-v1\n\(sum)\n\(nonce)\n"
        if declined {
            s += "declined\n"
        } else {
            if let proof { s += "proof \(proof)\n" }
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
