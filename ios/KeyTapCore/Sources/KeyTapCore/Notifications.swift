import CryptoKit
import Foundation

/// The optional notification path. A push says only THAT a request (or a dry run) waits and when it
/// expires — never the computer, user, command, file, code or note; those are read in the app. The
/// bridge seals that summary with AES-256-GCM under a key only it and this phone hold (from pairing),
/// with the request id as additional data; the Notification Service Extension opens it here.
/// Bridges before v0.3.2 also sealed request details; they are decoded nowhere and never shown.
public struct NotificationSummary: Codable, Sendable, Equatable {
    public let v: Int
    public let id: String
    public let kind: String?
    public let exp: Int64

    public var isTest: Bool { kind == "test" }
    public var expires: Date { Date(timeIntervalSince1970: TimeInterval(exp)) }
}

public enum NotificationCrypto {
    /// Opens the "k" field of a KeyTap push. nil if it is not ours, was tampered with, or belongs
    /// to another request id.
    public static func open(payload b64: String, key: Data, requestID: String) -> NotificationSummary? {
        guard key.count == 32, let sealed = Data(base64Encoded: b64), sealed.count > 28,
              let box = try? AES.GCM.SealedBox(combined: sealed),
              let plain = try? AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: Data(requestID.utf8)),
              let s = try? JSONDecoder().decode(NotificationSummary.self, from: plain), s.id == requestID else { return nil }
        return s
    }

    /// The APNs environment this build registers in: development builds get sandbox tokens,
    /// TestFlight and App Store builds production tokens.
    public static var apnsEnvironment: String {
        #if DEBUG
        "sandbox"
        #else
        "production"
        #endif
    }
}
