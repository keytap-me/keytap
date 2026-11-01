@preconcurrency import CoreNFC
import Foundation
import KeyTapCore

/// Runs one PIV conversation with a YubiKey held to the phone. The NFC sheet stays up for the
/// whole of `body` (select → verify PIN → ECDH), so the operator taps once.
final class NFCPIVSession: NSObject, NFCTagReaderSessionDelegate, @unchecked Sendable {
    private var session: NFCTagReaderSession?
    private var onTag: ((PIVTransport) async throws -> Void)?
    private var onEnd: ((Error?) -> Void)?
    private var finished = false
    private let lock = NSLock()

    static var isAvailable: Bool { NFCTagReaderSession.readingAvailable }

    /// The session on screen, so a withdrawn request can close it ("answered elsewhere").
    nonisolated(unsafe) private static weak var active: NFCPIVSession?
    private var withdrawnMessage: String?

    /// Closes the NFC sheet of the session in progress with a message; its run throws NFCError.withdrawn.
    static func cancelActive(message: String) {
        guard let s = active else { return }
        s.withdrawnMessage = message
        s.session?.invalidate(errorMessage: message)
    }

    static func run<T: Sendable>(prompt: String, done: String,
                                 _ body: @escaping @Sendable (PIVTransport) async throws -> T) async throws -> T {
        let s = NFCPIVSession()
        return try await withCheckedThrowingContinuation { cont in
            var result: T?
            s.onTag = { transport in result = try await body(transport) }
            s.onEnd = { error in
                if let error { cont.resume(throwing: error) } else { cont.resume(returning: result!) }
            }
            s.doneMessage = done
            guard let session = NFCTagReaderSession(pollingOption: .iso14443, delegate: s, queue: nil) else {
                cont.resume(throwing: NFCError.unavailable)
                return
            }
            session.alertMessage = prompt
            s.session = session
            active = s
            session.begin()
        }
    }

    private var doneMessage = ""

    private func end(_ error: Error?) {
        let first = lock.withLock { () -> Bool in
            defer { finished = true }
            return !finished
        }
        guard first else { return }
        onEnd?(error)
        onEnd = nil
        onTag = nil
    }

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        if let m = withdrawnMessage { end(NFCError.withdrawn(m)); return }
        end(Self.map(error))
    }

    /// A lost or moved key, a timeout: say so in words that lead to the retry (the request stays open).
    static func map(_ error: Error) -> Error {
        guard let code = (error as? NFCReaderError)?.code else { return error }
        switch code {
        case .readerSessionInvalidationErrorUserCanceled: return NFCError.cancelled
        case .readerTransceiveErrorTagConnectionLost, .readerTransceiveErrorTagResponseError, .readerTransceiveErrorRetryExceeded,
             .readerTransceiveErrorTagNotConnected, .readerTransceiveErrorPacketTooLong:
            return NFCError.tagLost
        case .readerSessionInvalidationErrorSessionTimeout, .readerSessionInvalidationErrorSessionTerminatedUnexpectedly:
            return NFCError.timedOut
        default: return error
        }
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard case .iso7816(let tag)? = tags.first(where: { if case .iso7816 = $0 { true } else { false } }) else {
            session.alertMessage = "That is not a YubiKey. Hold your YubiKey to the top of the iPhone."
            session.restartPolling()
            return
        }
        let box = SessionBox(session: session, tag: tag)
        session.connect(to: tags.first!) { [self] error in
            if let error {
                box.session.invalidate(errorMessage: "Lost the YubiKey — try again.")
                end(Self.map(error))
                return
            }
            Task { await converse(box) }
        }
    }

    private func converse(_ box: SessionBox) async {
        do {
            try await onTag?(NFCTransport(tag: box.tag))
            box.session.alertMessage = doneMessage
            box.session.invalidate()
            end(nil)
        } catch {
            let e = withdrawnMessage.map { NFCError.withdrawn($0) } ?? Self.map(error)
            box.session.invalidate(errorMessage: Self.sheetMessage(e))
            end(e)
        }
    }

    /// The NFC sheet's line: short (it is a small banner); the full text shows in the app afterwards.
    private static func sheetMessage(_ e: Error) -> String {
        switch e {
        case PIVError.wrongPIN, CTAPError.wrongPIN, CTAPError.pinInvalid: "Wrong PIN."
        case TapError.otherKeyTapped: "Another YubiKey — no PIN sent."
        case NFCError.tagLost: "Lost the YubiKey — try again."
        default: (e as? LocalizedError)?.errorDescription ?? "\(e)"
        }
    }
}

private struct SessionBox: @unchecked Sendable {
    let session: NFCTagReaderSession
    let tag: NFCISO7816Tag
}

struct NFCTransport: PIVTransport, @unchecked Sendable {
    let tag: NFCISO7816Tag

    func transmit(_ apdu: Data) async throws -> (data: Data, sw: UInt16) {
        guard let cmd = NFCISO7816APDU(data: apdu) else { throw NFCError.badAPDU }
        let (data, sw1, sw2) = try await tag.sendCommand(apdu: cmd)
        return (data, UInt16(sw1) << 8 | UInt16(sw2))
    }
}

enum NFCError: Error, LocalizedError {
    case unavailable, cancelled, badAPDU, tagLost, timedOut
    case withdrawn(String)

    var errorDescription: String? {
        switch self {
        case .unavailable: "This iPhone cannot read NFC tags."
        case .cancelled: "Cancelled."
        case .badAPDU: "Internal error building a YubiKey command."
        case .tagLost: "Lost the YubiKey. Hold it still at the top of the iPhone and tap Approve again."
        case .timedOut: "The YubiKey was not held to the iPhone in time. Tap Approve to try again."
        case .withdrawn(let m): m
        }
    }
}
