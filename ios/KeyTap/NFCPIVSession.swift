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
        let code = (error as? NFCReaderError)?.code
        end(code == .readerSessionInvalidationErrorUserCanceled ? NFCError.cancelled : error)
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
                end(error)
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
            box.session.invalidate(errorMessage: (error as? LocalizedError)?.errorDescription ?? "\(error)")
            end(error)
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
    case unavailable, cancelled, badAPDU

    var errorDescription: String? {
        switch self {
        case .unavailable: "This iPhone cannot read NFC tags."
        case .cancelled: "Cancelled."
        case .badAPDU: "Internal error building a YubiKey command."
        }
    }
}
