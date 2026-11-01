import Foundation
import Network

/// Can the phone reach the computer, and if not, why? iOS gates connections into the local
/// network behind a permission that it asks for once; after a "Don't Allow" the only way back is
/// Settings, so that case must be told apart from "computer off" and "bridge not running".
enum NetworkProbe {
    enum Outcome: Equatable {
        case reachable
        /// The computer answered but nothing listens: the bridge isn't running (normal between decrypts).
        case notListening
        case localNetworkDenied
        case unreachable(String)
    }

    static func check(_ hostPort: String, timeout: Duration = .seconds(4)) async -> Outcome {
        guard let colon = hostPort.lastIndex(of: ":"), let port = NWEndpoint.Port(String(hostPort[hostPort.index(after: colon)...])) else {
            return .unreachable("Invalid address \(hostPort)")
        }
        let host = NWEndpoint.Host(String(hostPort[..<colon]).trimmingCharacters(in: CharacterSet(charactersIn: "[]")))
        let conn = NWConnection(host: host, port: port, using: .tcp)
        let box = OnceBox()
        return await withCheckedContinuation { cont in
            let finish: @Sendable (Outcome) -> Void = { outcome in
                if box.claim() {
                    conn.cancel()
                    cont.resume(returning: outcome)
                }
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    finish(.reachable)
                case .waiting(let error), .failed(let error):
                    if conn.currentPath?.unsatisfiedReason == .localNetworkDenied {
                        finish(.localNetworkDenied)
                    } else if case .posix(.ECONNREFUSED) = error {
                        finish(.notListening)
                    } else if case .failed = state {
                        finish(.unreachable(error.localizedDescription))
                    }
                    // .waiting for another reason: keep waiting until the timeout
                default:
                    break
                }
            }
            conn.start(queue: .global(qos: .userInitiated))
            Task {
                try? await Task.sleep(for: timeout)
                finish(.unreachable("No answer from \(hostPort). Is the phone on the same network or VPN as the computer?"))
            }
        }
    }
}

private final class OnceBox: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func claim() -> Bool { lock.withLock { defer { done = true }; return !done } }
}
