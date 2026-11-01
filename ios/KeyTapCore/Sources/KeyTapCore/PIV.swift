import CryptoKit
import Foundation

/// A connection to a PIV applet: NFC (CoreNFC ISO 7816 tag) on the phone, or anything else that
/// moves APDUs. Returns the response data and the status word.
public protocol PIVTransport: Sendable {
    func transmit(_ apdu: Data) async throws -> (data: Data, sw: UInt16)
}

public enum PIVError: Error, Equatable, LocalizedError {
    case wrongPIN(retriesLeft: Int)
    case pinBlocked
    case wrongPUK(retriesLeft: Int)
    case pukBlocked
    case badNewPIN
    case slotEmpty
    case securityStatusNotSatisfied
    case keyMismatch
    case unexpected(sw: UInt16)
    case malformedResponse

    public var errorDescription: String? {
        switch self {
        case .wrongPIN(let n) where n == 1: "Wrong PIN — 1 try left. One more wrong PIN blocks it; then only the PUK unblocks it."
        case .wrongPIN(let n): "Wrong PIN — \(n) \(n == 1 ? "try" : "tries") left before the PIN locks."
        case .pinBlocked: "The PIN is blocked. Unblock it with the PUK (here in KeyTap, or ykman piv access unblock-pin)."
        case .wrongPUK(let n): "Wrong PUK — \(n) \(n == 1 ? "try" : "tries") left before the PUK locks."
        case .pukBlocked: "The PUK is blocked too. The PIV application can then only be reset on a computer, which deletes its keys."
        case .badNewPIN: "The new PIN must be 6 to 8 characters."
        case .slotEmpty: "This YubiKey has no key in the expected slot."
        case .securityStatusNotSatisfied: "The YubiKey refused the operation (PIN or touch not satisfied)."
        case .keyMismatch: "This is not the YubiKey the request was encrypted to."
        case .unexpected(let sw): String(format: "The YubiKey answered with status %04X.", sw)
        case .malformedResponse: "The YubiKey's answer could not be read."
        }
    }
}

/// The PIV operations KeyTap needs. Every APDU is built here so it can be unit tested without a card.
public struct PIV: Sendable {
    public static let aid = Data([0xA0, 0x00, 0x00, 0x03, 0x08])
    let t: PIVTransport

    public init(_ transport: PIVTransport) { self.t = transport }

    func send(_ apdu: Data) async throws -> (Data, UInt16) {
        var (data, sw) = try await t.transmit(apdu)
        // Response chaining: 61xx = more bytes waiting → GET RESPONSE.
        while sw >> 8 == 0x61 {
            let (more, next) = try await t.transmit(Data([0x00, 0xC0, 0x00, 0x00, UInt8(sw & 0xFF)]))
            data += more
            sw = next
        }
        return (data, sw)
    }

    public func select() async throws {
        let (_, sw) = try await send(Data([0x00, 0xA4, 0x04, 0x00, UInt8(Self.aid.count)]) + Self.aid)
        guard sw == 0x9000 else { throw PIVError.unexpected(sw: sw) }
    }

    /// PIN retries left without spending one (VERIFY with no data). nil = PIN already verified.
    public func pinRetries() async throws -> Int? {
        let (_, sw) = try await send(Data([0x00, 0x20, 0x00, 0x80]))
        if sw == 0x9000 { return nil }
        if sw & 0xFFF0 == 0x63C0 { return Int(sw & 0x0F) }
        if sw == 0x6983 { return 0 }
        throw PIVError.unexpected(sw: sw)
    }

    public static func verifyAPDU(pin: String) -> Data? {
        let p = Array(pin.utf8)
        guard (6...8).contains(p.count) else { return nil }
        return Data([0x00, 0x20, 0x00, 0x80, 0x08]) + p + Array(repeating: 0xFF, count: 8 - p.count)
    }

    public func verify(pin: String) async throws {
        guard var apdu = Self.verifyAPDU(pin: pin) else { throw PIVError.wrongPIN(retriesLeft: -1) }
        defer { apdu.resetBytes(in: 0..<apdu.count) }
        let (_, sw) = try await send(apdu)
        switch sw {
        case 0x9000: return
        case 0x6983: throw PIVError.pinBlocked
        case let s where s & 0xFFF0 == 0x63C0:
            let n = Int(s & 0x0F)
            throw n == 0 ? PIVError.pinBlocked : PIVError.wrongPIN(retriesLeft: n)
        default: throw PIVError.unexpected(sw: sw)
        }
    }

    static func pad8(_ s: String) -> [UInt8]? {
        let p = Array(s.utf8)
        guard (6...8).contains(p.count) else { return nil }
        return p + Array(repeating: 0xFF, count: 8 - p.count)
    }

    public static func unblockAPDU(puk: String, newPIN: String) -> Data? {
        guard let k = pad8(puk), let n = pad8(newPIN) else { return nil }
        return Data([0x00, 0x2C, 0x00, 0x80, 0x10]) + k + n
    }

    /// RESET RETRY COUNTER: unblocks the PIN with the PUK and sets a new PIN.
    public func unblockPIN(puk: String, newPIN: String) async throws {
        guard Self.pad8(newPIN) != nil else { throw PIVError.badNewPIN }
        guard var apdu = Self.unblockAPDU(puk: puk, newPIN: newPIN) else { throw PIVError.wrongPUK(retriesLeft: -1) }
        defer { apdu.resetBytes(in: 0..<apdu.count) }
        let (_, sw) = try await send(apdu)
        switch sw {
        case 0x9000: return
        case 0x6983: throw PIVError.pukBlocked
        case let s where s & 0xFFF0 == 0x63C0:
            let n = Int(s & 0x0F)
            throw n == 0 ? PIVError.pukBlocked : PIVError.wrongPUK(retriesLeft: n)
        default: throw PIVError.unexpected(sw: sw)
        }
    }

    /// PUK tries left, from GET METADATA on the PUK (firmware 5.3+); nil when unknown. Spends nothing.
    public func pukRetries() async throws -> Int? {
        let (m, sw) = try await send(Data([0x00, 0xF7, 0x00, 0x81, 0x00]))
        guard sw == 0x9000, let r = TLV.find(0x06, in: m), r.count == 2 else { return nil }
        return Int(r[r.startIndex + 1])
    }

    /// Yubico GET SERIAL (firmware 5+). nil when the key does not support it.
    public func serial() async throws -> UInt32? {
        let (s, sw) = try await send(Data([0x00, 0xF8, 0x00, 0x00, 0x00]))
        guard sw == 0x9000, s.count == 4 else { return nil }
        return s.reduce(0) { $0 << 8 | UInt32($1) }
    }

    /// GET METADATA (firmware 5.3+): the slot's public key as an X9.63 point.
    public func publicKey(slot: UInt8) async throws -> Data? {
        let (data, sw) = try await send(Data([0x00, 0xF7, 0x00, slot, 0x00]))
        if sw == 0x6A88 || sw == 0x6A82 { throw PIVError.slotEmpty }
        if sw == 0x6D00 { return nil } // older firmware: no metadata command
        guard sw == 0x9000 else { throw PIVError.unexpected(sw: sw) }
        guard let pk = TLV.find(0x04, in: data), let point = TLV.find(0x86, in: pk) else { return nil }
        return point
    }

    /// Read-only facts about the key and a slot, for the "Check YubiKey" screen.
    public struct Info: Sendable, Equatable {
        public var firmware: String?
        public var serial: UInt32?
        public var pinPolicy: UInt8?   // 1 never · 2 once · 3 always
        public var touchPolicy: UInt8? // 1 never · 2 always · 3 cached
        public var publicKey: Data?    // X9.63
        public var pinRetries: Int?

        public init(firmware: String? = nil, serial: UInt32? = nil, pinPolicy: UInt8? = nil, touchPolicy: UInt8? = nil,
                    publicKey: Data? = nil, pinRetries: Int? = nil) {
            self.firmware = firmware
            self.serial = serial
            self.pinPolicy = pinPolicy
            self.touchPolicy = touchPolicy
            self.publicKey = publicKey
            self.pinRetries = pinRetries
        }
    }

    public func info(slot: UInt8) async throws -> Info {
        var i = Info()
        let (v, vsw) = try await send(Data([0x00, 0xFD, 0x00, 0x00, 0x00]))
        if vsw == 0x9000, v.count >= 3 { i.firmware = v.prefix(3).map(String.init).joined(separator: ".") }
        let (s, ssw) = try await send(Data([0x00, 0xF8, 0x00, 0x00, 0x00]))
        if ssw == 0x9000, s.count == 4 { i.serial = s.reduce(0) { $0 << 8 | UInt32($1) } }
        let (m, msw) = try await send(Data([0x00, 0xF7, 0x00, slot, 0x00]))
        if msw == 0x9000 {
            if let pol = TLV.find(0x02, in: m), pol.count == 2 {
                i.pinPolicy = pol[pol.startIndex]
                i.touchPolicy = pol[pol.startIndex + 1]
            }
            if let pk = TLV.find(0x04, in: m) { i.publicKey = TLV.find(0x86, in: pk) }
        } else if msw == 0x6A88 || msw == 0x6A82 {
            throw PIVError.slotEmpty
        }
        if i.publicKey == nil { i.publicKey = try? await certificatePublicKey(slot: slot) }
        i.pinRetries = try? await pinRetries()
        return i
    }

    /// The slot's public key from the certificate age-plugin-yubikey stores beside it — for
    /// firmware older than 5.3, which has no GET METADATA. P-256 only: finds the SPKI bit string.
    public func certificatePublicKey(slot: UInt8) async throws -> Data? {
        guard (0x82...0x95).contains(slot) else { return nil }
        let object = 0x5FC10D + Int(slot - 0x82)
        let tag = Data([0x5C, 0x03, UInt8(object >> 16), UInt8((object >> 8) & 0xFF), UInt8(object & 0xFF)])
        let (data, sw) = try await send(Data([0x00, 0xCB, 0x3F, 0xFF, UInt8(tag.count)]) + tag + Data([0x00]))
        guard sw == 0x9000 else { return nil }
        let b = [UInt8](data)
        let marker: [UInt8] = [0x03, 0x42, 0x00, 0x04]
        guard b.count >= marker.count + 64 else { return nil }
        for i in 0...(b.count - marker.count - 64) where Array(b[i..<(i + 4)]) == marker {
            return Data(b[(i + 3)..<(i + 3 + 65)])
        }
        return nil
    }

    /// The phone-side dry run: PIN, then a key agreement on the card against an ephemeral key whose
    /// private half the phone holds, compared with the same agreement done in software. Proves the
    /// PIN, the touch (an NFC tap) and the slot's key without any computer, request or secret data.
    public func selfTest(slot: UInt8, pin: String, fallbackRecipient: Data? = nil) async throws -> Info {
        try await select()
        var info = try await info(slot: slot)
        let point: Data
        if let pk = info.publicKey {
            point = pk
        } else if let r = fallbackRecipient {
            point = try PivP256.decompress(r)
        } else {
            throw PIVError.slotEmpty
        }
        try await verify(pin: pin)
        let eph = P256.KeyAgreement.PrivateKey()
        let card = try await ecdh(slot: slot, peer: eph.publicKey.x963Representation)
        let expected = try eph.sharedSecretFromKeyAgreement(with: .init(x963Representation: point)).withUnsafeBytes { Data($0) }
        guard card == expected else { throw PIVError.keyMismatch }
        info.pinRetries = nil // verified
        return info
    }

    public static func ecdhAPDU(slot: UInt8, peer x963: Data) -> Data {
        let inner = Data([0x82, 0x00, 0x85]) + TLV.length(x963.count) + x963
        let body = Data([0x7C]) + TLV.length(inner.count) + inner
        return Data([0x00, 0x87, 0x11, slot, UInt8(body.count)]) + body + Data([0x00])
    }

    /// GENERAL AUTHENTICATE, ECDH with the slot's P-256 key. Returns the 32-byte shared x-coordinate.
    /// A slot with touch policy ALWAYS/CACHED blocks here until the touch is satisfied.
    public func ecdh(slot: UInt8, peer x963: Data) async throws -> Data {
        let (data, sw) = try await send(Self.ecdhAPDU(slot: slot, peer: x963))
        switch sw {
        case 0x9000: break
        case 0x6982: throw PIVError.securityStatusNotSatisfied
        case 0x6A80, 0x6A88, 0x6A82: throw PIVError.slotEmpty
        default: throw PIVError.unexpected(sw: sw)
        }
        guard let tpl = TLV.find(0x7C, in: data), let secret = TLV.find(0x82, in: tpl), secret.count == 32 else {
            throw PIVError.malformedResponse
        }
        return secret
    }
}

enum TLV {
    static func length(_ n: Int) -> Data {
        if n < 0x80 { return Data([UInt8(n)]) }
        if n <= 0xFF { return Data([0x81, UInt8(n)]) }
        return Data([0x82, UInt8(n >> 8), UInt8(n & 0xFF)])
    }

    /// The value of the first top-level TLV with a one-byte `tag`.
    static func find(_ tag: UInt8, in data: Data) -> Data? {
        let b = [UInt8](data)
        var i = 0
        while i + 1 < b.count {
            let t = b[i]
            var len = Int(b[i + 1])
            var off = i + 2
            if len == 0x81, off < b.count { len = Int(b[off]); off += 1 }
            else if len == 0x82, off + 1 < b.count { len = Int(b[off]) << 8 | Int(b[off + 1]); off += 2 }
            guard off + len <= b.count else { return nil }
            if t == tag { return Data(b[off..<(off + len)]) }
            i = off + len
        }
        return nil
    }
}
