import Foundation

/// The CBOR subset CTAP2 uses (RFC 8949): unsigned/negative integers, byte and text strings, arrays,
/// maps, booleans. Maps encode in CTAP2 canonical order (keys sorted by their encoding: shorter first,
/// then bytewise), which the authenticator requires.
public indirect enum CBOR: Equatable, Sendable {
    case int(Int)
    case bytes(Data)
    case text(String)
    case array([CBOR])
    case map([(CBOR, CBOR)])
    case bool(Bool)
    case null

    public static func == (a: CBOR, b: CBOR) -> Bool { a.encoded == b.encoded }

    // MARK: encoding

    public var encoded: Data {
        var out = Data()
        encode(into: &out)
        return out
    }

    private static func head(_ major: UInt8, _ n: UInt64, into out: inout Data) {
        let m = major << 5
        switch n {
        case 0..<24: out.append(m | UInt8(n))
        case 24..<0x100: out.append(m | 24); out.append(UInt8(n))
        case 0x100..<0x10000: out.append(m | 25); out.append(contentsOf: withUnsafeBytes(of: UInt16(n).bigEndian, Array.init))
        case 0x10000..<0x1_0000_0000: out.append(m | 26); out.append(contentsOf: withUnsafeBytes(of: UInt32(n).bigEndian, Array.init))
        default: out.append(m | 27); out.append(contentsOf: withUnsafeBytes(of: n.bigEndian, Array.init))
        }
    }

    private func encode(into out: inout Data) {
        switch self {
        case .int(let v):
            if v >= 0 { Self.head(0, UInt64(v), into: &out) } else { Self.head(1, UInt64(-1 - v), into: &out) }
        case .bytes(let d): Self.head(2, UInt64(d.count), into: &out); out.append(d)
        case .text(let s): let d = Data(s.utf8); Self.head(3, UInt64(d.count), into: &out); out.append(d)
        case .array(let a): Self.head(4, UInt64(a.count), into: &out); a.forEach { $0.encode(into: &out) }
        case .map(let m):
            Self.head(5, UInt64(m.count), into: &out)
            let sorted = m.map { (k: $0.0.encoded, v: $0.1) }.sorted { a, b in
                a.k.count != b.k.count ? a.k.count < b.k.count : a.k.lexicographicallyPrecedes(b.k)
            }
            for e in sorted { out.append(e.k); e.v.encode(into: &out) }
        case .bool(let b): out.append(b ? 0xF5 : 0xF4)
        case .null: out.append(0xF6)
        }
    }

    // MARK: decoding

    public enum DecodeError: Error { case truncated, unsupported(UInt8), tooDeep }

    public static func decode(_ data: Data) throws -> CBOR {
        var i = data.startIndex
        return try decode(data, &i, depth: 0)
    }

    private static func decode(_ d: Data, _ i: inout Data.Index, depth: Int) throws -> CBOR {
        guard depth < 16 else { throw DecodeError.tooDeep }
        guard i < d.endIndex else { throw DecodeError.truncated }
        let b = d[i]; i += 1
        let major = b >> 5, info = b & 0x1F
        func arg() throws -> UInt64 {
            let n: Int
            switch info {
            case 0..<24: return UInt64(info)
            case 24: n = 1
            case 25: n = 2
            case 26: n = 4
            case 27: n = 8
            default: throw DecodeError.unsupported(b)
            }
            guard d.endIndex - i >= n else { throw DecodeError.truncated }
            var v: UInt64 = 0
            for _ in 0..<n { v = v << 8 | UInt64(d[i]); i += 1 }
            return v
        }
        switch major {
        case 0: let v = try arg(); guard v <= UInt64(Int.max) else { throw DecodeError.unsupported(b) }; return .int(Int(v))
        case 1: let v = try arg(); guard v < UInt64(Int.max) else { throw DecodeError.unsupported(b) }; return .int(-1 - Int(v))
        case 2, 3:
            let n = try arg()
            guard UInt64(d.endIndex - i) >= n else { throw DecodeError.truncated }
            let s = d[i..<(i + Int(n))]; i += Int(n)
            return major == 2 ? .bytes(Data(s)) : .text(String(decoding: s, as: UTF8.self))
        case 4:
            let n = try arg()
            guard n <= 1024 else { throw DecodeError.unsupported(b) }
            return .array(try (0..<n).map { _ in try decode(d, &i, depth: depth + 1) })
        case 5:
            let n = try arg()
            guard n <= 1024 else { throw DecodeError.unsupported(b) }
            return .map(try (0..<n).map { _ in (try decode(d, &i, depth: depth + 1), try decode(d, &i, depth: depth + 1)) })
        case 7:
            switch info {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22, 23: return .null
            default: throw DecodeError.unsupported(b)
            }
        default: throw DecodeError.unsupported(b) // tags, floats: not used by CTAP2 responses we read
        }
    }

    // MARK: access

    public subscript(_ key: Int) -> CBOR? { self[.int(key)] }
    public subscript(_ key: String) -> CBOR? { self[.text(key)] }
    public subscript(_ key: CBOR) -> CBOR? {
        guard case .map(let m) = self else { return nil }
        return m.first { $0.0 == key }?.1
    }

    public var bytes: Data? { if case .bytes(let d) = self { d } else { nil } }
    public var int: Int? { if case .int(let v) = self { v } else { nil } }
    public var text: String? { if case .text(let s) = self { s } else { nil } }
    public var bool: Bool? { if case .bool(let b) = self { b } else { nil } }
    public var array: [CBOR]? { if case .array(let a) = self { a } else { nil } }
}
