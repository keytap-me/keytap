import Foundation

/// Bech32 (BIP-173) without the 90-character limit, as age uses it for recipients and identities.
public enum Bech32 {
    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l".utf8)

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        let gen: [UInt32] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        var chk: UInt32 = 1
        for v in values {
            let top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ UInt32(v)
            for i in 0..<5 where (top >> UInt32(i)) & 1 == 1 { chk ^= gen[i] }
        }
        return chk
    }

    private static func expand(_ hrp: [UInt8]) -> [UInt8] {
        hrp.map { $0 >> 5 } + [0] + hrp.map { $0 & 31 }
    }

    public static func encode(hrp: String, data: Data) -> String {
        let h = Array(hrp.lowercased().utf8)
        let values = convert(Array(data), from: 8, to: 5, pad: true)!
        let chk = polymod(expand(h) + values + [0, 0, 0, 0, 0, 0]) ^ 1
        var out = h + [UInt8(ascii: "1")] + values.map { charset[Int($0)] }
        for i in 0..<6 { out.append(charset[Int((chk >> UInt32(5 * (5 - i))) & 31)]) }
        return String(decoding: out, as: UTF8.self)
    }

    public static func decode(_ s: String) -> (hrp: String, data: Data)? {
        guard s == s.lowercased() || s == s.uppercased() else { return nil }
        let b = Array(s.lowercased().utf8)
        guard let pos = b.lastIndex(of: UInt8(ascii: "1")), pos >= 1, pos + 7 <= b.count else { return nil }
        var values: [UInt8] = []
        for c in b[(pos + 1)...] {
            guard let v = charset.firstIndex(of: c) else { return nil }
            values.append(UInt8(v))
        }
        let hrp = Array(b[..<pos])
        guard polymod(expand(hrp) + values) == 1,
              let data = convert(Array(values.dropLast(6)), from: 5, to: 8, pad: false) else { return nil }
        return (String(decoding: hrp, as: UTF8.self), Data(data))
    }

    private static func convert(_ input: [UInt8], from: Int, to: Int, pad: Bool) -> [UInt8]? {
        var acc = 0, bits = 0
        let maxv = (1 << to) - 1
        var out: [UInt8] = []
        for v in input {
            acc = (acc << from) | Int(v)
            bits += from
            while bits >= to {
                bits -= to
                out.append(UInt8((acc >> bits) & maxv))
            }
        }
        if pad {
            if bits > 0 { out.append(UInt8((acc << (to - bits)) & maxv)) }
        } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
            return nil
        }
        return out
    }
}
