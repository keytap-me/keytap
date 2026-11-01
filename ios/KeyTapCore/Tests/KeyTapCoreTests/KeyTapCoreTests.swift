import CryptoKit
import Foundation
import Testing
@testable import KeyTapCore

@Test func recipientParses() throws {
    let r = try #require(PivP256.parseRecipient("age1yubikey1qgarnds7s09l5vm5xgqf7k70ltzddsqtwwkt7lyvs6zmjgs9xm4dss5266r"))
    #expect(r.count == 33)
    #expect(PivP256.recipientString(r) == "age1yubikey1qgarnds7s09l5vm5xgqf7k70ltzddsqtwwkt7lyvs6zmjgs9xm4dss5266r")
}

@Test func wrapUnwrapRoundTrip() async throws {
    let key = SoftwareAgeKey()
    let fileKey = Data((0..<16).map { UInt8($0) })
    let (tag, epk, body) = try PivP256.wrap(fileKey: fileKey, recipient: key.recipientPoint)
    let req = ApprovalRequest(
        version: 1, id: "id", code: "ABC-DEF", nonce: "n", createdAt: .now, expiresAt: .now, host: "h", user: "u",
        command: "sops -d secrets/x.enc.yaml", cwd: "/", identities: [.init(serial: 1, slot: 0x82, tag: tag.base64Raw)],
        files: [.init(index: 3, stanzas: [.init(stanzaIndex: 1, tag: tag.base64Raw, epk: epk.base64Raw, body: body.base64Raw)])])
    let results = try await Approver.unwrap(req, with: key)
    #expect(results == [ApprovalResult(index: 3, fileKey: fileKey.base64Raw, error: nil)])

    let other = try await Approver.unwrap(req, with: SoftwareAgeKey())
    #expect(other.first?.fileKey == nil)
    #expect(req.targetFile == "secrets/x.enc.yaml")
}

@Test func tamperedBodyFails() throws {
    let key = SoftwareAgeKey()
    var (_, epk, body) = try PivP256.wrap(fileKey: Data(count: 16), recipient: key.recipientPoint)
    body[0] ^= 1
    let shared = try P256.KeyAgreement.PrivateKey(rawRepresentation: key.rawRepresentation)
        .sharedSecretFromKeyAgreement(with: .init(compressedRepresentation: epk)).withUnsafeBytes { Data($0) }
    #expect(throws: PivP256.Failure.unwrapFailed) {
        try PivP256.unwrap(sharedSecret: shared, epk: epk, recipient: key.recipientPoint, body: body)
    }
}

@Test func identityStringMatchesUpstreamLayout() throws {
    let id = PivP256.identityString(serial: 12345678, slot: 0x82, tag: Data([1, 2, 3, 4]))
    let (hrp, data) = try #require(Bech32.decode(id))
    #expect(hrp == "age-plugin-yubikey-")
    #expect(data == Data([0x4e, 0x61, 0xbc, 0x00, 0x82, 1, 2, 3, 4]))
}

@Test func apdus() {
    #expect(PIV.verifyAPDU(pin: "123456") == Data([0, 0x20, 0, 0x80, 8, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF]))
    #expect(PIV.verifyAPDU(pin: "12345") == nil)
    let point = Data([0x04]) + Data(repeating: 0xAB, count: 64)
    let apdu = PIV.ecdhAPDU(slot: 0x82, peer: point)
    #expect(apdu.prefix(5) == Data([0x00, 0x87, 0x11, 0x82, 0x47]))
    #expect(apdu[5...8] == Data([0x7C, 0x45, 0x82, 0x00]))
    #expect(apdu[9...10] == Data([0x85, 0x41]))
    #expect(apdu.last == 0x00)
    #expect(apdu.count == 5 + 0x47 + 1)
}

/// A fake card: answers GENERAL AUTHENTICATE with a software ECDH, so the PIV path is
/// exercised byte for byte without hardware.
struct FakeCard: PIVTransport {
    let key: P256.KeyAgreement.PrivateKey
    var serial: UInt32? = nil
    let pin = "123456"
    func transmit(_ apdu: Data) async throws -> (data: Data, sw: UInt16) {
        let a = [UInt8](apdu)
        switch a[1] {
        case 0xA4: return (Data(), 0x9000)
        case 0x20 where a.count == 4: return (Data(), 0x63C3)
        case 0x20: return Data(a[5..<13]) == PIV.verifyAPDU(pin: pin)![5..<13] ? (Data(), 0x9000) : (Data(), 0x63C2)
        case 0xF8:
            guard let serial else { return (Data(), 0x6D00) }
            return (withUnsafeBytes(of: serial.bigEndian) { Data($0) }, 0x9000)
        case 0xF7:
            let pt = key.publicKey.x963Representation
            let inner = Data([0x86, UInt8(pt.count)]) + pt
            return (Data([0x01, 0x01, 0x11, 0x04, UInt8(inner.count)]) + inner, 0x9000)
        case 0x87:
            let peer = try P256.KeyAgreement.PublicKey(x963Representation: Data(a[11..<(11 + 65)]))
            let s = try key.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
            return (Data([0x7C, 0x22, 0x82, 0x20]) + s, 0x9000)
        default: return (Data(), 0x6D00)
        }
    }
}

@Test func yubiKeyPathAgainstFakeCard() async throws {
    let cardKey = P256.KeyAgreement.PrivateKey()
    let piv = PIV(FakeCard(key: cardKey))
    try await piv.select()
    #expect(try await piv.pinRetries() == 3)
    await #expect(throws: PIVError.wrongPIN(retriesLeft: 2)) { try await piv.verify(pin: "000000") }
    try await piv.verify(pin: "123456")

    let recipient = cardKey.publicKey.compressedRepresentation
    let fileKey = Data(repeating: 7, count: 16)
    let (tag, epk, body) = try PivP256.wrap(fileKey: fileKey, recipient: recipient)
    let req = ApprovalRequest(
        version: 1, id: "id", code: "X", nonce: "n", createdAt: .now, expiresAt: .now, host: "h", user: "u",
        command: "age -d f.age", cwd: "/", identities: [.init(serial: 9, slot: 0x82, tag: tag.base64Raw)],
        files: [.init(index: 0, stanzas: [.init(stanzaIndex: 0, tag: tag.base64Raw, epk: epk.base64Raw, body: body.base64Raw)])])
    let results = try await Approver.unwrap(req, with: YubiKeyAgeKey(piv: piv, configuredRecipient: nil))
    #expect(results.first?.fileKey == fileKey.base64Raw)
}

@Test func signedMessageMatchesBridge() {
    // Same canonical text as signedMessage in bridge/request.go.
    let msg = ApprovalAnswer.signedMessage(requestBytes: Data(#"{"id":"x"}"#.utf8), nonce: "n", declined: false,
                                           results: [.init(index: 1, fileKey: "AAAA"), .init(index: 0, error: "x")])
    let sum = SHA256.hash(data: Data(#"{"id":"x"}"#.utf8)).map { String(format: "%02x", $0) }.joined()
    #expect(String(decoding: msg, as: UTF8.self) == "keytap-answer-v1\n\(sum)\nn\n0 !\n1 AAAA\n")
}

@Test func pairingLink() throws {
    let fp = Data(repeating: 1, count: 32).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    let l = try #require(PairingLink("keytap://pair?v=1&host=192.0.2.10:8743&fp=\(fp)&code=abc&name=workstation"))
    #expect(l.host == "192.0.2.10:8743" && l.name == "workstation" && l.code == "abc" && l.recipient == nil)
    #expect(PairingLink("https://pair?v=1") == nil)
}

/// The identity file lists all four YubiKeys: one stub and one stanza per key. Only the tapped
/// key's stanza may be used; the others are skipped, not errors.
@Test func severalYubiKeysOnlyTheTappedOneAnswers() async throws {
    let keys = (0..<4).map { _ in P256.KeyAgreement.PrivateKey() }
    let serials: [UInt32] = [11111111, 22222222, 33333333, 44444444]
    let fileKey = Data(repeating: 9, count: 16)
    var identities: [ApprovalRequest.Identity] = []
    var stanzas: [ApprovalRequest.Stanza] = []
    for (i, k) in keys.enumerated() {
        let (tag, epk, body) = try PivP256.wrap(fileKey: fileKey, recipient: k.publicKey.compressedRepresentation)
        identities.append(.init(serial: serials[i], slot: 0x82, tag: tag.base64Raw))
        stanzas.append(.init(stanzaIndex: i, tag: tag.base64Raw, epk: epk.base64Raw, body: body.base64Raw))
    }
    let req = ApprovalRequest(
        version: 1, id: "id", code: "X", nonce: "n", createdAt: .now, expiresAt: .now, host: "h", user: "u",
        command: "sops -d s.yaml", cwd: "/", identities: identities, files: [.init(index: 0, stanzas: stanzas)])

    // The third key is tapped: stanzas 0 and 1 belong to other keys and must be skipped.
    let piv = PIV(FakeCard(key: keys[2], serial: serials[2]))
    try await piv.select()
    let results = try await Approver.unwrap(req, with: YubiKeyAgeKey(piv: piv, configuredRecipient: nil))
    #expect(results.first?.fileKey == fileKey.base64Raw)

    // A key that is not in the list: nothing unwrapped, and no error thrown mid-session.
    let stranger = PIV(FakeCard(key: P256.KeyAgreement.PrivateKey(), serial: 55555555))
    try await stranger.select()
    let none = try await Approver.unwrap(req, with: YubiKeyAgeKey(piv: stranger, configuredRecipient: nil))
    #expect(none.first?.fileKey == nil)

    // Firmware without GET SERIAL: the tag check alone still picks the right stanza.
    let old = PIV(FakeCard(key: keys[3]))
    try await old.select()
    let viaTag = try await Approver.unwrap(req, with: YubiKeyAgeKey(piv: old, configuredRecipient: nil))
    #expect(viaTag.first?.fileKey == fileKey.base64Raw)
}

@Test func phoneSelfTestAgainstFakeCard() async throws {
    let key = P256.KeyAgreement.PrivateKey()
    let info = try await PIV(FakeCard(key: key, serial: 12345678)).selfTest(slot: 0x82, pin: "123456")
    #expect(info.serial == 12345678)
    #expect(info.publicKey == key.publicKey.x963Representation)
    await #expect(throws: PIVError.wrongPIN(retriesLeft: 2)) {
        try await PIV(FakeCard(key: key)).selfTest(slot: 0x82, pin: "654321")
    }
}

@Test func probeProofMatchesBridgeDerivation() async throws {
    // Same derivation as bridge/probe.go: HKDF(ECDH, epk ‖ recipient, "piv-p256") → HMAC("keytap-probe-v1" ‖ nonce).
    let card = SoftwareAgeKey()
    let eph = P256.KeyAgreement.PrivateKey()
    let epk = eph.publicKey.compressedRepresentation
    let shared = try eph.sharedSecretFromKeyAgreement(with: .init(compressedRepresentation: card.recipientPoint)).withUnsafeBytes { Data($0) }
    let wrap = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: shared), salt: epk + card.recipientPoint,
                                      info: Data("piv-p256".utf8), outputByteCount: 32)
    let tag = PivP256.tag(recipient: card.recipientPoint).base64Raw
    var req = ApprovalRequest(version: 1, id: "i", code: "C", nonce: "nonce-1", createdAt: .now, expiresAt: .now,
                              host: "h", user: "u", command: "", cwd: "", identities: [], files: [])
    req.kind = "test"
    req.probe = .init(serial: 1, slot: 0x82, tag: tag, epk: epk.base64Raw)
    let proof = try await Approver.probe(req, with: card)
    let want = Data(HMAC<SHA256>.authenticationCode(for: Data("keytap-probe-v1nonce-1".utf8), using: wrap)).base64Raw
    #expect(proof == want)
}

/// Sealed by bridge/push.go's algorithm in Go (AES-256-GCM, key 00…1f, nonce "0123456789ab", AAD = id).
@Test func notificationOpensGoCiphertext() throws {
    let key = Data((0..<32).map { UInt8($0) })
    let sealed = "MDEyMzQ1Njc4OWFiTDMkUWwWpSX+W3GBihnvfGbDJiM1vNfcl/KTJ13+P79fnKIje0Pqa89rV8M/6E3KJoJhOXrE2IaKDKtiAoJpAbMm2mLasnIt8StYcgtS+iTHNGBUDbVzG0QlJwxfp3/T5mG521JpZbzuZYtIGdx33RmiX24KAlUAp96hLfK2uOEVpDa9kd6k9Q=="
    let s = try #require(NotificationCrypto.open(payload: sealed, key: key, requestID: "req-1"))
    #expect(s.id == "req-1" && !s.isTest)
    #expect(NotificationCrypto.open(payload: sealed, key: key, requestID: "req-2") == nil)
    #expect(NotificationCrypto.open(payload: sealed, key: Data(count: 32), requestID: "req-1") == nil)
}

/// An older bridge (v0.3.0) still sealed the note and the details: they decode as unknown keys and
/// are never shown.
@Test func notificationIgnoresOldDetails() throws {
    let key = Data((0..<32).map { UInt8($0) })
    let sealed = "MDEyMzQ1Njc4OWFiTDMkUWwWpSX+W3GBihnvfGbAJiM1vNfcl/KTJ1v0Nr9Qlakje0Pqa89rV8M/6E3KJoJhOXrE2IaKDKtiAoJpAbMm2mLasnIt8StYcgtS+iTHNGBUDbVzG0QlJwxfp3/T5mG521JpZbzlco8PAddtv0bmDipTXAJdJanzWvTGHyG5C21166bpd+aagt9tM5qNwBAdr9X8iD/LMDyw3ePi6W1UPpQUZglRTZjcU0zQ6xGNRG8Qcqqp"
    let s = try #require(NotificationCrypto.open(payload: sealed, key: key, requestID: "req-2"))
    #expect(s.id == "req-2" && s.exp == 1_900_000_000)
}

@Test func requestNoteDecodes() throws {
    let base = #"{"version":1,"id":"i","code":"C","nonce":"n","created_at":"2026-10-30T12:00:00Z","expires_at":"2026-10-30T12:05:00Z","host":"h","user":"u","command":"sops -d x","cwd":"/","identities":[],"files":[]"#
    let with = try BridgeClient.decoder.decode(ApprovalRequest.self, from: Data((base + #","note":"  why  "}"#).utf8))
    let without = try BridgeClient.decoder.decode(ApprovalRequest.self, from: Data((base + "}").utf8))
    #expect(with.displayNote == "why")
    #expect(without.note == nil && without.displayNote == nil)
}
