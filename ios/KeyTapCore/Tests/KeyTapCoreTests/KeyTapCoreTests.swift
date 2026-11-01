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
    let results = try await Approver.unwrap(req, with: YubiKeyAgeKey(piv: piv))
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
    #expect(l.host == "192.0.2.10:8743" && l.name == "workstation" && l.code == "abc")
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
    let results = try await Approver.unwrap(req, with: YubiKeyAgeKey(piv: piv))
    #expect(results.first?.fileKey == fileKey.base64Raw)

    // A key that is not in the list: nothing unwrapped, and no error thrown mid-session.
    let stranger = PIV(FakeCard(key: P256.KeyAgreement.PrivateKey(), serial: 55555555))
    try await stranger.select()
    let none = try await Approver.unwrap(req, with: YubiKeyAgeKey(piv: stranger))
    #expect(none.first?.fileKey == nil)

    // Firmware without GET SERIAL: the tag check alone still picks the right stanza.
    let old = PIV(FakeCard(key: keys[3]))
    try await old.select()
    let viaTag = try await Approver.unwrap(req, with: YubiKeyAgeKey(piv: old))
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

// MARK: FIDO2 / SSH

@Test func cborRoundTripAndCanonicalOrder() throws {
    let m = CBOR.map([(.text("type"), .text("public-key")), (.int(-2), .bytes(Data([1, 2]))), (.text("id"), .bytes(Data([9]))),
                      (.int(3), .array([.bool(true), .null, .int(-25), .int(70000)]))])
    let enc = m.encoded
    #expect(try CBOR.decode(enc) == m)
    // canonical: 0x03 (int 3) < 0x21 (int -2) < "id" (3 bytes) < "type" (5 bytes)
    #expect(enc.prefix(2) == Data([0xA4, 0x03]))
}

private func sshRequest(_ cred: SoftFIDOAuthenticator.Credential, data: Data, uv: Bool = true) -> ApprovalRequest.SSHSign {
    ApprovalRequest.SSHSign(application: cred.rpId, credentialID: cred.id.base64Raw,
                            clientDataHash: Data(SHA256.hash(data: data)).base64Raw, algorithm: "ed25519",
                            userPresence: true, userVerification: uv, purpose: "login", login: "deploy")
}

private func verifyAssertion(_ a: CTAP2.Assertion, _ cred: SoftFIDOAuthenticator.Credential, data: Data) throws -> Bool {
    var msg = Data(SHA256.hash(data: Data(cred.rpId.utf8)))
    msg.append(a.flags)
    msg.append(contentsOf: withUnsafeBytes(of: a.counter.bigEndian, Array.init))
    msg += Data(SHA256.hash(data: data))
    return try Curve25519.Signing.PublicKey(rawRepresentation: cred.publicKey).isValidSignature(a.signature, for: msg)
}

@Test(arguments: [(true, [2, 1]), (false, [2, 1]), (false, [1])])
func sshSignatureWithPIN(pinUvAuthToken: Bool, protocols: [Int]) async throws {
    let cred = SoftFIDOAuthenticator.Credential(rpId: "ssh:deploy")
    let key = SoftFIDOAuthenticator(credential: cred, pin: "123456", pinUvAuthToken: pinUvAuthToken, protocols: protocols)
    let data = Data("userauth request bytes".utf8)
    let a = try await SSHSigner.sign(sshRequest(cred, data: data), pin: "123456", transport: key)
    #expect(a.flags == 0x05)         // user presence + user verification
    #expect(a.counter == 1)
    #expect(try verifyAssertion(a, cred, data: data))
    let b = try await SSHSigner.sign(sshRequest(cred, data: data), pin: "123456", transport: key)
    #expect(b.counter == 2)
}

/// The NFC select answer only names the protocols; a YubiKey 5 answers "U2F_V2" and still signs with FIDO2.
@Test(arguments: ["U2F_V2", "FIDO_2_0"])
func sshSelectReplyDoesNotDecideFIDO2(reply: String) async throws {
    let cred = SoftFIDOAuthenticator.Credential(rpId: "ssh:")
    let key = SoftFIDOAuthenticator(credential: cred, pin: "123456", selectReply: reply)
    let a = try await SSHSigner.sign(sshRequest(cred, data: Data([1])), pin: "123456", transport: key)
    #expect(try verifyAssertion(a, cred, data: Data([1])))
}

@Test func sshU2FOnlyKeyIsNamed() async throws {
    let cred = SoftFIDOAuthenticator.Credential(rpId: "ssh:")
    let key = SoftFIDOAuthenticator(credential: cred, pin: "123456", fido2: false)
    await #expect(throws: CTAPError.notFIDO2) {
        try await SSHSigner.sign(sshRequest(cred, data: Data([1])), pin: "123456", transport: key)
    }
}

@Test func sshWrongPINCountsDown() async throws {
    let cred = SoftFIDOAuthenticator.Credential(rpId: "ssh:")
    let key = SoftFIDOAuthenticator(credential: cred, pin: "123456")
    await #expect(throws: CTAPError.wrongPIN(retriesLeft: 7)) {
        try await SSHSigner.sign(sshRequest(cred, data: Data([1])), pin: "000000", transport: key)
    }
    #expect(await key.retries == 7)
}

@Test func sshOtherKeyHasNoCredential() async throws {
    let cred = SoftFIDOAuthenticator.Credential(rpId: "ssh:")
    let other = SoftFIDOAuthenticator(credential: .init(rpId: "ssh:"), pin: "123456")
    await #expect(throws: CTAPError.noCredential) {
        try await SSHSigner.sign(sshRequest(cred, data: Data([1])), pin: "123456", transport: other)
    }
}

@Test func sshVerifyRequiredNeedsPIN() async throws {
    let cred = SoftFIDOAuthenticator.Credential(rpId: "ssh:")
    let key = SoftFIDOAuthenticator(credential: cred, pin: "123456")
    await #expect(throws: CTAPError.pinRequired) {
        try await SSHSigner.sign(sshRequest(cred, data: Data([1])), pin: "", transport: key)
    }
}

/// The answer's signed message carries the assertion, in the same line format as bridge/request.go.
@Test func sshAnswerSignedMessage() throws {
    let ssh = SSHAnswer(signature: "c2ln", flags: 5, counter: 3)
    let m = String(decoding: ApprovalAnswer.signedMessage(requestBytes: Data("{}".utf8), nonce: "n", declined: false,
                                                          results: [], ssh: ssh), as: UTF8.self)
    #expect(m.hasSuffix("n\nssh c2ln 5 3\n"))
}

@Test func sshRequestDecodes() throws {
    let json = """
    {"version":1,"kind":"ssh","id":"i","code":"ABC-DEF","nonce":"n","created_at":"2026-11-01T10:00:00Z",
     "expires_at":"2026-11-01T10:05:00Z","host":"workstation","user":"you","command":"ssh build-server","cwd":"/",
     "identities":[],"files":[],
     "ssh":{"application":"ssh:deploy","credential_id":"AQI","client_data_hash":"AA","algorithm":"ed25519",
            "user_presence":true,"user_verification":true,"purpose":"login","login":"deploy",
            "key_fingerprint":"SHA256:x","key_name":"id_ed25519_sk"}}
    """
    let r = try BridgeClient.decoder.decode(ApprovalRequest.self, from: Data(json.utf8))
    #expect(r.isSSH && !r.isUnknownKind && r.ssh?.login == "deploy" && r.ssh?.keyName == "id_ed25519_sk")
}

// MARK: KeyTap 1.1 — any of the computer's keys, one PIN, one tap

/// Counts the PIN-carrying commands that reach the card (VERIFY with data, RESET RETRY COUNTER).
final class CountingCard: PIVTransport, @unchecked Sendable {
    let inner: FakeCard
    private let lock = NSLock()
    private var pins = 0
    init(_ inner: FakeCard) { self.inner = inner }
    var pinCommands: Int { lock.withLock { pins } }
    func transmit(_ apdu: Data) async throws -> (data: Data, sw: UInt16) {
        let a = [UInt8](apdu)
        if (a[1] == 0x20 && a.count > 4) || a[1] == 0x2C { lock.withLock { pins += 1 } }
        return try await inner.transmit(apdu)
    }
}

/// A computer serving one chain: answers recorded, continuations handed out in order.
actor FakeLink: ChainLink {
    var answers: [ApprovalAnswer] = []
    var queue: [(ApprovalRequest, Data)]
    let reason: String?
    init(next: [(ApprovalRequest, Data)], reason: String? = nil) {
        queue = next
        self.reason = reason
    }
    func send(_ answer: ApprovalAnswer) async throws { answers.append(answer) }
    func next(after id: String, timeout: Duration) async throws -> (ApprovalRequest, Data)? {
        queue.isEmpty ? nil : queue.removeFirst()
    }
    func endReason() async -> String? { reason }
}

private func chainRequest(id: String, identities: [ApprovalRequest.Identity], stanzas: [ApprovalRequest.Stanza],
                          continues: String? = nil) throws -> (ApprovalRequest, Data) {
    var r = ApprovalRequest(
        version: 2, id: id, code: "X", nonce: "n-\(id)", createdAt: .now, expiresAt: .now.addingTimeInterval(60), host: "h",
        user: "u", command: "sops -d s.yaml", cwd: "/", identities: identities, files: [.init(index: 0, stanzas: stanzas)])
    r.keys = [.init(serial: 1, label: "everyday"), .init(serial: 2, label: "spare"), .init(serial: 4, label: "safe")]
    r.defaultKey = 1
    r.continues = continues
    return (r, try JSONEncoder().encode(r))
}

@Test func heldKeyAnswersItsContinuationInTheSameTap() async throws {
    let fileKey = Data(repeating: 5, count: 16)
    let keyA = P256.KeyAgreement.PrivateKey(), keyD = P256.KeyAgreement.PrivateKey()
    let (t1, e1, b1) = try PivP256.wrap(fileKey: fileKey, recipient: keyA.publicKey.compressedRepresentation)
    let (t4, e4, b4) = try PivP256.wrap(fileKey: fileKey, recipient: keyD.publicKey.compressedRepresentation)
    // sops asks for the first key's stanza first; the user taps the fourth key
    let (first, fb) = try chainRequest(id: "r1", identities: [.init(serial: 1, slot: 0x82, tag: t1.base64Raw)],
                                       stanzas: [.init(stanzaIndex: 0, tag: t1.base64Raw, epk: e1.base64Raw, body: b1.base64Raw)])
    let (second, sb) = try chainRequest(id: "r2", identities: [.init(serial: 4, slot: 0x82, tag: t4.base64Raw)],
                                        stanzas: [.init(stanzaIndex: 3, tag: t4.base64Raw, epk: e4.base64Raw, body: b4.base64Raw)],
                                        continues: "r1")
    let card = CountingCard(FakeCard(key: keyD, serial: 4))
    let link = FakeLink(next: [(second, sb)])
    let out = try await TapChain.run(request: first, bytes: fb, picked: 4, pin: "123456", key: YubiKeyTap(card), link: link,
                                     signer: SoftwareSigner())
    #expect(out == .decrypted(files: 1))
    let answers = await link.answers
    #expect(answers.count == 2)
    #expect(answers[0].held == HeldKey(serial: 4))       // r1: not for keyD, held
    #expect(answers[0].results.isEmpty)
    #expect(answers[1].results.first?.fileKey == fileKey.base64Raw) // r2 unwrapped in the same tap
    #expect(card.pinCommands == 1)                          // one VERIFY, only once the key had a stanza
}

@Test func pinForAnotherKeyIsNeverSent() async throws {
    let keyD = P256.KeyAgreement.PrivateKey()
    let (t, e, b) = try PivP256.wrap(fileKey: Data(count: 16), recipient: keyD.publicKey.compressedRepresentation)
    let (req, bytes) = try chainRequest(id: "r1", identities: [.init(serial: 4, slot: 0x82, tag: t.base64Raw)],
                                        stanzas: [.init(stanzaIndex: 0, tag: t.base64Raw, epk: e.base64Raw, body: b.base64Raw)])
    let card = CountingCard(FakeCard(key: keyD, serial: 4))
    let link = FakeLink(next: [])
    // the PIN was typed for spare (2), keyD's key (4) is tapped
    await #expect(throws: TapError.otherKeyTapped(tapped: 4, tappedLabel: "safe", picked: 2, pickedLabel: "spare")) {
        try await TapChain.run(request: req, bytes: bytes, picked: 2, pin: "999999", key: YubiKeyTap(card), link: link,
                               signer: SoftwareSigner())
    }
    #expect(card.pinCommands == 0)
    #expect(await link.answers.isEmpty)
}

@Test func heldKeyWithNothingToAnswerEndsWithTheReason() async throws {
    let keyA = P256.KeyAgreement.PrivateKey()
    let (t, e, b) = try PivP256.wrap(fileKey: Data(count: 16), recipient: keyA.publicKey.compressedRepresentation)
    let (req, bytes) = try chainRequest(id: "r1", identities: [.init(serial: 1, slot: 0x82, tag: t.base64Raw)],
                                        stanzas: [.init(stanzaIndex: 0, tag: t.base64Raw, epk: e.base64Raw, body: b.base64Raw)])
    let card = CountingCard(FakeCard(key: P256.KeyAgreement.PrivateKey(), serial: 2))
    let link = FakeLink(next: [], reason: "spare is not one of the keys this request can use")
    await #expect(throws: TapError.notThisKey("Spare is not one of the keys this request can use.")) {
        try await TapChain.run(request: req, bytes: bytes, picked: 2, pin: "123456", key: YubiKeyTap(card), link: link,
                               signer: SoftwareSigner())
    }
    #expect(card.pinCommands == 0) // never verified: the key had nothing to unwrap
    let withdrawn = FakeLink(next: [], reason: "answered elsewhere")
    await #expect(throws: TapError.withdrawn("answered elsewhere")) {
        try await TapChain.run(request: req, bytes: bytes, picked: 2, pin: "123456", key: YubiKeyTap(card), link: withdrawn,
                               signer: SoftwareSigner())
    }
}

@Test func heldAnswerIsSignedLikeTheBridgeExpects() throws {
    let msg = ApprovalAnswer.signedMessage(requestBytes: Data("{}".utf8), nonce: "n", declined: false, results: [],
                                           held: HeldKey(serial: 22222222))
    #expect(String(decoding: msg, as: UTF8.self).hasSuffix("n\nheld 22222222\n"))
}

@Test func unblockAPDULayout() throws {
    let apdu = try #require(PIV.unblockAPDU(puk: "12345678", newPIN: "654321"))
    #expect(Array(apdu.prefix(5)) == [0x00, 0x2C, 0x00, 0x80, 0x10])
    #expect(Array(apdu.suffix(8)) == Array("654321".utf8) + [0xFF, 0xFF])
    #expect(PIV.unblockAPDU(puk: "123", newPIN: "654321") == nil)
}

@Test func requestOffersTheComputersKeys() throws {
    let json = #"{"version":2,"id":"a","code":"X","nonce":"n","created_at":"2026-11-01T10:00:00Z","expires_at":"2026-11-01T10:05:00Z","host":"h","user":"u","command":"c","cwd":"/","identities":[{"serial":7,"slot":130,"tag":"AAAAAA"}],"files":[],"keys":[{"serial":11111111,"label":"everyday"},{"serial":22222222,"label":"spare"}],"default":22222222,"continues":"z"}"#
    let r = try BridgeClient.decoder.decode(ApprovalRequest.self, from: Data(json.utf8))
    #expect(r.offeredKeys.map(\.label) == ["everyday", "spare"])
    #expect(r.defaultKey == 22222222)
    #expect(r.continues == "z")
    #expect(r.label(of: 7) == "YubiKey 7")
}
