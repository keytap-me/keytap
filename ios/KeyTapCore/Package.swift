// swift-tools-version: 6.0
// KeyTapCore — everything in KeyTap that is not UI: the piv-p256 unwrap, the PIV APDUs, the
// bridge client. Apple frameworks only (CryptoKit, Foundation, Security) — no third-party code.
import PackageDescription

let package = Package(
    name: "KeyTapCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "KeyTapCore", targets: ["KeyTapCore"]),
        .executable(name: "keytap-softphone", targets: ["keytap-softphone"]),
    ],
    targets: [
        .target(name: "KeyTapCore"),
        .executableTarget(name: "keytap-softphone", dependencies: ["KeyTapCore"]),
        .testTarget(name: "KeyTapCoreTests", dependencies: ["KeyTapCore"]),
    ]
)
