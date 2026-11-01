import Foundation

/// The only web addresses KeyTap knows. They open in Safari when the user taps them; the app
/// itself never connects anywhere but the paired computer (README: no server).
enum Links {
    static let website = URL(string: "https://keytap.me")!
    static let install = URL(string: "https://keytap.me/install")!
    static let security = URL(string: "https://keytap.me/security")!
    static let privacy = URL(string: "https://keytap.me/privacy")!
    static let support = URL(string: "https://keytap.me/support")!
    static let source = URL(string: "https://github.com/keytap-me/keytap")!
    static let imprint = URL(string: "https://keytap.me/imprint")!
    static let eula = URL(string: "https://www.apple.com/legal/internet-services/itunes/dev/stdeula/")!
}

enum AppInfo {
    static var version: String {
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let b = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "\(v) (\(b))"
    }
}
