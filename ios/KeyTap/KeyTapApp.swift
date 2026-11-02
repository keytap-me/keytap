import KeyTapCore
import SwiftUI

@main
struct KeyTapApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var model = AppModel()
    @State private var pendingLink: PairingLink?
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            @Bindable var model = model
            Group {
                if model.isDemo || (model.setupDone && model.pairing != nil) {
                    HomeView()
                } else {
                    SetupWizard(incomingLink: $pendingLink)
                }
            }
            .environment(model)
            // The request sheet sits at the root so it also appears during the wizard's dry run.
            .sheet(item: $model.request) { req in
                RequestView(request: req).environment(model).interactiveDismissDisabled()
            }
            .onOpenURL { url in
                guard let link = PairingLink(url.absoluteString) else { return }
                if model.setupDone { model.setupDone = false } // a new pairing link re-runs setup
                pendingLink = link
            }
            .onChange(of: scenePhase, initial: true) { _, phase in
                if phase == .active {
                    delegate.model = model
                    model.becameActive()
                    model.startPolling()
                    model.refreshPushRegistration()
                    Task {
                        await Notifications.remove(requestID: nil)
                        // a badge left by a push for a request that is gone; the poll sets it again if not
                        if model.request == nil { Notifications.setBadge(0) }
                    }
                } else {
                    model.stopPolling() // also under the NFC sheet (inactive): the tap fetches the chain itself
                    if phase == .background { model.leftScreen() }
                }
            }
        }
    }
}
