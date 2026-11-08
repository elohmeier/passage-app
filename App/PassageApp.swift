import SwiftUI

@main
struct PassageApp: App {
    @State private var model = AppModel.live()
    @State private var store = StoreModel(defaults: AppModel.sharedDefaults)
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(model)
                .environment(store)
                .onAppear { store.restore() }
                // Hide content in the app switcher.
                .overlay {
                    if scenePhase != .active {
                        PrivacyCover()
                    }
                }
                .alert(
                    "Error", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })
                ) {
                    Button("OK") {}
                } message: {
                    Text(model.errorMessage ?? "")
                }
                .alert(
                    "Store Error", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })
                ) {
                    Button("OK") {}
                } message: {
                    Text(store.errorMessage ?? "")
                }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background {
                model.lock()
            }
        }
    }
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.regularMaterial)
            Image(systemName: "lock.fill")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
        }
        .ignoresSafeArea()
    }
}
