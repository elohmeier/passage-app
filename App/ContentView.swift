import SwiftUI

/// Placeholder root until the store browser lands (M3).
struct ContentView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ContentUnavailableView(
                        "No Password Store",
                        systemImage: "lock.rectangle.stack",
                        description: Text("Open a passage store from Files or clone one from git."))
                }
                Section("Keys") {
                    NavigationLink {
                        KeysView()
                    } label: {
                        Label("Keys", systemImage: "key")
                            .badge(model.identities.count)
                    }
                    NavigationLink {
                        DecryptFileView()
                    } label: {
                        Label("Decrypt a File", systemImage: "doc.badge.ellipsis")
                    }
                }
            }
            .navigationTitle("Passage")
        }
    }
}

#Preview {
    ContentView()
        .environment(AppModel.preview())
}
