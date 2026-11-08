import AgeCrypto
import SwiftUI

/// Placeholder until onboarding and the store browser land (M2/M3).
struct ContentView: View {
    var body: some View {
        NavigationStack {
            ContentUnavailableView(
                "No Password Store",
                systemImage: "lock.rectangle.stack",
                description: Text("Open a passage store from Files or clone one from git."))
                .navigationTitle("Passage")
        }
    }
}

#Preview {
    ContentView()
}
