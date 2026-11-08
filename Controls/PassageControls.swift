import AppIntents
import SwiftUI
import WidgetKit

@main
struct PassageControls: WidgetBundle {
    var body: some Widget {
        SyncControl()
        SearchControl()
    }
}

/// Syncs in the background, without opening the app.
struct SyncControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: "de.nerdworks.passage.sync") {
            ControlWidgetButton(action: SyncPasswordsIntent()) {
                Label("Sync Passwords", systemImage: "arrow.triangle.2.circlepath")
            }
        }
        .displayName("Sync Passwords")
        .description("Pull and push your password store.")
    }
}

/// Opens Passage with search focused.
struct SearchControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: "de.nerdworks.passage.search") {
            ControlWidgetButton(action: SearchPasswordsIntent()) {
                Label("Search Passwords", systemImage: "key.viewfinder")
            }
        }
        .displayName("Search Passwords")
        .description("Open Passage to find a password.")
    }
}
