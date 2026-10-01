import QtQuick
import QtQuick.Window
import Quickshell

ShellRoot {
    // A source edit or checkout must not hot-reload a live chat window: reload
    // discards memory-only edits and forgets in-flight sends. Reload explicitly.
    Component.onCompleted: Quickshell.watchFiles = false
    ChatService { id: chatService; focused: window.contentItem.Window.active }
    ThemeTokens { id: colors; source: chatService.theme }
    FloatingWindow {
        id: window
        title: "OmaChat"
        implicitWidth: 1080
        implicitHeight: 760
        minimumSize: Qt.size(440, 480)
        visible: true
        color: colors.surface
        ChatView { anchors.fill: parent; service: chatService }
        CloseGuard { service: chatService }
    }
    Connections { target: Quickshell; function onLastWindowClosed() { Qt.quit() } }
}
