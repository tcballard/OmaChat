import QtQuick
import Quickshell

ShellRoot {
    Component.onCompleted: Quickshell.watchFiles = false
    ChatService { id: chatService }
    FloatingWindow {
        id: window
        title: "OmaChat"
        implicitWidth: 980
        implicitHeight: 680
        minimumSize: Qt.size(440, 480)
        visible: true
        color: "#17191e"
        ChatView { anchors.fill: parent; service: chatService }
    }
    Connections {
        target: Quickshell
        function onLastWindowClosed() { Qt.quit() }
    }
}
