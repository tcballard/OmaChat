import QtQuick
import QtQuick.Window
import Quickshell

ShellRoot {
    ChatService { id: chatService; focused: window.contentItem.Window.active }
    FloatingWindow {
        id: window
        title: "OmaChat"
        implicitWidth: 1080
        implicitHeight: 760
        minimumSize: Qt.size(440, 480)
        visible: true
        color: "#17191e"
        ChatView { anchors.fill: parent; service: chatService }
    }
    Connections { target: Quickshell; function onLastWindowClosed() { Qt.quit() } }
}
