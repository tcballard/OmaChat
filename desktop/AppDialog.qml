import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: dialog
    required property var theme
    property bool dismissible: true
    parent: Overlay.overlay
    anchors.centerIn: parent
    width: Math.min(520, parent ? parent.width - 32 : 520)
    // Bodies use a ScrollView; actions in the footer remain reachable on short windows.
    height: Math.min(implicitHeight, parent ? parent.height - 32 : implicitHeight)
    modal: true; focus: true; padding: 24
    closePolicy: dismissible ? Popup.CloseOnEscape : Popup.NoAutoClose
    palette.window: theme.panel; palette.windowText: theme.ink
    palette.base: theme.surface; palette.text: theme.ink
    palette.button: theme.control; palette.buttonText: theme.ink
    palette.highlight: theme.accent; palette.highlightedText: theme.primaryInk
    background: Rectangle { color: dialog.theme.panel; radius: 12; border.color: dialog.theme.line }
    Overlay.modal: Rectangle { color: "#66000000" }
    header: Item {
        implicitHeight: 66
        RowLayout {
            anchors.fill: parent; anchors.leftMargin: 24; anchors.rightMargin: 16; spacing: 12
            Label { text: dialog.title; textFormat: Text.PlainText; color: dialog.theme.ink; font.pixelSize: 19; font.weight: Font.DemiBold; elide: Text.ElideRight; Layout.fillWidth: true }
            AppButton { theme: dialog.theme; text: "×"; quiet: true; visible: dialog.dismissible; Accessible.name: "Close dialog"; onClicked: dialog.close() }
        }
    }
}
