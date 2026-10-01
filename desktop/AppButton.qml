import QtQuick
import QtQuick.Controls

Button {
    id: button
    required property var theme
    property bool primary: false
    property bool quiet: false
    property bool destructive: false
    implicitHeight: 40
    implicitWidth: Math.max(40, contentItem.implicitWidth + leftPadding + rightPadding)
    leftPadding: 14; rightPadding: 14
    focusPolicy: Qt.StrongFocus
    Accessible.name: text
    contentItem: Text {
        text: button.text; textFormat: Text.PlainText
        font.pixelSize: 13; font.weight: button.primary ? Font.DemiBold : Font.Normal
        color: !button.enabled ? button.theme.muted : button.primary ? button.theme.primaryInk : button.destructive ? button.theme.danger : button.theme.ink
        horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }
    background: Rectangle {
        radius: 8
        color: button.primary && button.enabled ? button.theme.accent : button.down ? button.theme.selected : button.hovered ? button.theme.hover : button.quiet ? "transparent" : button.theme.control
        border.color: button.activeFocus ? (button.primary && button.enabled ? button.theme.primaryInk : button.theme.accent) : button.primary || button.quiet ? "transparent" : button.theme.line
        border.width: button.activeFocus ? 2 : 1
        opacity: button.enabled ? 1 : 0.65
    }
}
