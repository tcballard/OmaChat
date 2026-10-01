import QtQuick
import QtQuick.Controls

TextField {
    id: field
    required property var theme
    implicitHeight: theme.controlHeight
    leftPadding: 12; rightPadding: 12
    color: theme.ink; placeholderTextColor: theme.muted
    selectionColor: theme.accent; selectedTextColor: theme.primaryInk
    selectByMouse: true; font.pixelSize: 14
    background: Rectangle {
        radius: field.theme.radiusControl; color: field.theme.surface
        border.color: field.activeFocus ? field.theme.accent : field.theme.line
        border.width: field.activeFocus ? 2 : 1
        opacity: field.enabled ? 1 : 0.6
    }
}
