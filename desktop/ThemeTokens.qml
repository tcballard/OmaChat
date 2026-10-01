import QtQuick
import "Theme.js" as Theme

QtObject {
    property var source: ({})
    property SystemPalette system: SystemPalette { colorGroup: SystemPalette.Active }
    readonly property var colors: Theme.tokens(source, {background:system.window, foreground:system.windowText, accent:system.highlight})
    readonly property color surface: colors.surface
    readonly property color panel: colors.panel
    readonly property color ink: colors.ink
    readonly property color muted: colors.muted
    readonly property color accent: colors.accent
    readonly property color primaryInk: colors.primaryInk
    readonly property color line: colors.line
    readonly property color control: colors.control
    readonly property color hover: colors.hover
    readonly property color selected: colors.selected
    readonly property color warning: colors.warning
    readonly property color danger: colors.danger
}
