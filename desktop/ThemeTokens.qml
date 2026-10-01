import QtQuick
import "Theme.js" as Theme

QtObject {
    // Geometry and type roles extend the user's native desktop palette/font.
    readonly property int spaceSmall: 8
    readonly property int spaceMedium: 16
    readonly property int spaceLarge: 24
    readonly property int controlHeight: 44
    readonly property int radiusControl: 6
    readonly property int radiusPanel: 10
    readonly property int textCaption: 12
    readonly property int textLabel: 13
    readonly property int textBody: 15
    readonly property int textHeading: 22
    readonly property int readingWidth: 820
    readonly property int sidebarWidth: 280
    readonly property int sidebarCompactWidth: 236
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
