import QtQuick
import QtQuick.Controls

ComboBox {
    id: combo
    required property var theme
    implicitHeight: combo.theme.controlHeight
    leftPadding: 12; rightPadding: 36
    palette.window: theme.panel; palette.base: theme.panel
    palette.text: theme.ink; palette.buttonText: theme.ink
    palette.highlight: theme.selected; palette.highlightedText: theme.ink
    contentItem: Text { text: combo.displayText; color: combo.enabled ? combo.theme.ink : combo.theme.muted; font.pixelSize: 14; verticalAlignment: Text.AlignVCenter; elide: Text.ElideRight }
    indicator: Text { x: combo.width - 26; anchors.verticalCenter: parent.verticalCenter; text: "⌄"; color: combo.theme.ink; font.pixelSize: 18 }
    background: Rectangle { color: combo.theme.surface; radius: combo.theme.radiusControl; border.color: combo.activeFocus ? combo.theme.accent : combo.theme.line; border.width: combo.activeFocus ? 2 : 1 }
    delegate: ItemDelegate {
        id: row
        required property int index
        required property var model
        width: combo.width - 2
        implicitHeight: combo.theme.controlHeight
        highlighted: combo.highlightedIndex === index
        contentItem: Text { text: combo.textRole ? row.model[combo.textRole] : row.model.modelData; textFormat: Text.PlainText; color: combo.theme.ink; font.pixelSize: 14; verticalAlignment: Text.AlignVCenter; elide: Text.ElideRight }
        background: Rectangle { color: row.highlighted ? combo.theme.selected : combo.theme.panel }
    }
    popup: Popup {
        objectName: "themedChoices"
        y: combo.height + 6; width: combo.width; padding: 1
        implicitHeight: Math.min(contentItem.implicitHeight + 2, 220)
        background: Rectangle { color: combo.theme.panel; radius: combo.theme.radiusControl; border.color: combo.theme.line }
        contentItem: ListView { clip: true; implicitHeight: contentHeight; model: combo.popup.visible ? combo.delegateModel : null; currentIndex: combo.highlightedIndex; ScrollIndicator.vertical: ScrollIndicator {} }
    }
}
