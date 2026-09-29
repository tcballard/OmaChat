import QtQuick
import QtQuick.Window
import QtQuick.Controls
import QtQuick.Layouts
import "ExitState.js" as ExitState

Item {
    id: guard
    objectName: "closeGuard"
    required property var service
    property bool allowClose: false
    property bool waiting: false
    property string failure: ""
    readonly property var hostWindow: guard.Window.window
    readonly property bool supportsSave: { service.revision; return service.ready && service.state.status.drafts_version === 1 && !service.state.settingsDirty && !service.state.configBusy }
    readonly property var work: { service.revision; return ExitState.inspect(service.state) }

    function finish() {
        waiting = false
        deadline.stop()
        allowClose = true
        prompt.close()
        hostWindow.close()
    }
    function saveAndClose() {
        failure = ""
        waiting = true
        deadline.restart()
        service.pumpDrafts()
        check()
    }
    function check() { if (waiting && ExitState.inspect(service.state).safe) finish() }
    onWorkChanged: check()

    Connections {
        target: guard.hostWindow
        function onClosing(event) {
            if (guard.allowClose || ExitState.inspect(guard.service.state).safe) return
            event.accepted = false
            if (!prompt.opened) { guard.failure = ""; prompt.open() }
        }
    }
    Timer {
        interval: 100; repeat: true; running: guard.waiting
        onTriggered: { guard.service.pumpDrafts(); guard.check() }
    }
    Timer {
        id: deadline
        objectName: "closeDeadline"
        interval: 10000
        onTriggered: {
            guard.waiting = false
            guard.failure = "Not all changes could be saved or acknowledged within ten seconds. Keep editing to resolve offline, storage, conflict, or pending send states. Your text is still here."
        }
    }
    Dialog {
        id: prompt
        objectName: "closeGuardDialog"
        parent: Overlay.overlay
        anchors.centerIn: parent
        width: Math.min(480, parent.width - 32)
        modal: true; focus: true
        title: "Finish before closing?"
        closePolicy: Popup.NoAutoClose
        contentItem: ColumnLayout {
            spacing: 14
            Label {
                Layout.fillWidth: true; wrapMode: Text.WordWrap
                text: { guard.service.revision; return ExitState.describe(guard.service.state) }
            }
            Label { Layout.fillWidth: true; wrapMode: Text.WordWrap; visible: !!guard.failure; text: guard.failure }
            Button {
                objectName: "saveAndClose"
                text: guard.waiting ? "Waiting for saved changes…" : "Save and close"
                enabled: !guard.waiting && guard.supportsSave && !guard.work.conflicts && !guard.work.unknown
                onClicked: guard.saveAndClose()
            }
            Button {
                objectName: "keepEditing"
                text: "Keep editing"; focus: true
                onClicked: { guard.waiting = false; deadline.stop(); prompt.close() }
            }
            Button { objectName: "closeAnyway"; text: "Close anyway"; onClicked: guard.finish() }
        }
    }
}
