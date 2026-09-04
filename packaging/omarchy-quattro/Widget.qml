import QtQuick
import Quickshell.Io

Item {
    id: root
    implicitWidth: label.implicitWidth + 12
    implicitHeight: label.implicitHeight + 6
    property string statusText: "OC —"

    Text {
        id: label
        anchors.centerIn: parent
        text: root.statusText
        textFormat: Text.PlainText
        color: "#d8dee9"
    }

    Process {
        id: statusPoll
        command: ["/usr/bin/timeout", "1s", "/usr/bin/omachat-ctl", "status", "--json"]
        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const state = JSON.parse(this.text)
                    const joined = Number(state.joined_geohashes?.length || 0)
                    const pending = Number(state.outbox_pending || 0)
                    root.statusText = "OC " + joined + (pending > 0 ? " ·" + pending : "")
                } catch (_) {
                    root.statusText = "OC —"
                }
            }
        }
        onExited: function(exitCode) {
            if (exitCode !== 0)
                root.statusText = "OC —"
        }
    }

    Timer {
        interval: 5000
        running: true
        repeat: true
        triggeredOnStart: true
        onTriggered: if (!statusPoll.running) statusPoll.running = true
    }
}
