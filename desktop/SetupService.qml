import QtQuick
import Quickshell
import Quickshell.Io

Item {
    id: setup
    property bool busy: false
    property string error: ""
    property string path: ""
    property string configRevision: ""
    property var dmRelays: []
    property var roomRelays: []
    property string backup: ""
    property bool restartRequired: false
    property var response: null
    signal loaded()

    function run(request, selectedPath) {
        if (busy) return
        busy = true; error = ""; response = null
        var command = ["/usr/bin/python3", Quickshell.shellPath("setup.py"), "--request", JSON.stringify(request)]
        var config = selectedPath || Quickshell.env("OMACHAT_CONFIG")
        if (config) command.push("--config", config)
        worker.command = command
        worker.running = true
        deadline.restart()
    }
    function read(selectedPath) { run({ method: "read" }, selectedPath) }
    function save(dm, rooms) {
        if (!configRevision) { error = "Load the configuration before saving."; return }
        run({ method: "apply", revision: configRevision, dm_relays: dm, room_relays: rooms }, path)
    }
    Process {
        id: worker
        stdout: SplitParser {
            onRead: function(line) {
                try { setup.response = JSON.parse(line) }
                catch (_) { setup.response = { ok: false, error: "Invalid setup response. Reload to check whether changes were saved." } }
            }
        }
        onRunningChanged: {
            if (!running && setup.busy) Qt.callLater(function() {
                deadline.stop(); setup.busy = false
                var result = setup.response
                if (!result || !result.ok) { setup.error = result ? result.error : "Setup stopped without confirmation. Reload to check the file."; return }
                setup.path = result.data.path
                setup.configRevision = result.data.revision
                setup.dmRelays = result.data.dm_relays
                setup.roomRelays = result.data.room_relays
                setup.backup = result.data.backup || ""
                if (result.data.restart_required) setup.restartRequired = true
                setup.loaded()
            })
        }
    }
    Timer {
        id: deadline; interval: 5000
        onTriggered: {
            setup.response = { ok: false, error: "Setup timed out. Reload before retrying; the file may already have changed." }
            if (worker.running) worker.running = false
            else { setup.error = setup.response.error; setup.busy = false }
        }
    }
}
