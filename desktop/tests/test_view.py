"""Offscreen Qt interaction checks. PySide6 is a test dependency only."""
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from pathlib import Path
import unittest
from PySide6.QtCore import QObject, QUrl, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtQuick import QQuickWindow  # register QQuickWindow wrapper
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtTest import QTest


class ViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QGuiApplication.instance() or QGuiApplication([])

    def setUp(self):
        self.engine = QQmlApplicationEngine()
        self.warnings = []
        self.engine.warnings.connect(lambda errors: self.warnings.extend(str(e) for e in errors))
        self.engine.load(QUrl.fromLocalFile(str(Path(__file__).with_name("Preview.qml"))))
        self.assertTrue(self.engine.rootObjects())
        self.window = self.engine.rootObjects()[0]
        QTest.qWait(80)

    def tearDown(self):
        self.assertEqual(self.warnings, [])
        self.window.property("backend").clearFixture()
        self.window.close()
        self.engine.deleteLater()
        self.app.processEvents()

    def test_hosted_admin_uses_only_owned_workspaces(self):
        backend = self.window.property("backend")
        backend.setProperty("hosted", {"state":"connected", "handle":"alice", "url":"ws://127.0.0.1:7448"})
        backend.setProperty("hostedConnected", True)
        backend.setProperty("workspaces", [
            {"workspace_id":"owned", "name":"My team", "role":"owner"},
            {"workspace_id":"joined", "name":"Other team", "role":"member"}])
        QTest.qWait(20)
        self.window.findChild(QObject, "openHostedAdmin").click()
        QTest.qWait(20)
        selector = self.window.findChild(QObject, "ownedWorkspace")
        self.assertEqual(selector.property("count"), 1)
        self.assertEqual(selector.property("currentText"), "My team")
        self.assertIn("operator can read", self.window.findChild(QObject, "hostedTrust").property("text"))

    def test_compose_send_and_multiline(self):
        composer = self.window.findChild(QObject, "composer")
        composer.forceActiveFocus()
        composer.setProperty("text", "hello")
        self.app.processEvents()
        button = self.window.findChild(QObject, "sendButton")
        self.assertTrue(button.property("enabled"))
        QTest.keyClick(self.window, Qt.Key_Return, Qt.ShiftModifier)
        self.assertIn("\n", composer.property("text"))
        QTest.keyClick(self.window, Qt.Key_Return)
        QTest.qWait(30)
        self.assertEqual(composer.property("text"), "")
        self.assertFalse(button.property("enabled"))
        self.assertEqual(self.window.findChild(QObject, "timeline").property("count"), 4)

    def test_narrow_and_light_render(self):
        self.window.setWidth(440); self.window.setHeight(540)
        backend = self.window.property("backend")
        backend.setProperty("theme", {"background":"#fafafa", "foreground":"#202020", "accent":"#236b50"})
        QTest.qWait(50)
        self.assertFalse(self.window.grabWindow().isNull())

    def test_keyboard_new_conversation_and_offline_draft(self):
        QTest.keyClick(self.window, Qt.Key_N, Qt.ControlModifier)
        QTest.qWait(20)
        peer = self.window.findChild(QObject, "peerKey")
        peer.setProperty("text", "@bob")
        peer.forceActiveFocus()
        QTest.keyClick(self.window, Qt.Key_Return)
        QTest.qWait(20)
        composer = self.window.findChild(QObject, "composer")
        composer.setProperty("text", "save my draft")
        backend = self.window.property("backend")
        backend.offline()
        QTest.qWait(20)
        self.assertEqual(composer.property("text"), "save my draft")
        self.assertFalse(self.window.findChild(QObject,"sendButton").property("enabled"))

    def test_saved_draft_conflict_preserves_local_text_until_choice(self):
        backend = self.window.property("backend")
        backend.conflictFixture()
        QTest.qWait(20)
        composer = self.window.findChild(QObject, "composer")
        self.assertEqual(composer.property("text"), "my unsaved text")
        self.assertIn("Another client", self.window.findChild(QObject, "draftStatus").property("text"))
        backend.resolveDraft(False)
        QTest.qWait(20)
        self.assertEqual(composer.property("text"), "their saved text")

    def test_close_refuses_unsaved_and_pending_work(self):
        composer = self.window.findChild(QObject, "composer")
        composer.setProperty("text", "do not lose me")
        self.window.close()
        QTest.qWait(20)
        self.assertTrue(self.window.isVisible())
        self.assertEqual(composer.property("text"), "do not lose me")
        self.assertTrue(self.window.findChild(QObject, "closeGuardDialog").property("opened"))
        self.window.findChild(QObject, "keepEditing").click()
        self.assertFalse(self.window.findChild(QObject, "closeGuardDialog").property("opened"))
        backend = self.window.property("backend")
        backend.clearFixture()
        backend.pendingFixture()
        self.window.close()
        QTest.qWait(20)
        self.assertTrue(self.window.isVisible())

    def test_close_accepts_saved_draft_and_explicit_discard(self):
        backend = self.window.property("backend")
        backend.savedFixture()
        self.window.close()
        QTest.qWait(20)
        self.assertFalse(self.window.isVisible())
        self.window.show()
        backend.clearFixture()
        self.window.findChild(QObject, "composer").setProperty("text", "discard explicitly")
        self.window.close()
        QTest.qWait(20)
        self.window.findChild(QObject, "closeAnyway").click()
        QTest.qWait(20)
        self.assertFalse(self.window.isVisible())

    def test_save_and_close_waits_for_acknowledged_state(self):
        backend = self.window.property("backend")
        backend.dirtyFixture()
        self.window.close()
        QTest.qWait(20)
        self.window.findChild(QObject, "saveAndClose").click()
        QTest.qWait(20)
        self.assertTrue(self.window.isVisible())
        backend.savedFixture()
        QTest.qWait(150)
        self.assertFalse(self.window.isVisible())

    def test_server_setup_collects_settings(self):
        self.window.findChild(QObject, "openServerSetup").click()
        QTest.qWait(20)
        self.assertTrue(self.window.findChild(QObject, "serverSetupDialog").property("opened"))
        self.assertIsNotNone(self.window.findChild(QObject, "saveServerSettings"))

    def test_close_save_timeout_keeps_text_and_window(self):
        backend = self.window.property("backend")
        backend.dirtyFixture()
        self.window.close()
        QTest.qWait(20)
        self.window.findChild(QObject, "closeDeadline").setProperty("interval", 30)
        self.window.findChild(QObject, "saveAndClose").click()
        QTest.qWait(80)
        self.assertTrue(self.window.isVisible())
        guard = self.window.findChild(QObject, "closeGuard")
        self.assertFalse(guard.property("waiting"))
        self.assertIn("could be saved", guard.property("failure"))
        self.assertEqual(self.window.findChild(QObject, "composer").property("text"), "waiting to save")

    def test_send_state_indicators_follow_in_place_conversation_updates(self):
        backend = self.window.property("backend")
        button = self.window.findChild(QObject, "sendButton")
        self.window.findChild(QObject, "composer").setProperty("text", "pending")
        backend.pendingFixture()
        QTest.qWait(20)
        self.assertEqual(button.property("text"), "Sending…")
        self.assertFalse(button.property("enabled"))
        backend.clearFixture()
        self.window.findChild(QObject, "composer").setProperty("text", "unknown")
        backend.uncertainFixture()
        QTest.qWait(20)
        self.assertTrue(self.window.findChild(QObject, "allowResend").property("visible"))
        self.assertIn("unknown", self.window.findChild(QObject, "sendError").property("text"))
        self.assertFalse(button.property("enabled"))
        backend.reviewedUnknown()
        QTest.qWait(20)
        self.assertFalse(self.window.findChild(QObject, "allowResend").property("visible"))
        self.assertTrue(button.property("enabled"))

    def test_theme_changes_preserve_draft_focus_and_selection(self):
        composer = self.window.findChild(QObject, "composer")
        composer.setProperty("text", "keep this draft")
        composer.forceActiveFocus()
        composer.select(0, 4)
        backend = self.window.property("backend")
        for palette in [
            {"background":"#1a1b26", "foreground":"#c0caf5", "accent":"#7aa2f7"},
            {"background":"#eff1f5", "foreground":"#4c4f69", "accent":"#8839ef"}]:
            backend.setProperty("theme", palette)
            QTest.qWait(20)
            self.assertEqual(composer.property("text"), "keep this draft")
            self.assertEqual(composer.property("selectedText"), "keep")
            self.assertTrue(composer.property("activeFocus"))
            self.assertGreater(composer.property("color").lightnessF(), 0)
        self.assertLess(composer.property("color").lightnessF(), .5)
        for button in self.window.findChildren(QObject):
            if button.property("text") == "New message" and hasattr(button, "click"):
                color = button.property("contentItem").property("color")
                self.assertTrue(color.isValid())
                self.assertGreater(color.lightnessF(), .8)

        self.window.findChild(QObject, "openServerSetup").click()
        QTest.qWait(20)
        dialog = self.window.findChild(QObject, "serverSetupDialog")
        self.assertGreater(dialog.property("background").property("color").lightnessF(), .8)

    def test_short_workspace_dialog_keeps_close_action_reachable(self):
        self.window.setWidth(440); self.window.setHeight(540)
        self.window.findChild(QObject, "openHostedAdmin").click()
        QTest.qWait(20)
        done = self.window.findChild(QObject, "closeWorkspaces")
        point = done.mapToScene(done.boundingRect().center())
        self.assertGreater(point.y(), 0)
        self.assertLess(point.y(), self.window.height() - 16)
        self.assertTrue(done.property("visible"))

    def test_server_offline_disables_send_with_local_daemon_ready(self):
        self.window.findChild(QObject, "composer").setProperty("text", "offline draft")
        self.window.property("backend").setProperty("hostedConnected", False)
        QTest.qWait(20)
        self.assertFalse(self.window.findChild(QObject, "sendButton").property("enabled"))
        self.assertEqual(self.window.findChild(QObject, "connectionStatus").property("text"), "Server offline")

    def test_workspace_dropdown_opens_with_themed_choices(self):
        self.window.property("backend").setProperty("workspaces", [
            {"workspace_id":"one", "name":"First team", "role":"owner"},
            {"workspace_id":"two", "name":"Second team", "role":"owner"}])
        self.window.findChild(QObject, "openHostedAdmin").click()
        QTest.qWait(20)
        selector = self.window.findChild(QObject, "ownedWorkspace")
        selector.forceActiveFocus()
        QTest.keyClick(self.window, Qt.Key_Space)
        QTest.qWait(20)
        self.assertTrue(selector.findChild(QObject, "themedChoices").property("visible"))
        QTest.keyClick(self.window, Qt.Key_Down)
        QTest.keyClick(self.window, Qt.Key_Return)
        QTest.qWait(20)
        self.assertEqual(selector.property("currentText"), "Second team")

    def test_search_can_be_cleared_without_losing_active_draft(self):
        composer = self.window.findChild(QObject, "composer")
        composer.setProperty("text", "keep while searching")
        search = self.window.findChild(QObject, "conversationSearch")
        search.setProperty("text", "nothing matches")
        QTest.qWait(20)
        self.assertEqual(self.window.findChild(QObject, "conversationList").property("count"), 0)
        self.window.findChild(QObject, "clearConversationSearch").click()
        QTest.qWait(20)
        self.assertEqual(search.property("text"), "")
        self.assertTrue(search.property("activeFocus"))
        self.assertEqual(composer.property("text"), "keep while searching")
        self.assertEqual(self.window.findChild(QObject, "conversationList").property("count"), 2)

    def test_latest_message_stays_visible_when_window_shrinks(self):
        timeline = self.window.findChild(QObject, "timeline")
        for width, height in [(1440,900), (860,640), (440,480)]:
            self.window.setWidth(width); self.window.setHeight(height)
            QTest.qWait(60)
            self.assertTrue(timeline.property("atYEnd"))
            button = self.window.findChild(QObject, "sendButton")
            point = button.mapToScene(button.boundingRect().center())
            self.assertLess(point.y(), height)
            self.assertGreaterEqual(button.property("height"), 44)
            self.assertLessEqual(timeline.property("width"), 820)

    def test_reading_older_messages_does_not_jump_on_draft_edit(self):
        self.window.setWidth(440); self.window.setHeight(480)
        QTest.qWait(40)
        timeline = self.window.findChild(QObject, "timeline")
        timeline.setProperty("followLatest", False)
        timeline.setProperty("contentY", 0)
        before = timeline.property("contentY")
        self.window.findChild(QObject, "composer").setProperty("text", "draft while reading")
        QTest.qWait(40)
        self.assertFalse(timeline.property("followLatest"))
        self.assertAlmostEqual(timeline.property("contentY"), before)

    def test_conflict_choices_remain_reachable_and_enter_cannot_send(self):
        self.window.setWidth(440); self.window.setHeight(480)
        self.window.property("backend").conflictFixture()
        QTest.qWait(40)
        self.assertEqual(self.window.findChild(QObject, "composerState").property("text"), "Review draft")
        self.assertFalse(self.window.findChild(QObject, "sendButton").property("enabled"))
        composer = self.window.findChild(QObject, "composer")
        composer.forceActiveFocus()
        QTest.keyClick(self.window, Qt.Key_Return)
        self.assertEqual(composer.property("text"), "my unsaved text")
        for name in ["keepLocalDraft", "useSavedDraft"]:
            button = self.window.findChild(QObject, name)
            point = button.mapToScene(button.boundingRect().center())
            self.assertTrue(button.property("visible"))
            self.assertGreater(point.y(), 84)
            self.assertLess(point.y(), 480)
        self.window.findChild(QObject, "keepLocalDraft").click()
        QTest.qWait(20)
        self.assertEqual(composer.property("text"), "my unsaved text")
        self.assertFalse(self.window.findChild(QObject, "keepLocalDraft").property("visible"))

    def test_invalid_handle_is_rejected(self):
        QTest.keyClick(self.window, Qt.Key_N, Qt.ControlModifier)
        QTest.qWait(20)
        peer = self.window.findChild(QObject, "peerKey")
        peer.setProperty("text", "invalid handle")
        peer.forceActiveFocus()
        QTest.keyClick(self.window, Qt.Key_Return)
        QTest.qWait(20)
        self.assertIn("Invalid handle", self.window.property("backend").property("actionError"))
        self.assertTrue(peer.property("visible"))


if __name__ == "__main__": unittest.main()
