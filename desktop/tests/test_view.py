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
