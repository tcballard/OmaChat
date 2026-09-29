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
        self.window.close()
        self.engine.deleteLater()
        self.app.processEvents()

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
        peer.setProperty("text", "nostr:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6")
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

    def test_secret_key_is_rejected_in_contact_dialog(self):
        QTest.keyClick(self.window, Qt.Key_N, Qt.ControlModifier)
        QTest.qWait(20)
        peer = self.window.findChild(QObject, "peerKey")
        peer.setProperty("text", "nostr:nsec1secret")
        peer.forceActiveFocus()
        QTest.keyClick(self.window, Qt.Key_Return)
        QTest.qWait(20)
        preview = self.window.findChild(QObject, "contactPreview")
        self.assertIn("private key", preview.property("text"))
        self.assertTrue(peer.property("visible"))


if __name__ == "__main__": unittest.main()
