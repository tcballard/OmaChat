"""Capture deterministic native QML screens: QT_QPA_PLATFORM=offscreen python desktop/tests/capture_ux.py OUTPUT_DIR."""
import sys
from pathlib import Path
from PySide6.QtCore import QObject, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQuick import QQuickWindow
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtTest import QTest
app=QGuiApplication([])
folder=Path(sys.argv[1]); folder.mkdir(parents=True,exist_ok=True)
palettes={'dark':{'background':'#1a1b26','foreground':'#c0caf5','accent':'#7aa2f7'},'light':{'background':'#eff1f5','foreground':'#4c4f69','accent':'#8839ef'},'warm':{'background':'#282828','foreground':'#ebdbb2','accent':'#b8bb26'}}
cases=[('01-dark-chat','dark','chat',1080,760),('02-dark-setup','dark','Set up messaging',1080,760),('03-dark-identity','dark','My identity & connection',1080,760),('04-dark-workspaces','dark','Workspaces',1080,760),('05-dark-dm','dark','New message',1080,760),('06-dark-close','dark','close',1080,760),('07-light-chat','light','chat',1080,760),('08-light-setup','light','Set up messaging',1080,760),('09-narrow-workspaces','warm','Workspaces',440,540),('10-narrow-chat','warm','chat',440,540)]
for name,palette,action,width,height in cases:
 engine=QQmlApplicationEngine();engine.load(QUrl.fromLocalFile(str(Path(__file__).with_name('Preview.qml'))))
 if not engine.rootObjects():raise RuntimeError('QML failed')
 window=engine.rootObjects()[0]; window.setWidth(width);window.setHeight(height);backend=window.property('backend');backend.setProperty('theme',palettes[palette]);backend.setProperty('workspaces',[{'workspace_id':'team','name':'OmaChat','role':'owner'}]);QTest.qWait(80)
 if action=='close':backend.dirtyFixture();window.close()
 elif action!='chat':
  candidates=[o for o in window.findChildren(QObject) if o.property('text')==action and hasattr(o,'click')]
  if not candidates:raise RuntimeError(action)
  candidates[0].click()
 QTest.qWait(60); assert window.grabWindow().save(str(folder/(name+'.png')))
 backend.clearFixture();window.close();engine.deleteLater();app.processEvents()
print('Captured',len(cases),'screens')
