import os
import sys

# Runtime hook to ensure Qt platform plugins are discoverable when bundled by PyInstaller.
def _set_qt_plugin_path():
    try:
        if getattr(sys, "frozen", False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))

        # Common location used by collect_data_files('PyQt5', subdir='Qt/plugins')
        candidate = os.path.join(base_path, "PyQt5", "Qt", "plugins")
        if os.path.isdir(candidate):
            os.environ.setdefault("QT_QPA_PLATFORM_PLUGIN_PATH", candidate)
    except Exception:
        pass

_set_qt_plugin_path()

import os
import sys

# Runtime hook to set QT_PLUGIN_PATH when running from a PyInstaller bundle.
if getattr(sys, "frozen", False):
    base_path = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    plugins_path = os.path.join(base_path, "PyQt5", "Qt", "plugins")
    # Prepend to existing QT_PLUGIN_PATH to prefer bundled plugins
    existing = os.environ.get("QT_PLUGIN_PATH", "")
    if existing:
        os.environ["QT_PLUGIN_PATH"] = plugins_path + os.pathsep + existing
    else:
        os.environ["QT_PLUGIN_PATH"] = plugins_path


