"""Test configuration for the kali-linux-automation script suite.

The scripts live in a flat ``python_scripts/`` directory rather than an
installable package, so the directory is added to ``sys.path`` to make them
importable from the tests.
"""

import sys
from pathlib import Path

PYTHON_SCRIPTS = Path(__file__).resolve().parent.parent / "python_scripts"
if str(PYTHON_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PYTHON_SCRIPTS))
