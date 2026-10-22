"""Puts the engine2 root on sys.path so tests import `models`, `stages.detect`, ..."""

import sys
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parent.parent
if str(ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(ENGINE_ROOT))
