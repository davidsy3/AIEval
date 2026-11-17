"""Puts the engine2 root on sys.path so tests import `models`, `stages.detect`, ...

Also opts the test suite into unisolated stage-4 runs, so `pytest` stays green
on a machine without Docker. With Docker and the `aieval-sandbox` image, stage 4
still uses the sandbox: the opt-in only matters when the sandbox is unavailable.
The code these tests run is the hand-made cases in fakes.py, which we wrote.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("AIEVAL_ALLOW_UNISOLATED", "1")   # before config is imported

ENGINE_ROOT = Path(__file__).resolve().parent.parent
if str(ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(ENGINE_ROOT))
