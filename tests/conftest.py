"""Make `import app` work no matter how pytest is invoked.

Running `python -m pytest` puts the current directory on sys.path, but running
the `pytest` console script does not — which is exactly what a CI step like
`run: pytest -q` does. Without this file that step dies with
`ModuleNotFoundError: No module named 'app'`.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
