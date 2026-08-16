"""Allow ``python -m baittrace`` as well as the ``baittrace`` console script.

Useful when the package is on ``PYTHONPATH`` but not installed, which is how
the test suite and a fresh checkout both run it.
"""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
