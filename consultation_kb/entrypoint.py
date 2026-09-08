"""Runtime-gated console entry point."""

from __future__ import annotations

import sys
from typing import Sequence


MINIMUM_RUNTIME = (3, 12)
UNSUPPORTED_PYTHON_MESSAGE = (
    "consultation-kb requires Python 3.12 or later; current interpreter is unsupported."
)


def main(argv: Sequence[str] | None = None) -> int:
    """Reject unsupported runtimes before importing the consultation CLI."""
    if sys.version_info < MINIMUM_RUNTIME:
        print(UNSUPPORTED_PYTHON_MESSAGE, file=sys.stderr)
        return 2

    from .cli import main as cli_main

    return cli_main(argv)
