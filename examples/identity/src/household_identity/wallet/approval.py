# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Terminal-stdin approval prompt for wallet sign operations.

The wallet always asks the human before signing. For the MVP the prompt is a
synchronous stdin read; a web UI is a discrete next step.
"""

from __future__ import annotations


def prompt_terminal(message: str) -> bool:
    """Display ``message``, then block on stdin for a y/N answer.

    Affirmative answers ("y", "yes", case-insensitive) return True. Anything
    else, including an empty line or EOF, returns False.
    """
    print(message)
    try:
        line = input("Approve? [y/N]: ")
    except EOFError:
        return False
    return line.strip().lower() in ("y", "yes")
