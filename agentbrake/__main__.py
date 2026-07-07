"""Allow ``python -m agentbrake`` as an alias for the ``agentbrake`` CLI."""

import sys

from agentbrake.cli import main

if __name__ == "__main__":
    sys.exit(main())
