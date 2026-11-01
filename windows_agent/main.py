"""Entry point for ssai-agent.exe (and for running from source: python main.py status)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ssai_agent.cli import main      # noqa: E402  (the path above must be set first)

if __name__ == "__main__":
    sys.exit(main())
