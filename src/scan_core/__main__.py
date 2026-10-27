"""Allow `python -m scan_core` during development and troubleshooting."""

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
