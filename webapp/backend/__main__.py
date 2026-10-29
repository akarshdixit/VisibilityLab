"""Start the VisibilityLab API on loopback:  python -m webapp.backend

Binding to a non-loopback address is refused unless VL_ALLOW_REMOTE=true.
"""

from __future__ import annotations

import ipaddress
import sys

import uvicorn

from .api import create_app
from .config import Settings


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> int:
    settings = Settings.from_env()
    if not _is_loopback(settings.host) and not settings.allow_remote:
        print(f"REFUSED: VL_HOST={settings.host} is not a loopback address. VisibilityLab is a local research "
              "tool; set VL_ALLOW_REMOTE=true only behind your own access control.", file=sys.stderr)
        return 2
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
