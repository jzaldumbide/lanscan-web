"""Native desktop launcher for LanScan Web (macOS & Windows).

Starts the FastAPI backend locally on 127.0.0.1 and opens a native OS WebView window
(WebKit on macOS, WebView2 on Windows), falling back to the system browser if needed.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
import urllib.request
import webbrowser

import uvicorn

from app.main import app


def _find_free_port(preferred: int = 8787) -> int:
    for port in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return s.getsockname()[1]
            except OSError:
                continue
    return 8787


def _wait_for_server(url: str, timeout: float = 12.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=0.6) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.15)
    return False


def main() -> None:
    port = int(os.environ.get("LANSCAN_PORT", "0")) or _find_free_port(8787)
    url = f"http://127.0.0.1:{port}"

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
        log_config=None,
    )
    server = uvicorn.Server(config)

    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    _wait_for_server(f"{url}/api/bootstrap")

    try:
        import webview  # type: ignore

        webview.create_window(
            title="LanScan Web — Multi-Subnet Network Scanner",
            url=url,
            width=1360,
            height=860,
            min_size=(960, 620),
            text_select=True,
        )
        webview.start()
    except Exception:
        # Fallback: open in default web browser and keep server alive until Ctrl+C
        webbrowser.open(url)
        try:
            while server_thread.is_alive():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
    finally:
        server.should_exit = True
        server_thread.join(timeout=2.0)
        sys.exit(0)


if __name__ == "__main__":
    main()
