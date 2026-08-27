"""Bounded loopback-only HTTP publication of current read-only status."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
from typing import Any

from .status import (
    KernelStatusSnapshot,
    StatusRejection,
    StatusSnapshotProvider,
)
from .evidence_health import KernelStatusV2


STATUS_PATH = "/status"
ALLOW = "GET, HEAD"


class StatusHTTPServer(HTTPServer):
    """HTTP server that rebuilds one immutable snapshot per request."""

    allow_reuse_address = False

    def __init__(
        self,
        server_address: tuple[str, int],
        snapshot_provider: StatusSnapshotProvider,
    ) -> None:
        self.snapshot_provider = snapshot_provider
        super().__init__(server_address, _StatusRequestHandler)


class _StatusRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: StatusHTTPServer

    def do_GET(self) -> None:
        self._serve_snapshot(head_only=False)

    def do_HEAD(self) -> None:
        self._serve_snapshot(head_only=True)

    def do_POST(self) -> None:
        self._method_not_allowed()

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def _serve_snapshot(self, *, head_only: bool) -> None:
        if self.path != STATUS_PATH:
            self._empty_response(404)
            return
        try:
            snapshot = self.server.snapshot_provider.publication_snapshot()
        except Exception:
            self._provider_unavailable()
            return
        if not isinstance(snapshot, (KernelStatusSnapshot, KernelStatusV2)):
            self._provider_unavailable()
            return
        if (
            snapshot.readiness == "ready"
            and self.headers.get("If-None-Match") == snapshot.etag
        ):
            self.send_response(304)
            self._send_common_headers(snapshot)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        status = 200 if snapshot.readiness == "ready" else 503
        self.send_response(status)
        self._send_common_headers(snapshot)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(snapshot.canonical_bytes)))
        self.end_headers()
        if not head_only:
            self.wfile.write(snapshot.canonical_bytes)

    def _provider_unavailable(self) -> None:
        self.send_response(503)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Skeleton-Readiness", "unavailable")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_common_headers(
        self, snapshot: KernelStatusSnapshot | KernelStatusV2
    ) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("ETag", snapshot.etag)
        self.send_header("X-Skeleton-Readiness", snapshot.readiness)

    def _method_not_allowed(self) -> None:
        self.send_response(405)
        self.send_header("Allow", ALLOW)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _empty_response(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        del format, args


def create_status_server(
    *,
    snapshot_provider: StatusSnapshotProvider,
    host: str = "127.0.0.1",
    port: int = 0,
) -> StatusHTTPServer:
    """Create an unstarted server after strict literal-loopback validation."""

    if not isinstance(snapshot_provider, StatusSnapshotProvider):
        raise TypeError("read-only StatusSnapshotProvider required")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise StatusRejection("status_bind_not_loopback") from error
    if not address.is_loopback:
        raise StatusRejection("status_bind_not_loopback")
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise StatusRejection("status_port_invalid")
    if address.version != 4:
        raise StatusRejection("status_bind_family_unsupported")
    try:
        return StatusHTTPServer((str(address), port), snapshot_provider)
    except OSError as error:
        raise StatusRejection("status_bind_failed") from error
