from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import NamedTuple
from .utils import inherit_default
from pathlib import Path
from ssl import SSLContext, PROTOCOL_TLS_SERVER


def make_server(
    ssl_context: SSLContext, port: int = 0, response_text: bytes = b"Secure hello!"
):
    class _ResponseHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(response_text)

    server = HTTPServer(("127.0.0.1", port), _ResponseHandler)
    server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    return server


def make_context(bundle: Path, keyfile: Path) -> SSLContext:
    ctx = SSLContext(PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(bundle, keyfile)
    return ctx


class Server(NamedTuple):
    server: HTTPServer
    thread: Thread

    @property
    def port(self):
        return self.server.server_port

    def url(self, host="127.0.0.1") -> str:
        return f"https://{host}:{self.port}/"

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def serve(
    privkey: Path,
    cert: Path,
    response_text: bytes = inherit_default(make_server, "response_text", bytes),
) -> Server:
    """
    Create and start an HTTP server, printing its information,
    and optionally opening a web browser to its page.

    Returns the server and the already-running thread.
    """
    ctx = make_context(Path(cert), Path(privkey))
    server = make_server(ctx, response_text=response_text)
    port = server.server_port

    thread = Thread(target=server.serve_forever)

    return Server(server, thread)
