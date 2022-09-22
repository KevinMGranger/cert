from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
import webbrowser
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


def serve(
    privkey: Path,
    cert: Path,
    browser: bool = False,
    response_text: bytes = inherit_default(make_server, "response_text", bytes),
) -> tuple[HTTPServer, Thread]:
    """
    Create and start an HTTP server, printing its information,
    and optionally opening a web browser to its page.

    Returns the server and the already-running thread.
    """
    ctx = make_context(Path(cert), Path(privkey))
    server = make_server(ctx, response_text=response_text)
    port = server.server_port

    thread = Thread(target=server.serve_forever)
    thread.start()

    ip_url = f"https://127.0.0.1:{port}/"

    print(f"Serving on:")
    print(ip_url)
    print(f"https://localhost:{port}/")

    if browser:
        webbrowser.open(ip_url)

    return server, thread
