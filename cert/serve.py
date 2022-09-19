from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from ssl import SSLContext, PROTOCOL_TLS_SERVER


class _ResponseHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Secure hello!")


def make_server(ssl_context: SSLContext, port: int = 0):
    server = HTTPServer(("127.0.0.1", port), _ResponseHandler)
    server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    return server


def make_context(bundle: Path, keyfile: Path) -> SSLContext:
    ctx = SSLContext(PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(bundle, keyfile)
    return ctx
