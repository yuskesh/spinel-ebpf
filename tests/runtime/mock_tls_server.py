#!/usr/bin/env python3
"""mock_tls_server.py -- a minimal HTTPS server, the peer for the TLS handshake smoke test.
Answers every GET with 200 "ok". --cert is a PEM holding both the cert and the key."""
import http.server
import ssl
import sys


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def main():
    port = int(sys.argv[1])
    cert = sys.argv[2]  # a PEM holding both the cert and the key
    httpd = http.server.HTTPServer(("127.0.0.1", port), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    sys.stderr.write(f"[mock-tls] listening on 127.0.0.1:{port}\n")
    sys.stderr.flush()
    httpd.serve_forever()


if __name__ == "__main__":
    main()
