#!/usr/bin/env python3
"""mock_otlp_receiver.py -- a minimal OTLP/HTTP receiver.

Lets the export path be verified on the host without standing up a real
OpenTelemetry Collector. Takes the protobuf body of a `POST /v1/metrics`, decodes
it into human-readable form with `protoc --decode`, writes that to --out, and
answers 200 with an empty ExportMetricsServiceResponse.

To run against a real Collector instead, see examples/observability/otlp/; this
mock is not needed there.
"""
import argparse
import http.server
import subprocess
import sys

DECODE_MSG = {
    "/v1/metrics": "opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest",
    "/v1/traces":  "opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest",
    "/v1/logs":    "opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest",
}
SERVICE_PROTO = {
    "/v1/metrics": "opentelemetry/proto/collector/metrics/v1/metrics_service.proto",
    "/v1/traces":  "opentelemetry/proto/collector/trace/v1/trace_service.proto",
    "/v1/logs":    "opentelemetry/proto/collector/logs/v1/logs_service.proto",
}

ARGS = None


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):  # quieter
        sys.stderr.write("[mock-otlp] " + (fmt % a) + "\n")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        ctype = self.headers.get("Content-Type", "")
        path = self.path
        # Log the received headers, so auth headers can be checked.
        for k, v in self.headers.items():
            sys.stderr.write(f"[mock-otlp] header {k}: {v}\n")
        # Decompress if the client sent Content-Encoding: gzip.
        if self.headers.get("Content-Encoding", "").strip() == "gzip":
            import gzip as _gz
            body = _gz.decompress(body)
            sys.stderr.write(f"[mock-otlp] gunzip -> {len(body)}B\n")
        sys.stderr.write(f"[mock-otlp] POST {path} ctype={ctype} {len(body)}B\n")

        decoded = ""
        msg = DECODE_MSG.get(path)
        if "application/json" in ctype:
            # OTLP/HTTP+JSON: store it as-is. json.loads is the validity check;
            # malformed input becomes DECODE_ERROR.
            import json as _json
            try:
                _json.loads(body.decode())
                decoded = body.decode()
            except Exception as e:  # noqa: BLE001
                decoded = "DECODE_ERROR\n" + str(e)
        elif msg and "application/x-protobuf" in ctype:
            try:
                r = subprocess.run(
                    [ARGS.protoc, f"--decode={msg}", "-I",
                     "third_party/opentelemetry-proto", SERVICE_PROTO[path]],
                    input=body, capture_output=True, cwd=ARGS.repo_root, check=True)
                decoded = r.stdout.decode()
            except subprocess.CalledProcessError as e:
                decoded = "DECODE_ERROR\n" + e.stderr.decode()

        if ARGS.out:
            with open(ARGS.out, "w") as f:
                f.write(decoded)
        sys.stderr.write("----- mock-otlp decoded -----\n" + decoded +
                         "-----------------------------\n")

        # 200 with an empty ExportXServiceResponse (an empty protobuf, 0 bytes, is valid)
        self.send_response(200)
        self.send_header("Content-Type", "application/x-protobuf")
        self.send_header("Content-Length", "0")
        self.end_headers()


def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4318)
    ap.add_argument("--out", default="")
    ap.add_argument("--protoc", default="protoc")
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--cert", default="")  # a PEM holding cert+key makes it listen with TLS (https)
    ap.add_argument("--client-ca", default="")  # a CA here requires and verifies a client cert (mTLS)
    ARGS = ap.parse_args()

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", ARGS.port), Handler)
    scheme = "http"
    if ARGS.cert:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(ARGS.cert)
        if ARGS.client_ca:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(ARGS.client_ca)
            scheme = "https+mtls"
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        if scheme == "http":
            scheme = "https"
    sys.stderr.write(f"[mock-otlp] listening on {scheme}://127.0.0.1:{ARGS.port}\n")
    sys.stderr.flush()
    httpd.serve_forever()


if __name__ == "__main__":
    main()
