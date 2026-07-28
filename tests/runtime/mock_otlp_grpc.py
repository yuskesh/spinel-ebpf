#!/usr/bin/env python3
"""mock_otlp_grpc.py -- a minimal OTLP/gRPC receiver for exercising the gRPC transport.

Accepts OTLP {Metrics,Trace,Logs}Service/Export through a grpcio generic handler,
decodes the request protobuf with `protoc --decode` and writes the result to --out.
grpcio does the HTTP/2 and gRPC framing, so a request from the hand-written HTTP/2
client can only reach this handler if its framing is correct -- receiving anything
at all is itself the proof.

Requires grpcio (venv: .venv-otlp/bin/python).
"""
import argparse
import subprocess
import sys
from concurrent import futures

import grpc

DECODE = {
    "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export":
        ("opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest",
         "opentelemetry/proto/collector/metrics/v1/metrics_service.proto"),
    "/opentelemetry.proto.collector.trace.v1.TraceService/Export":
        ("opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest",
         "opentelemetry/proto/collector/trace/v1/trace_service.proto"),
    "/opentelemetry.proto.collector.logs.v1.LogsService/Export":
        ("opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest",
         "opentelemetry/proto/collector/logs/v1/logs_service.proto"),
}

ARGS = None


class Handler(grpc.GenericRpcHandler):
    def service(self, hcd):
        info = DECODE.get(hcd.method)

        def unary(request_bytes, context):
            # Received metadata, so auth headers can be checked. grpcio has
            # already decompressed a gzipped body.
            for k, v in (context.invocation_metadata() or []):
                sys.stderr.write(f"[mock-grpc] meta {k}: {v}\n")
            decoded = ""
            if info:
                msg, proto = info
                try:
                    r = subprocess.run(
                        [ARGS.protoc, f"--decode={msg}", "-I",
                         "third_party/opentelemetry-proto", proto],
                        input=request_bytes, capture_output=True,
                        cwd=ARGS.repo_root, check=True)
                    decoded = r.stdout.decode()
                except subprocess.CalledProcessError as e:
                    decoded = "DECODE_ERROR\n" + e.stderr.decode()
            sys.stderr.write(f"[mock-grpc] {hcd.method} {len(request_bytes)}B\n"
                             f"----- decoded -----\n{decoded}-------------------\n")
            sys.stderr.flush()
            if ARGS.out:
                with open(ARGS.out, "w") as f:
                    f.write(decoded)
            return b""  # an empty ExportXServiceResponse

        # No deserializer or serializer on either side: raw bytes in, raw bytes out.
        return grpc.unary_unary_rpc_method_handler(unary)


def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4317)
    ap.add_argument("--out", default="")
    ap.add_argument("--protoc", default="protoc")
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--cert", default="")  # cert PEM (for grpcs:// TLS)
    ap.add_argument("--key", default="")   # key PEM
    ARGS = ap.parse_args()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    server.add_generic_rpc_handlers((Handler(),))
    addr = f"127.0.0.1:{ARGS.port}"
    scheme = "grpc"
    if ARGS.cert and ARGS.key:
        with open(ARGS.cert, "rb") as f:
            cert = f.read()
        with open(ARGS.key, "rb") as f:
            key = f.read()
        creds = grpc.ssl_server_credentials([(key, cert)])
        server.add_secure_port(addr, creds)
        scheme = "grpcs"
    else:
        server.add_insecure_port(addr)
    server.start()
    sys.stderr.write(f"[mock-grpc] listening on {scheme}://{addr}\n")
    sys.stderr.flush()
    server.wait_for_termination()


if __name__ == "__main__":
    main()
