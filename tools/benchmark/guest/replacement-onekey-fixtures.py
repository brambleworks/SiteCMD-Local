import base64
import http.client
import json
import os
import pathlib
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def openssl(*args):
    subprocess.run(["/usr/bin/openssl", *args], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, timeout=15)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self):
        data = None
        if self.command == "POST":
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 <= size <= 8192:
                return self.send_error(400)
            data = json.loads(self.rfile.read(size))
        self.server.requests.append({"method": self.command, "path": self.path,
                                     "echo": self.headers.get("X-Benchmark"), "data": data})
        if self.path.startswith("/stall"):
            time.sleep(67)
        if self.path.startswith("/delayed"):
            time.sleep(0.25)
        body = self.server.responses.setdefault(self.path, b"\x00\xff\x80" + secrets.token_bytes(48))
        self.send_response(418 if self.path.startswith("/status") else 200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    do_GET = do_POST = respond


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, context=None):
        self.context = context
        self.requests, self.rejections, self.responses = [], [], {}
        super().__init__(("127.0.0.1", 0), Handler)

    def get_request(self):
        connection, address = super().get_request()
        if self.context:
            try:
                connection.settimeout(3)
                connection = self.context.wrap_socket(connection, server_side=True)
            except ssl.SSLError as error:
                self.rejections.append(str(error))
                connection.close()
                raise
        return connection, address

    def handle_error(self, *_args):
        pass


class Fixtures:
    def __enter__(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sitecmd-private-tls-")
        directory = pathlib.Path(self.directory.name)
        config = directory / "openssl.cnf"
        config.write_text("[req]\ndistinguished_name=dn\n[dn]\n")
        os.environ["OPENSSL_CONF"] = str(config)
        ca_key, ca = directory / "ca.key", directory / "ca.pem"
        openssl("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca), "-subj", "/CN=SiteCMD qualification CA", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE")
        descriptor, public = tempfile.mkstemp(prefix="sitecmd-public-ca-", suffix=".pem")
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(ca.read_bytes())
        self.public_ca = pathlib.Path(public)
        self.public_ca.chmod(0o644)
        self.servers, self.urls = {}, {}
        for name in ("trusted", "untrusted", "wrong-host", "expired", "plain"):
            context = None
            if name != "plain":
                key, csr, cert = [directory / f"{name}.{suffix}" for suffix in ("key", "csr", "pem")]
                hostname = "wrong.invalid" if name == "wrong-host" else "localhost"
                openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={hostname}")
                extensions = directory / f"{name}.ext"
                extensions.write_text(f"subjectAltName=DNS:{hostname}\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
                signing = ["-signkey", str(key)] if name == "untrusted" else ["-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial"]
                openssl("x509", "-req", "-in", str(csr), "-out", str(cert), "-days", "-1" if name == "expired" else "1", "-extfile", str(extensions), *signing)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert, key)
            server = Server(context)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.servers[name] = server
            self.urls[name] = f'{"http" if name == "plain" else "https"}://localhost:{server.server_port}'
        for name, server in self.servers.items():
            context = ssl.create_default_context(cafile=self.public_ca)
            connection = http.client.HTTPConnection("localhost", server.server_port, timeout=3) if name == "plain" else http.client.HTTPSConnection("localhost", server.server_port, context=context, timeout=3)
            try:
                connection.request("GET", "/fixture-check")
                assert connection.getresponse().status == 200
                assert name in ("trusted", "plain")
            except ssl.SSLCertVerificationError:
                assert name not in ("trusted", "plain")
            finally:
                connection.close()
        return self

    def __exit__(self, *_args):
        for server in self.servers.values():
            server.shutdown()
            server.server_close()
        self.public_ca.unlink()
        self.directory.cleanup()

    def expected(self, server, path):
        return base64.b64encode(self.servers[server].responses[path]).decode()
