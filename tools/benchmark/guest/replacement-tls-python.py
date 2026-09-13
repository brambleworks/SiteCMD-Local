import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace


request = json.load(sys.stdin)
source = request["source"]
case_id = request["id"]


class Response:
    status_code = 200
    text = "ok"

    def json(self):
        return {"data": {"token": "fixture-token"}}

    def iter_content(self):
        return [b"first", b"second"]


def secure_verify(call):
    return call["kwargs"].get("verify", True) is not False


def install_bigflow_stubs(calls):
    requests = ModuleType("requests")

    def get(*args, **kwargs):
        calls.append({"method": "get", "args": args, "kwargs": kwargs})
        return Response()

    requests.get = get
    requests.Session = lambda: SimpleNamespace(get=get)
    toml = ModuleType("toml")
    toml.load = lambda _path: {}
    google = ModuleType("google")
    google.__path__ = []
    cloud = ModuleType("google.cloud")
    cloud.__path__ = []
    storage = ModuleType("google.cloud.storage")
    storage.Bucket = object
    storage.Blob = object
    storage.Client = object
    oauth2 = ModuleType("google.oauth2")
    oauth2.__path__ = []
    credentials = ModuleType("google.oauth2.credentials")
    credentials.Credentials = lambda token: token
    bigflow = ModuleType("bigflow")
    bigflow.__path__ = []
    build = ModuleType("bigflow.build")
    build.__path__ = []
    spec = ModuleType("bigflow.build.spec")
    spec.get_project_spec = lambda: SimpleNamespace(version="fixture")
    commons = ModuleType("bigflow.commons")
    commons.run_process = lambda *_args, **_kwargs: ""
    commons.decode_version_number_from_file_name = lambda _path: "1"
    commons.build_docker_image_tag = lambda repository, version: f"{repository}:{version}"
    commons.remove_docker_image_from_local_registry = lambda _tag: None
    sys.modules.update({
        "requests": requests,
        "toml": toml,
        "google": google,
        "google.cloud": cloud,
        "google.cloud.storage": storage,
        "google.oauth2": oauth2,
        "google.oauth2.credentials": credentials,
        "bigflow": bigflow,
        "bigflow.build": build,
        "bigflow.build.spec": spec,
        "bigflow.commons": commons,
    })


def observe_bigflow():
    calls = []
    install_bigflow_stubs(calls)
    namespace = {"__name__": "sitecmd_bigflow_probe", "__file__": "/work/bigflow/deploy.py"}
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        exec(compile(source, namespace["__file__"], "exec"), namespace)
    function = namespace.get("get_vault_token")
    if not callable(function):
        raise ValueError("get_vault_token is missing")
    token = function("https://vault.example/token", "fixture-secret")
    success_call = calls[-1] if calls else {"args": (), "kwargs": {}}
    missing_endpoint_rejected = False
    missing_secret_rejected = False
    try:
        function("", "fixture-secret")
    except Exception:
        missing_endpoint_rejected = True
    try:
        function("https://vault.example/token", "")
    except Exception:
        missing_secret_rejected = True
    return {
        "secureDefault": secure_verify(success_call),
        "endpointPreserved": success_call["args"][:1] == ("https://vault.example/token",),
        "secretHeaderPreserved": success_call["kwargs"].get("headers") == {"X-Vault-Token": "fixture-secret"},
        "tokenResponsePreserved": token == "fixture-token",
        "missingInputsRejected": missing_endpoint_rejected and missing_secret_rejected,
    }


def install_blackduck_stubs(calls):
    requests = ModuleType("requests")

    def record(method):
        def invoke(*args, **kwargs):
            calls.append({"method": method, "args": args, "kwargs": kwargs})
            return Response()
        return invoke

    requests.get = record("get")
    requests.post = record("post")
    requests.delete = record("delete")
    requests.put = record("put")
    requests.patch = record("patch")
    requests.packages = SimpleNamespace(urllib3=SimpleNamespace(disable_warnings=lambda: None))
    sys.modules["requests"] = requests


def blackduck_instance(namespace, insecure):
    instance = namespace["HubInstance"].__new__(namespace["HubInstance"])
    instance.config = {"insecure": insecure}
    instance.get_apibase = lambda: "https://hub.example/api"
    instance.get_headers = lambda: {"Authorization": "Bearer fixture"}
    return instance


def observe_blackduck():
    calls = []
    install_blackduck_stubs(calls)
    namespace = {"__name__": "sitecmd_blackduck_probe", "__file__": "/work/blackduck/HubRestApi.py"}
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        exec(compile(source, namespace["__file__"], "exec"), namespace)
    secure_hub = blackduck_instance(namespace, False)
    insecure_hub = blackduck_instance(namespace, True)
    with tempfile.TemporaryDirectory() as directory:
        json_file = Path(directory, "scan.json")
        bdio_file = Path(directory, "scan.bdio")
        json_file.write_text("{}", encoding="utf-8")
        bdio_file.write_bytes(b"fixture")
        secure_hub.upload_scan(str(json_file))
        secure_hub.upload_scan(str(bdio_file))
        insecure_hub.upload_scan(str(json_file))
        secure_hub.get_project_version_by_name = lambda *_args: {"fixture": True}
        secure_hub.get_version_codelocations = lambda _version: {
            "items": [{"_meta": {"links": [{
                "rel": "enclosure",
                "href": "https://hub.example/a/b/c/fixture.bdio",
            }]}}],
        }
        secure_hub.download_project_scans("project", "version", directory)
        downloaded = Path(directory, "fixture.bdio").read_bytes()
    upload_calls = [call for call in calls if call["method"] == "post"]
    download_calls = [call for call in calls if call["method"] == "get"]
    return {
        "secureUploads": len(upload_calls) >= 2 and all(secure_verify(call) for call in upload_calls[:2]),
        "explicitInsecureModePreserved": len(upload_calls) >= 3 and not secure_verify(upload_calls[2]),
        "secureDownloads": bool(download_calls) and secure_verify(download_calls[-1]),
        "uploadFormatsPreserved": len(upload_calls) >= 2
            and upload_calls[0]["kwargs"].get("headers", {}).get("Content-Type") == "application/ld+json"
            and upload_calls[1]["kwargs"].get("headers", {}).get("Content-Type") == "application/vnd.blackducksoftware.bdio+zip",
        "downloadBodyPreserved": downloaded == b"firstsecond",
    }


try:
    if case_id == "bigflow-deploy-tls-verification":
        observed = observe_bigflow()
    elif case_id == "blackduck-client-tls-verification":
        observed = observe_blackduck()
    else:
        raise ValueError(f"Unsupported Python TLS case: {case_id}")
    print(json.dumps({"observed": observed, "error": None}, sort_keys=True))
except Exception as error:
    print(json.dumps({
        "observed": {},
        "error": f"{type(error).__name__}: {error}",
    }, sort_keys=True))
