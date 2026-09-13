import contextlib
import io
import json
import sys
from types import ModuleType, SimpleNamespace
from urllib.parse import urlsplit


request_data = json.load(sys.stdin)
source = request_data["source"]


class Http404(Exception):
    pass


class ObjectDoesNotExist(Exception):
    pass


class UserRecord:
    def __init__(self, user_id, username, backend="fixture.backend"):
        self.id = user_id
        self.pk = user_id
        self.username = username
        self.backend = backend
        self.is_staff = True

    def get_username(self):
        return self.username


class UserManager:
    def __init__(self):
        self.users = {
            1: UserRecord(1, "original"),
            2: UserRecord(2, "target"),
        }
        self.queries = []

    def get(self, pk, is_staff=True):
        self.queries.append((pk, is_staff))
        try:
            return self.users[int(pk)]
        except (KeyError, TypeError, ValueError) as error:
            raise ObjectDoesNotExist() from error


class User:
    objects = UserManager()


def allowed_redirect(url, allowed_hosts, require_https=False):
    if (
        not isinstance(url, str)
        or not url
        or url.startswith("///")
        or "\\" in url
        or any(ord(character) < 32 for character in url)
    ):
        return False
    parsed = urlsplit(url)
    if parsed.scheme and parsed.scheme not in ({"https"} if require_https else {"http", "https"}):
        return False
    if parsed.netloc:
        return parsed.netloc in set(allowed_hosts or ())
    return url.startswith("/") and not url.startswith("//")


def install_stubs(state):
    django = ModuleType("django")
    django.__path__ = []
    conf = ModuleType("django.conf")
    conf.settings = SimpleNamespace(AUTHENTICATION_BACKENDS=[])
    contrib = ModuleType("django.contrib")
    contrib.__path__ = []
    messages = ModuleType("django.contrib.messages")
    messages.ERROR = "error"
    messages.add_message = lambda request, level, message: state["messages"].append((level, str(message)))
    admin = ModuleType("django.contrib.admin")
    admin.__path__ = []
    admin_views = ModuleType("django.contrib.admin.views")
    admin_views.__path__ = []
    decorators = ModuleType("django.contrib.admin.views.decorators")
    decorators.staff_member_required = lambda function: function
    auth = ModuleType("django.contrib.auth")
    auth.load_backend = lambda _name: SimpleNamespace(get_user=lambda _pk: None)
    auth.login = lambda request, user: state["logins"].append(user.id)
    auth.get_user_model = lambda: User
    auth_models = ModuleType("django.contrib.auth.models")
    auth_models.User = User
    core = ModuleType("django.core")
    core.__path__ = []
    exceptions = ModuleType("django.core.exceptions")
    exceptions.ObjectDoesNotExist = ObjectDoesNotExist
    http = ModuleType("django.http")
    http.Http404 = Http404
    shortcuts = ModuleType("django.shortcuts")
    shortcuts.redirect = lambda url: {"redirect": url}
    utils = ModuleType("django.utils")
    utils.__path__ = []
    html = ModuleType("django.utils.html")
    html.escape = lambda value: str(value)
    http_utils = ModuleType("django.utils.http")
    http_utils.url_has_allowed_host_and_scheme = allowed_redirect
    translation = ModuleType("django.utils.translation")
    translation.gettext_lazy = lambda value: value
    grappelli = ModuleType("grappelli")
    grappelli.__path__ = []
    grappelli_settings = ModuleType("grappelli.settings")
    grappelli_settings.SWITCH_USER_ORIGINAL = lambda _user: True
    grappelli_settings.SWITCH_USER_TARGET = lambda _original, _target: True
    sys.modules.update({
        "django": django,
        "django.conf": conf,
        "django.contrib": contrib,
        "django.contrib.messages": messages,
        "django.contrib.admin": admin,
        "django.contrib.admin.views": admin_views,
        "django.contrib.admin.views.decorators": decorators,
        "django.contrib.auth": auth,
        "django.contrib.auth.models": auth_models,
        "django.core": core,
        "django.core.exceptions": exceptions,
        "django.http": http,
        "django.shortcuts": shortcuts,
        "django.utils": utils,
        "django.utils.html": html,
        "django.utils.http": http_utils,
        "django.utils.translation": translation,
        "grappelli": grappelli,
        "grappelli.settings": grappelli_settings,
    })


def make_request(redirect, secure=True):
    return SimpleNamespace(
        user=User.objects.users[1],
        session={},
        GET={"redirect": redirect} if redirect is not None else {},
        get_host=lambda: "app.example",
        is_secure=lambda: secure,
    )


def invoke(function, redirect, secure=True, object_id=2):
    request = make_request(redirect, secure)
    try:
        result = function(request, object_id)
        return {"rejected": False, "result": result, "request": request}
    except Http404:
        return {"rejected": True, "result": None, "request": request}


try:
    state = {"messages": [], "logins": []}
    install_stubs(state)
    namespace = {"__name__": "sitecmd_redirect_probe", "__file__": "/work/grappelli/views/switch.py"}
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        exec(compile(source, namespace["__file__"], "exec"), namespace)
    function = namespace.get("switch_user")
    if not callable(function):
        raise ValueError("switch_user is missing")

    relative = invoke(function, "/admin/users/")
    same_origin = invoke(function, "https://app.example/admin/users/")
    hostile_host = invoke(function, "https://attackerapp.example/collect")
    protocol_relative = invoke(function, "//attackerapp.example/collect")
    userinfo = invoke(function, "https://app.example@attacker.example/collect")
    wrong_port = invoke(function, "https://app.example:444/collect")
    backslash = invoke(function, "/\\attacker.example/collect")
    control_character = invoke(function, "/safe\nLocation: https://attacker.example/")
    dangerous_scheme = invoke(function, "javascript:alert(1)")
    downgrade = invoke(function, "http://app.example/admin/users/", secure=True)
    missing = invoke(function, None)

    state["messages"].clear()
    namespace["SWITCH_USER_ORIGINAL"] = lambda _user: False
    denied = invoke(function, "/admin/denied/")
    namespace["SWITCH_USER_ORIGINAL"] = lambda _user: True

    observed = {
        "hostileHostRejected": hostile_host["rejected"],
        "protocolRelativeRejected": protocol_relative["rejected"],
        "userinfoRejected": userinfo["rejected"],
        "wrongPortRejected": wrong_port["rejected"],
        "backslashRejected": backslash["rejected"],
        "controlCharacterRejected": control_character["rejected"],
        "dangerousSchemeRejected": dangerous_scheme["rejected"],
        "httpsDowngradeRejected": downgrade["rejected"],
        "missingRedirectRejected": missing["rejected"],
        "relativeRedirectPreserved": not relative["rejected"]
            and relative["result"] == {"redirect": "/admin/users/"},
        "sameOriginRedirectPreserved": not same_origin["rejected"]
            and same_origin["result"] == {"redirect": "https://app.example/admin/users/"},
        "loginAndSessionPreserved": state["logins"].count(2) >= 2
            and relative["request"].session.get("original_user") == {"id": 1, "username": "original"},
        "permissionFailurePreserved": not denied["rejected"]
            and denied["result"] == {"redirect": "/admin/denied/"}
            and any("Permission denied" in message for _level, message in state["messages"]),
    }
    print(json.dumps({"observed": observed, "error": None}, sort_keys=True))
except Exception as error:
    print(json.dumps({
        "observed": {},
        "error": f"{type(error).__name__}: {error}",
    }, sort_keys=True))
