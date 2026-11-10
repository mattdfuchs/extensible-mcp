# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The realm's users' first passkeys, as two operator commands.

The committed realm ships ``parent`` and ``child`` with no credential, so
that nothing in the file is a secret -- and a user with no credential cannot
start a passwordless login, so somebody has to open the door once. Keycloak's
own way of doing that is an action link sent by email, which the realm has
no mail server for. This is the other way:

    python3 first_passkeys.py arm    # then each person signs in once
    python3 first_passkeys.py seal   # once each holds a passkey

``arm`` points the realm's browser flow at Keycloak's built-in password flow,
gives each user a one-off password and prints it, and arms the
``webauthn-register-passwordless`` required action, so the first sign-in at
the demo's own page (``http://localhost:7500``) registers the passkey inside
the flow and comes back to the page. ``seal`` refuses until every user holds
a ``webauthn-passwordless`` credential, then puts the passwordless flow
back, deletes the passwords and ends every session, so the next sign-in is
username plus passkey and the token carries the ``hwk`` AMR the approval
service requires. Nothing here touches the committed realm file.

Standard library only; speaks to the admin API of the running overlay.
Settings, all with the overlay's defaults: ``KEYCLOAK_URL``
(``http://localhost:8080``), ``KEYCLOAK_ADMIN`` / ``KEYCLOAK_ADMIN_PASSWORD``
(``admin`` / ``admin``), ``KEYCLOAK_REALM`` (``household``).
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
ADMIN = os.environ.get("KEYCLOAK_ADMIN", "admin")
ADMIN_PASSWORD = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
REALM = os.environ.get("KEYCLOAK_REALM", "household")
PASSWORDLESS_FLOW = "webauthn-passwordless-browser"  # the realm file's own
PASSWORD_FLOW = "browser"  # Keycloak's built-in, present in every realm
REGISTER = "webauthn-register-passwordless"
PASSKEY = "webauthn-passwordless"
USAGE = "usage: first_passkeys.py arm|seal"


def _call(method: str, path: str, body=None, *, token: str | None = None, form: bool = False):
    data = None
    headers = {}
    if body is not None:
        data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
        headers["content-type"] = (
            "application/x-www-form-urlencoded" if form else "application/json"
        )
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(URL + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path}: HTTP {e.code} {e.read().decode(errors='replace')[:200]}")
    except urllib.error.URLError as e:
        sys.exit(f"{method} {path}: {e.reason} -- is the Keycloak overlay up at {URL}?")
    return json.loads(raw) if raw else None


class Admin:
    def __init__(self) -> None:
        self.token = _call(
            "POST", "/realms/master/protocol/openid-connect/token",
            {"client_id": "admin-cli", "grant_type": "password",
             "username": ADMIN, "password": ADMIN_PASSWORD},
            form=True,
        )["access_token"]
        self.base = f"/admin/realms/{REALM}"

    def get(self, path: str):
        return _call("GET", self.base + path, token=self.token)

    def put(self, path: str, body) -> None:
        _call("PUT", self.base + path, body, token=self.token)

    def post(self, path: str, body=None) -> None:
        _call("POST", self.base + path, body, token=self.token)

    def delete(self, path: str) -> None:
        _call("DELETE", self.base + path, token=self.token)

    def users(self) -> list[dict]:
        return self.get("/users?max=100")

    def credentials(self, uid: str) -> list[dict]:
        return self.get(f"/users/{uid}/credentials")


def arm(kc: Admin) -> None:
    kc.put("", {"browserFlow": PASSWORD_FLOW})
    print(f"realm {REALM}: browser flow is {PASSWORD_FLOW} until `seal`\n")
    for u in kc.users():
        password = f"{u['username']}-{secrets.token_hex(3)}"
        kc.put(f"/users/{u['id']}/reset-password",
               {"type": "password", "value": password, "temporary": False})
        kc.put(f"/users/{u['id']}", {"requiredActions": [REGISTER]})
        print(f"  {u['username']:<8} {password}")
    print(
        "\nEach person: open http://localhost:7500 in a browser window of their own\n"
        "(two roles need two cookie jars: a Private window for the second), sign in\n"
        "with the password above, register the passkey when asked, and stop there.\n"
        "Then run: first_passkeys.py seal"
    )


def seal(kc: Admin) -> None:
    users = kc.users()
    missing = [u["username"] for u in users
               if not any(c["type"] == PASSKEY for c in kc.credentials(u["id"]))]
    if missing:
        sys.exit(f"not sealing: no passkey yet for {', '.join(missing)}")
    kc.put("", {"browserFlow": PASSWORDLESS_FLOW})
    for u in users:
        for c in kc.credentials(u["id"]):
            if c["type"] == "password":
                kc.delete(f"/users/{u['id']}/credentials/{c['id']}")
        kc.put(f"/users/{u['id']}", {"requiredActions": []})
        kc.post(f"/users/{u['id']}/logout")
    print(f"realm {REALM}: browser flow is {PASSWORDLESS_FLOW}; passwords deleted; "
          "sessions ended")
    for u in users:
        kinds = sorted(c["type"] for c in kc.credentials(u["id"]))
        print(f"  {u['username']:<8} credentials: {', '.join(kinds)}")
    print(
        "\nEveryone closes their window and opens a new one at the approval page:"
        "\nthe sign-in is now username plus passkey, and the page cannot enrol under"
        "\nthe one the arm step left in the old window."
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("arm", "seal"):
        print(USAGE, file=sys.stderr)
        return 2
    kc = Admin()
    (arm if argv[1] == "arm" else seal)(kc)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
