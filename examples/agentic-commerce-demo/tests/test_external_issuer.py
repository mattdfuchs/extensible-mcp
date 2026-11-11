# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The approval service in external-issuer mode: the realm's tokens, verified
with the proxy's own verifier, with the page's flow relayed to the provider.

No Keycloak runs here. The provider is a fake behind an ``httpx2``
mock transport that serves discovery, a JWKS and a token endpoint, and the
tokens are minted with a local RSA keypair shaped exactly as the committed
realm's mappers emit them -- ``aud``, a ``roles`` list, ``amr`` -- so this
file and ``test_keycloak_realm.py`` pin one contract from both sides. The
opt-in test at the end runs against a real Keycloak when ``KEYCLOAK_URL``
is set."""

from __future__ import annotations

import base64
import json
import os
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from fastmcp.server.auth.providers.jwt import RSAKeyPair

from extensible_mcp_vc.oauth import (
    AUDIENCE,
    CLIENT_ID,
    ROLES,
    ROLES_CLAIM,
    ExternalIssuer,
    ExternalIssuerConfig,
)
from extensible_mcp_vc.webauthn import b64url_encode

from .idp_fixtures import INTERNAL, ISSUER, FakeProvider, bearer, mint, mock_client
from .webauthn_fixtures import attestation_object, load_approval_module

@pytest.fixture
def keypair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture
def provider(keypair) -> FakeProvider:
    return FakeProvider(keypair)


def load_external(monkeypatch, provider, *, with_admin_key: bool = False, **env: str):
    """The service module in external mode, pointed at the fake provider."""
    monkeypatch.setenv("APPROVAL_ISSUER", ISSUER)
    monkeypatch.setenv("APPROVAL_ISSUER_INTERNAL", INTERNAL)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    mod = load_approval_module(with_admin_key=with_admin_key)
    assert mod._external is not None
    mod._external = ExternalIssuer(
        mod._external.config,
        http_client=mock_client(provider),
    )
    return mod


@pytest.fixture
def external(monkeypatch, provider):
    return load_external(monkeypatch, provider)


@pytest.fixture
def client(external) -> TestClient:
    return TestClient(external.app)


def register(client, headers, **body):
    key = ec.generate_private_key(ec.SECP256R1())
    body.setdefault(
        "attestationObject", b64url_encode(attestation_object(key.public_key(), b"cred-ext"))
    )
    return client.post("/register", json=body, headers=headers)


# -- the enrollment binds the passkey to the account that enrolled it ------- #


def test_the_enrollment_names_the_account_the_passkey_was_enrolled_from(
    monkeypatch, provider, keypair
):
    """The invoice bundle's ``account_bound`` check reads the enrollment VC's
    ``accounts`` against the console session's principal; the sign-in that
    enrolled the passkey is what says which account that is. Found in the
    organization shape's live test: without this list every charge was
    denied as unbound, with both approvals in."""
    mod = load_external(monkeypatch, provider, with_admin_key=True)
    client = TestClient(mod.app)
    r = register(client, bearer(mint(keypair, ["child"], sub="child-uuid")))
    assert r.status_code == 200, r.text
    assert r.json()["adminAttested"] is True
    e = client.get(f"/enrollment/{r.json()['credentialId']}").json()
    subject = e["claims"]["vc"]["credentialSubject"]
    assert subject["role"] == "child"
    assert subject["accounts"] == [{"idp": ISSUER, "account": "child-uuid"}]
    payload = e["jws"].split(".")[1]
    signed = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert signed == e["claims"]


# -- verification ----------------------------------------------------------- #


def test_a_realm_shaped_token_enrols_under_its_role(client, keypair, provider):
    r = register(client, bearer(mint(keypair, ["parent"])))
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "parent"
    # The key came from the provider's JWKS, fetched at the internal base.
    assert f"{INTERNAL}/protocol/openid-connect/certs" in provider.requests
    assert not any(u.startswith(ISSUER) for u in provider.requests)


def test_the_config_is_the_realms_values():
    cfg = ExternalIssuerConfig.from_env({"APPROVAL_ISSUER": ISSUER + "/"})
    assert cfg.issuer == ISSUER and cfg.internal_base == ISSUER
    assert cfg.audience == AUDIENCE and cfg.client_id == CLIENT_ID
    assert cfg.required_amr == frozenset({"hwk"})
    assert ExternalIssuerConfig.from_env({}) is None


@pytest.mark.parametrize("bad", [
    {"audience": "another-service"},
    {"issuer": "http://idp.test/realms/other"},
])
def test_a_token_for_another_audience_or_issuer_is_refused(client, keypair, bad):
    r = register(client, bearer(mint(keypair, ["parent"], **bad)))
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith("Bearer")
    assert "could not be verified" in r.json()["detail"]


def test_the_services_own_token_is_refused_in_external_mode(client, external):
    """One mode per process: a token this server minted is nobody's now."""
    own = external._auth._mint_token("child", "child")
    assert register(client, bearer(own)).status_code == 401
    assert client.get("/me", headers=bearer(own)).status_code == 401


def test_a_token_signed_by_an_unknown_key_is_refused(client, keypair):
    other = RSAKeyPair.generate()
    r = register(client, bearer(mint(other, ["parent"])))
    assert r.status_code == 401


def test_a_provider_that_cannot_be_reached_is_a_503_not_a_401(monkeypatch, keypair):
    """No judgement was made, so the caller is not told its token was bad."""
    class Down(FakeProvider):
        def handler(self, request):
            raise httpx2.ConnectError("refused")
    mod = load_external(monkeypatch, Down(keypair))
    r = TestClient(mod.app).get("/me", headers=bearer(mint(keypair, ["parent"])))
    assert r.status_code == 503 and "unreachable" in r.json()["detail"]


def test_discovery_naming_another_issuer_is_refused(monkeypatch, keypair):
    provider = FakeProvider(keypair)
    provider.discovery_issuer = "http://idp.test/realms/other"
    mod = load_external(monkeypatch, provider)
    r = TestClient(mod.app).get("/me", headers=bearer(mint(keypair, ["parent"])))
    assert r.status_code == 503 and "names issuer" in r.json()["detail"]


# -- the claims contract ---------------------------------------------------- #


def test_both_roles_need_a_selection_and_the_body_cannot_widen(client, keypair):
    both = bearer(mint(keypair, list(ROLES)))
    r = register(client, both)
    assert r.status_code == 400 and "must select one" in r.json()["detail"]
    r = register(client, both, role="child")
    assert r.status_code == 200 and r.json()["role"] == "child"
    r = register(client, both, role="merchant")
    assert r.status_code == 400


def test_a_body_role_is_ignored_when_the_token_grants_one(client, keypair):
    r = register(client, bearer(mint(keypair, ["child"])), role="parent")
    assert r.status_code == 200 and r.json()["role"] == "child"


def test_no_enrollable_role_is_refused(client, keypair):
    r = register(client, bearer(mint(keypair, ["admin"])))
    assert r.status_code == 403 and "no enrollable role" in r.json()["detail"]
    assert register(client, bearer(mint(keypair, []))).status_code == 403


def test_a_sign_in_without_a_hardware_key_cannot_enrol(client, keypair):
    """The realm's passwordless flow records ``hwk``; a password sign-in at
    the provider would carry ``pwd``, and enrollment is the first link."""
    assert register(client, bearer(mint(keypair, ["parent"], amr=["pwd"]))).status_code == 403
    r = register(client, bearer(mint(keypair, ["parent"], amr=None)))
    assert r.status_code == 403 and "authentication method" in r.json()["detail"]
    # Approving is still open to it: the assertion itself proves the key.
    assert client.get("/me", headers=bearer(mint(keypair, ["parent"], amr=None))).status_code == 200


def test_the_required_amr_is_configurable(monkeypatch, keypair, provider):
    mod = load_external(monkeypatch, provider, APPROVAL_REQUIRED_AMR="swk, hwk")
    c = TestClient(mod.app)
    assert register(c, bearer(mint(keypair, ["parent"], amr=["swk"]))).status_code == 200
    mod = load_external(monkeypatch, provider, APPROVAL_REQUIRED_AMR="")
    c = TestClient(mod.app)
    assert register(c, bearer(mint(keypair, ["parent"], amr=["pwd"]))).status_code == 200


def test_me_reports_the_role_or_leaves_the_choice(client, keypair):
    one = client.get("/me", headers=bearer(mint(keypair, ["parent"]))).json()
    assert one == {"sub": "parent-uuid", "role": "parent", "roles": ["parent"]}
    both = client.get("/me", headers=bearer(mint(keypair, list(ROLES)))).json()
    assert both["role"] is None and both["roles"] == list(ROLES)


# -- the relayed flow ------------------------------------------------------- #

PAGE_QUERY = {
    "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": "/",
    "state": "xyz", "code_challenge": "c" * 43, "code_challenge_method": "S256",
}


def test_authorize_sends_the_browser_to_the_provider(client):
    r = client.get("/authorize", params=PAGE_QUERY, follow_redirects=False)
    assert r.status_code == 302, r.text
    target = urlparse(r.headers["location"])
    assert f"{target.scheme}://{target.netloc}{target.path}" == f"{ISSUER}/protocol/openid-connect/auth"
    q = {k: v[0] for k, v in parse_qs(target.query).items()}
    assert q == {
        "response_type": "code", "client_id": CLIENT_ID,
        "redirect_uri": "http://testserver/",   # the page's "/" made absolute
        "scope": "openid", "code_challenge": "c" * 43,
        "code_challenge_method": "S256", "state": "xyz",
    }


def test_the_first_passkey_route_is_a_sign_in_that_keeps_nothing(client, provider):
    """``first_passkeys.py arm`` sends each person here: the provider's flow
    registers the passkey, and the page that comes back only says thank you.
    It exchanges no code, so no token from a password sign-in is left in
    the window to be refused at Enroll later."""
    r = client.get("/first-passkey", follow_redirects=False)
    assert r.status_code == 302, r.text
    target = urlparse(r.headers["location"])
    assert f"{target.scheme}://{target.netloc}{target.path}" == f"{ISSUER}/protocol/openid-connect/auth"
    q = {k: v[0] for k, v in parse_qs(target.query).items()}
    assert q["client_id"] == CLIENT_ID
    assert q["redirect_uri"] == "http://testserver/first-passkey"
    assert q["code_challenge_method"] == "S256" and len(q["code_challenge"]) == 43
    before = len(provider.token_requests)
    r = client.get("/first-passkey", params={"code": "abc", "state": q["state"]})
    assert r.status_code == 200 and "Thank you" in r.text and "close this window" in r.text
    assert len(provider.token_requests) == before
    r = client.get("/first-passkey", params={"error": "access_denied"})
    assert r.status_code == 200 and "access_denied" in r.text and "Try again" in r.text


def test_authorize_still_validates_the_request_before_redirecting(client):
    r = client.get("/authorize", params={**PAGE_QUERY, "code_challenge_method": "plain"})
    assert r.status_code == 400
    r = client.get("/authorize", params={**PAGE_QUERY, "redirect_uri": "https://evil.example/"})
    assert r.status_code == 400


def test_the_login_form_is_gone(client):
    assert client.post("/authorize", data={"username": "parent", "password": "x"}).status_code == 404


def test_the_code_exchange_is_forwarded_with_the_verifier(client, provider):
    r = client.post("/token", data={
        "grant_type": "authorization_code", "code": "abc", "code_verifier": "v" * 43,
        "redirect_uri": "/", "client_id": CLIENT_ID,
    })
    assert r.status_code == 200, r.text
    assert r.json()["access_token"] == "provider-token"
    assert r.headers["Cache-Control"] == "no-store"
    assert provider.token_requests == [{
        "grant_type": "authorization_code", "code": "abc", "code_verifier": "v" * 43,
        "redirect_uri": "http://testserver/", "client_id": CLIENT_ID,
    }]
    assert f"{INTERNAL}/protocol/openid-connect/token" in provider.requests


def test_the_providers_refusal_passes_through(client, provider):
    provider.token_response = (400, {"error": "invalid_grant", "error_description": "bad code"})
    r = client.post("/token", data={
        "grant_type": "authorization_code", "code": "abc", "code_verifier": "v",
        "redirect_uri": "/", "client_id": CLIENT_ID,
    })
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_another_client_id_is_not_forwarded(client, provider):
    r = client.post("/token", data={
        "grant_type": "authorization_code", "code": "abc", "code_verifier": "v",
        "redirect_uri": "/", "client_id": "someone-else",
    })
    assert r.status_code == 400 and r.json()["error"] == "unauthorized_client"
    assert provider.token_requests == []


# -- internal mode is untouched --------------------------------------------- #


def test_internal_mode_reports_its_one_role_the_same_way(monkeypatch):
    monkeypatch.delenv("APPROVAL_ISSUER", raising=False)
    mod = load_approval_module()
    assert mod._external is None
    from .webauthn_fixtures import sign_in
    c = TestClient(mod.app)
    me = c.get("/me", headers=sign_in(c, "child")).json()
    assert me == {"sub": "child", "role": "child", "roles": ["child"]}


# -- opt-in: a real Keycloak ------------------------------------------------ #


@pytest.mark.skipif(not os.environ.get("KEYCLOAK_URL"), reason="set KEYCLOAK_URL to run")
async def test_the_pinned_keycloak_publishes_what_the_recipe_says():
    """``KEYCLOAK_URL`` is where this test reaches Keycloak (the internal
    base, e.g. ``http://127.0.0.1:8080``); ``KEYCLOAK_ISSUER`` is what the
    realm names in ``iss``, defaulting to the recipe's
    ``http://localhost:8080/realms/household``. Two values on purpose: it
    is the rewrite the compose overlay relies on, run for real. A token
    cannot be obtained headlessly -- the realm is passwordless and its users
    hold no credential until a passkey is registered -- so this checks the
    published half: discovery names the configured issuer, the JWKS carries
    an RS256 key, the token endpoint answers, and the verifier built from
    them refuses a token it cannot verify rather than failing to build."""
    base = os.environ["KEYCLOAK_URL"].rstrip("/")
    cfg = ExternalIssuerConfig.from_env({
        "APPROVAL_ISSUER": os.environ.get("KEYCLOAK_ISSUER", "http://localhost:8080/realms/household"),
        "APPROVAL_ISSUER_INTERNAL": f"{base}/realms/household",
    })
    ext = ExternalIssuer(cfg)
    doc = await ext.discovery()
    assert doc["issuer"] == cfg.issuer
    async with httpx2.AsyncClient() as http:
        jwks = (await http.get(cfg.internal(doc["jwks_uri"]))).json()
    status, body = await ext.exchange_code(
        code="not-a-code", code_verifier="v" * 43,
        redirect_uri="http://localhost:7500/", client_id=CLIENT_ID,
    )
    assert status == 400 and body.get("error") == "invalid_grant"
    assert any(k.get("alg") == "RS256" and k.get("use") == "sig" for k in jwks["keys"])
    with pytest.raises(Exception) as refused:
        await ext.verify_token("Bearer not-a-token")
    assert "could not be verified" in str(refused.value)
    print(json.dumps({k: doc[k] for k in ("issuer", "authorization_endpoint", "token_endpoint")}))
