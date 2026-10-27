# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The committed Keycloak realm is a tested artifact, not a documentation
sample.

No container runs here. What a live Keycloak does with this file was measured
once, against the pinned version, and written down in
`deploy/keycloak/README.md`; what these tests hold is that the file still says
what that document claims it says — the mappers parse, and they claim the
audience, the roles and the AMR value the recipe promises.

The audience mapper is asserted hardest, because it is the one that fails
silently: Keycloak does not put a resource server in `aud` by itself, and a
realm missing this mapper issues tokens that look right and are rejected by
every audience-checking verifier.

The second thing these tests guard is that the file stays secret-free *by
construction* — no signing keys, no client secret, no user credentials — since
that property is a decision about how the file is built and nothing in the
format enforces it.
"""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path

import pytest

from extensible_mcp_vc.oauth import AUDIENCE, CLIENT_ID, DemoUserStore

DEPLOY = Path(__file__).resolve().parents[1] / "deploy" / "keycloak"
REALM_FILE = DEPLOY / "household-realm.json"
RECIPE = DEPLOY / "README.md"
CURATION = DEPLOY / "REALM-CURATION.md"

# RFC 8176's registered Authentication Method Reference values. The point of
# the AMR mapper is that the vocabulary is ours to choose -- Keycloak checks
# nothing -- so the test is that what we chose is a registered value and not a
# word somebody invented.
RFC_8176_VALUES = frozenset(
    """face fpt geo hwk iris kba mca mfa otp pin pwd rba retina sc sms swk
    tel user vbm wia""".split()
)

AUDIENCE_MAPPER = "oidc-audience-mapper"
ROLE_MAPPER = "oidc-usermodel-realm-role-mapper"
AMR_MAPPER = "oidc-amr-mapper"
PASSWORDLESS_AUTHENTICATOR = "webauthn-authenticator-passwordless"

ROLES_CLAIM = "roles"


@pytest.fixture(scope="module")
def realm() -> dict:
    return json.loads(REALM_FILE.read_text())


@pytest.fixture(scope="module")
def client(realm: dict) -> dict:
    """The approval page's client, found by the id the service actually uses."""
    matches = [c for c in realm["clients"] if c["clientId"] == CLIENT_ID]
    assert len(matches) == 1, f"expected exactly one {CLIENT_ID!r} client"
    return matches[0]


def mappers(client: dict, protocol_mapper: str) -> list[dict]:
    return [
        m
        for m in client.get("protocolMappers", [])
        if m.get("protocolMapper") == protocol_mapper
    ]


def walk(node, path="$"):
    """Every (path, key, value) in the document, so a scan can be exhaustive."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield f"{path}.{k}", k, v
            yield from walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk(v, f"{path}[{i}]")


# --------------------------------------------------------------------------- #
# the audience mapper: the one that silently breaks token validation
# --------------------------------------------------------------------------- #


def test_audience_mapper_exists_at_all(client: dict) -> None:
    """Keycloak does not set `aud` to your resource by default.

    Measured on the pinned version: an otherwise identical client without this
    mapper issues an access token with no `aud` claim whatsoever.
    """
    assert len(mappers(client, AUDIENCE_MAPPER)) == 1


def test_audience_mapper_names_the_resource_the_service_verifies(client: dict) -> None:
    """The emitted audience is the one `verify_token` requires, not a client id.

    If these two drift apart, every token is rejected -- so the constant in
    `oauth.py` is the assertion rather than a copy of the string.
    """
    config = mappers(client, AUDIENCE_MAPPER)[0]["config"]
    assert config["included.custom.audience"] == AUDIENCE


def test_audience_mapper_targets_the_access_token(client: dict) -> None:
    """A mapper configured only for the ID token leaves bearer calls failing."""
    config = mappers(client, AUDIENCE_MAPPER)[0]["config"]
    assert config["access.token.claim"] == "true"


def test_audience_is_a_custom_value_not_another_client(client: dict) -> None:
    """`included.client.audience` would make `aud` some other client in the
    realm. The resource here is a service name, so that field must stay unset:
    setting both is the quiet way to end up with the wrong audience."""
    config = mappers(client, AUDIENCE_MAPPER)[0]["config"]
    assert not config.get("included.client.audience")


def test_recipe_documents_the_audience_it_emits() -> None:
    text = RECIPE.read_text()
    assert AUDIENCE in text
    assert AUDIENCE_MAPPER in text


# --------------------------------------------------------------------------- #
# the role mapper, and the scope mapping without which it emits nothing
# --------------------------------------------------------------------------- #


def test_realm_declares_exactly_our_role_vocabulary(realm: dict) -> None:
    """The roles are the demo's own two, taken from the code rather than
    retyped: `DemoUserStore` is what issues them on the non-Keycloak path."""
    expected = set(inspect.signature(DemoUserStore.__init__).parameters["roles"].default)
    assert {r["name"] for r in realm["roles"]["realm"]} == expected


def test_role_mapper_emits_the_documented_claim(client: dict) -> None:
    config = mappers(client, ROLE_MAPPER)[0]["config"]
    assert config["claim.name"] == ROLES_CLAIM
    assert config["access.token.claim"] == "true"


def test_role_claim_is_multivalued(client: dict) -> None:
    """A Keycloak user can hold both roles, so the claim is a list. The recipe
    says so, and a verifier written against a single string would break."""
    config = mappers(client, ROLE_MAPPER)[0]["config"]
    assert config["multivalued"] == "true"


def test_roles_are_in_the_clients_scope(realm: dict, client: dict) -> None:
    """With `fullScopeAllowed: false` a mapper alone emits nothing.

    Measured on the pinned version: without the scope mapping the `roles` claim
    and Keycloak's own `realm_access` are both absent, exactly as if no mapper
    were configured. So the two settings are asserted as a pair.
    """
    assert client["fullScopeAllowed"] is False
    granted = {
        role
        for entry in realm.get("scopeMappings", [])
        if entry.get("client") == CLIENT_ID
        for role in entry.get("roles", [])
    }
    assert granted == {r["name"] for r in realm["roles"]["realm"]}


def test_recipe_documents_the_role_claim() -> None:
    text = RECIPE.read_text()
    assert ROLES_CLAIM in text
    assert "scopeMappings" in text


# --------------------------------------------------------------------------- #
# the AMR mapper, and the per-execution config that feeds it
# --------------------------------------------------------------------------- #


def test_amr_mapper_is_present_and_on_both_tokens(client: dict) -> None:
    config = mappers(client, AMR_MAPPER)[0]["config"]
    assert config["access.token.claim"] == "true"
    assert config["id.token.claim"] == "true"


def passwordless_execution(realm: dict) -> dict:
    found = [
        execution
        for flow in realm["authenticationFlows"]
        for execution in flow["authenticationExecutions"]
        if execution.get("authenticator") == PASSWORDLESS_AUTHENTICATOR
    ]
    assert len(found) == 1, "expected one WebAuthn-passwordless execution"
    return found[0]


def test_browser_flow_is_bound_to_the_passwordless_flow(realm: dict) -> None:
    """The binding is by alias, and the alias has to be a flow in this file."""
    aliases = {flow["alias"] for flow in realm["authenticationFlows"]}
    assert realm["browserFlow"] in aliases
    top_level = [
        flow
        for flow in realm["authenticationFlows"]
        if flow["alias"] == realm["browserFlow"]
    ]
    assert top_level[0]["topLevel"] is True


def test_passwordless_execution_is_required(realm: dict) -> None:
    """ALTERNATIVE here would make the passkey leg skippable."""
    assert passwordless_execution(realm)["requirement"] == "REQUIRED"


def test_no_password_authenticator_anywhere_in_the_flows(realm: dict) -> None:
    """Passwordless is the claim; a password form in any flow this file defines
    would make it false."""
    authenticators = {
        execution.get("authenticator")
        for flow in realm["authenticationFlows"]
        for execution in flow["authenticationExecutions"]
    }
    assert not {a for a in authenticators if a and "password-form" in a}


def amr_config(realm: dict) -> dict:
    alias = passwordless_execution(realm)["authenticatorConfig"]
    found = [c for c in realm["authenticatorConfig"] if c["alias"] == alias]
    assert len(found) == 1, f"execution names config {alias!r}, which is not defined"
    return found[0]["config"]


def test_amr_value_is_a_registered_rfc_8176_string(realm: dict) -> None:
    """Keycloak checks nothing here, so this test is the check."""
    assert amr_config(realm)["default.reference.value"] in RFC_8176_VALUES


def test_amr_max_age_is_positive(realm: dict) -> None:
    """`AmrUtils.isAmrValid` tests `authTime + maxAge >= now`, and the default
    for a missing key is `"0"` -- which expires the factor the instant it is
    used and drops the value out of the claim with no error. A positive value
    is what makes the `amr` claim appear at all."""
    max_age = amr_config(realm)["default.reference.maxAge"]
    assert int(max_age) > 0


def test_recipe_documents_the_amr_value_it_chose(realm: dict) -> None:
    """The recipe explains why this string and not another; if the file changes
    the string, the explanation stops being about the file."""
    assert amr_config(realm)["default.reference.value"] in RECIPE.read_text()


# --------------------------------------------------------------------------- #
# secret-free by construction
# --------------------------------------------------------------------------- #

# Key names an export would carry secrets under. `credentials` covers user
# password and OTP material; `components` is where the `rsa-generated` and
# `hmac-generated` providers keep private keys, and is also what has to be
# absent for Keycloak to generate fresh ones at import. A *public* key is not
# on this list -- a private-key-JWT client would legitimately carry its public
# JWK here, and that is not a secret.
FORBIDDEN_KEYS = frozenset(
    {
        "secret",
        "credentials",
        "privateKey",
        "components",
        "smtpServer",
    }
)


def test_no_secret_bearing_keys_anywhere(realm: dict) -> None:
    offenders = [path for path, key, _ in walk(realm) if key in FORBIDDEN_KEYS]
    assert offenders == [], f"secret-bearing keys present: {offenders}"


def test_no_pem_or_key_material_in_any_value(realm: dict) -> None:
    offenders = [
        path
        for path, _, value in walk(realm)
        if isinstance(value, str) and "-----BEGIN" in value
    ]
    assert offenders == []


def test_users_carry_no_credentials(realm: dict) -> None:
    """Enrolment is a manual step precisely so this stays true."""
    for user in realm["users"]:
        assert "credentials" not in user
        assert "webauthn-register-passwordless" in user["requiredActions"]


def test_users_can_complete_a_first_login(realm: dict) -> None:
    """`VERIFY_PROFILE` is a default required action, so a user with no profile
    fields is stuck before the passkey prompt."""
    for user in realm["users"]:
        assert user["firstName"] and user["lastName"] and user["email"]
        assert user["emailVerified"] is True


def test_client_is_public_with_pkce(client: dict) -> None:
    """A public client has no secret to commit; PKCE is what replaces one."""
    assert client["publicClient"] is True
    assert client["attributes"]["pkce.code.challenge.method"] == "S256"
    assert client["standardFlowEnabled"] is True
    assert client["implicitFlowEnabled"] is False
    assert client["directAccessGrantsEnabled"] is False
    assert client["serviceAccountsEnabled"] is False


def test_curation_note_exists(realm: dict) -> None:
    """A regeneration that re-adds what was stripped is the failure mode this
    file guards against, and the note is what makes it noticeable."""
    text = CURATION.read_text()
    assert "components" in text
    assert "credentials" in text


# --------------------------------------------------------------------------- #
# the recipe pins one version, and names it
# --------------------------------------------------------------------------- #


def test_recipe_pins_exactly_one_keycloak_version() -> None:
    """Every claim in the recipe was measured against one image. Two tags in
    the document would mean half of it was measured against something else."""
    tags = set(re.findall(r"keycloak/keycloak:([\w.\-]+)", RECIPE.read_text()))
    assert len(tags) == 1, f"recipe names several Keycloak versions: {sorted(tags)}"
    (tag,) = tags
    assert re.fullmatch(r"\d+\.\d+\.\d+", tag), f"pin a full version, got {tag!r}"


def test_realm_file_name_matches_the_realm(realm: dict) -> None:
    """A directory import requires `<realm>-realm.json`; the pinned version
    refuses to start on a mismatch."""
    assert REALM_FILE.name == f"{realm['realm']}-realm.json"
