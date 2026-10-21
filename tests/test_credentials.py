# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The credential seam: both shipping grants, against a stub token endpoint.

The stub authorization server (``tests/conftest.py``) is a real HTTP service
on loopback that verifies client authentication and answers with an RFC 6749
token response, so these tests exercise the grants rather than a mock of
them: a ``private_key_jwt`` assertion is signed here and verified there.
"""

from __future__ import annotations

import logging
import socket

import httpx
import pytest

from extensible_mcp.credentials import (
    PROXY_ITSELF,
    ClientCredentialsOAuthProvider,
    CredentialError,
    OAuthGrantAuth,
    PrivateKeyJWTOAuthProvider,
    ProxyItself,
    build_provider,
)
from extensible_mcp.types import CredentialConfig

CLIENT_ID = "extensible-mcp-proxy"


def write_ec_key(tmp_path, name="proxy-signing.pem"):
    """A P-256 private key on disk, with its public half for the stub."""
    from joserfc.jwk import ECKey

    key = ECKey.generate_key("P-256")
    path = tmp_path / name
    path.write_bytes(key.as_pem(private=True))
    return path, key.as_pem(private=False)


def write_rsa_key(tmp_path, name="proxy-rsa.pem"):
    from joserfc.jwk import RSAKey

    key = RSAKey.generate_key(2048)
    path = tmp_path / name
    path.write_bytes(key.as_pem(private=True))
    return path, key.as_pem(private=False)


def closed_port_url() -> str:
    """A URL nothing is listening on: bind a port, learn it, release it."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"http://127.0.0.1:{port}/oauth/token"


def secret_provider(stub, *, secret="s3cr3t", **kwargs):
    stub.register_client_secret(CLIENT_ID, secret)
    return ClientCredentialsOAuthProvider(
        name="legacy-as",
        token_endpoint=stub.url,
        client_id=CLIENT_ID,
        client_secret_env="TEST_CLIENT_SECRET",
        **kwargs,
    )


def key_provider(stub, tmp_path, **kwargs):
    private_key_file, public_pem = write_ec_key(tmp_path)
    stub.register_client_key(CLIENT_ID, public_pem, "ES256")
    return PrivateKeyJWTOAuthProvider(
        name="corp-as",
        token_endpoint=stub.url,
        client_id=CLIENT_ID,
        private_key_file=private_key_file,
        **kwargs,
    )


class TestClientCredentialsGrant:
    async def test_acquires_a_token(self, stub_auth_server, monkeypatch):
        monkeypatch.setenv("TEST_CLIENT_SECRET", "s3cr3t")
        provider = secret_provider(stub_auth_server)

        assert await provider.token(PROXY_ITSELF) == "correct-token"

        (request,) = stub_auth_server.token_requests
        assert request["grant_type"] == "client_credentials"
        assert request["client_id"] == CLIENT_ID
        assert request["client_secret"] == "s3cr3t"

    async def test_scope_and_audience_travel_with_the_request(
        self, stub_auth_server, monkeypatch
    ):
        monkeypatch.setenv("TEST_CLIENT_SECRET", "s3cr3t")
        provider = secret_provider(
            stub_auth_server, scope="payments.invoke", audience="https://payments/"
        )

        await provider.token(PROXY_ITSELF)

        (request,) = stub_auth_server.token_requests
        assert request["scope"] == "payments.invoke"
        assert request["audience"] == "https://payments/"

    async def test_unset_environment_variable_is_a_credential_error(
        self, stub_auth_server, monkeypatch
    ):
        monkeypatch.delenv("TEST_CLIENT_SECRET", raising=False)
        provider = secret_provider(stub_auth_server)

        with pytest.raises(CredentialError, match="TEST_CLIENT_SECRET"):
            await provider.token(PROXY_ITSELF)
        # Nothing was asked of the authorization server: there was nothing to
        # authenticate with.
        assert stub_auth_server.token_requests == []

    async def test_a_wrong_secret_is_a_credential_error(
        self, stub_auth_server, monkeypatch
    ):
        monkeypatch.setenv("TEST_CLIENT_SECRET", "not-the-secret")
        provider = secret_provider(stub_auth_server, secret="s3cr3t")

        with pytest.raises(CredentialError, match="HTTP 401"):
            await provider.token(PROXY_ITSELF)

    async def test_the_secret_is_not_logged(
        self, stub_auth_server, monkeypatch, caplog
    ):
        monkeypatch.setenv("TEST_CLIENT_SECRET", "s3cr3t")
        provider = secret_provider(stub_auth_server)
        with caplog.at_level(logging.DEBUG, logger="extensible_mcp.credentials"):
            await provider.token(PROXY_ITSELF)
        assert "s3cr3t" not in caplog.text
        assert "correct-token" not in caplog.text


class TestPrivateKeyJWTGrant:
    async def test_the_assertion_is_verified_by_the_authorization_server(
        self, stub_auth_server, tmp_path
    ):
        provider = key_provider(stub_auth_server, tmp_path)

        assert await provider.token(PROXY_ITSELF) == "correct-token"

        (request,) = stub_auth_server.token_requests
        assert request["client_assertion_type"] == (
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        )
        # Nothing replayable was transmitted.
        assert "client_secret" not in request
        (claims,) = stub_auth_server.verified_assertions
        assert claims["iss"] == CLIENT_ID
        assert claims["sub"] == CLIENT_ID
        assert claims["aud"] == stub_auth_server.url
        assert claims["exp"] > claims["iat"]

    async def test_each_acquisition_signs_a_fresh_single_use_assertion(
        self, stub_auth_server, tmp_path
    ):
        """The stub rejects a reused ``jti``, so a second acquisition that
        replayed the first assertion would fail rather than pass quietly."""
        provider = key_provider(stub_auth_server, tmp_path)

        await provider.token(PROXY_ITSELF)
        await provider.token(PROXY_ITSELF, force_refresh=True)

        first, second = stub_auth_server.verified_assertions
        assert first["jti"] != second["jti"]

    async def test_an_rsa_key_signs_with_rs256(self, stub_auth_server, tmp_path):
        private_key_file, public_pem = write_rsa_key(tmp_path)
        stub_auth_server.register_client_key(CLIENT_ID, public_pem, "RS256")
        provider = PrivateKeyJWTOAuthProvider(
            name="corp-as",
            token_endpoint=stub_auth_server.url,
            client_id=CLIENT_ID,
            private_key_file=private_key_file,
        )

        assert await provider.token(PROXY_ITSELF) == "correct-token"
        assert len(stub_auth_server.verified_assertions) == 1

    async def test_a_key_the_server_does_not_know_is_refused(
        self, stub_auth_server, tmp_path
    ):
        """Signing with one key and registering another must not pass: it is
        the check that proves the assertion is really being verified."""
        key_provider(stub_auth_server, tmp_path)
        other_key_file, _ = write_ec_key(tmp_path, name="other.pem")
        provider = PrivateKeyJWTOAuthProvider(
            name="corp-as",
            token_endpoint=stub_auth_server.url,
            client_id=CLIENT_ID,
            private_key_file=other_key_file,
        )

        with pytest.raises(CredentialError, match="HTTP 401"):
            await provider.token(PROXY_ITSELF)

    async def test_a_missing_key_file_is_a_credential_error(
        self, stub_auth_server, tmp_path
    ):
        provider = PrivateKeyJWTOAuthProvider(
            name="corp-as",
            token_endpoint=stub_auth_server.url,
            client_id=CLIENT_ID,
            private_key_file=tmp_path / "nowhere.pem",
        )

        with pytest.raises(CredentialError, match="cannot read private_key_file"):
            await provider.token(PROXY_ITSELF)
        assert stub_auth_server.token_requests == []

    async def test_a_file_that_is_not_a_key_is_a_credential_error(
        self, stub_auth_server, tmp_path
    ):
        not_a_key = tmp_path / "notes.txt"
        not_a_key.write_text("this is not a PEM private key\n")
        provider = PrivateKeyJWTOAuthProvider(
            name="corp-as",
            token_endpoint=stub_auth_server.url,
            client_id=CLIENT_ID,
            private_key_file=not_a_key,
        )

        with pytest.raises(CredentialError, match="not a readable unencrypted PEM"):
            await provider.token(PROXY_ITSELF)

    async def test_an_unsupported_key_type_is_a_credential_error(
        self, stub_auth_server, tmp_path
    ):
        from joserfc.jwk import OKPKey

        key_file = tmp_path / "ed25519.pem"
        key_file.write_bytes(OKPKey.generate_key("Ed25519").as_pem(private=True))
        provider = PrivateKeyJWTOAuthProvider(
            name="corp-as",
            token_endpoint=stub_auth_server.url,
            client_id=CLIENT_ID,
            private_key_file=key_file,
        )

        with pytest.raises(CredentialError, match="supports RSA and EC"):
            await provider.token(PROXY_ITSELF)


class TestCaching:
    async def test_a_token_is_reused_until_it_nears_expiry(
        self, stub_auth_server, tmp_path
    ):
        provider = key_provider(stub_auth_server, tmp_path)

        for _ in range(3):
            assert await provider.token(PROXY_ITSELF) == "correct-token"

        assert len(stub_auth_server.token_requests) == 1

    async def test_force_refresh_reacquires(self, stub_auth_server, tmp_path):
        provider = key_provider(stub_auth_server, tmp_path)
        stub_auth_server.issue = ["first-token", "second-token"]

        assert await provider.token(PROXY_ITSELF) == "first-token"
        assert await provider.token(PROXY_ITSELF, force_refresh=True) == "second-token"
        assert len(stub_auth_server.token_requests) == 2

    async def test_a_token_expiring_within_the_skew_is_reacquired(
        self, stub_auth_server, tmp_path
    ):
        """A token that would expire in flight is not served from the cache."""
        provider = key_provider(stub_auth_server, tmp_path)
        stub_auth_server.expires_in = 5  # well inside EXPIRY_SKEW_SECONDS

        await provider.token(PROXY_ITSELF)
        await provider.token(PROXY_ITSELF)

        assert len(stub_auth_server.token_requests) == 2

    async def test_a_response_without_expires_in_is_cached(
        self, stub_auth_server, tmp_path
    ):
        provider = key_provider(stub_auth_server, tmp_path)
        stub_auth_server.expires_in = None

        await provider.token(PROXY_ITSELF)
        await provider.token(PROXY_ITSELF)

        assert len(stub_auth_server.token_requests) == 1


class TestTheTokenEndpointContract:
    async def test_an_unreachable_endpoint_is_a_credential_error(self, tmp_path):
        private_key_file, _ = write_ec_key(tmp_path)
        provider = PrivateKeyJWTOAuthProvider(
            name="corp-as",
            token_endpoint=closed_port_url(),
            client_id=CLIENT_ID,
            private_key_file=private_key_file,
        )

        with pytest.raises(CredentialError, match="could not be reached"):
            await provider.token(PROXY_ITSELF)

    async def test_a_response_without_an_access_token_is_a_credential_error(
        self, tmp_path
    ):
        private_key_file, _ = write_ec_key(tmp_path)
        provider = PrivateKeyJWTOAuthProvider(
            name="corp-as",
            token_endpoint="http://as.invalid/oauth/token",
            client_id=CLIENT_ID,
            private_key_file=private_key_file,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"token_type": "Bearer"})
            ),
        )

        with pytest.raises(CredentialError, match="no 'access_token'"):
            await provider.token(PROXY_ITSELF)

    async def test_a_non_bearer_token_type_is_refused(self, tmp_path):
        """A DPoP-bound token presented as a bearer would not work, and
        guessing how to present it is worse than failing."""
        private_key_file, _ = write_ec_key(tmp_path)
        provider = PrivateKeyJWTOAuthProvider(
            name="corp-as",
            token_endpoint="http://as.invalid/oauth/token",
            client_id=CLIENT_ID,
            private_key_file=private_key_file,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200, json={"access_token": "t", "token_type": "DPoP"}
                )
            ),
        )

        with pytest.raises(CredentialError, match="unsupported token_type"):
            await provider.token(PROXY_ITSELF)


class TestThePrincipalParameter:
    """The seam takes a principal now so that per-principal credentials
    extend it rather than replace it. Exactly one value exists today."""

    async def test_the_proxy_itself_is_the_only_accepted_principal(
        self, stub_auth_server, tmp_path
    ):
        provider = key_provider(stub_auth_server, tmp_path)

        assert await provider.token(PROXY_ITSELF) == "correct-token"

        for other in ("a-user", None, object(), ProxyItself()):
            with pytest.raises(CredentialError, match="only acquire a credential"):
                await provider.token(other)  # type: ignore[arg-type]

    def test_the_module_exposes_exactly_one_principal(self):
        """Pin it: a second principal value would mean the proxy had grown a
        notion of caller identity, which is a different change."""
        import extensible_mcp.credentials as credentials

        principals = {
            name: value
            for name, value in vars(credentials).items()
            if isinstance(value, ProxyItself)
        }
        assert list(principals) == ["PROXY_ITSELF"]
        assert principals["PROXY_ITSELF"] is PROXY_ITSELF

    async def test_the_auth_flow_presents_the_proxys_own_credential(
        self, stub_auth_server, tmp_path
    ):
        """And the transport passes that one principal, not something else."""
        seen: list[object] = []

        class RecordingProvider:
            async def token(self, principal, *, force_refresh=False):
                seen.append(principal)
                return "t"

        auth = OAuthGrantAuth(RecordingProvider())
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200)), auth=auth
        ) as client:
            await client.get("http://downstream.invalid/mcp")

        assert seen == [PROXY_ITSELF]


class TestBuildProvider:
    def test_private_key_jwt(self, tmp_path):
        provider = build_provider(
            CredentialConfig(
                name="corp-as",
                grant="private_key_jwt",
                token_endpoint="https://as.example.com/oauth/token",
                client_id=CLIENT_ID,
                private_key_file=tmp_path / "k.pem",
            ),
            scope="payments.invoke",
            audience="https://payments.example.com",
        )
        assert isinstance(provider, PrivateKeyJWTOAuthProvider)
        assert provider.scope == "payments.invoke"
        assert provider.audience == "https://payments.example.com"

    def test_client_credentials(self):
        provider = build_provider(
            CredentialConfig(
                name="legacy-as",
                grant="client_credentials",
                token_endpoint="https://legacy.example.com/oauth/token",
                client_id=CLIENT_ID,
                client_secret_env="LEGACY_CLIENT_SECRET",
            )
        )
        assert isinstance(provider, ClientCredentialsOAuthProvider)
        assert provider.client_secret_env == "LEGACY_CLIENT_SECRET"

    def test_an_unimplemented_grant_fails_closed(self):
        """A config naming a grant this build does not implement -- a workload
        identity, say -- is refused, not approximated with another grant."""
        with pytest.raises(CredentialError, match="unsupported grant"):
            build_provider(
                CredentialConfig(
                    name="k8s",
                    grant="workload_identity",
                    token_endpoint="https://as.example.com/oauth/token",
                    client_id=CLIENT_ID,
                )
            )

    def test_a_grant_missing_its_own_field_fails_closed(self):
        with pytest.raises(CredentialError, match="needs 'private_key_file'"):
            build_provider(
                CredentialConfig(
                    name="corp-as",
                    grant="private_key_jwt",
                    token_endpoint="https://as.example.com/oauth/token",
                    client_id=CLIENT_ID,
                )
            )
        with pytest.raises(CredentialError, match="needs 'client_secret_env'"):
            build_provider(
                CredentialConfig(
                    name="legacy-as",
                    grant="client_credentials",
                    token_endpoint="https://legacy.example.com/oauth/token",
                    client_id=CLIENT_ID,
                )
            )


class TestOAuthGrantAuthRefresh:
    """Refresh lives in the transport: a refusal re-acquires and retries once."""

    def _refusing_once(self, presented: list[str]):
        # The header is read here rather than from a stored Request: httpx
        # retries by re-sending the *same* request object, so a later
        # inspection would see only the header it was last given.
        def handler(request: httpx.Request) -> httpx.Response:
            presented.append(request.headers["authorization"])
            if len(presented) == 1:
                return httpx.Response(401, text="Bad bearer")
            return httpx.Response(200, text="ok")

        return handler

    async def test_a_401_reacquires_and_retries_once(
        self, stub_auth_server, tmp_path
    ):
        provider = key_provider(stub_auth_server, tmp_path)
        stub_auth_server.issue = ["stale-token", "fresh-token"]
        presented: list[str] = []

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(self._refusing_once(presented)),
            auth=OAuthGrantAuth(provider),
        ) as client:
            response = await client.post("http://downstream.invalid/mcp")

        assert response.status_code == 200
        assert presented == ["Bearer stale-token", "Bearer fresh-token"]
        # Two acquisitions: the first token, then the replacement.
        assert len(stub_auth_server.token_requests) == 2

    async def test_a_second_refusal_is_not_retried_again(
        self, stub_auth_server, tmp_path
    ):
        """Bounded at one retry: a second refusal means the authorization
        server and the resource server disagree, and a third token will not
        settle it."""
        provider = key_provider(stub_auth_server, tmp_path)
        requests: list[httpx.Request] = []

        def always_401(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(401, text="Bad bearer")

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(always_401),
            auth=OAuthGrantAuth(provider),
        ) as client:
            response = await client.post("http://downstream.invalid/mcp")

        assert response.status_code == 401
        assert len(requests) == 2
        assert len(stub_auth_server.token_requests) == 2

    async def test_a_success_acquires_once_and_does_not_refresh(
        self, stub_auth_server, tmp_path
    ):
        provider = key_provider(stub_auth_server, tmp_path)
        requests: list[httpx.Request] = []

        def ok(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, text="ok")

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(ok), auth=OAuthGrantAuth(provider)
        ) as client:
            await client.post("http://downstream.invalid/mcp")
            await client.post("http://downstream.invalid/mcp")

        assert len(requests) == 2
        assert len(stub_auth_server.token_requests) == 1
