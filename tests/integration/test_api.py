from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from unittest import mock

import aiohttp
import pytest
from aiohttp.web import HTTPOk
from aiohttp.web_exceptions import (
    HTTPBadRequest,
    HTTPCreated,
    HTTPForbidden,
    HTTPNoContent,
    HTTPNotFound,
    HTTPServiceUnavailable,
    HTTPUnauthorized,
)

from platform_secrets.api import create_app
from platform_secrets.config import Config

from .conftest import ApiAddress, create_local_app_server, random_name
from .conftest_auth import _User


@dataclass(frozen=True)
class SecretsApiEndpoints:
    address: ApiAddress

    @property
    def api_v1_endpoint(self) -> str:
        return f"http://{self.address.host}:{self.address.port}/api/v1"

    @property
    def ping_url(self) -> str:
        return f"{self.api_v1_endpoint}/ping"

    @property
    def secured_ping_url(self) -> str:
        return f"{self.api_v1_endpoint}/secured-ping"

    @property
    def endpoint(self) -> str:
        return f"{self.api_v1_endpoint}/secrets"


@pytest.fixture
async def secrets_api(config: Config) -> AsyncIterator[SecretsApiEndpoints]:
    app = await create_app(config)
    async with create_local_app_server(app, port=8080) as address:
        yield SecretsApiEndpoints(address=address)


@pytest.fixture
async def secrets_api_cluster_maintenance(
    config_cluster_maintenance: Config,
) -> AsyncIterator[SecretsApiEndpoints]:
    app = await create_app(config_cluster_maintenance)
    async with create_local_app_server(app, port=8081) as address:
        yield SecretsApiEndpoints(address=address)


@pytest.fixture
async def secrets_api_org_cluster_maintenance(
    config_org_cluster_maintenance: Config,
) -> AsyncIterator[SecretsApiEndpoints]:
    app = await create_app(config_org_cluster_maintenance)
    async with create_local_app_server(app, port=8082) as address:
        yield SecretsApiEndpoints(address=address)


class TestApi:
    async def test_ping(
        self, secrets_api: SecretsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.get(secrets_api.ping_url) as resp:
            assert resp.status == HTTPOk.status_code
            text = await resp.text()
            assert text == "Pong"

    async def test_ping_includes_version(
        self, secrets_api: SecretsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.get(secrets_api.ping_url) as resp:
            assert resp.status == HTTPOk.status_code
            assert "platform-secrets" in resp.headers["X-Service-Version"]

    async def test_secured_ping(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        admin_token: str,
    ) -> None:
        headers = {"Authorization": f"Bearer {admin_token}"}
        async with client.get(secrets_api.secured_ping_url, headers=headers) as resp:
            assert resp.status == HTTPOk.status_code
            text = await resp.text()
            assert text == "Secured Pong"

    async def test_secured_ping_no_token_provided_unauthorized(
        self, secrets_api: SecretsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        url = secrets_api.secured_ping_url
        async with client.get(url) as resp:
            assert resp.status == HTTPUnauthorized.status_code

    async def test_secured_ping_non_existing_token_unauthorized(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        token_factory: Callable[[str], str],
    ) -> None:
        url = secrets_api.secured_ping_url
        token = token_factory("non-existing-user")
        headers = {"Authorization": f"Bearer {token}"}
        async with client.get(url, headers=headers) as resp:
            assert resp.status == HTTPUnauthorized.status_code

    async def test_ping_unknown_origin(
        self, secrets_api: SecretsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.get(
            secrets_api.ping_url, headers={"Origin": "http://unknown"}
        ) as response:
            assert response.status == HTTPOk.status_code, await response.text()
            assert "Access-Control-Allow-Origin" not in response.headers

    async def test_ping_allowed_origin(
        self, secrets_api: SecretsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.get(
            secrets_api.ping_url, headers={"Origin": "https://neu.ro"}
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            assert resp.headers["Access-Control-Allow-Origin"] == "https://neu.ro"
            assert resp.headers["Access-Control-Allow-Credentials"] == "true"
            # TODO: re-enable this when aiohttp-cors is updated
            # assert resp.headers["Access-Control-Expose-Headers"] == ""

    async def test_ping_options_no_headers(
        self, secrets_api: SecretsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.options(secrets_api.ping_url) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()
            assert await resp.text() == (
                "CORS preflight request failed: "
                "origin header is not specified in the request"
            )

    async def test_ping_options_unknown_origin(
        self, secrets_api: SecretsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.options(
            secrets_api.ping_url,
            headers={
                "Origin": "http://unknown",
                "Access-Control-Request-Method": "GET",
            },
        ) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()
            assert await resp.text() == (
                "CORS preflight request failed: "
                "origin 'http://unknown' is not allowed"
            )

    async def test_ping_options(
        self, secrets_api: SecretsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.options(
            secrets_api.ping_url,
            headers={
                "Origin": "https://neu.ro",
                "Access-Control-Request-Method": "GET",
            },
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            assert resp.headers["Access-Control-Allow-Origin"] == "https://neu.ro"
            assert resp.headers["Access-Control-Allow-Credentials"] == "true"
            assert resp.headers["Access-Control-Allow-Methods"] == "GET"

    async def test_get_secrets__unauthorized(
        self, secrets_api: SecretsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.get(secrets_api.endpoint) as resp:
            assert resp.status == HTTPUnauthorized.status_code, await resp.text()

    async def test_get_secrets__no_permissions(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory(skip_grant=True)
        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == []

    async def test_get_secrets__none(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory()
        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == []

    async def test_post_secret__unauthorized(
        self, secrets_api: SecretsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        payload: dict[str, Any] = {"key": "kkkk", "value": "vvvv"}
        async with client.post(secrets_api.endpoint, json=payload) as resp:
            assert resp.status == HTTPUnauthorized.status_code, await resp.text()

    async def test_post_secret__forbidden(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        payload: dict[str, Any] = {"key": "kkkk", "value": "vvvv"}
        user = await regular_user_factory(skip_grant=True)
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()

    async def test_post_secret__unprocessible_payload(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory()
        async with client.post(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPBadRequest.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"error": mock.ANY}
            assert "Expecting value" in resp_payload["error"]

    async def test_post_secret__invalid_payload(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory()
        payload: dict[str, Any] = {}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPBadRequest.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"error": mock.ANY}
            assert "is required" in resp_payload["error"]

    async def test_post_secret(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory()
        payload: dict[str, Any] = {"key": "kkkk", "value": "vvvv"}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"key": "kkkk", "owner": user.name, "org_name": None}

        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == [
                {"key": "kkkk", "owner": user.name, "org_name": None}
            ]

    async def test_post_secret_with_org(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory(org_name="test-org")
        payload: dict[str, Any] = {
            "key": "kkkk",
            "value": "vvvv",
            "org_name": "test-org",
        }
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {
                "key": "kkkk",
                "owner": user.name,
                "org_name": "test-org",
            }

        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == [
                {"key": "kkkk", "owner": user.name, "org_name": "test-org"}
            ]

    async def test_post_secret_username_with_slash(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        base_name = random_name()
        await regular_user_factory(base_name)
        user = await regular_user_factory(f"{base_name}/something/more")
        payload: dict[str, Any] = {"key": "kkkk", "value": "vvvv"}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"key": "kkkk", "owner": user.name, "org_name": None}

        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == [
                {"key": "kkkk", "owner": user.name, "org_name": None}
            ]

    async def test_post_secret_replace_remove(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory()

        payload: dict[str, Any] = {"key": "k1", "value": "vvvv"}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"key": "k1", "owner": user.name, "org_name": None}

        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            resp_payload = sorted(resp_payload, key=lambda s: s["key"])
            assert resp_payload == [{"key": "k1", "owner": user.name, "org_name": None}]

        payload = {"key": "k2", "value": "vvvv"}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"key": "k2", "owner": user.name, "org_name": None}

        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            resp_payload = sorted(resp_payload, key=lambda s: s["key"])
            assert resp_payload == [
                {"key": "k1", "owner": user.name, "org_name": None},
                {"key": "k2", "owner": user.name, "org_name": None},
            ]

        payload = {"key": "k1", "value": "rrrr"}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"key": "k1", "owner": user.name, "org_name": None}

        payload = {"key": "k1", "value": "rrrr"}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"key": "k1", "owner": user.name, "org_name": None}

        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            resp_payload = sorted(resp_payload, key=lambda s: s["key"])
            assert resp_payload == [
                {"key": "k1", "owner": user.name, "org_name": None},
                {"key": "k2", "owner": user.name, "org_name": None},
            ]

        async with client.delete(
            secrets_api.endpoint + "/k1", headers=user.headers
        ) as resp:
            assert resp.status == HTTPNoContent.status_code, await resp.text()

        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            resp_payload = sorted(resp_payload, key=lambda s: s["key"])
            assert resp_payload == [
                {"key": "k2", "owner": user.name, "org_name": None},
            ]

        async with client.delete(
            secrets_api.endpoint + "/k2", headers=user.headers
        ) as resp:
            assert resp.status == HTTPNoContent.status_code, await resp.text()

        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            resp_payload = sorted(resp_payload, key=lambda s: s["key"])
            assert resp_payload == []

    async def test_delete_secret__unauthorized(
        self, secrets_api: SecretsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.delete(secrets_api.endpoint + "/key") as resp:
            assert resp.status == HTTPUnauthorized.status_code, await resp.text()

    async def test_delete_secret__forbidden(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory(skip_grant=True)
        async with client.delete(
            secrets_api.endpoint + "/key", headers=user.headers
        ) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()

    async def test_delete_secret__invalid_key(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory()
        async with client.delete(
            secrets_api.endpoint + "/...", headers=user.headers
        ) as resp:
            assert resp.status == HTTPBadRequest.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"error": mock.ANY}
            assert "does not match pattern" in resp_payload["error"]

    async def test_delete_secret__not_found(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory()
        async with client.delete(
            secrets_api.endpoint + "/unknown", headers=user.headers
        ) as resp:
            assert resp.status == HTTPNotFound.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"error": "Secret 'unknown' not found"}

    async def test_shared_secret(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
        share_secret: Callable[[str, str, str], Awaitable[None]],
    ) -> None:
        user1 = await regular_user_factory()
        user2 = await regular_user_factory()

        payload: dict[str, Any] = {"key": "k1", "value": "vvvv"}
        async with client.post(
            secrets_api.endpoint, headers=user1.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"key": "k1", "owner": user1.name, "org_name": None}

        async with client.get(secrets_api.endpoint, headers=user2.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == []

        await share_secret(user2.name, user1.name, "k1")

        async with client.get(secrets_api.endpoint, headers=user2.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == [
                {"key": "k1", "owner": user1.name, "org_name": None},
            ]

    async def test_org_level_access(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
        share_secret: Callable[[str, str, str], Awaitable[None]],
    ) -> None:
        org_name = random_name(5)
        user1 = await regular_user_factory(org_name=org_name)
        user2 = await regular_user_factory(org_name=org_name)
        user3 = await regular_user_factory(org_name=org_name, org_level=True)

        payload: dict[str, Any] = {"key": "k1", "value": "vvvv", "org_name": org_name}
        async with client.post(
            secrets_api.endpoint, headers=user1.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {
                "key": "k1",
                "owner": user1.name,
                "org_name": org_name,
            }

        async with client.post(
            secrets_api.endpoint, headers=user2.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {
                "key": "k1",
                "owner": user2.name,
                "org_name": org_name,
            }

        async with client.get(secrets_api.endpoint, headers=user3.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert len(resp_payload) == 2
            if resp_payload[0]["owner"] == user2.name:
                resp_payload[0], resp_payload[1] = resp_payload[1], resp_payload[0]
            assert resp_payload == [
                {"key": "k1", "owner": user1.name, "org_name": org_name},
                {"key": "k1", "owner": user2.name, "org_name": org_name},
            ]

    async def test_post_secret_cluster_maintenance(
        self,
        secrets_api_cluster_maintenance: SecretsApiEndpoints,
        on_maintenance_cluster_name: str,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory(
            override_cluster_name=on_maintenance_cluster_name
        )
        payload: dict[str, Any] = {"key": "kkkk", "value": "vvvv"}
        async with client.post(
            secrets_api_cluster_maintenance.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPServiceUnavailable.status_code, await resp.text()
            resp_payload = await resp.json()
            assert "maintenance" in resp_payload["error"]

    async def test_post_secret_org_cluster_maintenance(
        self,
        secrets_api_org_cluster_maintenance: SecretsApiEndpoints,
        on_maintenance_org_cluster_name: str,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory(
            override_cluster_name=on_maintenance_org_cluster_name, org_name="org"
        )
        payload: dict[str, Any] = {"key": "kkkk", "value": "vvvv", "org_name": "org"}
        async with client.post(
            secrets_api_org_cluster_maintenance.endpoint,
            headers=user.headers,
            json=payload,
        ) as resp:
            assert resp.status == HTTPServiceUnavailable.status_code, await resp.text()
            resp_payload = await resp.json()
            assert "maintenance" in resp_payload["error"]

    async def test_post_secret_org_cluster_maintenance_ok_base_cluster(
        self,
        secrets_api_org_cluster_maintenance: SecretsApiEndpoints,
        on_maintenance_org_cluster_name: str,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory(
            override_cluster_name=on_maintenance_org_cluster_name
        )
        payload: dict[str, Any] = {"key": "kkkk", "value": "vvvv"}
        async with client.post(
            secrets_api_org_cluster_maintenance.endpoint,
            headers=user.headers,
            json=payload,
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
