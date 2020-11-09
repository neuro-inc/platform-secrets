from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable, Dict
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
    HTTPUnauthorized,
)

from platform_secrets.api import create_app
from platform_secrets.config import Config

from .conftest import ApiAddress, create_local_app_server
from .conftest_auth import _User


pytestmark = pytest.mark.asyncio


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


class TestApi:
    async def test_ping(
        self, secrets_api: SecretsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.get(secrets_api.ping_url) as resp:
            assert resp.status == HTTPOk.status_code
            text = await resp.text()
            assert text == "Pong"

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

    async def test_get_secrets__forbidden(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory(skip_grant=True)
        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()

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
        async with client.post(secrets_api.endpoint) as resp:
            assert resp.status == HTTPUnauthorized.status_code, await resp.text()

    async def test_post_secret__forbidden(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory(skip_grant=True)
        async with client.post(secrets_api.endpoint, headers=user.headers) as resp:
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
        payload: Dict[str, Any] = {}
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
        payload: Dict[str, Any] = {"key": "kkkk", "value": "vvvv"}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"key": "kkkk"}

        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == [{"key": "kkkk"}]

    async def test_post_secret_replace_remove(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory()

        payload: Dict[str, Any] = {"key": "k1", "value": "vvvv"}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"key": "k1"}

        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            resp_payload = sorted(resp_payload, key=lambda s: s["key"])
            assert resp_payload == [{"key": "k1"}]

        payload = {"key": "k2", "value": "vvvv"}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"key": "k2"}

        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            resp_payload = sorted(resp_payload, key=lambda s: s["key"])
            assert resp_payload == [
                {"key": "k1"},
                {"key": "k2"},
            ]

        payload = {"key": "k1", "value": "rrrr"}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"key": "k1"}

        payload = {"key": "k1", "value": "rrrr"}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"key": "k1"}

        async with client.get(secrets_api.endpoint, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            resp_payload = sorted(resp_payload, key=lambda s: s["key"])
            assert resp_payload == [
                {"key": "k1"},
                {"key": "k2"},
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
                {"key": "k2"},
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
