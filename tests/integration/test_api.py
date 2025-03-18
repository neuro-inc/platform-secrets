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
    HTTPUnauthorized,
)

from platform_secrets.api import create_app
from platform_secrets.config import Config
from platform_secrets.service import NO_ORG

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
        project_name: str,
    ) -> None:
        user = await regular_user_factory(skip_grant=True)
        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == []

    async def test_get_secrets__none(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
        project_name: str,
    ) -> None:
        user = await regular_user_factory(project_name="test-project")
        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == []

    async def test_get_secrets__with_org_filter(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
        project_name: str,
    ) -> None:
        user = await regular_user_factory(project_name=project_name)
        payload: dict[str, Any] = {
            "key": "kkkk",
            "value": "vvvv",
            "project_name": project_name,
        }
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()

        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"org_name": "NO_ORG", "project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == [
                {
                    "key": "kkkk",
                    "owner": "test-project",
                    "org_name": NO_ORG,
                    "project_name": project_name,
                }
            ]

        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"org_name": "other-org", "project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == []

    async def test_get_secrets__with_project_filter(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory(project_name="test-project")
        payload: dict[str, Any] = {
            "key": "kkkk",
            "value": "vvvv",
            "project_name": "test-project",
        }
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()

        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"project_name": "test-project"},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == [
                {
                    "key": "kkkk",
                    "owner": "test-project",
                    "org_name": NO_ORG,
                    "project_name": "test-project",
                }
            ]

        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"project_name": "other-project"},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == []

    async def test_post_secret__unauthorized(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        project_name: str,
    ) -> None:
        payload: dict[str, Any] = {
            "key": "kkkk",
            "value": "vvvv",
            "project_name": project_name,
        }
        async with client.post(secrets_api.endpoint, json=payload) as resp:
            assert resp.status == HTTPUnauthorized.status_code, await resp.text()

    async def test_post_project_secret__forbidden(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        payload: dict[str, Any] = {
            "key": "kkkk",
            "value": "vvvv",
            "project_name": "test-project",
        }
        user = await regular_user_factory(skip_grant=True)
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()

    async def test_post_secret__unprocessable_payload(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory(project_name="test-project")
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
        user = await regular_user_factory(project_name="test-project")
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
        project_name: str,
    ) -> None:
        user = await regular_user_factory(project_name="test-project")
        payload: dict[str, Any] = {
            "key": "kkkk",
            "value": "vvvv",
            "project_name": project_name,
        }
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {
                "key": "kkkk",
                "owner": "test-project",
                "org_name": NO_ORG,
                "project_name": project_name,
            }

        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == [
                {
                    "key": "kkkk",
                    "owner": "test-project",
                    "org_name": NO_ORG,
                    "project_name": project_name,
                }
            ]

    async def test_post_secret_with_org(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
        project_name: str,
    ) -> None:
        user = await regular_user_factory(
            org_name="test-org", project_name=project_name
        )
        payload: dict[str, Any] = {
            "key": "kkkk",
            "value": "vvvv",
            "org_name": "test-org",
            "project_name": project_name,
        }
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {
                "key": "kkkk",
                "owner": "test-project",
                "org_name": "test-org",
                "project_name": project_name,
            }

        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"org_name": "test-org", "project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == [
                {
                    "key": "kkkk",
                    "owner": "test-project",
                    "org_name": "test-org",
                    "project_name": project_name,
                }
            ]

    async def test_post_secret_username_with_slash(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
        project_name: str,
    ) -> None:
        base_name = random_name()
        await regular_user_factory(base_name, project_name=project_name)
        user = await regular_user_factory(
            f"{base_name}/something/more", project_name=project_name
        )
        payload: dict[str, Any] = {
            "key": "kkkk",
            "value": "vvvv",
            "project_name": project_name,
        }
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {
                "key": "kkkk",
                "owner": project_name,
                "org_name": NO_ORG,
                "project_name": project_name,
            }

        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == [
                {
                    "key": "kkkk",
                    "owner": project_name,
                    "org_name": NO_ORG,
                    "project_name": project_name,
                }
            ]

    async def test_post_secret_replace_remove(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
        project_name: str,
    ) -> None:
        user = await regular_user_factory(project_name=project_name)

        payload: dict[str, Any] = {
            "key": "k1",
            "value": "vvvv",
            "project_name": project_name,
        }
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {
                "key": "k1",
                "owner": "test-project",
                "org_name": NO_ORG,
                "project_name": project_name,
            }

        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            resp_payload = sorted(resp_payload, key=lambda s: s["key"])
            assert resp_payload == [
                {
                    "key": "k1",
                    "owner": "test-project",
                    "org_name": NO_ORG,
                    "project_name": project_name,
                }
            ]

        payload = {"key": "k2", "value": "vvvv", "project_name": project_name}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {
                "key": "k2",
                "owner": "test-project",
                "org_name": NO_ORG,
                "project_name": project_name,
            }

        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            resp_payload = sorted(resp_payload, key=lambda s: s["key"])
            assert resp_payload == [
                {
                    "key": "k1",
                    "owner": "test-project",
                    "org_name": NO_ORG,
                    "project_name": project_name,
                },
                {
                    "key": "k2",
                    "owner": "test-project",
                    "org_name": NO_ORG,
                    "project_name": project_name,
                },
            ]

        payload = {"key": "k1", "value": "rrrr", "project_name": project_name}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {
                "key": "k1",
                "owner": "test-project",
                "org_name": NO_ORG,
                "project_name": project_name,
            }

        payload = {"key": "k1", "value": "rrrr", "project_name": project_name}
        async with client.post(
            secrets_api.endpoint, headers=user.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {
                "key": "k1",
                "owner": "test-project",
                "org_name": NO_ORG,
                "project_name": project_name,
            }

        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            resp_payload = sorted(resp_payload, key=lambda s: s["key"])
            assert resp_payload == [
                {
                    "key": "k1",
                    "owner": "test-project",
                    "org_name": NO_ORG,
                    "project_name": project_name,
                },
                {
                    "key": "k2",
                    "owner": "test-project",
                    "org_name": NO_ORG,
                    "project_name": project_name,
                },
            ]

        async with client.delete(
            secrets_api.endpoint + "/k1?project_name=test-project", headers=user.headers
        ) as resp:
            assert resp.status == HTTPNoContent.status_code, await resp.text()

        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            resp_payload = sorted(resp_payload, key=lambda s: s["key"])
            assert resp_payload == [
                {
                    "key": "k2",
                    "owner": "test-project",
                    "org_name": NO_ORG,
                    "project_name": project_name,
                },
            ]

        async with client.delete(
            secrets_api.endpoint + "/k2?project_name=test-project", headers=user.headers
        ) as resp:
            assert resp.status == HTTPNoContent.status_code, await resp.text()

        async with client.get(
            secrets_api.endpoint,
            headers=user.headers,
            params={"project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            resp_payload = sorted(resp_payload, key=lambda s: s["key"])
            assert resp_payload == []

    async def test_delete_secret__unauthorized(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        project_name: str,
    ) -> None:
        async with client.delete(
            secrets_api.endpoint + "/key", params={"project_name": project_name}
        ) as resp:
            assert resp.status == HTTPUnauthorized.status_code, await resp.text()

    async def test_delete_secret__forbidden(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
        project_name: str,
    ) -> None:
        user = await regular_user_factory(skip_grant=True)
        async with client.delete(
            secrets_api.endpoint + "/key",
            headers=user.headers,
            params={"project_name": project_name},
        ) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()

    async def test_delete_secret__invalid_key(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
    ) -> None:
        user = await regular_user_factory(project_name="test-project")
        async with client.delete(
            secrets_api.endpoint + "/...?project_name=test-project",
            headers=user.headers,
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
        user = await regular_user_factory(project_name="test-project")
        async with client.delete(
            secrets_api.endpoint + "/unknown?project_name=test-project",
            headers=user.headers,
        ) as resp:
            assert resp.status == HTTPNotFound.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {"error": "Secret 'unknown' not found"}

    async def test__secret_accessible_within_project(
        self,
        secrets_api: SecretsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: Callable[..., Awaitable[_User]],
        share_secret: Callable[[str, str, str], Awaitable[None]],
        project_name: str,
    ) -> None:
        user1 = await regular_user_factory(project_name=project_name)
        user2 = await regular_user_factory(project_name=project_name)

        payload: dict[str, Any] = {
            "key": "k1",
            "value": "vvvv",
            "project_name": project_name,
        }
        async with client.post(
            secrets_api.endpoint, headers=user1.headers, json=payload
        ) as resp:
            assert resp.status == HTTPCreated.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == {
                "key": "k1",
                "owner": project_name,
                "org_name": NO_ORG,
                "project_name": project_name,
            }

        async with client.get(
            secrets_api.endpoint,
            headers=user1.headers,
            params={"project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == [
                {
                    "key": "k1",
                    "owner": project_name,
                    "org_name": NO_ORG,
                    "project_name": project_name,
                },
            ]

        async with client.get(
            secrets_api.endpoint,
            headers=user2.headers,
            params={"project_name": project_name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            resp_payload = await resp.json()
            assert resp_payload == [
                {
                    "key": "k1",
                    "owner": project_name,
                    "org_name": NO_ORG,
                    "project_name": project_name,
                },
            ]
