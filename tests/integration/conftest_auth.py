from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass

import pytest
from aiohttp.hdrs import AUTHORIZATION
from jose import jwt
from neuro_auth_client import AuthClient, Permission, User as AuthClientUser
from yarl import URL

from platform_secrets.config import PlatformAuthConfig
from tests.integration.conftest import get_service_url, random_name


@pytest.fixture(scope="session")
def token_factory() -> Iterator[Callable[[str], str]]:
    def _factory(name: str) -> str:
        payload = {"identity": name}
        return jwt.encode(payload, "secret", algorithm="HS256")

    yield _factory


@pytest.fixture(scope="session")
def admin_token(token_factory: Callable[[str], str]) -> str:
    return token_factory("admin")


@pytest.fixture(scope="session")
def compute_token(token_factory: Callable[[str], str]) -> str:
    return token_factory("compute")


@pytest.fixture(scope="session")
def auth_config(token_factory: Callable[[str], str]) -> Iterator[PlatformAuthConfig]:
    platform_auth = get_service_url("platformauthapi", namespace="default")
    yield PlatformAuthConfig(
        url=URL(platform_auth),
        token=token_factory("compute"),  # token is hard-coded in the yaml configuration
    )


@pytest.fixture
async def auth_client(
    auth_config: PlatformAuthConfig,
) -> AsyncGenerator[AuthClient]:
    async with AuthClient(auth_config.url, auth_config.token) as client:
        await client.ping()
        yield client


@dataclass(frozen=True)
class _User(AuthClientUser):
    token: str = ""

    @property
    def headers(self) -> dict[str, str]:
        return {AUTHORIZATION: f"Bearer {self.token}"}


@pytest.fixture
async def regular_user_factory(
    auth_client: AuthClient,
    token_factory: Callable[[str], str],
    admin_token: str,
    cluster_name: str,
) -> AsyncIterator[Callable[[str | None], Awaitable[_User]]]:
    async def _factory(
        name: str | None = None,
        skip_grant: bool = False,
        org_name: str | None = None,
        org_level: bool = False,
        project_name: str | None = None,
    ) -> _User:
        if not name:
            name = f"user-{random_name()}"
        user = AuthClientUser(name=name)
        await auth_client.add_user(user, token=admin_token)
        if not skip_grant:
            org_path = f"/{org_name}" if org_name else ""
            project_path = f"/{project_name}" if project_name else ""
            name_path = "" if org_level else f"/{name}"
            permissions = [
                Permission(uri=f"secret://{cluster_name}/{name}", action="write")
            ]
            if org_path:
                permissions.append(
                    Permission(
                        uri=f"secret://{cluster_name}{org_path}{name_path}",
                        action="write",
                    )
                )
            if project_path:
                permissions.append(
                    Permission(
                        uri=f"secret://{cluster_name}{org_path}{project_path}",
                        action="write",
                    )
                )
            await auth_client.grant_user_permissions(
                name, permissions, token=admin_token
            )

        return _User(name=user.name, token=token_factory(user.name))

    yield _factory


@pytest.fixture
async def share_secret(
    auth_client: AuthClient,
    token_factory: Callable[[str], str],
    admin_token: str,
    cluster_name: str,
) -> AsyncIterator[Callable[[str, str, str], Awaitable[None]]]:
    async def _do_grant(username: str, owner: str, key: str) -> None:
        permission = Permission(
            uri=f"secret://{cluster_name}/{owner}/{key}", action="write"
        )
        await auth_client.grant_user_permissions(
            username, [permission], token=admin_token
        )

    yield _do_grant


@pytest.fixture
async def share_project(
    auth_client: AuthClient,
    token_factory: Callable[[str], str],
    admin_token: str,
    cluster_name: str,
) -> AsyncIterator[Callable[[str, str], Awaitable[None]]]:
    async def _do_grant(username: str, project: str) -> None:
        permission = Permission(
            uri=f"secret://{cluster_name}/{project}", action="write"
        )
        await auth_client.grant_user_permissions(
            username, [permission], token=admin_token
        )

    yield _do_grant
