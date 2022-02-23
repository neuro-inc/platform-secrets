from __future__ import annotations

import asyncio
import logging
import secrets
import subprocess
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from typing import Any

import aiohttp
import aiohttp.web
import pytest
from yarl import URL

from platform_secrets.config import (
    Config,
    CORSConfig,
    KubeConfig,
    PlatformAdminConfig,
    PlatformAuthConfig,
    PlatformConfigConfig,
    ServerConfig,
)

logger = logging.getLogger(__name__)


pytest_plugins = [
    "tests.integration.docker",
    "tests.integration.config",
    "tests.integration.admin",
    "tests.integration.conftest_auth",
    "tests.integration.conftest_kube",
]


@pytest.fixture(scope="session")
def event_loop() -> Iterator[asyncio.AbstractEventLoop]:
    asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
    loop = asyncio.get_event_loop_policy().new_event_loop()
    loop.set_debug(True)
    yield loop
    loop.close()


def random_name(length: int = 8) -> str:
    return secrets.token_hex(length // 2 + length % 2)[:length]


@pytest.fixture
async def client() -> AsyncIterator[aiohttp.ClientSession]:
    async with aiohttp.ClientSession() as session:
        yield session


@pytest.fixture
def config_factory(
    auth_config: PlatformAuthConfig,
    kube_config: KubeConfig,
    cluster_name: str,
    admin_url: URL,
    config_url: URL,
) -> Callable[..., Config]:
    def _f(**kwargs: Any) -> Config:
        defaults = dict(
            server=ServerConfig(host="0.0.0.0", port=8080),
            platform_auth=auth_config,
            platform_admin=PlatformAdminConfig(
                url=admin_url,
                token=auth_config.token,
            ),
            platform_config=PlatformConfigConfig(
                url=config_url,
                token=auth_config.token,
            ),
            kube=kube_config,
            cluster_name=cluster_name,
            cors=CORSConfig(allowed_origins=["https://neu.ro"]),
        )
        kwargs = {**defaults, **kwargs}
        return Config(**kwargs)

    return _f


@pytest.fixture
def config(config_factory: Callable[..., Config]) -> Config:
    return config_factory()


@pytest.fixture
def config_cluster_maintenance(
    config: Config, on_maintenance_cluster_name: str
) -> Config:
    return replace(config, cluster_name=on_maintenance_cluster_name)


@pytest.fixture
def config_org_cluster_maintenance(
    config: Config, on_maintenance_org_cluster_name: str
) -> Config:
    return replace(config, cluster_name=on_maintenance_org_cluster_name)


@dataclass(frozen=True)
class ApiAddress:
    host: str
    port: int


@asynccontextmanager
async def create_local_app_server(
    app: aiohttp.web.Application, port: int = 8080
) -> AsyncIterator[ApiAddress]:
    runner = aiohttp.web.AppRunner(app)
    try:
        await runner.setup()
        api_address = ApiAddress("0.0.0.0", port)
        site = aiohttp.web.TCPSite(runner, api_address.host, api_address.port)
        await site.start()
        yield api_address
    finally:
        await runner.shutdown()
        await runner.cleanup()


class ApiRunner:
    def __init__(self, app: aiohttp.web.Application, port: int) -> None:
        self._app = app
        self._port = port

        self._api_address_future: asyncio.Future[ApiAddress] = asyncio.Future()
        self._cleanup_future: asyncio.Future[None] = asyncio.Future()
        self._task: asyncio.Task[None] | None = None

    async def _run(self) -> None:
        async with create_local_app_server(self._app, port=self._port) as api_address:
            self._api_address_future.set_result(api_address)
            await self._cleanup_future

    async def run(self) -> ApiAddress:
        loop = asyncio.get_event_loop()
        self._task = loop.create_task(self._run())
        return await self._api_address_future

    async def close(self) -> None:
        if self._task:
            task = self._task
            self._task = None
            self._cleanup_future.set_result(None)
            await task

    @property
    def closed(self) -> bool:
        return not bool(self._task)


def get_service_url(service_name: str, namespace: str = "default") -> str:
    # ignore type because the linter does not know that `pytest.fail` throws an
    # exception, so it requires to `return None` explicitly, so that the method
    # will return `Optional[List[str]]` which is incorrect
    timeout_s = 60
    interval_s = 10

    while timeout_s:
        process = subprocess.run(
            ("minikube", "service", "-n", namespace, service_name, "--url"),
            stdout=subprocess.PIPE,
        )
        output = process.stdout
        if output:
            url = output.decode().strip()
            # Sometimes `minikube service ... --url` returns a prefixed
            # string such as: "* https://127.0.0.1:8081/"
            start_idx = url.find("http")
            if start_idx > 0:
                url = url[start_idx:]
            return url
        time.sleep(interval_s)
        timeout_s -= interval_s

    pytest.fail(f"Service {service_name} is unavailable.")


@pytest.fixture
def cluster_name() -> str:
    return "test-cluster"


@pytest.fixture
def on_maintenance_cluster_name() -> str:
    return "cluster-on-maintenance"


@pytest.fixture
def on_maintenance_org_cluster_name() -> str:
    return "cluster-with-org-on-maintenance"
