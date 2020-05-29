import asyncio
import logging
import subprocess
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Iterator
from uuid import uuid1

import aiohttp
import aiohttp.web
import pytest
from async_timeout import timeout
from yarl import URL

from platform_secrets.config import (
    Config,
    CORSConfig,
    KubeConfig,
    PlatformAuthConfig,
    ServerConfig,
)


logger = logging.getLogger(__name__)


pytest_plugins = [
    "tests.integration.conftest_auth",
    "tests.integration.conftest_kube",
]


@pytest.fixture(scope="session")
def event_loop() -> Iterator[asyncio.AbstractEventLoop]:
    """ This fixture fixes scope mismatch error with implicitly added "event_loop".
    see https://github.com/pytest-dev/pytest-asyncio/issues/68
    """
    asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
    loop = asyncio.get_event_loop_policy().new_event_loop()
    loop.set_debug(True)

    watcher = asyncio.SafeChildWatcher()
    watcher.attach_loop(loop)
    asyncio.get_event_loop_policy().set_child_watcher(watcher)

    yield loop
    loop.close()


def random_str(length: int = 8) -> str:
    return str(uuid1())[:length]


@pytest.fixture
async def client() -> AsyncIterator[aiohttp.ClientSession]:
    async with aiohttp.ClientSession() as session:
        yield session


async def wait_for_service(
    service_name: str,
    service_ping_url: URL,
    timeout_s: float = 30,
    interval_s: float = 1,
) -> None:
    async with timeout(timeout_s):
        while True:
            try:
                async with aiohttp.ClientSession() as client:
                    async with client.get(service_ping_url) as resp:
                        assert resp.status == aiohttp.web.HTTPOk.status_code
                        return
            except aiohttp.ClientError as e:
                logging.info(
                    f"Failed to ping service '{service_name}' "
                    f"via url '{service_ping_url}': {e}"
                )
                pass
            await asyncio.sleep(interval_s)


@pytest.fixture
def config_factory(
    auth_config: PlatformAuthConfig, kube_config: KubeConfig, cluster_name: str,
) -> Callable[..., Config]:
    def _f(**kwargs: Any) -> Config:
        defaults = dict(
            server=ServerConfig(host="0.0.0.0", port=8080),
            platform_auth=auth_config,
            kube=kube_config,
            cluster_name=cluster_name,
            cors=CORSConfig(allowed_origins=["https://neu.ro"]),
        )
        kwargs = {**defaults, **kwargs}
        return Config(**kwargs)

    return _f


@pytest.fixture
def config(config_factory: Callable[..., Config],) -> Config:
    return config_factory()


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


def get_service_url(  # type: ignore
    service_name: str, namespace: str = "default"
) -> str:
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
