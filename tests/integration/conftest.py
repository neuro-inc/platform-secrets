import logging
import os
import secrets
import subprocess
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import aiohttp
import aiohttp.web
import pytest

from platform_secrets.config import Config, KubeConfig, PlatformAuthConfig, ServerConfig

logger = logging.getLogger(__name__)


pytest_plugins = [
    "tests.integration.conftest_auth",
    "tests.integration.conftest_kube",
]


def random_name(length: int = 8) -> str:
    return secrets.token_hex(length // 2 + length % 2)[:length]


@pytest.fixture
async def client() -> AsyncIterator[aiohttp.ClientSession]:
    async with aiohttp.ClientSession() as session:
        yield session


@pytest.fixture
def config_factory(
    auth_config: PlatformAuthConfig, kube_config: KubeConfig, cluster_name: str
) -> Callable[..., Config]:
    def _f(**kwargs: Any) -> Config:
        defaults = {
            "server": ServerConfig(host="0.0.0.0", port=8080),
            "platform_auth": auth_config,
            "kube": kube_config,
            "cluster_name": cluster_name,
        }
        kwargs = {**defaults, **kwargs}
        return Config(**kwargs)

    return _f


@pytest.fixture
def config(config_factory: Callable[..., Config]) -> Config:
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


def get_service_url(service_name: str, namespace: str = "default") -> str:
    # ignore type because the linter does not know that `pytest.fail` throws an
    # exception, so it requires to `return None` explicitly, so that the method
    # will return `Optional[List[str]]` which is incorrect
    timeout_s = 60
    interval_s = 10

    process = subprocess.Popen(
        ("minikube", "service", "-n", namespace, service_name, "--url"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setpgrp,
    )
    stdout = process.stdout
    assert stdout
    while timeout_s:
        output = stdout.readline()
        url = output.decode().strip()
        # Sometimes `minikube service ... --url` returns a prefixed
        # string such as: "* https://127.0.0.1:8081/"
        start_idx = url.find("http")
        if start_idx >= 0:
            url = url[start_idx:]
            return url

        time.sleep(interval_s)
        timeout_s -= interval_s

    pytest.fail(f"Service {service_name} is unavailable.")


@pytest.fixture
def cluster_name() -> str:
    return "test-cluster"
