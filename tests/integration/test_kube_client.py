from __future__ import annotations

import asyncio
import os
import tempfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import aiohttp
import aiohttp.web
import pytest

from platform_secrets.config import KubeClientAuthType
from platform_secrets.kube_client import KubeClient

from .conftest import create_local_app_server

TOKEN_KEY = aiohttp.web.AppKey("token", dict[str, str])


class TestKubeClientTokenUpdater:
    @pytest.fixture
    async def kube_app(self) -> aiohttp.web.Application:
        async def _get_secrets(request: aiohttp.web.Request) -> aiohttp.web.Response:
            auth = request.headers["Authorization"]
            token = auth.split()[-1]
            app[TOKEN_KEY]["value"] = token
            return aiohttp.web.json_response({"kind": "SecretList", "items": []})

        app = aiohttp.web.Application()
        app[TOKEN_KEY] = {"value": ""}
        app.router.add_routes(
            [aiohttp.web.get("/api/v1/namespaces/default/secrets", _get_secrets)]
        )
        return app

    @pytest.fixture
    async def kube_server(
        self, kube_app: aiohttp.web.Application, unused_tcp_port_factory: Any
    ) -> AsyncIterator[str]:
        async with create_local_app_server(
            kube_app, port=unused_tcp_port_factory()
        ) as address:
            yield f"http://{address.host}:{address.port}"

    @pytest.fixture
    def kube_token_path(self) -> Iterator[str]:
        _, path = tempfile.mkstemp()
        Path(path).write_text("token-1")
        yield path
        os.remove(path)

    @pytest.fixture
    async def kube_client(
        self, kube_server: str, kube_token_path: str
    ) -> AsyncIterator[KubeClient]:
        async with KubeClient(
            base_url=kube_server,
            namespace="default",
            auth_type=KubeClientAuthType.TOKEN,
            token_path=kube_token_path,
            token_update_interval_s=1,
        ) as client:
            yield client

    async def test_token_periodically_updated(
        self,
        kube_app: aiohttp.web.Application,
        kube_client: KubeClient,
        kube_token_path: str,
    ) -> None:
        await kube_client.list_secrets()
        assert kube_app[TOKEN_KEY]["value"] == "token-1"

        Path(kube_token_path).write_text("token-2")
        await asyncio.sleep(2)

        await kube_client.list_secrets()
        assert kube_app[TOKEN_KEY]["value"] == "token-2"
