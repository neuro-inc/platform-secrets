from dataclasses import dataclass
from typing import AsyncIterator, Callable

import aiohttp
import pytest
from aiohttp.web import HTTPOk
from aiohttp.web_exceptions import HTTPForbidden, HTTPUnauthorized
from yarl import URL

from platform_secrets.api import create_app
from platform_secrets.config import Config

from .conftest import ApiAddress, create_local_app_server


@dataclass(frozen=True)
class MonitoringApiEndpoints:
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
        return f"{self.api_v1_endpoint}/jobs"

    def generate_top_url(self, job_id: str) -> str:
        return f"{self.endpoint}/{job_id}/top"

    def generate_log_url(self, job_id: str) -> str:
        return f"{self.endpoint}/{job_id}/log"

    def generate_save_url(self, job_id: str) -> str:
        return f"{self.endpoint}/{job_id}/save"


@dataclass(frozen=True)
class PlatformApiEndpoints:
    url: URL

    @property
    def endpoint(self) -> str:
        return str(self.url)

    @property
    def platform_config_url(self) -> str:
        return f"{self.endpoint}/config"

    @property
    def jobs_base_url(self) -> str:
        return f"{self.endpoint}/jobs"

    def generate_job_url(self, job_id: str) -> str:
        return f"{self.jobs_base_url}/{job_id}"


@pytest.fixture
async def secrets_api(config: Config) -> AsyncIterator[MonitoringApiEndpoints]:
    app = await create_app(config)
    async with create_local_app_server(app, port=8080) as address:
        yield MonitoringApiEndpoints(address=address)


class TestApi:
    @pytest.mark.asyncio
    async def test_ping(
        self, monitoring_api: MonitoringApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.get(monitoring_api.ping_url) as resp:
            assert resp.status == HTTPOk.status_code
            text = await resp.text()
            assert text == "Pong"

    @pytest.mark.asyncio
    async def test_secured_ping(
        self,
        monitoring_api: MonitoringApiEndpoints,
        client: aiohttp.ClientSession,
        admin_token: str,
    ) -> None:
        headers = {"Authorization": f"Bearer {admin_token}"}
        async with client.get(monitoring_api.secured_ping_url, headers=headers) as resp:
            assert resp.status == HTTPOk.status_code
            text = await resp.text()
            assert text == "Secured Pong"

    @pytest.mark.asyncio
    async def test_secured_ping_no_token_provided_unauthorized(
        self, monitoring_api: MonitoringApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        url = monitoring_api.secured_ping_url
        async with client.get(url) as resp:
            assert resp.status == HTTPUnauthorized.status_code

    @pytest.mark.asyncio
    async def test_secured_ping_non_existing_token_unauthorized(
        self,
        monitoring_api: MonitoringApiEndpoints,
        client: aiohttp.ClientSession,
        token_factory: Callable[[str], str],
    ) -> None:
        url = monitoring_api.secured_ping_url
        token = token_factory("non-existing-user")
        headers = {"Authorization": f"Bearer {token}"}
        async with client.get(url, headers=headers) as resp:
            assert resp.status == HTTPUnauthorized.status_code

    @pytest.mark.asyncio
    async def test_ping_unknown_origin(
        self, monitoring_api: MonitoringApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.get(
            monitoring_api.ping_url, headers={"Origin": "http://unknown"}
        ) as response:
            assert response.status == HTTPOk.status_code, await response.text()
            assert "Access-Control-Allow-Origin" not in response.headers

    @pytest.mark.asyncio
    async def test_ping_allowed_origin(
        self, monitoring_api: MonitoringApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.get(
            monitoring_api.ping_url, headers={"Origin": "https://neu.ro"}
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            assert resp.headers["Access-Control-Allow-Origin"] == "https://neu.ro"
            assert resp.headers["Access-Control-Allow-Credentials"] == "true"
            assert resp.headers["Access-Control-Expose-Headers"] == ""

    @pytest.mark.asyncio
    async def test_ping_options_no_headers(
        self, monitoring_api: MonitoringApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.options(monitoring_api.ping_url) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()
            assert await resp.text() == (
                "CORS preflight request failed: "
                "origin header is not specified in the request"
            )

    @pytest.mark.asyncio
    async def test_ping_options_unknown_origin(
        self, monitoring_api: MonitoringApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.options(
            monitoring_api.ping_url,
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

    @pytest.mark.asyncio
    async def test_ping_options(
        self, monitoring_api: MonitoringApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.options(
            monitoring_api.ping_url,
            headers={
                "Origin": "https://neu.ro",
                "Access-Control-Request-Method": "GET",
            },
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            assert resp.headers["Access-Control-Allow-Origin"] == "https://neu.ro"
            assert resp.headers["Access-Control-Allow-Credentials"] == "true"
            assert resp.headers["Access-Control-Allow-Methods"] == "GET"
