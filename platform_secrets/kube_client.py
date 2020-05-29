import logging
import ssl
from pathlib import Path
from typing import Any, Dict, NoReturn, Optional
from urllib.parse import urlsplit

import aiohttp

from .config import KubeClientAuthType, KubeConfig


logger = logging.getLogger(__name__)


class KubeClientException(Exception):
    pass


class JobException(Exception):
    pass


class JobError(JobException):
    pass


class JobNotFoundException(JobException):
    pass


class KubeClient:
    def __init__(
        self,
        *,
        base_url: str,
        namespace: str,
        cert_authority_path: Optional[str] = None,
        cert_authority_data_pem: Optional[str] = None,
        auth_type: KubeClientAuthType = KubeClientAuthType.CERTIFICATE,
        auth_cert_path: Optional[str] = None,
        auth_cert_key_path: Optional[str] = None,
        token: Optional[str] = None,
        token_path: Optional[str] = None,
        conn_timeout_s: int = 300,
        read_timeout_s: int = 100,
        conn_pool_size: int = 100,
    ) -> None:
        self._base_url = base_url
        self._namespace = namespace

        self._cert_authority_data_pem = cert_authority_data_pem
        self._cert_authority_path = cert_authority_path

        self._auth_type = auth_type
        self._auth_cert_path = auth_cert_path
        self._auth_cert_key_path = auth_cert_key_path
        self._token = token
        self._token_path = token_path

        self._conn_timeout_s = conn_timeout_s
        self._read_timeout_s = read_timeout_s
        self._conn_pool_size = conn_pool_size
        self._client: Optional[aiohttp.ClientSession] = None

    @property
    def _is_ssl(self) -> bool:
        return urlsplit(self._base_url).scheme == "https"

    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self._is_ssl:
            return None
        ssl_context = ssl.create_default_context(
            cafile=self._cert_authority_path, cadata=self._cert_authority_data_pem
        )
        if self._auth_type == KubeClientAuthType.CERTIFICATE:
            ssl_context.load_cert_chain(
                self._auth_cert_path,  # type: ignore
                self._auth_cert_key_path,
            )
        return ssl_context

    async def init(self) -> None:
        self._client = await self.create_http_client()

    async def create_http_client(self) -> aiohttp.ClientSession:
        connector = aiohttp.TCPConnector(
            limit=self._conn_pool_size, ssl=self._create_ssl_context()
        )
        if self._auth_type == KubeClientAuthType.TOKEN:
            token = self._token
            if not token:
                assert self._token_path is not None
                token = Path(self._token_path).read_text()
            headers = {"Authorization": "Bearer " + token}
        else:
            headers = {}
        timeout = aiohttp.ClientTimeout(
            connect=self._conn_timeout_s, total=self._read_timeout_s
        )
        return aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers
        )

    @property
    def namespace(self) -> str:
        return self._namespace

    async def close(self) -> None:
        if self._client:
            await self._client.close()
            self._client = None

    async def __aenter__(self) -> "KubeClient":
        await self.init()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    @property
    def _api_v1_url(self) -> str:
        return f"{self._base_url}/api/v1"

    def _generate_namespace_url(self, namespace_name: str) -> str:
        return f"{self._api_v1_url}/namespaces/{namespace_name}"

    @property
    def _namespace_url(self) -> str:
        return self._generate_namespace_url(self._namespace)

    async def _request(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        assert self._client, "client is not initialized"
        async with self._client.request(*args, **kwargs) as response:
            # TODO (A Danshyn 05/21/18): check status code etc
            payload = await response.json()
            logger.debug("k8s response payload: %s", payload)
            return payload

    async def _check_response_status(self, response: aiohttp.ClientResponse) -> None:
        if response.status != 200:
            payload = await response.text()
            raise KubeClientException(payload)

    def _assert_resource_kind(
        self, expected_kind: str, payload: Dict[str, Any]
    ) -> None:
        kind = payload["kind"]
        if kind == "Status":
            self._raise_status_job_exception(payload, job_id="")
        elif kind != expected_kind:
            raise ValueError(f"unknown kind: {kind}")

    def _raise_status_job_exception(
        self, pod: Dict[str, Any], job_id: Optional[str]
    ) -> NoReturn:
        if pod["code"] == 409:
            raise JobError(f"job '{job_id}' already exist")
        elif pod["code"] == 404:
            raise JobNotFoundException(f"job '{job_id}' was not found")
        elif pod["code"] == 422:
            raise JobError(f"can not create job with id '{job_id}'")
        else:
            raise JobError("unexpected error")
