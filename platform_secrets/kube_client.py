import json
import logging
import ssl
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import aiohttp

from .config import KubeClientAuthType


logger = logging.getLogger(__name__)


SECRET_DUMMY_KEY = "---neuro---"


class KubeClientException(Exception):
    pass


class ResourceNotFound(KubeClientException):
    pass


class ResourceInvalid(KubeClientException):
    pass


class ResourceBadRequest(KubeClientException):
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
        trace_configs: Optional[List[aiohttp.TraceConfig]] = None,
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
        self._trace_configs = trace_configs

        self._client: Optional[aiohttp.ClientSession] = None

        self._dummy_secret_key = SECRET_DUMMY_KEY

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
            connector=connector,
            timeout=timeout,
            headers=headers,
            trace_configs=self._trace_configs,
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

    def _generate_namespace_url(self, namespace_name: Optional[str] = None) -> str:
        namespace_name = namespace_name or self._namespace
        return f"{self._api_v1_url}/namespaces/{namespace_name}"

    def _generate_all_secrets_url(self, namespace_name: Optional[str] = None) -> str:
        namespace_url = self._generate_namespace_url(namespace_name)
        return f"{namespace_url}/secrets"

    def _generate_secret_url(
        self, secret_name: str, namespace_name: Optional[str] = None
    ) -> str:
        all_secrets_url = self._generate_all_secrets_url(namespace_name)
        return f"{all_secrets_url}/{secret_name}"

    async def _request(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        assert self._client, "client is not initialized"
        async with self._client.request(*args, **kwargs) as response:
            # TODO (A Danshyn 05/21/18): check status code etc
            payload = await response.json()
            return payload

    def _raise_for_status(self, payload: Dict[str, Any]) -> None:
        kind = payload["kind"]
        if kind == "Status":
            code = payload["code"]
            if code == 400:
                raise ResourceBadRequest(payload)
            if code == 404:
                raise ResourceNotFound(payload)
            if code == 422:
                raise ResourceInvalid(payload["message"])
            raise KubeClientException(payload["message"])

    async def create_secret(
        self,
        secret_name: str,
        data: Dict[str, str],
        labels: Dict[str, str],
        *,
        namespace_name: Optional[str] = None,
    ) -> None:
        url = self._generate_all_secrets_url(namespace_name)
        data = data.copy()
        data[self._dummy_secret_key] = ""
        payload = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": secret_name, "labels": labels},
            "data": data,
            "type": "Opaque",
        }
        headers = {"Content-Type": "application/json"}
        req_data = BytesIO(json.dumps(payload).encode())
        payload = await self._request(
            method="POST", url=url, headers=headers, data=req_data
        )
        self._raise_for_status(payload)

    async def add_secret_key(
        self,
        secret_name: str,
        key: str,
        value: str,
        *,
        namespace_name: Optional[str] = None,
    ) -> None:
        url = self._generate_secret_url(secret_name, namespace_name)
        headers = {"Content-Type": "application/json-patch+json"}
        patches = [{"op": "add", "path": f"/data/{key}", "value": value}]
        req_data = BytesIO(json.dumps(patches).encode())
        payload = await self._request(
            method="PATCH", url=url, headers=headers, data=req_data
        )
        self._raise_for_status(payload)

    async def remove_secret(
        self, secret_name: str, *, namespace_name: Optional[str] = None
    ) -> None:
        url = self._generate_secret_url(secret_name, namespace_name)
        await self._request(method="DELETE", url=url)

    async def remove_secret_key(
        self, secret_name: str, key: str, *, namespace_name: Optional[str] = None
    ) -> None:
        url = self._generate_secret_url(secret_name, namespace_name)
        headers = {"Content-Type": "application/json-patch+json"}
        patches = [{"op": "remove", "path": f"/data/{key}"}]
        payload = await self._request(
            method="PATCH", url=url, headers=headers, json=patches
        )
        self._raise_for_status(payload)

    def _cleanup_secret_payload(self, payload: Dict[str, Any]) -> None:
        data = payload.get("data", {})
        data.pop(self._dummy_secret_key, None)
        payload["data"] = data

    async def get_secret(
        self, secret_name: str, *, namespace_name: Optional[str] = None
    ) -> Dict[str, Any]:
        url = self._generate_secret_url(secret_name, namespace_name)
        payload = await self._request(method="GET", url=url)
        self._raise_for_status(payload)
        self._cleanup_secret_payload(payload)
        return payload

    async def list_secrets(self) -> List[Dict[str, Any]]:
        url = self._generate_all_secrets_url()
        payload = await self._request(method="GET", url=url)
        self._raise_for_status(payload)
        items = payload.get("items", [])
        for item in items:
            self._cleanup_secret_payload(item)
        return items
