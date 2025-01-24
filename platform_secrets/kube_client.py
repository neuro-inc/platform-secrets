import asyncio
import json
import logging
import ssl
import typing
from contextlib import suppress
from io import BytesIO
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import urlsplit

import aiohttp
from yarl import URL

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


class ResourceConflict(KubeClientException):
    pass


class KubeClientUnauthorized(Exception):
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
        token_update_interval_s: int = 300,
        conn_timeout_s: int = 300,
        read_timeout_s: int = 100,
        conn_pool_size: int = 100,
        trace_configs: Optional[list[aiohttp.TraceConfig]] = None,
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
        self._token_update_interval_s = token_update_interval_s

        self._conn_timeout_s = conn_timeout_s
        self._read_timeout_s = read_timeout_s
        self._conn_pool_size = conn_pool_size
        self._trace_configs = trace_configs

        self._client: Optional[aiohttp.ClientSession] = None
        self._token_updater_task: Optional[asyncio.Task[None]] = None

        self._dummy_secret_key = SECRET_DUMMY_KEY

    @property
    def _is_ssl(self) -> bool:
        return urlsplit(self._base_url).scheme == "https"

    def _create_ssl_context(self) -> Union[bool, ssl.SSLContext]:
        if not self._is_ssl:
            return True
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
        connector = aiohttp.TCPConnector(
            limit=self._conn_pool_size, ssl=self._create_ssl_context()
        )
        if self._token_path:
            self._token = self._token_from_path()
            self._token_updater_task = asyncio.create_task(self._start_token_updater())
        timeout = aiohttp.ClientTimeout(
            connect=self._conn_timeout_s, total=self._read_timeout_s
        )
        self._client = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            trace_configs=self._trace_configs,
        )

    async def _start_token_updater(self) -> None:
        if not self._token_path:
            return
        while True:
            try:
                token = self._token_from_path()
                if token != self._token:
                    self._token = token
                    logger.info("Kube token was refreshed")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception("Failed to update kube token: %s", exc)
            await asyncio.sleep(self._token_update_interval_s)

    def _token_from_path(self) -> str:
        token_path = typing.cast(str, self._token_path)
        return Path(token_path).read_text().strip()

    @property
    def namespace(self) -> str:
        return self._namespace

    async def close(self) -> None:
        if self._client:
            await self._client.close()
            self._client = None
        if self._token_updater_task:
            self._token_updater_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._token_updater_task
            self._token_updater_task = None

    async def __aenter__(self) -> "KubeClient":
        await self.init()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    @property
    def _api_v1_url(self) -> str:
        return f"{self._base_url}/api/v1"

    @property
    def _namespaces_url(self) -> str:
        return f"{self._api_v1_url}/namespaces"

    def _generate_namespace_url(self, namespace_name: Optional[str] = None) -> str:
        namespace_name = namespace_name or self._namespace
        return f"{self._namespaces_url}/{namespace_name}"

    def _generate_all_secrets_url(self, namespace_name: Optional[str] = None) -> str:
        namespace_url = self._generate_namespace_url(namespace_name)
        return f"{namespace_url}/secrets"

    def _generate_secret_url(
        self, secret_name: str, namespace_name: Optional[str] = None
    ) -> str:
        all_secrets_url = self._generate_all_secrets_url(namespace_name)
        return f"{all_secrets_url}/{secret_name}"

    def _create_headers(
        self, headers: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        headers = dict(headers) if headers else {}
        if self._auth_type == KubeClientAuthType.TOKEN and self._token:
            headers["Authorization"] = "Bearer " + self._token
        return headers

    async def _request(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        headers = self._create_headers(kwargs.pop("headers", None))
        assert self._client, "client is not initialized"
        async with self._client.request(*args, headers=headers, **kwargs) as response:
            payload = await response.json()
            logging.debug("k8s response payload: %s", payload)
            self._raise_for_status(payload)
            return payload

    def _raise_for_status(self, payload: dict[str, Any]) -> None:
        kind = payload["kind"]
        if kind == "Status":
            if payload.get("status") == "Success":
                return
            code = payload.get("code")
            if code == 400:
                raise ResourceBadRequest(payload)
            if code == 401:
                raise KubeClientUnauthorized(payload)
            if code == 404:
                raise ResourceNotFound(payload)
            if code == 422:
                raise ResourceInvalid(payload["message"])
            if code == 409:
                raise ResourceConflict(payload["message"])
            raise KubeClientException(payload["message"])

    async def create_secret(
        self,
        secret_name: str,
        data: Union[str, dict[str, str]],
        labels: dict[str, str],
        *,
        namespace_name: Optional[str] = None,
        replace_on_conflict: bool = False,
    ) -> None:
        url = self._generate_all_secrets_url(namespace_name)
        if isinstance(data, dict):
            data_payload = data.copy()
            data_payload[self._dummy_secret_key] = ""
        else:
            data_payload = {secret_name: data}

        payload = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": secret_name, "labels": labels},
            "data": data_payload,
            "type": "Opaque",
        }
        try:
            await self._request(method="POST", url=url, json=payload)
        except ResourceConflict as e:
            if not replace_on_conflict:
                raise e
            # replace a secret
            url = f"{url}/{secret_name}"
            await self._request(method="PUT", url=url, json=payload)

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
        await self._request(method="PATCH", url=url, headers=headers, data=req_data)

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
        await self._request(method="PATCH", url=url, headers=headers, json=patches)

    def _cleanup_secret_payload(self, payload: dict[str, Any]) -> None:
        data = payload.get("data", {})
        data.pop(self._dummy_secret_key, None)
        payload["data"] = data

    async def get_secret(
        self, secret_name: str, *, namespace_name: Optional[str] = None
    ) -> dict[str, Any]:
        url = self._generate_secret_url(secret_name, namespace_name)
        payload = await self._request(method="GET", url=url)
        self._cleanup_secret_payload(payload)
        return payload

    async def list_secrets(
        self, label_selector: Optional[str] = None
    ) -> list[dict[str, Any]]:
        url = URL(self._generate_all_secrets_url())
        if label_selector:
            url = url.with_query(labelSelector=label_selector)
        payload = await self._request(method="GET", url=url)
        items = payload.get("items", [])
        for item in items:
            self._cleanup_secret_payload(item)
        return items

    async def create_namespace(self, name: str) -> None:
        """Creates a namespace. Ignores conflict errors"""
        url = URL(self._namespaces_url)
        payload = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": name},
        }
        try:
            await self._request(method="POST", url=url, json=payload)
        except ResourceConflict:
            # ignore on conflict
            return
