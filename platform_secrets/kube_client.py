import json
import logging
from io import BytesIO
from typing import Any, Optional, Union

from apolo_kube_client.client import KubeClient
from apolo_kube_client.errors import ResourceExists
from yarl import URL

logger = logging.getLogger(__name__)


SECRET_DUMMY_KEY = "---neuro---"


class KubeApi:
    def __init__(
        self,
        kube_client: KubeClient,
    ) -> None:
        self._kube = kube_client
        self._dummy_secret_key = SECRET_DUMMY_KEY

    def _generate_all_secrets_url(self, namespace_name: str) -> str:
        namespace_url = self._kube.generate_namespace_url(namespace_name)
        return f"{namespace_url}/secrets"

    def _generate_secret_url(self, secret_name: str, namespace_name: str) -> str:
        all_secrets_url = self._generate_all_secrets_url(namespace_name)
        return f"{all_secrets_url}/{secret_name}"

    async def create_secret(
        self,
        secret_name: str,
        data: Union[str, dict[str, str]],
        labels: dict[str, str],
        *,
        namespace_name: str,
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
            await self._kube.request(method="POST", url=url, json=payload)
        except ResourceExists as e:
            if not replace_on_conflict:
                raise e
            # replace a secret
            url = f"{url}/{secret_name}"
            await self._kube.request(method="PUT", url=url, json=payload)

    async def add_secret_key(
        self,
        secret_name: str,
        key: str,
        value: str,
        *,
        namespace_name: str,
    ) -> None:
        url = self._generate_secret_url(secret_name, namespace_name)
        headers = {"Content-Type": "application/json-patch+json"}
        patches = [{"op": "add", "path": f"/data/{key}", "value": value}]
        req_data = BytesIO(json.dumps(patches).encode())
        await self._kube.request(
            method="PATCH", url=url, headers=headers, data=req_data
        )

    async def remove_secret(
        self,
        secret_name: str,
        *,
        namespace_name: str,
    ) -> None:
        url = self._generate_secret_url(secret_name, namespace_name)
        await self._kube.request(method="DELETE", url=url)

    async def remove_secret_key(
        self, secret_name: str, key: str, *, namespace_name: str
    ) -> None:
        url = self._generate_secret_url(secret_name, namespace_name)
        headers = {"Content-Type": "application/json-patch+json"}
        patches = [{"op": "remove", "path": f"/data/{key}"}]
        await self._kube.request(method="PATCH", url=url, headers=headers, json=patches)

    def _cleanup_secret_payload(self, payload: dict[str, Any]) -> None:
        data = payload.get("data", {})
        data.pop(self._dummy_secret_key, None)
        payload["data"] = data

    async def get_secret(
        self, secret_name: str, *, namespace_name: str
    ) -> dict[str, Any]:
        url = self._generate_secret_url(secret_name, namespace_name)
        payload = await self._kube.request(method="GET", url=url)
        self._cleanup_secret_payload(payload)
        return payload

    async def list_secrets(
        self, namespace_name: str, label_selector: Optional[str] = None
    ) -> list[dict[str, Any]]:
        url = URL(self._generate_all_secrets_url(namespace_name))
        if label_selector:
            url = url.with_query(labelSelector=label_selector)
        payload = await self._kube.request(method="GET", url=url)
        items = payload.get("items", [])
        for item in items:
            self._cleanup_secret_payload(item)
        return items

    async def get_namespace(self, name: str) -> dict[str, Any]:
        url = URL(self._kube.generate_namespace_url(namespace_name=name))
        return await self._kube.request(method="GET", url=url)

    async def create_namespace(
        self, name: str, labels: dict[str, str]
    ) -> dict[str, Any]:
        """Creates a namespace."""
        url = URL(f"{self._kube.api_v1_url}/namespaces")
        payload = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": name,
                "labels": labels,
            },
        }
        return await self._kube.request(method="POST", url=url, json=payload)
