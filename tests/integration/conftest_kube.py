import json
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Optional

import pytest

from platform_secrets.config import KubeConfig
from platform_secrets.kube_client import KubeClient


@pytest.fixture(scope="session")
def kube_config_payload() -> dict[str, Any]:
    result = subprocess.run(
        ["kubectl", "config", "view", "-o", "json"], stdout=subprocess.PIPE
    )
    payload_str = result.stdout.decode().rstrip()
    return json.loads(payload_str)


@pytest.fixture(scope="session")
def kube_config_cluster_payload(kube_config_payload: dict[str, Any]) -> Any:
    cluster_name = "minikube"
    clusters = {
        cluster["name"]: cluster["cluster"]
        for cluster in kube_config_payload["clusters"]
    }
    return clusters[cluster_name]


@pytest.fixture(scope="session")
def kube_config_user_payload(kube_config_payload: dict[str, Any]) -> Any:
    user_name = "minikube"
    users = {user["name"]: user["user"] for user in kube_config_payload["users"]}
    return users[user_name]


@pytest.fixture(scope="session")
def cert_authority_data_pem(
    kube_config_cluster_payload: dict[str, Any]
) -> Optional[str]:
    ca_path = kube_config_cluster_payload["certificate-authority"]
    if ca_path:
        return Path(ca_path).read_text()
    return None


@pytest.fixture
async def kube_config(
    kube_config_cluster_payload: dict[str, Any],
    kube_config_user_payload: dict[str, Any],
    cert_authority_data_pem: Optional[str],
) -> KubeConfig:
    cluster = kube_config_cluster_payload
    user = kube_config_user_payload
    kube_config = KubeConfig(
        endpoint_url=cluster["server"],
        cert_authority_data_pem=cert_authority_data_pem,
        auth_cert_path=user["client-certificate"],
        auth_cert_key_path=user["client-key"],
        namespace="default",
    )
    return kube_config


@pytest.fixture(autouse=True)
async def kube_client(kube_config: KubeConfig) -> AsyncIterator[KubeClient]:
    # TODO (A Danshyn 06/06/18): create a factory method
    client = KubeClient(
        base_url=kube_config.endpoint_url,
        auth_type=kube_config.auth_type,
        cert_authority_data_pem=kube_config.cert_authority_data_pem,
        cert_authority_path=None,  # disabled, see `cert_authority_data_pem`
        auth_cert_path=kube_config.auth_cert_path,
        auth_cert_key_path=kube_config.auth_cert_key_path,
        namespace=kube_config.namespace,
        conn_timeout_s=kube_config.client_conn_timeout_s,
        read_timeout_s=kube_config.client_read_timeout_s,
        conn_pool_size=kube_config.client_conn_pool_size,
    )

    async def _drop_all_secrets(client: KubeClient) -> None:
        for item in await client.list_secrets():
            secret_name: str = item["metadata"]["name"]
            if secret_name.startswith("user--") or secret_name.startswith("project--"):
                await client.remove_secret(secret_name)

    async with client:
        await _drop_all_secrets(client)
        yield client
        await _drop_all_secrets(client)
