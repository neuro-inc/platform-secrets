import json
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Optional

import pytest
from apolo_kube_client.apolo import generate_namespace_name
from apolo_kube_client.client import KubeClientAuthType, kube_client_from_config

from platform_secrets.config import KubeConfig
from platform_secrets.kube_client import KubeApi
from platform_secrets.service import NO_ORG


@pytest.fixture
def org_name() -> str:
    return "test-org"


@pytest.fixture
def project_name() -> str:
    return "test-project"


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
    kube_config_cluster_payload: dict[str, Any],
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
        auth_type=KubeClientAuthType.CERTIFICATE,
    )
    return kube_config


@pytest.fixture(autouse=True)
async def kube_api(
    kube_config: KubeConfig,
    org_name: str,
    project_name: str,
) -> AsyncIterator[KubeApi]:
    async def _drop_all_secrets(client: KubeApi) -> None:
        orgs = [org_name, NO_ORG]
        for org in orgs:
            namespace_name = generate_namespace_name(org, project_name)
            for item in await client.list_secrets(namespace_name):
                secret_name: str = item["metadata"]["name"]
                if secret_name.startswith("user--") or secret_name.startswith(
                    "project--"
                ):
                    await client.remove_secret(
                        secret_name, namespace_name=namespace_name
                    )

    async with kube_client_from_config(config=kube_config) as kube_client:
        kube_api = KubeApi(kube_client=kube_client)
        await _drop_all_secrets(kube_api)
        yield kube_api
        await _drop_all_secrets(kube_api)
