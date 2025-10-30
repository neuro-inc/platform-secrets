import json
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from apolo_kube_client import KubeClientAuthType, KubeConfig, KubeClientSelector
from apolo_kube_client import V1Secret, V1SecretList


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
) -> str | None:
    ca_path = kube_config_cluster_payload["certificate-authority"]
    if ca_path:
        return Path(ca_path).read_text()
    return None


@pytest.fixture
async def kube_config(
    kube_config_cluster_payload: dict[str, Any],
    kube_config_user_payload: dict[str, Any],
    cert_authority_data_pem: str | None,
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
async def kube_selector(
    kube_config: KubeConfig,
    org_name: str,
    project_name: str,
) -> AsyncIterator[KubeClientSelector]:
    async def _drop_all_secrets(kube_client_selector: KubeClientSelector) -> None:
        async with kube_client_selector.get_client(
            org_name=org_name,
            project_name=project_name,
        ) as kube_client:
            secret_list: V1SecretList = await kube_client.core_v1.secret.get_list()
            secret: V1Secret
            for secret in secret_list.items:
                assert secret.metadata.name is not None
                secret_name = secret.metadata.name
                if secret_name.startswith("user--") or secret_name.startswith(
                    "project--"
                ):
                    await kube_client.core_v1.secret.delete(secret_name)

    async with KubeClientSelector(config=kube_config) as kube_client_selector:
        await _drop_all_secrets(kube_client_selector)
        yield kube_client_selector
        await _drop_all_secrets(kube_client_selector)
