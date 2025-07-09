from __future__ import annotations

import asyncio
import base64
from uuid import uuid4

import pytest
from apolo_kube_client import KubeClient
from apolo_kube_client.apolo import generate_namespace_name
from kubernetes.client import V1SecretList

# from platform_secrets.kube_client import KubeApi
from platform_secrets.service import (
    NO_ORG,
    NO_ORG_NORMALIZED,
    Secret,
    SecretNotFound,
    Service,
)


class TestService:
    @pytest.fixture
    def service(self, kube_client: KubeClient) -> Service:
        return Service(kube_client=kube_client)

    @pytest.mark.parametrize("key", ["!@#", ".", "..", "...", " ", "\n", "\t", ""])
    async def test_add_secret_invalid_key(
        self,
        service: Service,
        org_name: str,
        project_name: str,
        key: str,
    ) -> None:
        secret = Secret(
            key, org_name, project_name, base64.b64encode(b"testvalue").decode()
        )
        with pytest.raises(ValueError, match="Secret key '.*' or its value not valid"):
            await service.add_secret(secret)

    @pytest.mark.parametrize("key", ["-", "_", ".-", "0"])
    async def test_add_secret_valid_key(
        self,
        service: Service,
        kube_client: KubeClient,
        org_name: str,
        project_name: str,
        key: str,
    ) -> None:
        # ensure that currently the expected namespace doesn't have any secrets
        namespace_name = generate_namespace_name(org_name, project_name)
        namespace_secrets: V1SecretList = await kube_client.core_v1.secret.get_list(namespace=namespace_name)
        assert len(namespace_secrets.items) == 0

        secret = Secret(
            key, org_name, project_name, base64.b64encode(b"testvalue").decode()
        )
        await service.add_secret(secret)

        # ensure that secrets were created in a proper namespace
        namespace_secrets: V1SecretList = await kube_client.core_v1.secret.get_list(
            namespace=namespace_name)
        assert len(namespace_secrets.items) == 1
        expected_secret_name = (
            f"project--{secret.org_name}--{secret.project_name}--secrets"
        )
        assert namespace_secrets.items[0].metadata.name == expected_secret_name

    @pytest.mark.parametrize("key", ["-", "_", ".-", "0"])
    async def test_with_org(
        self,
        service: Service,
        key: str,
        org_name: str,
        project_name: str,
    ) -> None:
        secret = Secret(
            key,
            org_name,
            project_name,
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret)
        assert set(
            await service.get_all_secrets(org_name, project_name, with_values=True)
        ) == {secret}

    async def test_add_secret_invalid_value(
        self, service: Service, org_name: str, project_name: str
    ) -> None:
        secret = Secret("testkey", org_name, project_name, "testvalue")
        with pytest.raises(
            ValueError, match="Secret key 'testkey' or its value not valid"
        ):
            await service.add_secret(secret)

    async def test_remove_secret_not_found(
        self,
        service: Service,
        org_name: str,
        project_name: str,
    ) -> None:
        secret = Secret(
            "testkey",
            org_name,
            project_name,
            base64.b64encode(b"testvalue").decode(),
        )
        with pytest.raises(SecretNotFound, match="Secret 'testkey' not found"):
            await service.remove_secret(secret)

    async def test_remove_secret_only_key(
        self,
        service: Service,
        org_name: str,
        project_name: str,
    ) -> None:
        secret = Secret(
            "testkey",
            org_name,
            project_name,
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret)

        secrets = await service.get_all_secrets(org_name, project_name)
        assert set(secrets) == {Secret("testkey", org_name, project_name)}

        await service.remove_secret(secret)

        secrets = await service.get_all_secrets(org_name, project_name)
        assert not secrets

    async def test_add_secret_max_key(
        self,
        service: Service,
        org_name: str,
        project_name: str,
    ) -> None:
        secret = Secret(
            "a" * 253,
            org_name,
            project_name,
            base64.b64encode(b"testvalue1").decode(),
        )
        await service.add_secret(secret)

        secret = Secret(
            "a" * 254,
            org_name,
            project_name,
            base64.b64encode(b"testvalue1").decode(),
        )
        with pytest.raises(
            ValueError, match=f"Secret key '{secret.key}' or its value not valid"
        ):
            await service.add_secret(secret)

    async def test_add_secret_max_value(
        self,
        org_name: str,
        project_name: str,
        service: Service,
    ) -> None:
        secret = Secret(
            "a" * 253,
            org_name,
            project_name,
            base64.b64encode(b"v" * 1 * 1024 * 1024).decode(),
        )
        await service.add_secret(secret)

        secret = Secret(
            "a" * 253,
            org_name,
            project_name,
            base64.b64encode(b"v" * (1 * 1024 * 1024 + 1)).decode(),
        )
        with pytest.raises(
            ValueError, match=f"Secret key '{secret.key}' or its value not valid"
        ):
            await service.add_secret(secret)

    async def test_add_secret_replace(
        self,
        service: Service,
        org_name: str,
        project_name: str,
    ) -> None:
        secret = Secret(
            "testkey",
            org_name,
            project_name,
            base64.b64encode(b"testvalue1").decode(),
        )
        await service.add_secret(secret)
        secrets = await service.get_all_secrets(
            org_name, project_name, with_values=True
        )
        assert set(secrets) == {secret}

        secret = Secret(
            "testkey",
            org_name,
            project_name,
            base64.b64encode(b"testvalue2").decode(),
        )
        await service.add_secret(secret)
        secrets = await service.get_all_secrets(
            org_name, project_name, with_values=True
        )
        assert set(secrets) == {secret}

    async def test_remove_secret_key_not_found(
        self,
        service: Service,
        org_name: str,
        project_name: str,
    ) -> None:
        secret1 = Secret(
            "testkey1",
            org_name,
            project_name,
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret1)
        secret2 = Secret(
            "testkey2",
            org_name,
            project_name,
            base64.b64encode(b"testvalue").decode(),
        )
        with pytest.raises(SecretNotFound, match="Secret 'testkey2' not found"):
            await service.remove_secret(secret2)

    async def test_add_secret(
        self,
        service: Service,
        org_name: str,
        project_name: str,
    ) -> None:
        secret1 = Secret(
            "testkey1",
            org_name,
            project_name,
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret1)
        secret2 = Secret(
            "testkey2",
            org_name,
            project_name,
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret2)

        secret3 = Secret(
            "testkey3",
            org_name,
            project_name,
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret3)

        secrets = await service.get_all_secrets(org_name, project_name)
        assert set(secrets) == {
            Secret("testkey1", org_name, project_name),
            Secret("testkey2", org_name, project_name),
            Secret("testkey3", org_name, project_name),
        }

        await service.remove_secret(secret2)

        secrets = await service.get_all_secrets(org_name, project_name)
        assert set(secrets) == {
            Secret("testkey1", org_name, project_name),
            Secret("testkey3", org_name, project_name),
        }

    async def test_add_secret_no_org(
        self,
        service: Service,
        project_name: str,
    ) -> None:
        secret1 = Secret(
            "testkey1",
            NO_ORG,
            project_name,
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret1)

        secrets = await service.get_all_secrets(NO_ORG, project_name)
        assert len(secrets) == 1
        actual_secret = secrets[0]

        assert f"{NO_ORG_NORMALIZED}--{project_name}" in actual_secret.namespace_name
        assert "testkey1" == actual_secret.key
        assert NO_ORG == actual_secret.org_name
        assert project_name == actual_secret.project_name

    async def test_add_remove_add_secret(
        self,
        service: Service,
        org_name: str,
        project_name: str,
    ) -> None:
        secret1 = Secret(
            "testkey1", org_name, project_name, base64.b64encode(b"value").decode()
        )
        await service.add_secret(secret1)

        await service.remove_secret(secret1)

        secrets = await service.get_all_secrets(org_name, project_name)
        assert set(secrets) == set()

        await service.add_secret(secret1)
        secrets = await service.get_all_secrets(org_name, project_name)
        assert set(secrets) == {Secret("testkey1", org_name, project_name)}

    async def test_get_secrets_empty(
        self,
        service: Service,
        org_name: str,
        project_name: str,
    ) -> None:
        secrets = await service.get_all_secrets(org_name, project_name)
        assert not secrets

    @pytest.fixture
    async def two_secrets(
        self, project_name: str, org_name: str, service: Service
    ) -> list[tuple[str, str]]:
        """Creates two dummy secrets."""
        first_secret_key, first_secret_value = uuid4().hex, uuid4().hex
        second_secret_key, second_secret_value = uuid4().hex, uuid4().hex

        for key, value in (
            (first_secret_key, first_secret_value),
            (second_secret_key, second_secret_value),
        ):
            await service.add_secret(
                Secret(
                    key=key,
                    org_name=org_name,
                    project_name=project_name,
                    value=base64.b64encode(value.encode("utf-8")).decode(),
                )
            )

        return [
            (first_secret_key, first_secret_value),
            (second_secret_key, second_secret_value),
        ]
