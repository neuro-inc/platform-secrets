from __future__ import annotations

import base64
from uuid import uuid4

import pytest

from platform_secrets.kube_client import KubeClient
from platform_secrets.service import (
    APPS_SECRET_NAME,
    CopyScopeMissingError,
    Secret,
    SecretNotFound,
    Service,
)


class TestService:
    @pytest.fixture
    def service(self, kube_client: KubeClient) -> Service:
        return Service(kube_client=kube_client)

    @pytest.mark.parametrize("key", ["!@#", ".", "..", "...", " ", "\n", "\t", ""])
    async def test_add_secret_invalid_key(self, service: Service, key: str) -> None:
        secret = Secret(key, "test-project", base64.b64encode(b"testvalue").decode())
        with pytest.raises(ValueError, match="Secret key '.*' or its value not valid"):
            await service.add_secret(secret)

    @pytest.mark.parametrize("key", ["-", "_", ".-", "0"])
    async def test_add_secret_valid_key(self, service: Service, key: str) -> None:
        secret = Secret(key, "test-project", base64.b64encode(b"testvalue").decode())
        await service.add_secret(secret)

    @pytest.mark.parametrize("key", ["-", "_", ".-", "0"])
    async def test_with_org(self, service: Service, key: str) -> None:
        secret = Secret(
            key,
            "test-project",
            base64.b64encode(b"testvalue").decode(),
            org_name="test",
        )
        await service.add_secret(secret)
        assert set(await service.get_all_secrets(with_values=True)) == {secret}

    async def test_add_secret_invalid_value(self, service: Service) -> None:
        secret = Secret("testkey", "test-project", "testvalue")
        with pytest.raises(
            ValueError, match="Secret key 'testkey' or its value not valid"
        ):
            await service.add_secret(secret)

    async def test_remove_secret_not_found(self, service: Service) -> None:
        secret = Secret(
            "testkey",
            "test-project",
            base64.b64encode(b"testvalue").decode(),
        )
        with pytest.raises(SecretNotFound, match="Secret 'testkey' not found"):
            await service.remove_secret(secret)

    async def test_remove_secret_only_key(self, service: Service) -> None:
        secret = Secret(
            "testkey",
            "test-project",
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret)

        secrets = await service.get_all_secrets()
        assert set(secrets) == {Secret("testkey", "test-project")}

        await service.remove_secret(secret)

        secrets = await service.get_all_secrets()
        assert not secrets

    async def test_add_secret_max_key(self, service: Service) -> None:
        secret = Secret(
            "a" * 253,
            "test-project",
            base64.b64encode(b"testvalue1").decode(),
        )
        await service.add_secret(secret)

        secret = Secret(
            "a" * 254,
            "test-project",
            base64.b64encode(b"testvalue1").decode(),
        )
        with pytest.raises(
            ValueError, match=f"Secret key '{secret.key}' or its value not valid"
        ):
            await service.add_secret(secret)

    async def test_add_secret_max_value(self, service: Service) -> None:
        secret = Secret(
            "a" * 253,
            "test-project",
            base64.b64encode(b"v" * 1 * 1024 * 1024).decode(),
        )
        await service.add_secret(secret)

        secret = Secret(
            "a" * 253,
            "test-project",
            base64.b64encode(b"v" * (1 * 1024 * 1024 + 1)).decode(),
        )
        with pytest.raises(
            ValueError, match=f"Secret key '{secret.key}' or its value not valid"
        ):
            await service.add_secret(secret)

    async def test_add_secret_replace(self, service: Service) -> None:
        secret = Secret(
            "testkey",
            "test-project",
            base64.b64encode(b"testvalue1").decode(),
        )
        await service.add_secret(secret)
        secrets = await service.get_all_secrets(with_values=True)
        assert set(secrets) == {secret}

        secret = Secret(
            "testkey",
            "test-project",
            base64.b64encode(b"testvalue2").decode(),
        )
        await service.add_secret(secret)
        secrets = await service.get_all_secrets(with_values=True)
        assert set(secrets) == {secret}

    async def test_remove_secret_key_not_found(self, service: Service) -> None:
        secret1 = Secret(
            "testkey1",
            "test-project",
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret1)
        secret2 = Secret(
            "testkey2",
            "test-project",
            base64.b64encode(b"testvalue").decode(),
        )
        with pytest.raises(SecretNotFound, match="Secret 'testkey2' not found"):
            await service.remove_secret(secret2)

    async def test_add_secret(self, service: Service) -> None:
        secret1 = Secret(
            "testkey1",
            "test-project",
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret1)
        secret2 = Secret(
            "testkey2",
            "test-project",
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret2)

        secret3 = Secret(
            "testkey3",
            "test-project",
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret3)

        secrets = await service.get_all_secrets()
        assert set(secrets) == {
            Secret("testkey1", "test-project"),
            Secret("testkey2", "test-project"),
            Secret("testkey3", "test-project"),
        }

        await service.remove_secret(secret2)

        secrets = await service.get_all_secrets()
        assert set(secrets) == {
            Secret("testkey1", "test-project"),
            Secret("testkey3", "test-project"),
        }

    async def test_add_remove_add_secret(self, service: Service) -> None:
        secret1 = Secret(
            "testkey1", "test-project", base64.b64encode(b"value").decode()
        )
        await service.add_secret(secret1)

        await service.remove_secret(secret1)

        secrets = await service.get_all_secrets()
        assert set(secrets) == set()

        await service.add_secret(secret1)
        secrets = await service.get_all_secrets()
        assert set(secrets) == {Secret("testkey1", "test-project")}

    async def test_get_secrets_empty(self, service: Service) -> None:
        secrets = await service.get_all_secrets()
        assert not secrets

    async def test_migrate_user_to_project_secrets(
        self, service: Service, kube_client: KubeClient
    ) -> None:
        await kube_client.create_secret(
            "user--test-user--secrets",
            {"secret-key": base64.b64encode(b"secret-value").decode()},
            {"label-key": "label-value"},
        )

        await service.migrate_user_to_project_secrets()

        old_secret = await kube_client.get_secret("user--test-user--secrets")
        new_secret = await kube_client.get_secret("project--test-user--secrets")

        assert old_secret["metadata"]["labels"] == new_secret["metadata"]["labels"]
        assert old_secret["data"] == new_secret["data"]

        # multiple migrations should not fail
        await service.migrate_user_to_project_secrets()

    @pytest.fixture
    def project_name(self) -> str:
        return "project"

    @pytest.fixture
    def org_name(self) -> str:
        return "org"

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
                    project_name=project_name,
                    value=base64.b64encode(value.encode("utf-8")).decode(),
                    org_name=org_name,
                )
            )

        return [
            (first_secret_key, first_secret_value),
            (second_secret_key, second_secret_value),
        ]

    async def test_copy_all_secrets(
        self,
        service: Service,
        kube_client: KubeClient,
        org_name: str,
        project_name: str,
        two_secrets: list[tuple[str, str]],
    ) -> None:
        """Ensures that all secrets are copied"""
        new_namespace_name = uuid4().hex
        first_secret, second_secret = two_secrets
        first_secret_key, first_secret_value = first_secret
        second_secret_key, second_secret_value = second_secret

        await service.copy_to_namespace(
            org_name=org_name,
            project_name=project_name,
            target_namespace=new_namespace_name,
            secret_names=[first_secret_key, second_secret_key],
        )

        new_secrets = await kube_client.get_secret(
            APPS_SECRET_NAME, namespace_name=new_namespace_name
        )
        data = new_secrets["data"]
        assert (
            base64.b64decode(data[first_secret_key]).decode("utf-8")
            == first_secret_value
        )
        assert (
            base64.b64decode(data[second_secret_key]).decode("utf-8")
            == second_secret_value
        )

    async def test_copy_secrets_subset(
        self,
        service: Service,
        kube_client: KubeClient,
        org_name: str,
        project_name: str,
        two_secrets: list[tuple[str, str]],
    ) -> None:
        """
        Ensures that it is possible to copy only a subset of the secrets
        """
        new_namespace_name = uuid4().hex
        first_secret, second_secret = two_secrets
        first_secret_key, first_secret_value = first_secret
        second_secret_key, _ = second_secret

        await service.copy_to_namespace(
            org_name=org_name,
            project_name=project_name,
            target_namespace=new_namespace_name,
            secret_names=[
                first_secret_key,
            ],
        )

        new_secrets = await kube_client.get_secret(
            APPS_SECRET_NAME, namespace_name=new_namespace_name
        )
        data = new_secrets["data"]
        assert (
            base64.b64decode(data[first_secret_key]).decode("utf-8")
            == first_secret_value
        )
        assert second_secret_key not in data  # a second key shouldn't be there

    async def test_copy_secrets__secret_does_not_exist(
        self,
        service: Service,
        kube_client: KubeClient,
        org_name: str,
        project_name: str,
        two_secrets: list[tuple[str, str]],
    ) -> None:
        new_namespace_name = uuid4().hex
        with pytest.raises(CopyScopeMissingError) as e:
            await service.copy_to_namespace(
                org_name=org_name,
                project_name=project_name,
                target_namespace=new_namespace_name,
                secret_names=["first-unknown", "second-unknown"],
            )
            assert str(e) == f"Missing secrets: first-unknown, second-unknown"

    async def test_create_namespace__conflict_handled(
        self, kube_client: KubeClient
    ) -> None:
        namespace_name = uuid4().hex
        # let's try to create namespace two times.
        # we expect no errors to be raised
        await kube_client.create_namespace(namespace_name)
        try:
            await kube_client.create_namespace(namespace_name)
        except Exception:
            pytest.fail("creation of namespace must be idempotent")
