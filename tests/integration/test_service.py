import base64

import pytest

from platform_secrets.kube_client import KubeClient
from platform_secrets.service import Secret, SecretNotFound, Service


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

    async def test_add_legacy_secret(self, service: Service) -> None:
        secret1 = Secret(
            "testkey1",
            "test-user",
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret1, create_legacy_secret=True)
        secret2 = Secret(
            "testkey2",
            "test-user",
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret2)
        secret3 = Secret(
            "testkey3",
            "test-user",
            base64.b64encode(b"testvalue").decode(),
        )
        await service.add_secret(secret3)

        secrets = await service.get_all_secrets(project_name="test-user")
        assert set(secrets) == {
            Secret("testkey1", "test-user"),
            Secret("testkey2", "test-user"),
            Secret("testkey3", "test-user"),
        }

        await service.remove_secret(secret2)

        secrets = await service.get_all_secrets(project_name="test-user")
        assert set(secrets) == {
            Secret("testkey1", "test-user"),
            Secret("testkey3", "test-user"),
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
