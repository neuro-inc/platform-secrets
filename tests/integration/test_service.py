import base64

import pytest
from neuro_auth_client import User

from platform_secrets.kube_client import KubeClient
from platform_secrets.service import Secret, SecretNotFound, Service

from tests.integration.conftest import random_name



class TestService:
    @pytest.fixture
    def service(self, kube_client: KubeClient) -> Service:
        return Service(kube_client=kube_client)

    @pytest.mark.parametrize("key", ["!@#", ".", "..", "...", " ", "\n", "\t", ""])
    async def test_add_secret_invalid_key(self, service: Service, key: str) -> None:
        user = User(name=random_name())
        secret = Secret(key, user.name, base64.b64encode(b"testvalue").decode())
        with pytest.raises(ValueError, match="Secret key '.*' or its value not valid"):
            await service.add_secret(secret)

    @pytest.mark.parametrize("key", ["-", "_", ".-", "0"])
    async def test_add_secret_valid_key(self, service: Service, key: str) -> None:
        user = User(name=random_name())
        secret = Secret(key, user.name, base64.b64encode(b"testvalue").decode())
        await service.add_secret(secret)

    @pytest.mark.parametrize("key", ["-", "_", ".-", "0"])
    async def test_with_org(self, service: Service, key: str) -> None:
        user = User(name=random_name())
        secret = Secret(
            key, user.name, base64.b64encode(b"testvalue").decode(), org_name="test"
        )
        await service.add_secret(secret)
        assert set(await service.get_all_secrets(with_values=True)) == {secret}

    async def test_add_secret_invalid_value(self, service: Service) -> None:
        user = User(name=random_name())
        secret = Secret("testkey", user.name, "testvalue")
        with pytest.raises(
            ValueError, match="Secret key 'testkey' or its value not valid"
        ):
            await service.add_secret(secret)

    async def test_remove_secret_not_found(self, service: Service) -> None:
        user = User(name=random_name())
        secret = Secret("testkey", user.name, base64.b64encode(b"testvalue").decode())
        with pytest.raises(SecretNotFound, match="Secret 'testkey' not found"):
            await service.remove_secret(secret)

    async def test_remove_secret_only_key(self, service: Service) -> None:
        user = User(name=random_name())
        secret = Secret("testkey", user.name, base64.b64encode(b"testvalue").decode())
        await service.add_secret(secret)

        secrets = await service.get_all_secrets()
        assert set(secrets) == {Secret("testkey", user.name)}

        await service.remove_secret(secret)

        secrets = await service.get_all_secrets()
        assert not secrets

    async def test_add_secret_max_key(self, service: Service) -> None:
        user = User(name=random_name())

        secret = Secret("a" * 253, user.name, base64.b64encode(b"testvalue1").decode())
        await service.add_secret(secret)

        secret = Secret("a" * 254, user.name, base64.b64encode(b"testvalue1").decode())
        with pytest.raises(
            ValueError, match=f"Secret key '{secret.key}' or its value not valid"
        ):
            await service.add_secret(secret)

    async def test_add_secret_max_value(self, service: Service) -> None:
        user = User(name=random_name())

        secret = Secret(
            "a" * 253, user.name, base64.b64encode(b"v" * 1 * 1024 * 1024).decode()
        )
        await service.add_secret(secret)

        secret = Secret(
            "a" * 253,
            user.name,
            base64.b64encode(b"v" * (1 * 1024 * 1024 + 1)).decode(),
        )
        with pytest.raises(
            ValueError, match=f"Secret key '{secret.key}' or its value not valid"
        ):
            await service.add_secret(secret)

    async def test_add_secret_replace(self, service: Service) -> None:
        user = User(name=random_name())

        secret = Secret("testkey", user.name, base64.b64encode(b"testvalue1").decode())
        await service.add_secret(secret)
        secrets = await service.get_all_secrets(with_values=True)
        assert set(secrets) == {secret}

        secret = Secret("testkey", user.name, base64.b64encode(b"testvalue2").decode())
        await service.add_secret(secret)
        secrets = await service.get_all_secrets(with_values=True)
        assert set(secrets) == {secret}

    async def test_remove_secret_key_not_found(self, service: Service) -> None:
        user = User(name=random_name())
        secret1 = Secret("testkey1", user.name, base64.b64encode(b"testvalue").decode())
        await service.add_secret(secret1)
        secret2 = Secret("testkey2", user.name, base64.b64encode(b"testvalue").decode())
        with pytest.raises(SecretNotFound, match="Secret 'testkey2' not found"):
            await service.remove_secret(secret2)

    async def test_add_secret(self, service: Service) -> None:
        user1 = User(name=random_name())
        secret1 = Secret(
            "testkey1", user1.name, base64.b64encode(b"testvalue").decode()
        )
        await service.add_secret(secret1)
        secret2 = Secret(
            "testkey2", user1.name, base64.b64encode(b"testvalue").decode()
        )
        await service.add_secret(secret2)

        user2 = User(name=random_name())
        secret3 = Secret(
            "testkey3", user2.name, base64.b64encode(b"testvalue").decode()
        )
        await service.add_secret(secret3)

        secrets = await service.get_all_secrets()
        assert set(secrets) == {
            Secret("testkey1", user1.name),
            Secret("testkey2", user1.name),
            Secret("testkey3", user2.name),
        }

        await service.remove_secret(secret2)

        secrets = await service.get_all_secrets()
        assert set(secrets) == {
            Secret("testkey1", user1.name),
            Secret("testkey3", user2.name),
        }

    async def test_add_remove_add_secret(self, service: Service) -> None:
        user1 = User(name=random_name())
        secret1 = Secret("testkey1", user1.name, base64.b64encode(b"value").decode())
        await service.add_secret(secret1)

        await service.remove_secret(secret1)

        secrets = await service.get_all_secrets()
        assert set(secrets) == set()

        await service.add_secret(secret1)
        secrets = await service.get_all_secrets()
        assert set(secrets) == {Secret("testkey1", user1.name)}

    async def test_get_secrets_empty(self, service: Service) -> None:
        secrets = await service.get_all_secrets()
        assert not secrets
