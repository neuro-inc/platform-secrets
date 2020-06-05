import base64

import pytest
from neuro_auth_client import User

from platform_secrets.kube_client import KubeClient
from platform_secrets.service import Secret, SecretNotFound, Service
from tests.integration.conftest import random_name


pytestmark = pytest.mark.asyncio


class TestService:
    @pytest.fixture
    def service(self, kube_client: KubeClient) -> Service:
        return Service(kube_client=kube_client)

    @pytest.mark.parametrize("key", ["!@#", ".", "..", "...", " ", "\n", "\t", ""])
    async def test_add_secret_invalid_key(self, service: Service, key: str) -> None:
        user = User(name=random_name())
        secret = Secret(key, base64.b64encode(b"testvalue").decode())
        with pytest.raises(ValueError, match="Secret key '.*' or its value not valid"):
            await service.add_secret(user, secret)

    @pytest.mark.parametrize("key", ["-", "_", ".-", "0"])
    async def test_add_secret_valid_key(self, service: Service, key: str) -> None:
        user = User(name=random_name())
        secret = Secret(key, base64.b64encode(b"testvalue").decode())
        await service.add_secret(user, secret)

    async def test_add_secret_invalid_value(self, service: Service) -> None:
        user = User(name=random_name())
        secret = Secret("testkey", "testvalue")
        with pytest.raises(
            ValueError, match="Secret key 'testkey' or its value not valid"
        ):
            await service.add_secret(user, secret)

    async def test_remove_secret_not_found(self, service: Service) -> None:
        user = User(name=random_name())
        secret = Secret("testkey", base64.b64encode(b"testvalue").decode())
        with pytest.raises(SecretNotFound, match="Secret 'testkey' not found"):
            await service.remove_secret(user, secret)

    async def test_remove_secret_only_key(self, service: Service) -> None:
        user = User(name=random_name())
        secret = Secret("testkey", base64.b64encode(b"testvalue").decode())
        await service.add_secret(user, secret)

        secrets = await service.get_secrets(user)
        assert set(secrets) == {Secret("testkey")}

        await service.remove_secret(user, secret)

        secrets = await service.get_secrets(user)
        assert not secrets

    async def test_add_secret_max_key(self, service: Service) -> None:
        user = User(name=random_name())

        secret = Secret("a" * 253, base64.b64encode(b"testvalue1").decode())
        await service.add_secret(user, secret)

        secret = Secret("a" * 254, base64.b64encode(b"testvalue1").decode())
        with pytest.raises(
            ValueError, match=f"Secret key '{secret.key}' or its value not valid"
        ):
            await service.add_secret(user, secret)

    async def test_add_secret_max_value(self, service: Service) -> None:
        user = User(name=random_name())

        secret = Secret("a" * 253, base64.b64encode(b"v" * 1 * 1024 * 1024).decode())
        await service.add_secret(user, secret)

        secret = Secret(
            "a" * 253, base64.b64encode(b"v" * (1 * 1024 * 1024 + 1)).decode()
        )
        with pytest.raises(
            ValueError, match=f"Secret key '{secret.key}' or its value not valid"
        ):
            await service.add_secret(user, secret)

    async def test_add_secret_replace(self, service: Service) -> None:
        user = User(name=random_name())

        secret = Secret("testkey", base64.b64encode(b"testvalue1").decode())
        await service.add_secret(user, secret)
        secrets = await service.get_secrets(user, with_values=True)
        assert set(secrets) == {secret}

        secret = Secret("testkey", base64.b64encode(b"testvalue2").decode())
        await service.add_secret(user, secret)
        secrets = await service.get_secrets(user, with_values=True)
        assert set(secrets) == {secret}

    async def test_remove_secret_key_not_found(self, service: Service) -> None:
        user = User(name=random_name())
        secret1 = Secret("testkey1", base64.b64encode(b"testvalue").decode())
        await service.add_secret(user, secret1)
        secret2 = Secret("testkey2", base64.b64encode(b"testvalue").decode())
        with pytest.raises(SecretNotFound, match="Secret 'testkey2' not found"):
            await service.remove_secret(user, secret2)

    async def test_add_secret(self, service: Service) -> None:
        user1 = User(name=random_name())
        secret1 = Secret("testkey1", base64.b64encode(b"testvalue").decode())
        await service.add_secret(user1, secret1)
        secret2 = Secret("testkey2", base64.b64encode(b"testvalue").decode())
        await service.add_secret(user1, secret2)

        user2 = User(name=random_name())
        secret3 = Secret("testkey3", base64.b64encode(b"testvalue").decode())
        await service.add_secret(user2, secret3)

        secrets = await service.get_secrets(user1)
        assert set(secrets) == {Secret("testkey1"), Secret("testkey2")}

        secrets = await service.get_secrets(user2)
        assert set(secrets) == {Secret("testkey3")}

        await service.remove_secret(user1, secret2)

        secrets = await service.get_secrets(user1)
        assert set(secrets) == {Secret("testkey1")}

        secrets = await service.get_secrets(user2)
        assert set(secrets) == {Secret("testkey3")}

    async def test_get_secrets_empty(self, service: Service) -> None:
        user = User(name=random_name())
        secrets = await service.get_secrets(user)
        assert not secrets
