from dataclasses import dataclass, field
from typing import List

from neuro_auth_client import User

from .kube_client import (
    KubeClient,
    ResourceBadRequest,
    ResourceInvalid,
    ResourceNotFound,
)


class SecretNotFound(Exception):
    @classmethod
    def create(cls, secret_key: str) -> "SecretNotFound":
        return cls(f"Secret {secret_key!r} not found")


@dataclass(frozen=True)
class Secret:
    key: str
    value: str = field(repr=False, default="")


class Service:
    def __init__(self, kube_client: KubeClient) -> None:
        self._kube_client = kube_client

    def _get_kube_secret_name(self, user: User) -> str:
        return f"user--{user.name}--secrets"

    async def add_secret(self, user: User, secret: Secret) -> None:
        secret_name = self._get_kube_secret_name(user)
        try:
            try:
                await self._kube_client.add_secret_key(
                    secret_name, secret.key, secret.value
                )
            except ResourceNotFound:
                await self._kube_client.create_secret(
                    secret_name, {secret.key: secret.value}
                )
        except ResourceInvalid:
            raise ValueError(f"Secret key {secret.key!r} not valid")
        except ResourceBadRequest:
            raise ValueError(f"Secret value for key {secret.key!r} not valid")

    async def remove_secret(self, user: User, secret: Secret) -> None:
        secret_name = self._get_kube_secret_name(user)
        try:
            await self._kube_client.remove_secret_key(secret_name, secret.key)
        except (ResourceNotFound, ResourceInvalid):
            raise SecretNotFound.create(secret.key)

    async def get_secrets(self, user: User) -> List[Secret]:
        secret_name = self._get_kube_secret_name(user)
        try:
            payload = await self._kube_client.get_secret(secret_name)
            return [Secret(key=key) for key in payload.get("data", {}).keys()]
        except ResourceNotFound:
            return []
