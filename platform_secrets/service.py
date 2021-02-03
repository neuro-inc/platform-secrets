import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

from .kube_client import (
    KubeClient,
    ResourceBadRequest,
    ResourceInvalid,
    ResourceNotFound,
)


logger = logging.getLogger()


class SecretNotFound(Exception):
    @classmethod
    def create(cls, secret_key: str) -> "SecretNotFound":
        return cls(f"Secret {secret_key!r} not found")


@dataclass(frozen=True)
class Secret:
    key: str
    owner: str
    value: str = field(repr=False, default="")


class Service:
    def __init__(self, kube_client: KubeClient) -> None:
        self._kube_client = kube_client

    def _get_kube_secret_name(self, owner: str) -> str:
        return f"user--{owner}--secrets"

    def _get_owner_from_secret_name(self, secret_name: str) -> Optional[str]:
        match = re.fullmatch(r"user--(?P<user_name>.*)--secrets", secret_name)
        if match:
            return match.group("user_name")
        return None

    async def add_secret(self, secret: Secret) -> None:
        secret_name = self._get_kube_secret_name(secret.owner)
        try:
            try:
                await self._kube_client.add_secret_key(
                    secret_name, secret.key, secret.value
                )
            except ResourceNotFound:
                await self._kube_client.create_secret(
                    secret_name, {secret.key: secret.value}
                )
        except (ResourceInvalid, ResourceBadRequest):
            logger.exception(f"Failed to add/replace secret key {secret.key!r}")
            raise ValueError(f"Secret key {secret.key!r} or its value not valid")

    async def remove_secret(self, secret: Secret) -> None:
        secret_name = self._get_kube_secret_name(secret.owner)
        try:
            await self._kube_client.remove_secret_key(secret_name, secret.key)
        except (ResourceNotFound, ResourceInvalid):
            raise SecretNotFound.create(secret.key)

    async def get_all_secrets(self, with_values: bool = False) -> List[Secret]:
        payload = await self._kube_client.list_secrets()
        result = []
        for item in payload:
            owner = self._get_owner_from_secret_name(item["metadata"]["name"])
            if not owner:
                continue
            if with_values:
                result += [
                    Secret(key=key, value=value, owner=owner)
                    for key, value in item.get("data", {}).items()
                ]
            else:
                result += [
                    Secret(key=key, owner=owner) for key in item.get("data", {}).keys()
                ]
        return result
