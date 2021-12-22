import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from .kube_client import (
    KubeClient,
    ResourceBadRequest,
    ResourceInvalid,
    ResourceNotFound,
)

logger = logging.getLogger()

SECRET_API_ORG_LABEL = "platform.neuromation.io/secret-api-org-name"


class SecretNotFound(Exception):
    @classmethod
    def create(cls, secret_key: str) -> "SecretNotFound":
        return cls(f"Secret {secret_key!r} not found")


@dataclass(frozen=True)
class Secret:
    key: str
    owner: str
    value: str = field(repr=False, default="")
    org_name: Optional[str] = None


class Service:
    def __init__(self, kube_client: KubeClient) -> None:
        self._kube_client = kube_client

    def _get_kube_secret_name(self, owner: str, org_name: Optional[str]) -> str:
        path = owner
        if org_name:
            path = f"{org_name}/{path}"
        return f"user--{path.replace('/', '--')}--secrets"

    def _get_org_owner_from_secret_name(
        self,
        secret_name: str,
        org_name: Optional[str],
    ) -> tuple[Optional[str], Optional[str]]:
        match = re.fullmatch(r"user--(?P<user_name>.*)--secrets", secret_name)
        if match:
            path: str = match.group("user_name").replace("--", "/")
            if org_name:
                assert path.startswith(org_name + "/")
                _, username = path.split("/", 1)
            else:
                username = path
            return username, org_name
        return None, None

    async def add_secret(self, secret: Secret) -> None:
        secret_name = self._get_kube_secret_name(secret.owner, secret.org_name)
        try:
            try:
                await self._kube_client.add_secret_key(
                    secret_name, secret.key, secret.value
                )
            except ResourceNotFound:
                labels = {}
                if secret.org_name:
                    labels[SECRET_API_ORG_LABEL] = secret.org_name
                await self._kube_client.create_secret(
                    secret_name, {secret.key: secret.value}, labels=labels
                )
        except (ResourceInvalid, ResourceBadRequest):
            logger.exception(f"Failed to add/replace secret key {secret.key!r}")
            raise ValueError(f"Secret key {secret.key!r} or its value not valid")

    async def remove_secret(self, secret: Secret) -> None:
        secret_name = self._get_kube_secret_name(secret.owner, secret.org_name)
        try:
            await self._kube_client.remove_secret_key(secret_name, secret.key)
        except (ResourceNotFound, ResourceInvalid):
            raise SecretNotFound.create(secret.key)

    async def get_all_secrets(self, with_values: bool = False) -> list[Secret]:
        payload = await self._kube_client.list_secrets()
        result = []
        for item in payload:
            owner, org_name = self._get_org_owner_from_secret_name(
                item["metadata"]["name"],
                org_name=item["metadata"].get("labels", {}).get(SECRET_API_ORG_LABEL),
            )
            if not owner:
                continue
            if with_values:
                result += [
                    Secret(key=key, value=value, owner=owner, org_name=org_name)
                    for key, value in item.get("data", {}).items()
                ]
            else:
                result += [
                    Secret(key=key, owner=owner, org_name=org_name)
                    for key in item.get("data", {}).keys()
                ]
        return result
