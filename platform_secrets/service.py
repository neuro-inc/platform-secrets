import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from .kube_client import (
    KubeClient,
    ResourceBadRequest,
    ResourceConflict,
    ResourceInvalid,
    ResourceNotFound,
)

logger = logging.getLogger()

SECRET_API_ORG_LABEL = "platform.neuromation.io/secret-api-org-name"

NO_ORG = "NO_ORG"


class SecretNotFound(Exception):
    @classmethod
    def create(cls, secret_key: str) -> "SecretNotFound":
        return cls(f"Secret {secret_key!r} not found")


@dataclass(frozen=True)
class Secret:
    key: str
    project_name: str
    value: str = field(repr=False, default="")
    org_name: Optional[str] = None


class Service:
    def __init__(self, kube_client: KubeClient) -> None:
        self._kube_client = kube_client

    def _get_kube_secret_name(self, project_name: str, org_name: Optional[str]) -> str:
        path = project_name
        if org_name:
            path = f"{org_name}/{path}"
        return f"project--{path.replace('/', '--')}--secrets"

    def _get_project_name_from_secret_name(
        self, secret_name: str, org_name: Optional[str]
    ) -> Optional[str]:
        match = re.fullmatch(r"project--(?P<user_name>.*)--secrets", secret_name)
        if match:
            path: str = match.group("user_name").replace("--", "/")
            if org_name:
                assert path.startswith(org_name + "/")
                _, username = path.split("/", 1)
            else:
                username = path
            return username
        return None

    async def add_secret(self, secret: Secret) -> None:
        secret_name = self._get_kube_secret_name(secret.project_name, secret.org_name)
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
        try:
            secret_name = self._get_kube_secret_name(
                secret.project_name, secret.org_name
            )
            await self._kube_client.remove_secret_key(secret_name, secret.key)
        except (ResourceNotFound, ResourceInvalid):
            raise SecretNotFound.create(secret.key)

    async def get_all_secrets(
        self,
        with_values: bool = False,
        org_name: Optional[str] = None,
        project_name: Optional[str] = None,
    ) -> list[Secret]:
        label_selectors = []
        if org_name and org_name.upper() == NO_ORG:
            label_selectors += [f"!{SECRET_API_ORG_LABEL}"]
        elif org_name:
            label_selectors += [f"{SECRET_API_ORG_LABEL}={org_name}"]
        label_selector = ",".join(label_selectors) if label_selectors else None
        payload = await self._kube_client.list_secrets(label_selector)
        result = []
        for item in payload:
            labels = item["metadata"].get("labels", {})
            secret_org_name = labels.get(SECRET_API_ORG_LABEL)
            secret_project_name = self._get_project_name_from_secret_name(
                item["metadata"]["name"], secret_org_name
            )
            if not secret_project_name:
                continue
            if project_name and project_name != secret_project_name:
                continue
            result += [
                Secret(
                    key=key,
                    value=value if with_values else Secret.value,
                    project_name=secret_project_name,
                    org_name=secret_org_name,
                )
                for key, value in item.get("data", {}).items()
            ]
        return result

    async def unwrap_to_namespace(
        self, org_name: str, project_name: str, target_namespace: str
    ) -> None:
        """
        Unwraps secrets from a dict and extracts them to a dedicated namespace.
        """
        secrets = await self.get_all_secrets(
            with_values=True,
            org_name=org_name,
            project_name=project_name,
        )
        tasks = []
        for secret in secrets:
            tasks.append(
                self._kube_client.create_secret(
                    secret_name=secret.key,
                    data=secret.value,
                    labels={},
                    namespace_name=target_namespace,
                    replace_on_conflict=True,
                )
            )

        await asyncio.gather(*tasks)

    async def migrate_user_to_project_secrets(self) -> None:
        # TODO: remove migration after deploy to prod
        user_secrets = [
            s
            for s in await self._kube_client.list_secrets()
            if s["metadata"]["name"].startswith("user--")
        ]

        for s in user_secrets:
            new_name = "project--" + s["metadata"]["name"][6:]
            try:
                await self._kube_client.create_secret(
                    new_name, s["data"], s["metadata"].get("labels", {})
                )
                logger.info("Migrated user secret to %s", new_name)
            except ResourceConflict:
                logger.info("Project secret %s exists", new_name)
