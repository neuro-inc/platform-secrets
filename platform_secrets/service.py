from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field

from apolo_kube_client.apolo import (
    NO_ORG,
    create_namespace,
    generate_namespace_name,
    normalize_name,
)
from apolo_kube_client.errors import (
    ResourceBadRequest,
    ResourceInvalid,
    ResourceNotFound,
)

from .kube_client import KubeApi

logger = logging.getLogger()

SECRET_API_ORG_LABEL = "platform.neuromation.io/secret-api-org-name"
APPS_SECRET_NAME = "apps-secrets"

NO_ORG_NORMALIZED = normalize_name(NO_ORG)


class PlatformSecretsError(Exception):
    """
    Base service error
    """


class SecretNotFound(PlatformSecretsError):
    @classmethod
    def create(cls, secret_key: str) -> SecretNotFound:
        return cls(f"Secret {secret_key!r} not found")


class CopyScopeMissingError(PlatformSecretsError):
    @classmethod
    def create(cls, missing_keys: set[str]) -> CopyScopeMissingError:
        return cls(f"Missing secrets: {', '.join(missing_keys)}")


class NamespaceForbiddenError(PlatformSecretsError):
    @classmethod
    def create(cls) -> NamespaceForbiddenError:
        return cls(f"Forbidden")


@dataclass(frozen=True)
class Secret:
    key: str
    org_name: str
    project_name: str
    value: str = field(repr=False, default="")

    @property
    def namespace_name(self) -> str:
        return generate_namespace_name(self.org_name, self.project_name)


class Service:
    def __init__(self, kube_api: KubeApi) -> None:
        self._kube_api = kube_api

    def _get_kube_secret_name(self, project_name: str, org_name: str) -> str:
        path = project_name
        org_name = NO_ORG_NORMALIZED if org_name == NO_ORG else org_name
        path = f"{org_name}/{path}"
        return f"project--{path.replace('/', '--')}--secrets"

    def _get_project_name_from_secret_name(
        self, secret_name: str, org_name: str
    ) -> str | None:
        match = re.fullmatch(r"project--(?P<user_name>.*)--secrets", secret_name)
        if match:
            path: str = match.group("user_name").replace("--", "/")
            org_name = NO_ORG_NORMALIZED if org_name == NO_ORG else org_name
            assert path.startswith(org_name + "/")
            _, username = path.split("/", 1)
            return username
        return None

    async def add_secret(self, secret: Secret) -> None:
        secret_name = self._get_kube_secret_name(secret.project_name, secret.org_name)
        await create_namespace(
            self._kube_api._kube, secret.org_name, secret.project_name
        )
        try:
            try:
                await self._kube_api.add_secret_key(
                    secret_name,
                    secret.key,
                    secret.value,
                    namespace_name=secret.namespace_name,
                )
            except ResourceNotFound:
                labels = {SECRET_API_ORG_LABEL: secret.org_name}
                await self._kube_api.create_secret(
                    secret_name,
                    {secret.key: secret.value},
                    namespace_name=secret.namespace_name,
                    labels=labels,
                )
        except (ResourceInvalid, ResourceBadRequest):
            logger.exception(f"Failed to add/replace secret key {secret.key!r}")
            raise ValueError(f"Secret key {secret.key!r} or its value not valid")

    async def remove_secret(self, secret: Secret) -> None:
        try:
            secret_name = self._get_kube_secret_name(
                secret.project_name, secret.org_name
            )
            await self._kube_api.remove_secret_key(
                secret_name, secret.key, namespace_name=secret.namespace_name
            )
        except (ResourceNotFound, ResourceInvalid):
            raise SecretNotFound.create(secret.key)

    async def get_all_secrets(
        self,
        org_name: str,
        project_name: str,
        with_values: bool = False,
    ) -> list[Secret]:
        label_selectors = [f"{SECRET_API_ORG_LABEL}={org_name}"]
        namespace = await create_namespace(self._kube_api._kube, org_name, project_name)
        label_selector = ",".join(label_selectors) if label_selectors else None
        payload = await self._kube_api.list_secrets(namespace.name, label_selector)
        result = []
        for item in payload:
            secret_project_name = self._get_project_name_from_secret_name(
                item["metadata"]["name"], org_name
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
                    org_name=org_name,
                )
                for key, value in item.get("data", {}).items()
            ]
        return result

    # TODO: remove migration after deploy to prod
    async def migrate_secrets_to_namespace_approach(self) -> None:
        secrets = await self._kube_api.list_secrets(namespace_name="platform-jobs")
        secrets_by_org_project = defaultdict(list)

        for secret in secrets:
            secret_name = secret["metadata"]["name"]

            if not secret_name.startswith("project--"):
                # not in scope
                continue

            if not secret["data"]:
                # doesn't contain any data
                continue

            # let's parse a name
            parts = secret_name.split("--")
            if len(parts) == 3:
                # doesn't have an org, so we can default to NO_ORG
                org_name = NO_ORG
                project_name = parts[1]
            elif len(parts) == 4:
                org_name = parts[1]
                project_name = parts[2]
            else:
                logger.error(
                    "unable to parse a secret name", extra={"name": secret_name}
                )
                continue

            secrets_by_org_project[(org_name, project_name)].append(secret)

        for (org_name, project_name), secrets in secrets_by_org_project.items():
            await create_namespace(self._kube_api._kube, org_name, project_name)
            for secret in secrets:
                for key, value in secret["data"].items():
                    await self.add_secret(
                        Secret(
                            key=key,
                            value=value,
                            org_name=org_name,
                            project_name=project_name,
                        )
                    )
