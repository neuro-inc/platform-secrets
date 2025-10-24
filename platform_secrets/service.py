from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from apolo_kube_client import (
    ResourceBadRequest,
    ResourceInvalid,
    ResourceNotFound,
    KubeClientSelector,
)
from apolo_kube_client.apolo import (
    generate_namespace_name,
)
from apolo_kube_client import V1SecretList
from apolo_kube_client import V1ObjectMeta, V1Secret

logger = logging.getLogger()

SECRET_API_ORG_LABEL = "platform.neuromation.io/secret-api-org-name"
APPS_SECRET_NAME = "apps-secrets"


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
        return cls("Forbidden")


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
    def __init__(self, kube_client_selector: KubeClientSelector) -> None:
        self._kube_client_selector = kube_client_selector

    def _get_kube_secret_name(self, project_name: str, org_name: str) -> str:
        path = f"{org_name}/{project_name}"
        return f"project--{path.replace('/', '--')}--secrets"

    def _get_project_name_from_secret_name(
        self, secret_name: str, org_name: str
    ) -> str | None:
        match = re.fullmatch(r"project--(?P<user_name>.*)--secrets", secret_name)
        if match:
            path: str = match.group("user_name").replace("--", "/")
            assert path.startswith(org_name + "/")
            _, username = path.split("/", 1)
            return username
        return None

    async def add_secret(self, secret: Secret, encode: bool = False) -> None:
        secret_name = self._get_kube_secret_name(secret.project_name, secret.org_name)
        async with self._kube_client_selector.get_client(
            org_name=secret.org_name, project_name=secret.project_name
        ) as kube_client:
            try:
                try:
                    await kube_client.core_v1.secret.add_key(
                        secret_name,
                        secret.key,
                        secret.value,
                        encode=encode,
                    )
                except ResourceNotFound:
                    labels = {SECRET_API_ORG_LABEL: secret.org_name}
                    await kube_client.core_v1.secret.create(
                        model=V1Secret(
                            api_version="v1",
                            kind="Secret",
                            metadata=V1ObjectMeta(name=secret_name, labels=labels),
                            data={secret.key: secret.value},
                            type="Opaque",
                        ),
                    )
            except (ResourceInvalid, ResourceBadRequest):
                logger.exception(f"Failed to add/replace secret key {secret.key!r}")
                raise ValueError(f"Secret key {secret.key!r} or its value not valid")

    async def remove_secret(self, secret: Secret) -> None:
        async with self._kube_client_selector.get_client(
            org_name=secret.org_name, project_name=secret.project_name
        ) as kube_client:
            try:
                secret_name = self._get_kube_secret_name(
                    secret.project_name, secret.org_name
                )
                await kube_client.core_v1.secret.delete_key(secret_name, secret.key)
            except (ResourceNotFound, ResourceInvalid):
                raise SecretNotFound.create(secret.key)

    async def get_secret(self, secret: Secret) -> Secret:
        try:
            secret_name = self._get_kube_secret_name(
                secret.project_name, secret.org_name
            )
            async with self._kube_client_selector.get_client(
                org_name=secret.org_name, project_name=secret.project_name
            ) as kube_client:
                kube_secret: V1Secret = await kube_client.core_v1.secret.get(
                    secret_name
                )
            if not kube_secret.data or secret.key not in kube_secret.data:
                raise SecretNotFound.create(secret.key)

            raw_value = kube_secret.data[secret.key]

            return Secret(
                key=secret.key,
                value=raw_value,
                org_name=secret.org_name,
                project_name=secret.project_name,
            )
        except ResourceNotFound:
            raise SecretNotFound.create(secret.key)

    async def get_all_secrets(
        self,
        org_name: str,
        project_name: str,
        with_values: bool = False,
    ) -> list[Secret]:
        label_selector = f"{SECRET_API_ORG_LABEL}={org_name}"
        async with self._kube_client_selector.get_client(
            org_name=org_name, project_name=project_name
        ) as kube_client:
            secret_list: V1SecretList = await kube_client.core_v1.secret.get_list(
                label_selector=label_selector
            )
        result = []
        secret: V1Secret
        for secret in secret_list.items:
            assert secret.metadata.name is not None
            secret_project_name = self._get_project_name_from_secret_name(
                secret.metadata.name, org_name
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
                for key, value in (secret.data or {}).items()
            ]
        return result

    async def delete_all_secrets_for_project(
        self, org_name: str, project_name: str
    ) -> None:
        kube_secret_name = self._get_kube_secret_name(project_name, org_name)

        try:
            async with self._kube_client_selector.get_client(
                org_name=org_name, project_name=project_name
            ) as kube_client:
                await kube_client.core_v1.secret.delete(kube_secret_name)
            logger.info(
                f"Deleted K8s secret {kube_secret_name!r} for project {project_name!r} "
                f"in org {org_name!r}"
            )
        except ResourceNotFound:
            logger.debug(
                f"secret {kube_secret_name!r} not found for project {project_name!r} "
                f"in org {org_name!r}"
            )
