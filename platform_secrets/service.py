from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from apolo_kube_client import (
    KubeClient,
    ResourceBadRequest,
    ResourceInvalid,
    ResourceNotFound,
)
from apolo_kube_client.apolo import (
    NO_ORG,
    create_namespace,
    generate_namespace_name,
    normalize_name,
)
from kubernetes.client import V1SecretList
from kubernetes.client.models import V1ObjectMeta, V1Secret

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
    def __init__(self, kube_client: KubeClient) -> None:
        self._kube_client = kube_client

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

    async def add_secret(self, secret: Secret, encode: bool = False) -> None:
        secret_name = self._get_kube_secret_name(secret.project_name, secret.org_name)
        namespace = await create_namespace(
            self._kube_client, secret.org_name, secret.project_name
        )
        try:
            try:
                await self._kube_client.core_v1.secret.add_key(
                    secret_name,
                    secret.key,
                    secret.value,
                    encode=encode,
                    namespace=namespace.metadata.name,
                )
            except ResourceNotFound:
                labels = {SECRET_API_ORG_LABEL: secret.org_name}
                await self._kube_client.core_v1.secret.create(
                    model=V1Secret(
                        api_version="v1",
                        kind="Secret",
                        metadata=V1ObjectMeta(name=secret_name, labels=labels),
                        data={secret.key: secret.value},
                        type="Opaque",
                    ),
                    namespace=namespace.metadata.name,
                )
        except (ResourceInvalid, ResourceBadRequest):
            logger.exception(f"Failed to add/replace secret key {secret.key!r}")
            raise ValueError(f"Secret key {secret.key!r} or its value not valid")

    async def remove_secret(self, secret: Secret) -> None:
        try:
            secret_name = self._get_kube_secret_name(
                secret.project_name, secret.org_name
            )
            await self._kube_client.core_v1.secret.delete_key(
                secret_name, secret.key, namespace=secret.namespace_name
            )
        except (ResourceNotFound, ResourceInvalid):
            raise SecretNotFound.create(secret.key)

    async def get_secret(self, secret: Secret) -> Secret:
        try:
            secret_name = self._get_kube_secret_name(
                secret.project_name, secret.org_name
            )
            namespace_name = generate_namespace_name(
                secret.org_name, secret.project_name
            )
            kube_secret: V1Secret = await self._kube_client.core_v1.secret.get(
                secret_name, namespace=namespace_name
            )
            if not kube_secret.data or secret.key not in kube_secret.data:
                raise SecretNotFound.create(secret.key)

            return Secret(
                key=secret.key,
                value=kube_secret.data[secret.key],
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
        namespace = await create_namespace(self._kube_client, org_name, project_name)
        label_selector = f"{SECRET_API_ORG_LABEL}={org_name}"
        secret_list: V1SecretList = await self._kube_client.core_v1.secret.get_list(
            label_selector=label_selector, namespace=namespace.metadata.name
        )
        result = []
        secret: V1Secret
        for secret in secret_list.items:
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
        namespace_name = generate_namespace_name(org_name, project_name)

        try:
            await self._kube_client.core_v1.secret.delete(
                kube_secret_name, namespace=namespace_name
            )
            logger.info(
                f"Deleted K8s secret {kube_secret_name!r} for project {project_name!r} "
                f"from namespace {namespace_name!r}"
            )
        except ResourceNotFound:
            logger.debug(
                f"K8s secret {kube_secret_name!r} not found in namespace {namespace_name!r}"
            )
