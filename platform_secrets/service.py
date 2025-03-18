from __future__ import annotations

import hashlib
import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from apolo_kube_client.errors import (
    ResourceBadRequest,
    ResourceExists,
    ResourceInvalid,
    ResourceNotFound,
)

from .kube_client import KubeApi

logger = logging.getLogger()

SECRET_API_ORG_LABEL = "platform.neuromation.io/secret-api-org-name"
APPS_SECRET_NAME = "apps-secrets"

NO_ORG = "NO_ORG"
NO_ORG_NORMALIZED = "no-org"

NAMESPACE_ORG_LABEL = "platform.apolo.us/org"
NAMESPACE_PROJECT_LABEL = "platform.apolo.us/project"

KUBE_NAME_LENGTH_MAX = 63
KUBE_NAMESPACE_SEP = "--"
KUBE_NAMESPACE_PREFIX = "platform"
KUBE_NAMESPACE_HASH_LENGTH = 24


def generate_namespace_name(org_name: str, project_name: str) -> str:
    """
    returns a Kubernetes resource name in the format
    `platform--<org_name>--<project_name>--<hash>`,
    ensuring that the total length does not exceed `KUBE_NAME_LENGTH_MAX` characters.

    - `platform--` prefix is never truncated
    - `<hash>` (a sha256 truncated to 24 chars), is also never truncated
    - if the names are long, we truncate them evenly,
      so at least some parts of both org and proj names will remain
    """
    if org_name == NO_ORG:
        org_name = NO_ORG_NORMALIZED

    hashable = f"{org_name}{KUBE_NAMESPACE_SEP}{project_name}"
    name_hash = hashlib.sha256(hashable.encode("utf-8")).hexdigest()[
        :KUBE_NAMESPACE_HASH_LENGTH
    ]

    len_reserved = (
        len(KUBE_NAMESPACE_PREFIX)
        + (len(KUBE_NAMESPACE_SEP) * 2)
        + KUBE_NAMESPACE_HASH_LENGTH
    )
    len_free = KUBE_NAME_LENGTH_MAX - len_reserved
    if len(hashable) <= len_free:
        return (
            f"{KUBE_NAMESPACE_PREFIX}"
            f"{KUBE_NAMESPACE_SEP}"
            f"{hashable}"
            f"{KUBE_NAMESPACE_SEP}"
            f"{name_hash}"
        )

    # org and project names do not fit into a full length.
    # let's figure out the full length of org and proj, and calculate a ratio
    # between org and project, so that we'll truncate more chars from the
    # string which actually has more chars
    len_org, len_proj = len(org_name), len(project_name)
    len_org_proj = len_org + len_proj + len(KUBE_NAMESPACE_SEP)
    exceeds = len_org_proj - len_free

    # ratio calculation. for proj can be derived via an org ratio
    remove_from_org = math.ceil((len_org / len_org_proj) * exceeds)
    remove_from_proj = exceeds - remove_from_org

    new_org_name = org_name[: max(1, len_org - remove_from_org)]
    new_project_name = project_name[: max(1, len_proj - remove_from_proj)]

    return (
        f"{KUBE_NAMESPACE_PREFIX}"
        f"{KUBE_NAMESPACE_SEP}"
        f"{new_org_name}"
        f"{KUBE_NAMESPACE_SEP}"
        f"{new_project_name}"
        f"{KUBE_NAMESPACE_SEP}"
        f"{name_hash}"
    )


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

    def _get_kube_secret_name(self, project_name: str, org_name: Optional[str]) -> str:
        path = project_name
        if org_name:
            org_name = NO_ORG_NORMALIZED if org_name == NO_ORG else org_name
            path = f"{org_name}/{path}"
        return f"project--{path.replace('/', '--')}--secrets"

    def _get_project_name_from_secret_name(
        self, secret_name: str, org_name: str
    ) -> Optional[str]:
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
        await self.get_or_create_namespace(secret.org_name, secret.project_name)
        try:
            try:
                await self._kube_api.add_secret_key(
                    secret_name,
                    secret.key,
                    secret.value,
                    namespace_name=secret.namespace_name,
                )
            except ResourceNotFound:
                labels = {}
                if secret.org_name:
                    labels[SECRET_API_ORG_LABEL] = secret.org_name
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
        await self.get_or_create_namespace(org_name, project_name)
        namespace_name = generate_namespace_name(org_name, project_name)
        label_selector = ",".join(label_selectors) if label_selectors else None
        payload = await self._kube_api.list_secrets(namespace_name, label_selector)
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

    async def get_or_create_namespace(
        self, org_name: str, project_name: str
    ) -> dict[str, Any]:
        namespace_name = generate_namespace_name(org_name, project_name)
        try:
            # let's try to create a namespace
            return await self._kube_api.create_namespace(
                name=namespace_name,
                labels={
                    NAMESPACE_ORG_LABEL: org_name,
                    NAMESPACE_PROJECT_LABEL: project_name,
                },
            )
        except ResourceExists:
            return await self._kube_api.get_namespace(name=namespace_name)
