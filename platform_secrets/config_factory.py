import logging
import os
from pathlib import Path

from apolo_kube_client import KubeClientAuthType, KubeConfig
from apolo_events_client import EventsClientConfig
from yarl import URL

from .config import (
    Config,
    PlatformAuthConfig,
    ServerConfig,
)

logger = logging.getLogger(__name__)


class EnvironConfigFactory:
    def __init__(self, environ: dict[str, str] | None = None) -> None:
        self._environ = environ or os.environ

    def _get_url(self, name: str) -> URL | None:
        value = self._environ[name]
        if value == "-":
            return None
        else:
            return URL(value)

    def create(self) -> Config:
        cluster_name = self._environ.get("NP_CLUSTER_NAME", "")
        return Config(
            server=self._create_server(),
            platform_auth=self._create_platform_auth(),
            kube=self._create_kube(),
            cluster_name=cluster_name,
            events=self._create_events(),
        )

    def _create_server(self) -> ServerConfig:
        host = self._environ.get("NP_SECRETS_API_HOST", ServerConfig.host)
        port = int(self._environ.get("NP_SECRETS_API_PORT", ServerConfig.port))
        return ServerConfig(host=host, port=port)

    def _create_platform_auth(self) -> PlatformAuthConfig:
        url = self._get_url("NP_SECRETS_PLATFORM_AUTH_URL")
        token = self._environ["NP_SECRETS_PLATFORM_AUTH_TOKEN"]
        return PlatformAuthConfig(url=url, token=token)

    def _create_kube(self) -> KubeConfig:
        endpoint_url = self._environ["NP_SECRETS_K8S_API_URL"]
        auth_type = KubeClientAuthType(
            self._environ.get("NP_SECRETS_K8S_AUTH_TYPE", KubeClientAuthType.NONE)
        )
        ca_path = self._environ.get("NP_SECRETS_K8S_CA_PATH")
        ca_data = Path(ca_path).read_text() if ca_path else None

        token_path = self._environ.get("NP_SECRETS_K8S_TOKEN_PATH")
        token = Path(token_path).read_text() if token_path else None

        return KubeConfig(
            endpoint_url=endpoint_url,
            cert_authority_data_pem=ca_data,
            auth_type=auth_type,
            auth_cert_path=self._environ.get("NP_SECRETS_K8S_AUTH_CERT_PATH"),
            auth_cert_key_path=self._environ.get("NP_SECRETS_K8S_AUTH_CERT_KEY_PATH"),
            token=token,
            token_path=token_path,
            namespace=self._environ.get(
                "NP_SECRETS_K8S_NS", KubeConfig.model_fields["namespace"].default
            ),
            client_conn_timeout_s=int(
                self._environ.get("NP_SECRETS_K8S_CLIENT_CONN_TIMEOUT")
                or KubeConfig.model_fields["client_conn_timeout_s"].default
            ),
            client_read_timeout_s=int(
                self._environ.get("NP_SECRETS_K8S_CLIENT_READ_TIMEOUT")
                or KubeConfig.model_fields["client_read_timeout_s"].default
            ),
            client_conn_pool_size=int(
                self._environ.get("NP_SECRETS_K8S_CLIENT_CONN_POOL_SIZE")
                or KubeConfig.model_fields["client_conn_pool_size"].default
            ),
        )

    def _create_events(self) -> EventsClientConfig | None:
        events_url = self._environ.get("PLATFORM_EVENTS_URL")
        if not events_url:
            return None
        return EventsClientConfig(
            url=URL(events_url),
            token=self._environ["PLATFORM_EVENTS_TOKEN"],
            name="platform-secrets",
        )
