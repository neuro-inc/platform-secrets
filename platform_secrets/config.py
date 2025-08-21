from dataclasses import dataclass, field

from apolo_kube_client import KubeConfig
from apolo_events_client import EventsClientConfig
from yarl import URL


@dataclass(frozen=True)
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8080


@dataclass(frozen=True)
class PlatformAuthConfig:
    url: URL | None
    token: str = field(repr=False)


@dataclass(frozen=True)
class Config:
    server: ServerConfig
    platform_auth: PlatformAuthConfig
    kube: KubeConfig
    cluster_name: str
    events: EventsClientConfig | None
