from dataclasses import dataclass, field
from typing import Optional

from apolo_kube_client.config import KubeConfig
from yarl import URL


@dataclass(frozen=True)
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8080


@dataclass(frozen=True)
class PlatformAuthConfig:
    url: Optional[URL]
    token: str = field(repr=False)


@dataclass(frozen=True)
class Config:
    server: ServerConfig
    platform_auth: PlatformAuthConfig
    kube: KubeConfig
    cluster_name: str
