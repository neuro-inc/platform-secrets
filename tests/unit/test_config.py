from pathlib import Path
from typing import Any

import pytest
from yarl import URL

from platform_secrets.config import (
    Config,
    CORSConfig,
    KubeClientAuthType,
    KubeConfig,
    PlatformAuthConfig,
    SentryConfig,
    ServerConfig,
    ZipkinConfig,
)
from platform_secrets.config_factory import EnvironConfigFactory


CA_DATA_PEM = "this-is-certificate-authority-public-key"
TOKEN = "this-is-token"


@pytest.fixture()
def cert_authority_path(tmp_path: Path) -> str:
    ca_path = tmp_path / "ca.crt"
    ca_path.write_text(CA_DATA_PEM)
    return str(ca_path)


@pytest.fixture()
def token_path(tmp_path: Path) -> str:
    token_path = tmp_path / "token"
    token_path.write_text(TOKEN)
    return str(token_path)


def test_create_default() -> None:
    environ: dict[str, Any] = {
        "NP_SECRETS_PLATFORM_AUTH_URL": "-",
        "NP_SECRETS_PLATFORM_AUTH_TOKEN": "platform-auth-token",
        "NP_SECRETS_K8S_API_URL": "https://localhost:8443",
    }
    config = EnvironConfigFactory(environ).create()
    assert config == Config(
        server=ServerConfig(host="0.0.0.0", port=8080),
        platform_auth=PlatformAuthConfig(url=None, token="platform-auth-token"),
        kube=KubeConfig(
            endpoint_url="https://localhost:8443",
            auth_type=KubeClientAuthType.CERTIFICATE,
        ),
        cluster_name="",
        cors=CORSConfig(),
    )


def test_create_custom(cert_authority_path: str, token_path: str) -> None:
    environ: dict[str, Any] = {
        "NP_SECRETS_API_HOST": "0.0.0.0",
        "NP_SECRETS_API_PORT": 8080,
        "NP_SECRETS_PLATFORM_AUTH_URL": "http://platformauthapi/api/v1",
        "NP_SECRETS_PLATFORM_AUTH_TOKEN": "platform-auth-token",
        "NP_SECRETS_K8S_API_URL": "https://localhost:8443",
        "NP_SECRETS_K8S_AUTH_TYPE": "token",
        "NP_SECRETS_K8S_CA_PATH": cert_authority_path,
        "NP_SECRETS_K8S_TOKEN_PATH": token_path,
        "NP_SECRETS_K8S_AUTH_CERT_PATH": "/cert_path",
        "NP_SECRETS_K8S_AUTH_CERT_KEY_PATH": "/cert_key_path",
        "NP_SECRETS_K8S_NS": "other-namespace",
        "NP_SECRETS_K8S_CLIENT_CONN_TIMEOUT": "111",
        "NP_SECRETS_K8S_CLIENT_READ_TIMEOUT": "222",
        "NP_SECRETS_K8S_CLIENT_CONN_POOL_SIZE": "333",
        "NP_CLUSTER_NAME": "default",
        "NP_CORS_ORIGINS": "https://domain1.com,http://do.main",
        "NP_ZIPKIN_URL": "https://zipkin:9411",
        "NP_SENTRY_DSN": "https://sentry",
        "NP_SENTRY_CLUSTER_NAME": "test",
    }
    config = EnvironConfigFactory(environ).create()
    assert config == Config(
        server=ServerConfig(host="0.0.0.0", port=8080),
        platform_auth=PlatformAuthConfig(
            url=URL("http://platformauthapi/api/v1"), token="platform-auth-token"
        ),
        kube=KubeConfig(
            endpoint_url="https://localhost:8443",
            cert_authority_data_pem=CA_DATA_PEM,
            auth_type=KubeClientAuthType.TOKEN,
            token=TOKEN,
            auth_cert_path="/cert_path",
            auth_cert_key_path="/cert_key_path",
            namespace="other-namespace",
            client_conn_timeout_s=111,
            client_read_timeout_s=222,
            client_conn_pool_size=333,
        ),
        cluster_name="default",
        cors=CORSConfig(["https://domain1.com", "http://do.main"]),
        zipkin=ZipkinConfig(url=URL("https://zipkin:9411")),
        sentry=SentryConfig(dsn=URL("https://sentry"), cluster_name="test"),
    )


def test_create_zipkin_none() -> None:
    result = EnvironConfigFactory({}).create_zipkin()

    assert result is None


def test_create_zipkin_default() -> None:
    env = {"NP_ZIPKIN_URL": "https://zipkin:9411"}
    result = EnvironConfigFactory(env).create_zipkin()

    assert result == ZipkinConfig(url=URL("https://zipkin:9411"))


def test_create_zipkin_custom() -> None:
    env = {
        "NP_ZIPKIN_URL": "https://zipkin:9411",
        "NP_ZIPKIN_APP_NAME": "api",
        "NP_ZIPKIN_SAMPLE_RATE": "1",
    }
    result = EnvironConfigFactory(env).create_zipkin()

    assert result == ZipkinConfig(
        url=URL("https://zipkin:9411"), app_name="api", sample_rate=1
    )


def test_create_sentry_none() -> None:
    result = EnvironConfigFactory({}).create_sentry()

    assert result is None


def test_create_sentry_default() -> None:
    env = {
        "NP_SENTRY_DSN": "https://sentry",
        "NP_SENTRY_CLUSTER_NAME": "test",
    }
    result = EnvironConfigFactory(env).create_sentry()

    assert result == SentryConfig(dsn=URL("https://sentry"), cluster_name="test")


def test_create_sentry_custom() -> None:
    env = {
        "NP_SENTRY_DSN": "https://sentry",
        "NP_SENTRY_APP_NAME": "api",
        "NP_SENTRY_CLUSTER_NAME": "test",
        "NP_SENTRY_SAMPLE_RATE": "1",
    }
    result = EnvironConfigFactory(env).create_sentry()

    assert result == SentryConfig(
        dsn=URL("https://sentry"),
        app_name="api",
        cluster_name="test",
        sample_rate=1,
    )
