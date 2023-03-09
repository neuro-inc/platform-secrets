import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from importlib.metadata import version
from typing import Optional

import aiohttp
import aiohttp.web
import aiohttp_cors
from aiohttp.web import (
    HTTPBadRequest,
    HTTPCreated,
    HTTPInternalServerError,
    HTTPNoContent,
    HTTPNotFound,
    Request,
    Response,
    StreamResponse,
    json_response,
    middleware,
)
from aiohttp.web_urldispatcher import AbstractRoute
from aiohttp_security import check_authorized
from neuro_auth_client import (
    AuthClient,
    ClientSubTreeViewRoot,
    Permission,
    User,
    check_permissions,
)
from neuro_auth_client.security import AuthScheme, setup_security
from neuro_logging import (
    init_logging,
    make_sentry_trace_config,
    make_zipkin_trace_config,
    notrace,
    setup_sentry,
    setup_zipkin,
    setup_zipkin_tracer,
)

from .config import Config, CORSConfig, KubeConfig
from .config_factory import EnvironConfigFactory
from .identity import untrusted_user
from .kube_client import KubeClient
from .service import Secret, SecretNotFound, Service
from .validators import (
    secret_key_validator,
    secret_list_response_validator,
    secret_request_validator,
    secret_response_validator,
)

logger = logging.getLogger(__name__)


class ApiHandler:
    def register(self, app: aiohttp.web.Application) -> list[AbstractRoute]:
        return app.add_routes(
            [
                aiohttp.web.get("/ping", self.handle_ping),
                aiohttp.web.get("/secured-ping", self.handle_secured_ping),
            ]
        )

    @notrace
    async def handle_ping(self, request: Request) -> Response:
        return Response(text="Pong")

    @notrace
    async def handle_secured_ping(self, request: Request) -> Response:
        await check_authorized(request)
        return Response(text="Secured Pong")


class SecretsApiHandler:
    def __init__(self, app: aiohttp.web.Application, config: Config) -> None:
        self._app = app
        self._config = config

    def register(self, app: aiohttp.web.Application) -> None:
        app.add_routes(
            [
                aiohttp.web.post("", self.handle_post),
                aiohttp.web.get("", self.handle_get_all),
                aiohttp.web.delete("/{key}", self.handle_delete),
            ]
        )

    @property
    def _service(self) -> Service:
        return self._app["service"]

    @property
    def _auth_client(self) -> AuthClient:
        return self._app["auth_client"]

    async def _get_untrusted_user(self, request: Request) -> User:
        identity = await untrusted_user(request)
        return User(name=identity.name)

    @property
    def _secret_cluster_uri(self) -> str:
        return f"secret://{self._config.cluster_name}"

    def _get_org_secrets_uri(self, org_name: str) -> str:
        return f"{self._secret_cluster_uri}/{org_name}"

    def _get_secrets_uri(self, project_name: str, org_name: Optional[str]) -> str:
        if org_name is None:
            base = self._secret_cluster_uri
        else:
            base = self._get_org_secrets_uri(org_name)
        return f"{base}/{project_name}"

    def _get_secret_uri(self, secret: Secret) -> str:
        base = self._get_secrets_uri(secret.project_name, secret.org_name)
        if secret.owner == secret.project_name:
            return f"{base}/{secret.key}"
        return base

    def _get_secret_read_perm(self, secret: Secret) -> Permission:
        return Permission(self._get_secret_uri(secret), "read")

    def _get_secrets_write_perm(
        self, project_name: str, org_name: Optional[str]
    ) -> Permission:
        return Permission(
            self._get_secrets_uri(project_name, org_name),
            "write",
        )

    def _convert_secret_to_payload(self, secret: Secret) -> dict[str, Optional[str]]:
        return {
            "key": secret.key,
            "org_name": secret.org_name,
            "project_name": secret.project_name,
            # NOTE: We store all user/project keys in one k8s secret.
            # Project k8s secret can contain keys from multiple users, so
            # there is no single owner of k8s secret, we loose owner when we work
            # with project secrets.
            # For backward compatibility leave `owner` field. It will
            # contain username for secrets without project.
            "owner": secret.project_name,
        }

    def _check_secret_read_perm(
        self, secret: Secret, tree: ClientSubTreeViewRoot
    ) -> bool:
        return tree.allows(self._get_secret_read_perm(secret))

    async def handle_post(self, request: Request) -> Response:
        user = await self._get_untrusted_user(request)
        payload = await request.json()
        payload = secret_request_validator.check(payload)
        org_name = payload.get("org_name")
        project_name = payload.get("project_name", user.name)
        await check_permissions(
            request,
            [self._get_secrets_write_perm(project_name, org_name)],
        )
        secret = Secret(
            key=payload["key"],
            value=payload["value"],
            owner=user.name,
            org_name=org_name,
            project_name=project_name,
        )
        await self._service.add_secret(secret)
        resp_payload = self._convert_secret_to_payload(secret)
        resp_payload = secret_response_validator.check(resp_payload)
        return json_response(resp_payload, status=HTTPCreated.status_code)

    async def handle_get_all(self, request: Request) -> Response:
        username = await check_authorized(request)
        org_name = request.query.get("org_name")
        project_name = request.query.get("project_name")
        tree = await self._auth_client.get_permissions_tree(
            username, self._secret_cluster_uri
        )
        secrets = [
            secret
            for secret in await self._service.get_all_secrets(
                org_name=org_name, project_name=project_name
            )
            if self._check_secret_read_perm(secret, tree)
        ]
        resp_payload = [self._convert_secret_to_payload(secret) for secret in secrets]
        resp_payload = secret_list_response_validator.check(resp_payload)
        return json_response(resp_payload)

    async def handle_delete(self, request: Request) -> Response:
        user = await self._get_untrusted_user(request)
        org_name = request.query.get("org_name")
        project_name = request.query.get("project_name") or user.name
        await check_permissions(
            request,
            [self._get_secrets_write_perm(project_name, org_name)],
        )
        secret_key = request.match_info["key"]
        secret_key = secret_key_validator.check(secret_key)
        secret = Secret(
            key=secret_key,
            org_name=org_name,
            project_name=project_name,
        )
        try:
            await self._service.remove_secret(secret)
        except SecretNotFound as exc:
            resp_payload = {"error": str(exc)}
            return json_response(resp_payload, status=HTTPNotFound.status_code)
        raise HTTPNoContent()


@middleware
async def handle_exceptions(
    request: Request, handler: Callable[[Request], Awaitable[StreamResponse]]
) -> StreamResponse:
    try:
        return await handler(request)
    except ValueError as e:
        payload = {"error": str(e)}
        return json_response(payload, status=HTTPBadRequest.status_code)
    except aiohttp.web.HTTPException:
        raise
    except Exception as e:
        msg_str = (
            f"Unexpected exception: {str(e)}. " f"Path with query: {request.path_qs}."
        )
        logging.exception(msg_str)
        payload = {"error": msg_str}
        return json_response(payload, status=HTTPInternalServerError.status_code)


async def create_secrets_app(config: Config) -> aiohttp.web.Application:
    app = aiohttp.web.Application()
    handler = SecretsApiHandler(app, config)
    handler.register(app)
    return app


@asynccontextmanager
async def create_kube_client(
    config: KubeConfig, trace_configs: list[aiohttp.TraceConfig]
) -> AsyncIterator[KubeClient]:
    client = KubeClient(
        base_url=config.endpoint_url,
        namespace=config.namespace,
        cert_authority_path=config.cert_authority_path,
        cert_authority_data_pem=config.cert_authority_data_pem,
        auth_type=config.auth_type,
        auth_cert_path=config.auth_cert_path,
        auth_cert_key_path=config.auth_cert_key_path,
        token=config.token,
        token_path=None,  # TODO (A Yushkovskiy) add support for token_path or drop
        conn_timeout_s=config.client_conn_timeout_s,
        read_timeout_s=config.client_read_timeout_s,
        conn_pool_size=config.client_conn_pool_size,
        trace_configs=trace_configs,
    )
    try:
        await client.init()
        yield client
    finally:
        await client.close()


def _setup_cors(app: aiohttp.web.Application, config: CORSConfig) -> None:
    if not config.allowed_origins:
        return

    logger.info(f"Setting up CORS with allowed origins: {config.allowed_origins}")
    default_options = aiohttp_cors.ResourceOptions(
        allow_credentials=True, expose_headers="*", allow_headers="*"
    )
    cors = aiohttp_cors.setup(
        app, defaults={origin: default_options for origin in config.allowed_origins}
    )
    for route in app.router.routes():
        logger.debug(f"Setting up CORS for {route}")
        cors.add(route)


package_version = version(__package__)


async def add_version_to_header(request: Request, response: StreamResponse) -> None:
    response.headers["X-Service-Version"] = f"platform-secrets/{package_version}"


def make_tracing_trace_configs(config: Config) -> list[aiohttp.TraceConfig]:
    trace_configs = []

    if config.zipkin:
        trace_configs.append(make_zipkin_trace_config())

    if config.sentry:
        trace_configs.append(make_sentry_trace_config())

    return trace_configs


async def create_app(config: Config) -> aiohttp.web.Application:
    app = aiohttp.web.Application(middlewares=[handle_exceptions])
    app["config"] = config

    async def _init_app(app: aiohttp.web.Application) -> AsyncIterator[None]:
        async with AsyncExitStack() as exit_stack:
            logger.info("Initializing Auth client")
            auth_client = await exit_stack.enter_async_context(
                AuthClient(
                    config.platform_auth.url,
                    config.platform_auth.token,
                    make_tracing_trace_configs(config),
                )
            )

            await setup_security(
                app=app, auth_client=auth_client, auth_scheme=AuthScheme.BEARER
            )

            logger.info("Initializing Kubernetes client")
            kube_client = await exit_stack.enter_async_context(
                create_kube_client(
                    config.kube,
                    make_tracing_trace_configs(config),
                )
            )

            logger.info("Initializing Service")
            app["secrets_app"]["service"] = Service(kube_client)
            app["secrets_app"]["auth_client"] = auth_client

            yield

    app.cleanup_ctx.append(_init_app)

    api_v1_app = aiohttp.web.Application()
    api_v1_handler = ApiHandler()
    probes_routes = api_v1_handler.register(api_v1_app)
    app["api_v1_app"] = api_v1_app

    secrets_app = await create_secrets_app(config)
    app["secrets_app"] = secrets_app
    api_v1_app.add_subapp("/secrets", secrets_app)

    app.add_subapp("/api/v1", api_v1_app)

    _setup_cors(app, config.cors)

    app.on_response_prepare.append(add_version_to_header)

    if config.zipkin:
        setup_zipkin(app, skip_routes=probes_routes)

    return app


def setup_tracing(config: Config) -> None:
    if config.zipkin:
        setup_zipkin_tracer(
            config.zipkin.app_name,
            config.server.host,
            config.server.port,
            config.zipkin.url,
            config.zipkin.sample_rate,
        )

    if config.sentry:
        setup_sentry(
            config.sentry.dsn,
            app_name=config.sentry.app_name,
            cluster_name=config.sentry.cluster_name,
            sample_rate=config.sentry.sample_rate,
        )


def main() -> None:  # pragma: no coverage
    init_logging()
    config = EnvironConfigFactory().create()
    logging.info("Loaded config: %r", config)
    setup_tracing(config)
    aiohttp.web.run_app(
        create_app(config), host=config.server.host, port=config.server.port
    )
