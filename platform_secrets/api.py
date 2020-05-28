import asyncio
import json
import logging
import shlex
from contextlib import AsyncExitStack, asynccontextmanager, suppress
from pathlib import Path
from tempfile import mktemp
from typing import Any, AsyncIterator, Awaitable, Callable, Dict

import aiohttp
import aiohttp.web
import aiohttp_cors
from aiodocker.stream import Stream
from aioelasticsearch import Elasticsearch
from aiohttp.web import (
    HTTPBadRequest,
    HTTPInternalServerError,
    Request,
    Response,
    StreamResponse,
    WebSocketResponse,
    json_response,
    middleware,
)
from aiohttp_security import check_authorized
from neuro_auth_client import AuthClient, Permission, check_permissions
from neuro_auth_client.security import AuthScheme, setup_security
from neuromation.api import (
    Client as PlatformApiClient,
    Factory as PlatformClientFactory,
    JobDescription as Job,
)
from platform_logging import init_logging
from platform_monitoring.user import untrusted_user

from .base import JobStats, Telemetry
from .config import (
    Config,
    CORSConfig,
    ElasticsearchConfig,
    KubeConfig,
    PlatformApiConfig,
    PlatformAuthConfig,
)
from .config_factory import EnvironConfigFactory
from .jobs_service import Container, JobException, JobsService
from .kube_client import JobError, KubeClient, KubeTelemetry
from .utils import JobsHelper, KubeHelper, LogReaderFactory
from .validators import create_save_request_payload_validator


logger = logging.getLogger(__name__)


class ApiHandler:
    def register(self, app: aiohttp.web.Application) -> None:
        app.add_routes(
            [
                aiohttp.web.get("/ping", self.handle_ping),
                aiohttp.web.get("/secured-ping", self.handle_secured_ping),
            ]
        )

    async def handle_ping(self, request: Request) -> Response:
        return Response(text="Pong")

    async def handle_secured_ping(self, request: Request) -> Response:
        await check_authorized(request)
        return Response(text=f"Secured Pong")


class MonitoringApiHandler:
    def __init__(self, app: aiohttp.web.Application, config: Config) -> None:
        self._app = app
        self._config = config
        self._jobs_helper = JobsHelper(cluster_name=config.cluster_name)
        self._kube_helper = KubeHelper()

        self._save_request_payload_validator = create_save_request_payload_validator(
            config.registry.host
        )

    def register(self, app: aiohttp.web.Application) -> None:
        app.add_routes(
            [
                aiohttp.web.get("/{job_id}/log", self.stream_log),
                aiohttp.web.get("/{job_id}/top", self.stream_top),
                aiohttp.web.post("/{job_id}/save", self.stream_save),
                aiohttp.web.post("/{job_id}/attach", self.ws_attach),
                aiohttp.web.post("/{job_id}/resize", self.resize),
                aiohttp.web.post("/{job_id}/exec", self.ws_exec),
            ]
        )

    @property
    def _jobs_service(self) -> JobsService:
        return self._app["jobs_service"]

    @property
    def _kube_client(self) -> KubeClient:
        return self._app["kube_client"]

    @property
    def _log_reader_factory(self) -> LogReaderFactory:
        return self._app["log_reader_factory"]

    async def stream_log(self, request: Request) -> StreamResponse:
        user = await untrusted_user(request)
        job_id = request.match_info["job_id"]
        job = await self._get_job(job_id)

        permission = Permission(uri=self._jobs_helper.job_to_uri(job), action="read")
        logger.info("Checking whether %r has %r", user, permission)
        await check_permissions(request, [permission])

        pod_name = self._kube_helper.get_job_pod_name(job)
        log_reader = await self._log_reader_factory.get_pod_log_reader(pod_name)

        # TODO (A Danshyn, 05.07.2018): expose. make configurable
        chunk_size = 1024
        response = StreamResponse(status=200)
        response.enable_chunked_encoding()
        response.enable_compression(aiohttp.web.ContentCoding.identity)
        response.content_type = "text/plain"
        response.charset = "utf-8"
        await response.prepare(request)

        async with log_reader:
            while True:
                chunk = await log_reader.read(size=chunk_size)
                if not chunk:
                    break
                await response.write(chunk)

        await response.write_eof()
        return response

    async def stream_top(self, request: Request) -> WebSocketResponse:
        user = await untrusted_user(request)
        job_id = request.match_info["job_id"]
        job = await self._get_job(job_id)

        permission = Permission(uri=self._jobs_helper.job_to_uri(job), action="read")
        logger.info("Checking whether %r has %r", user, permission)
        await check_permissions(request, [permission])

        logger.info("Websocket connection starting")
        ws = WebSocketResponse()
        await ws.prepare(request)
        logger.info("Websocket connection ready")

        # TODO (truskovskiyk 09/12/18) remove CancelledError
        # https://github.com/aio-libs/aiohttp/issues/3443

        # TODO expose configuration
        sleep_timeout = 1

        telemetry = await self._get_job_telemetry(job)

        async with telemetry:

            try:
                while True:
                    # client closed connection
                    assert request.transport is not None
                    if request.transport.is_closing():
                        break

                    # TODO (A Yushkovskiy 06-Jun-2019) don't make slow HTTP requests to
                    #  platform-api to check job's status every iteration: we better
                    #  retrieve this information directly form kubernetes
                    job = await self._get_job(job_id)

                    if self._jobs_helper.is_job_running(job):
                        job_stats = await telemetry.get_latest_stats()
                        if job_stats:
                            message = self._convert_job_stats_to_ws_message(job_stats)
                            await ws.send_json(message)

                    if self._jobs_helper.is_job_finished(job):
                        break

                    await asyncio.sleep(sleep_timeout)

            except JobError as e:
                raise JobError(f"Failed to get telemetry for job {job.id}: {e}") from e

            except asyncio.CancelledError as ex:
                logger.info(f"got cancelled error {ex}")

            finally:
                if not ws.closed:
                    await ws.close()

        return ws

    async def _get_job(self, job_id: str) -> Job:
        return await self._jobs_service.get(job_id)

    async def _get_job_telemetry(self, job: Job) -> Telemetry:
        pod_name = self._kube_helper.get_job_pod_name(job)
        return KubeTelemetry(
            self._kube_client,
            namespace_name=self._kube_client.namespace,
            pod_name=pod_name,
            container_name=pod_name,
        )

    def _convert_job_stats_to_ws_message(self, job_stats: JobStats) -> Dict[str, Any]:
        message = {
            "cpu": job_stats.cpu,
            "memory": job_stats.memory,
            "timestamp": job_stats.timestamp,
        }
        if job_stats.gpu_duty_cycle is not None:
            message["gpu_duty_cycle"] = job_stats.gpu_duty_cycle
        if job_stats.gpu_memory is not None:
            message["gpu_memory"] = job_stats.gpu_memory
        return message

    async def stream_save(self, request: Request) -> StreamResponse:
        user = await untrusted_user(request)
        job_id = request.match_info["job_id"]
        job = await self._get_job(job_id)

        permission = Permission(uri=self._jobs_helper.job_to_uri(job), action="write")
        logger.info("Checking whether %r has %r", user, permission)
        await check_permissions(request, [permission])

        container = await self._parse_save_container(request)

        # Following docker engine API, the response should conform ndjson
        # see https://github.com/ndjson/ndjson-spec
        encoding = "utf-8"
        response = StreamResponse(status=200)
        response.enable_compression(aiohttp.web.ContentCoding.identity)
        response.content_type = "application/x-ndjson"
        response.charset = encoding
        await response.prepare(request)

        try:
            async for chunk in self._jobs_service.save(job, user, container):
                await response.write(self._serialize_chunk(chunk, encoding))
        except JobException as e:
            # Serialize an exception in a similar way as docker does:
            chunk = {"error": str(e), "errorDetail": {"message": str(e)}}
            await response.write(self._serialize_chunk(chunk, encoding))
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # middleware don't work for prepared StreamResponse, so we need to
            # catch a general exception and send it as a chunk
            msg_str = f"Unexpected error: {e}"
            logging.exception(msg_str)
            chunk = {"error": msg_str}
            await response.write(self._serialize_chunk(chunk, encoding))
        finally:
            return response

    def _serialize_chunk(self, chunk: Dict[str, Any], encoding: str = "utf-8") -> bytes:
        chunk_str = json.dumps(chunk) + "\r\n"
        return chunk_str.encode(encoding)

    async def _parse_save_container(self, request: Request) -> Container:
        payload = await request.json()
        payload = self._save_request_payload_validator.check(payload)

        image = payload["container"]["image"]
        if image.domain != self._config.registry.host:
            raise ValueError("Unknown registry host")

        return Container(image=image)

    async def resize(self, request: Request) -> Response:
        user = await untrusted_user(request)
        job_id = request.match_info["job_id"]
        job = await self._get_job(job_id)

        w = int(request.query.get("w", "80"))
        h = int(request.query.get("h", "25"))

        permission = Permission(uri=self._jobs_helper.job_to_uri(job), action="write")
        logger.info("Checking whether %r has %r", user, permission)
        await check_permissions(request, [permission])

        await self._jobs_service.resize(job, w=w, h=h)
        return json_response(None)

    async def ws_attach(self, request: Request) -> StreamResponse:
        user = await untrusted_user(request)
        job_id = request.match_info["job_id"]
        job = await self._get_job(job_id)

        w = int(request.query.get("w", "80"))
        h = int(request.query.get("h", "25"))
        stdin = _parse_bool(request.query.get("stdin", "0"))
        stdout = _parse_bool(request.query.get("stdout", "0"))
        stderr = _parse_bool(request.query.get("stderr", "0"))
        logs = _parse_bool(request.query.get("logs", "0"))

        if not (stdin or stdout or stderr):
            raise ValueError("Required at least one of stdin, stdout or stderr")

        permission = Permission(uri=self._jobs_helper.job_to_uri(job), action="write")
        logger.info("Checking whether %r has %r", user, permission)
        await check_permissions(request, [permission])

        await self._jobs_service.resize(job, w=w, h=h)

        response = WebSocketResponse()
        await response.prepare(request)

        async with self._jobs_service.attach(
            job, stdin=stdin, stdout=stdout, stderr=stderr, logs=logs
        ) as stream:
            await self._transfer_data(response, stream, stdin, stdout or stderr)

        return response

    async def ws_exec(self, request: Request) -> StreamResponse:
        user = await untrusted_user(request)
        job_id = request.match_info["job_id"]
        job = await self._get_job(job_id)

        cmd = shlex.split(request.query["cmd"])
        stdin = _parse_bool(request.query.get("stdin", "1"))
        stdout = _parse_bool(request.query.get("stdout", "1"))
        stderr = _parse_bool(request.query.get("stderr", "0"))
        tty = _parse_bool(request.query.get("tty", "0"))

        permission = Permission(uri=self._jobs_helper.job_to_uri(job), action="write")
        logger.info("Checking whether %r has %r", user, permission)
        await check_permissions(request, [permission])

        response = WebSocketResponse()
        await response.prepare(request)

        async with self._jobs_service.exec(
            job, cmd=cmd, stdin=stdin, stdout=stdout, stderr=stderr, tty=tty
        ) as stream:
            await self._transfer_data(response, stream, stdin, stdout or stderr)

        return response

    async def _transfer_data(
        self, response: WebSocketResponse, stream: Stream, stdin: bool, stdout: bool
    ) -> None:
        tasks = []
        if stdin:
            tasks.append(asyncio.create_task(self._do_input(response, stream)))
        if stdout:
            tasks.append(asyncio.create_task(self._do_output(response, stream)))

        try:
            await asyncio.gather(*tasks)
        except:  # noqa: E722
            for task in tasks:
                if not task.done():
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task
            raise

    @staticmethod
    async def _do_input(response: WebSocketResponse, stream: Stream) -> None:
        async for msg in response:
            if msg.type == aiohttp.WSMsgType.BINARY:
                await stream.write_in(msg.data)
            elif msg.type == aiohttp.WSMsgType.ERROR:
                exc = response.exception()
                logger.error(
                    "WS connection closed with exception %s", exc, exc_info=exc
                )
            else:
                raise ValueError(f"Unsupported WS message type {msg.type}")

    @staticmethod
    async def _do_output(response: WebSocketResponse, stream: Stream) -> None:
        while True:
            try:
                data = await stream.read_out()
            except aiohttp.EofStream:
                break
            await response.send_bytes(bytes([data.stream]) + data.data)


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


async def create_api_v1_app() -> aiohttp.web.Application:
    api_v1_app = aiohttp.web.Application()
    api_v1_handler = ApiHandler()
    api_v1_handler.register(api_v1_app)
    return api_v1_app


async def create_monitoring_app(config: Config) -> aiohttp.web.Application:
    monitoring_app = aiohttp.web.Application()
    notifications_handler = MonitoringApiHandler(monitoring_app, config)
    notifications_handler.register(monitoring_app)
    return monitoring_app


@asynccontextmanager
async def create_platform_api_client(
    config: PlatformApiConfig,
) -> AsyncIterator[PlatformApiClient]:
    tmp_config = Path(mktemp())
    platform_api_factory = PlatformClientFactory(tmp_config)
    await platform_api_factory.login_with_token(url=config.url, token=config.token)
    client = None
    try:
        client = await platform_api_factory.get()
        yield client
    finally:
        if client:
            await client.close()


@asynccontextmanager
async def create_auth_client(config: PlatformAuthConfig) -> AsyncIterator[AuthClient]:
    async with AuthClient(config.url, config.token) as client:
        yield client


@asynccontextmanager
async def create_kube_client(config: KubeConfig) -> AsyncIterator[KubeClient]:
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
        kubelet_node_port=config.kubelet_node_port,
    )
    try:
        await client.init()
        yield client
    finally:
        await client.close()


@asynccontextmanager
async def create_elasticsearch_client(
    config: ElasticsearchConfig,
) -> AsyncIterator[Elasticsearch]:
    async with Elasticsearch(hosts=config.hosts) as client:
        await client.ping()
        yield client


def _setup_cors(app: aiohttp.web.Application, config: CORSConfig) -> None:
    if not config.allowed_origins:
        return

    logger.info(f"Setting up CORS with allowed origins: {config.allowed_origins}")
    default_options = aiohttp_cors.ResourceOptions(
        allow_credentials=True, expose_headers="*", allow_headers="*",
    )
    cors = aiohttp_cors.setup(
        app, defaults={origin: default_options for origin in config.allowed_origins}
    )
    for route in app.router.routes():
        logger.debug(f"Setting up CORS for {route}")
        cors.add(route)


async def create_app(config: Config) -> aiohttp.web.Application:
    app = aiohttp.web.Application(middlewares=[handle_exceptions])
    app["config"] = config

    async def _init_app(app: aiohttp.web.Application) -> AsyncIterator[None]:
        async with AsyncExitStack() as exit_stack:
            logger.info("Initializing Platform API client")
            platform_client = await exit_stack.enter_async_context(
                create_platform_api_client(config.platform_api)
            )

            logger.info("Initializing Auth client")
            auth_client = await exit_stack.enter_async_context(
                create_auth_client(config.platform_auth)
            )

            await setup_security(
                app=app, auth_client=auth_client, auth_scheme=AuthScheme.BEARER
            )

            logger.info("Initializing Elasticsearc client")
            es_client = await exit_stack.enter_async_context(
                create_elasticsearch_client(config.elasticsearch)
            )

            logger.info("Initializing Kubernetes client")
            kube_client = await exit_stack.enter_async_context(
                create_kube_client(config.kube)
            )
            app["monitoring_app"]["kube_client"] = kube_client

            log_reader_factory = LogReaderFactory(kube_client, es_client)
            app["monitoring_app"]["log_reader_factory"] = log_reader_factory

            app["monitoring_app"]["jobs_service"] = JobsService(
                jobs_client=platform_client.jobs,
                kube_client=kube_client,
                docker_config=config.docker,
            )

            yield

    app.cleanup_ctx.append(_init_app)

    api_v1_app = await create_api_v1_app()
    app["api_v1_app"] = api_v1_app

    monitoring_app = await create_monitoring_app(config)
    app["monitoring_app"] = monitoring_app
    api_v1_app.add_subapp("/jobs", monitoring_app)

    app.add_subapp("/api/v1", api_v1_app)

    _setup_cors(app, config.cors)
    return app


def _parse_bool(value: str) -> bool:
    if value == "0":
        return False
    elif value == "1":
        return True
    else:
        raise ValueError('Required "0" or "1"')


def main() -> None:  # pragma: no coverage
    init_logging()
    config = EnvironConfigFactory().create()
    logging.info("Loaded config: %r", config)
    aiohttp.web.run_app(
        create_app(config), host=config.server.host, port=config.server.port
    )
