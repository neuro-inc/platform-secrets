import asyncio
import io
import uuid
from typing import Any, AsyncIterator, Dict
from unittest import mock
from uuid import uuid4

import pytest
from aioelasticsearch import Elasticsearch
from aiohttp import web
from async_timeout import timeout
from platform_monitoring.base import LogReader
from platform_monitoring.config import KubeConfig
from platform_monitoring.kube_client import (
    JobNotFoundException,
    KubeClient,
    KubeClientException,
    PodContainerStats,
)
from platform_monitoring.logs import ElasticsearchLogReader, PodContainerLogReader
from platform_monitoring.utils import LogReaderFactory
from yarl import URL

from tests.integration.conftest import ApiAddress, create_local_app_server

from .conftest_kube import MyKubeClient, MyPodDescriptor


@pytest.fixture
def job_pod() -> MyPodDescriptor:
    return MyPodDescriptor(f"job-{uuid4()}")


@pytest.fixture
async def mock_kubernetes_server() -> AsyncIterator[ApiAddress]:
    async def _get_pod(request: web.Request) -> web.Response:
        payload: Dict[str, Any] = {
            "kind": "Pod",
            "metadata": {"name": "testname"},
            "spec": {
                "containers": [{"name": "testname", "image": "testimage"}],
                "nodeName": "whatever",
            },
            "status": {"phase": "Running"},
        }

        return web.json_response(payload)

    async def _stats_summary(request: web.Request) -> web.Response:
        # Explicitly return plain text to trigger ContentTypeError
        return web.Response(content_type="text/plain")

    def _create_app() -> web.Application:
        app = web.Application()
        app.add_routes(
            [
                web.get("/api/v1/namespaces/mock/pods/whatever", _get_pod),
                web.get(
                    "/api/v1/nodes/whatever:10255/proxy/stats/summary", _stats_summary
                ),
            ]
        )
        return app

    app = _create_app()
    async with create_local_app_server(app) as address:
        yield address


class TestKubeClient:
    @pytest.mark.asyncio
    async def test_wait_pod_is_running_not_found(
        self, kube_client: MyKubeClient
    ) -> None:
        with pytest.raises(JobNotFoundException):
            await kube_client.wait_pod_is_running(pod_name="unknown")

    @pytest.mark.asyncio
    async def test_wait_pod_is_running_timed_out(
        self,
        kube_config: KubeConfig,
        kube_client: MyKubeClient,
        job_pod: MyPodDescriptor,
    ) -> None:
        # TODO (A Yushkovskiy, 31-May-2019) check returned job_pod statuses
        await kube_client.create_pod(job_pod.payload)
        with pytest.raises(asyncio.TimeoutError):
            await kube_client.wait_pod_is_running(pod_name=job_pod.name, timeout_s=0.1)
        await kube_client.delete_pod(job_pod.name)

    @pytest.mark.asyncio
    async def test_wait_pod_is_running(
        self,
        kube_config: KubeConfig,
        kube_client: MyKubeClient,
        job_pod: MyPodDescriptor,
    ) -> None:
        # TODO (A Yushkovskiy, 31-May-2019) check returned job_pod statuses
        await kube_client.create_pod(job_pod.payload)
        is_waiting = await kube_client.is_container_waiting(job_pod.name)
        assert is_waiting
        await kube_client.wait_pod_is_running(pod_name=job_pod.name, timeout_s=60.0)
        is_waiting = await kube_client.is_container_waiting(job_pod.name)
        assert not is_waiting
        await kube_client.delete_pod(job_pod.name)

    @pytest.mark.asyncio
    async def test_get_pod_container_stats_error_json_response_parsing(
        self, mock_kubernetes_server: ApiAddress
    ) -> None:
        srv = mock_kubernetes_server
        async with KubeClient(
            base_url=str(f"http://{srv.host}:{srv.port}"), namespace="mock"
        ) as client:
            stats = await client.get_pod_container_stats("whatever", "whenever")
            assert stats is None

    @pytest.mark.asyncio
    async def test_get_pod_container_stats(
        self,
        kube_config: KubeConfig,
        kube_client: MyKubeClient,
        job_pod: MyPodDescriptor,
    ) -> None:
        command = 'bash -c "for i in {1..5}; do echo $i; sleep 1; done"'
        job_pod.set_command(command)
        await kube_client.create_pod(job_pod.payload)
        await kube_client.wait_pod_is_running(pod_name=job_pod.name, timeout_s=60.0)

        pod_metrics = []
        while True:
            stats = await kube_client.get_pod_container_stats(
                job_pod.name, job_pod.name
            )
            if stats:
                pod_metrics.append(stats)
            else:
                break
            await asyncio.sleep(1)

        assert pod_metrics
        assert pod_metrics[0] == PodContainerStats(cpu=mock.ANY, memory=mock.ANY)
        assert pod_metrics[0].cpu >= 0.0
        assert pod_metrics[0].memory > 0.0

    @pytest.mark.asyncio
    async def test_get_pod_container_stats_no_pod(
        self, kube_config: KubeConfig, kube_client: MyKubeClient
    ) -> None:
        pod_name = str(uuid.uuid4())
        with pytest.raises(JobNotFoundException):
            await kube_client.get_pod_container_stats(pod_name, pod_name)

    @pytest.mark.asyncio
    async def test_get_pod_container_stats_not_scheduled_yet(
        self,
        kube_config: KubeConfig,
        kube_client: MyKubeClient,
        job_pod: MyPodDescriptor,
    ) -> None:
        await kube_client.create_pod(job_pod.payload)

        stats = await kube_client.get_pod_container_stats(job_pod.name, job_pod.name)
        assert stats is None

    @pytest.mark.asyncio
    async def test_check_pod_exists_true(
        self, kube_client: MyKubeClient, job_pod: MyPodDescriptor
    ) -> None:
        await kube_client.create_pod(job_pod.payload)
        does_exist = await kube_client.check_pod_exists(pod_name=job_pod.name)
        assert does_exist is True
        await kube_client.delete_pod(job_pod.name)

    @pytest.mark.asyncio
    async def test_check_pod_exists_false(
        self, kube_client: MyKubeClient, job_pod: MyPodDescriptor
    ) -> None:
        does_exist = await kube_client.check_pod_exists(pod_name="unknown")
        assert does_exist is False

    @pytest.mark.asyncio
    async def test_create_log_stream_not_found(self, kube_client: KubeClient) -> None:
        with pytest.raises(KubeClientException):
            async with kube_client.create_pod_container_logs_stream(
                pod_name="unknown", container_name="unknown"
            ):
                pass

    @pytest.mark.asyncio
    async def test_create_log_stream_creating(
        self,
        kube_config: KubeConfig,
        kube_client: MyKubeClient,
        job_pod: MyPodDescriptor,
    ) -> None:
        await kube_client.create_pod(job_pod.payload)

        async with timeout(5.0):
            while True:
                try:
                    stream_cm = kube_client.create_pod_container_logs_stream(
                        pod_name=job_pod.name, container_name=job_pod.name
                    )
                    with pytest.raises(KubeClientException, match="ContainerCreating"):
                        async with stream_cm:
                            pass
                    break
                except AssertionError as exc:
                    if "Pattern" not in str(exc):
                        raise
                await asyncio.sleep(0.1)

    @pytest.mark.asyncio
    async def test_create_log_stream(
        self,
        kube_config: KubeConfig,
        kube_client: MyKubeClient,
        job_pod: MyPodDescriptor,
    ) -> None:
        await kube_client.create_pod(job_pod.payload)
        await kube_client.wait_pod_is_running(pod_name=job_pod.name, timeout_s=60.0)
        stream_cm = kube_client.create_pod_container_logs_stream(
            pod_name=job_pod.name, container_name=job_pod.name
        )
        async with stream_cm as stream:
            payload = await stream.read()
            assert payload == b""

    @pytest.mark.asyncio
    async def test_get_node_proxy_client(
        self, kube_config: KubeConfig, kube_client: MyKubeClient
    ) -> None:
        node_list = await kube_client.get_node_list()
        node_name = node_list["items"][0]["metadata"]["name"]
        async with kube_client.get_node_proxy_client(
            node_name, KubeConfig.kubelet_node_port
        ) as client:
            assert client.url == URL(
                kube_config.endpoint_url
                + f"/api/v1/nodes/{node_name}:{KubeConfig.kubelet_node_port}/proxy"
            )

            async with client.session.get(URL(f"{client.url}/stats/summary")) as resp:
                assert resp.status == 200, await resp.text()
                payload = await resp.json()
                assert "node" in payload


class TestLogReader:
    async def _consume_log_reader(
        self, log_reader: LogReader, chunk_size: int = -1
    ) -> bytes:
        istream = io.BytesIO()
        try:
            async with log_reader:
                while True:
                    chunk = await log_reader.read(chunk_size)
                    if not chunk:
                        break
                    assert chunk_size < 0 or len(chunk) <= chunk_size
                    istream.write(chunk)
        except asyncio.CancelledError:
            pass
        istream.flush()
        istream.seek(0)
        return istream.read()

    @pytest.mark.asyncio
    async def test_read_instantly_succeeded(
        self,
        kube_config: KubeConfig,
        kube_client: MyKubeClient,
        job_pod: MyPodDescriptor,
    ) -> None:
        await kube_client.create_pod(job_pod.payload)
        log_reader = PodContainerLogReader(
            client=kube_client, pod_name=job_pod.name, container_name=job_pod.name
        )
        payload = await self._consume_log_reader(log_reader)
        assert payload == b""

    @pytest.mark.asyncio
    async def test_read_instantly_failed(
        self,
        kube_config: KubeConfig,
        kube_client: MyKubeClient,
        job_pod: MyPodDescriptor,
    ) -> None:
        command = 'bash -c "echo -n Failure!; false"'
        job_pod.set_command(command)
        await kube_client.create_pod(job_pod.payload)
        log_reader = PodContainerLogReader(
            client=kube_client, pod_name=job_pod.name, container_name=job_pod.name
        )
        payload = await self._consume_log_reader(log_reader)
        assert payload == b"Failure!"

    @pytest.mark.asyncio
    async def test_read_timed_out(
        self,
        kube_config: KubeConfig,
        kube_client: MyKubeClient,
        job_pod: MyPodDescriptor,
    ) -> None:
        command = 'bash -c "sleep 5; echo -n Success!"'
        job_pod.set_command(command)
        await kube_client.create_pod(job_pod.payload)
        log_reader = PodContainerLogReader(
            client=kube_client,
            pod_name=job_pod.name,
            container_name=job_pod.name,
            client_read_timeout_s=1,
        )
        with pytest.raises(asyncio.TimeoutError):
            await self._consume_log_reader(log_reader)

    @pytest.mark.asyncio
    async def test_read_succeeded(
        self,
        kube_config: KubeConfig,
        kube_client: MyKubeClient,
        job_pod: MyPodDescriptor,
    ) -> None:
        command = 'bash -c "for i in {1..5}; do echo $i; sleep 1; done"'
        job_pod.set_command(command)
        await kube_client.create_pod(job_pod.payload)
        log_reader = PodContainerLogReader(
            client=kube_client, pod_name=job_pod.name, container_name=job_pod.name
        )
        payload = await self._consume_log_reader(log_reader, chunk_size=1)
        expected_payload = "\n".join(str(i) for i in range(1, 6)) + "\n"
        assert payload == expected_payload.encode()

    @pytest.mark.asyncio
    async def test_read_cancelled(
        self,
        kube_config: KubeConfig,
        kube_client: MyKubeClient,
        job_pod: MyPodDescriptor,
    ) -> None:
        command = 'bash -c "for i in {1..60}; do echo $i; sleep 1; done"'
        job_pod.set_command(command)
        await kube_client.create_pod(job_pod.payload)
        await kube_client.wait_pod_is_running(pod_name=job_pod.name, timeout_s=60.0)
        log_reader = PodContainerLogReader(
            client=kube_client, pod_name=job_pod.name, container_name=job_pod.name
        )
        task = asyncio.ensure_future(self._consume_log_reader(log_reader, chunk_size=1))
        await asyncio.sleep(10)
        task.cancel()
        payload = await task
        expected_payload = "\n".join(str(i) for i in range(1, 6))
        assert payload.startswith(expected_payload.encode())

    @pytest.mark.asyncio
    async def test_elasticsearch_log_reader(
        self,
        kube_config: KubeConfig,
        kube_client: MyKubeClient,
        job_pod: MyPodDescriptor,
        es_client: Elasticsearch,
    ) -> None:
        command = 'bash -c "for i in {1..5}; do echo $i; sleep 1; done"'
        expected_payload = ("\n".join(str(i) for i in range(1, 6)) + "\n").encode()
        job_pod.set_command(command)
        await kube_client.create_pod(job_pod.payload)
        await kube_client.wait_pod_is_terminated(job_pod.name)

        await self._check_kube_logs(
            kube_client,
            namespace_name=kube_config.namespace,
            pod_name=job_pod.name,
            container_name=job_pod.name,
            expected_payload=expected_payload,
        )

        await self._check_es_logs(
            es_client,
            namespace_name=kube_config.namespace,
            pod_name=job_pod.name,
            container_name=job_pod.name,
            expected_payload=expected_payload,
        )

    async def _check_kube_logs(
        self,
        kube_client: KubeClient,
        namespace_name: str,
        pod_name: str,
        container_name: str,
        expected_payload: Any,
    ) -> None:
        log_reader = PodContainerLogReader(
            client=kube_client, pod_name=pod_name, container_name=container_name
        )
        payload = await self._consume_log_reader(log_reader, chunk_size=1)
        assert payload == expected_payload, "Pod logs did not match."

    async def _check_es_logs(
        self,
        es_client: Elasticsearch,
        namespace_name: str,
        pod_name: str,
        container_name: str,
        expected_payload: Any,
        timeout_s: float = 120.0,
        interval_s: float = 1.0,
    ) -> None:
        payload = b""
        try:
            async with timeout(timeout_s):
                while True:
                    log_reader = ElasticsearchLogReader(
                        es_client,
                        namespace_name=namespace_name,
                        pod_name=pod_name,
                        container_name=container_name,
                    )
                    payload = await self._consume_log_reader(log_reader, chunk_size=1)
                    if payload == expected_payload:
                        return
                    await asyncio.sleep(interval_s)
        except asyncio.TimeoutError:
            pytest.fail(f"Pod logs did not match. Last payload: {payload!r}")

    @pytest.mark.asyncio
    async def test_elasticsearch_log_reader_empty(
        self, es_client: Elasticsearch
    ) -> None:
        namespace_name = pod_name = container_name = str(uuid.uuid4())
        log_reader = ElasticsearchLogReader(
            es_client,
            namespace_name=namespace_name,
            pod_name=pod_name,
            container_name=container_name,
        )
        payload = await self._consume_log_reader(log_reader, chunk_size=1)
        assert payload == b""

    @pytest.mark.asyncio
    async def test_get_job_log_reader(
        self,
        kube_config: KubeConfig,
        kube_client: MyKubeClient,
        es_client: Elasticsearch,
        job_pod: MyPodDescriptor,
    ) -> None:
        command = 'bash -c "for i in {1..5}; do echo $i; sleep 1; done"'
        job_pod.set_command(command)
        await kube_client.create_pod(job_pod.payload)

        expected_payload = ("\n".join(str(i) for i in range(1, 6)) + "\n").encode()

        pod_name = job_pod.name

        await kube_client.wait_pod_is_terminated(pod_name)

        factory = LogReaderFactory(kube_client, es_client)

        log_reader = await factory.get_pod_log_reader(pod_name)
        assert isinstance(log_reader, PodContainerLogReader)

        await kube_client.delete_pod(job_pod.name)

        timeout_s = 120.0
        interval_s = 1.0
        payload = b""
        try:
            async with timeout(timeout_s):
                while True:
                    log_reader = await factory.get_pod_log_reader(pod_name)
                    assert isinstance(log_reader, ElasticsearchLogReader)
                    payload = await self._consume_log_reader(log_reader, chunk_size=1)
                    if payload == expected_payload:
                        break
                    await asyncio.sleep(interval_s)
        except asyncio.TimeoutError:
            pytest.fail(f"Pod logs did not match. Last payload: {payload!r}")
