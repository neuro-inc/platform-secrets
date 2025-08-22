from unittest.mock import AsyncMock, Mock
import pytest
from yarl import URL
from apolo_events_client import EventsClientConfig, EventType, RecvEvent, StreamType

from platform_secrets.project_deleter import ProjectDeleter
from platform_secrets.service import Service


@pytest.fixture
def mock_service() -> Mock:
    service = Mock(spec=Service)
    service.delete_all_secrets_for_project = AsyncMock()
    return service


@pytest.fixture
def events_config() -> EventsClientConfig:
    return EventsClientConfig(
        url=URL("http://platform-events:8080/apis/events"),
        token="test-token",
        name="platform-secrets",
    )


@pytest.fixture
def project_remove_event() -> RecvEvent:
    event = Mock(spec=RecvEvent)
    event.event_type = EventType("project-remove")
    event.cluster = "test-cluster"
    event.org = "test-org"
    event.project = "test-project"
    event.tag = "test-tag"
    return event


@pytest.fixture
def other_event() -> RecvEvent:
    event = Mock(spec=RecvEvent)
    event.event_type = EventType("other-event")
    event.cluster = "test-cluster"
    event.org = "test-org"
    event.project = "test-project"
    event.tag = "test-tag"
    return event


class TestProjectDeleter:
    def test_constants(self) -> None:
        assert ProjectDeleter.ADMIN_STREAM == StreamType("platform-admin")
        assert ProjectDeleter.PROJECT_REMOVE == EventType("project-remove")

    @pytest.mark.asyncio
    async def test_process_project_deletion_success(
        self,
        events_config: EventsClientConfig,
        mock_service: Mock,
        project_remove_event: RecvEvent,
    ) -> None:
        deleter = ProjectDeleter(events_config, mock_service)

        await deleter._process_project_deletion(project_remove_event)

        mock_service.delete_all_secrets_for_project.assert_called_once_with(
            "test-org", "test-project"
        )

    @pytest.mark.asyncio
    async def test_on_admin_event_project_remove(
        self,
        events_config: EventsClientConfig,
        mock_service: Mock,
        project_remove_event: RecvEvent,
    ) -> None:
        deleter = ProjectDeleter(events_config, mock_service)
        deleter._client = AsyncMock()

        await deleter._on_admin_event(project_remove_event)

        mock_service.delete_all_secrets_for_project.assert_called_once_with(
            "test-org", "test-project"
        )
        deleter._client.ack.assert_called_once_with(
            {StreamType("platform-admin"): ["test-tag"]}
        )

    @pytest.mark.asyncio
    async def test_on_admin_event_other_event(
        self,
        events_config: EventsClientConfig,
        mock_service: Mock,
        other_event: RecvEvent,
    ) -> None:
        deleter = ProjectDeleter(events_config, mock_service)
        deleter._client = AsyncMock()

        await deleter._on_admin_event(other_event)

        mock_service.delete_all_secrets_for_project.assert_not_called()
        deleter._client.ack.assert_called_once_with(
            {StreamType("platform-admin"): ["test-tag"]}
        )

    @pytest.mark.asyncio
    async def test_on_admin_event_handles_service_exception(
        self,
        events_config: EventsClientConfig,
        mock_service: Mock,
        project_remove_event: RecvEvent,
    ) -> None:
        deleter = ProjectDeleter(events_config, mock_service)
        deleter._client = AsyncMock()
        mock_service.delete_all_secrets_for_project.side_effect = Exception(
            "Service error"
        )

        await deleter._on_admin_event(project_remove_event)

        mock_service.delete_all_secrets_for_project.assert_called_once_with(
            "test-org", "test-project"
        )
        deleter._client.ack.assert_called_once_with(
            {StreamType("platform-admin"): ["test-tag"]}
        )
