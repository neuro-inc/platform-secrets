import logging
from typing import Self

from apolo_events_client import (
    EventType,
    EventsClientConfig,
    RecvEvent,
    StreamType,
    from_config,
)

from .service import Service

logger = logging.getLogger(__name__)


class ProjectDeleter:
    ADMIN_STREAM = StreamType("platform-admin")
    PROJECT_REMOVE = EventType("project-remove")

    def __init__(
        self,
        config: EventsClientConfig,
        service: Service,
    ) -> None:
        self._service = service
        self._client = from_config(config)

    async def __aenter__(self) -> Self:
        await self._client.__aenter__()
        await self._client.subscribe_group(self.ADMIN_STREAM, self._on_admin_event)
        return self

    async def __aexit__(self, exc_typ: object, exc_val: object, exc_tb: object) -> None:
        await self._client.aclose()

    async def _on_admin_event(self, ev: RecvEvent) -> None:
        if ev.event_type == self.PROJECT_REMOVE:
            try:
                await self._process_project_deletion(ev)
            except Exception:
                logger.exception("Error in _on_admin_event")

        await self._client.ack({self.ADMIN_STREAM: [ev.tag]})

    async def _process_project_deletion(self, ev: RecvEvent) -> None:
        cluster = ev.cluster
        assert cluster is not None
        org = ev.org
        assert org is not None
        project = ev.project
        assert project is not None

        try:
            await self._service.delete_all_secrets_for_project(org, project)
        except Exception:
            logger.exception(
                "Cannot delete secrets for project %r (cluster=%r, org=%r)",
                project,
                cluster,
                org,
            )
