"""Abstract base collector."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import boto3


@dataclass
class CollectedData:
    """Normalized data returned by all collectors."""

    source: str
    account_id: str
    region: str
    resource_type: str
    data: dict[str, Any]
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class BaseCollector(ABC):
    """Base class for all AWS data collectors."""

    source: str = "unknown"

    def __init__(self, session: boto3.Session):
        self.session = session

    def _get_account_id(self) -> str:
        sts = self.session.client("sts")
        return sts.get_caller_identity()["Account"]

    @abstractmethod
    async def collect(self, **kwargs) -> list[CollectedData]:
        """Collect and return normalized infrastructure data."""
        ...
