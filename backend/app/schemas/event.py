"""The unified event schema — every parser normalizes to this.

After ingest, nothing downstream cares whether data came from Sysmon, EVTX,
Wazuh, JSON, or CSV. This model is the contract.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EventType(str, Enum):
    process_create = "process_create"
    network_connect = "network_connect"
    image_load = "image_load"
    create_remote_thread = "create_remote_thread"
    file_create = "file_create"
    registry_set = "registry_set"
    dns_query = "dns_query"
    logon = "logon"
    privilege_use = "privilege_use"
    account_created = "account_created"
    unknown = "unknown"


class ProcessInfo(BaseModel):
    name: str | None = None
    pid: int | None = None
    ppid: int | None = None
    parent: str | None = None        # parent image name, e.g. "explorer.exe"
    cmdline: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)


class NetworkInfo(BaseModel):
    dest_ip: str | None = None
    dest_port: int | None = None
    direction: str | None = None     # outbound | inbound
    domain: str | None = None


class FileInfo(BaseModel):
    path: str | None = None
    action: str | None = None        # create | modify | delete


class LogonInfo(BaseModel):
    type: int | None = None          # Windows logon type (2,3,10,...)
    result: str | None = None        # success | failure
    src_ip: str | None = None


class UnifiedEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    source: str                       # sysmon | winevent | json | csv
    event_type: EventType = EventType.unknown
    host: str | None = None
    user: str | None = None
    process: ProcessInfo = Field(default_factory=ProcessInfo)
    network: NetworkInfo = Field(default_factory=NetworkInfo)
    file: FileInfo = Field(default_factory=FileInfo)
    logon: LogonInfo = Field(default_factory=LogonInfo)
    raw: dict = Field(default_factory=dict)   # original record, always preserved

    def flat_columns(self) -> dict:
        """Columns lifted out for indexed querying in the events table."""
        return {
            "event_id": str(self.event_id),
            "timestamp": self.timestamp,
            "source": self.source,
            "event_type": self.event_type.value,
            "host": self.host,
            "user": self.user,
            "process_name": self.process.name,
            "cmdline": self.process.cmdline,
            "dest_ip": self.network.dest_ip,
            "dest_port": self.network.dest_port,
        }
