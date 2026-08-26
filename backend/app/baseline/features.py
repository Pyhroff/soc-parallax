"""Feature extraction: an event -> the (entity, feature, value) observations it contributes.

This is the 'DNA' definition. Each observation feeds a per-entity distribution.
Keep this list honest and defensible — every feature here must map to a real
behavioral question ("does this user normally log in at this hour?").
"""
from __future__ import annotations

from typing import NamedTuple

from app.schemas.event import EventType, UnifiedEvent


class Observation(NamedTuple):
    entity_type: str   # user | host | process
    entity_id: str
    feature: str
    value: str
    numeric: bool = False   # if True, value is a number tracked as mean/std


def extract(ev: UnifiedEvent) -> list[Observation]:
    obs: list[Observation] = []

    # ---- USER behavior ----
    if ev.user:
        if ev.event_type == EventType.logon and ev.logon.type is not None:
            obs.append(Observation("user", ev.user, "login_hour", str(ev.timestamp.hour)))
            if ev.logon.src_ip:
                obs.append(Observation("user", ev.user, "src_ip", ev.logon.src_ip))
        if ev.event_type == EventType.process_create and ev.process.name:
            obs.append(Observation("user", ev.user, "process_name", ev.process.name.lower()))
        if ev.event_type == EventType.privilege_use:
            obs.append(Observation("user", ev.user, "privilege_use", "1"))

    # ---- HOST behavior ----
    if ev.host:
        if ev.process.name:
            obs.append(Observation("host", ev.host, "process_name", ev.process.name.lower()))
        if ev.process.parent and ev.process.name:
            pair = f"{ev.process.parent.lower()}->{ev.process.name.lower()}"
            obs.append(Observation("host", ev.host, "parent_child", pair))
        if ev.network.dest_ip:
            obs.append(Observation("host", ev.host, "dest_ip", ev.network.dest_ip))
        if ev.network.dest_port is not None:
            obs.append(Observation("host", ev.host, "dest_port", str(ev.network.dest_port)))
        if ev.network.domain:
            obs.append(Observation("host", ev.host, "domain", ev.network.domain.lower()))

    # ---- PROCESS behavior (keyed by process name) ----
    if ev.process.name:
        if ev.process.parent:
            obs.append(
                Observation("process", ev.process.name.lower(), "parent", ev.process.parent.lower())
            )
        if ev.network.dest_port is not None:
            obs.append(
                Observation("process", ev.process.name.lower(),
                           "dest_port", str(ev.network.dest_port))
            )

    return obs
