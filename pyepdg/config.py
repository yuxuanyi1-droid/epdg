from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class HTTPConfig:
    listen: str = ":19090"


@dataclass
class IPSecConfig:
    backend: str = "noop"
    mode: str = "passive"
    swanctl_bin: str = "/usr/sbin/swanctl"
    connection_name: str = "epdg-ike"
    child_prefix: str = "ue"
    child_name: str = "ue-default"
    timeout_seconds: float = 5.0


@dataclass
class PyHSSAPIConfig:
    base_url: str = "http://127.0.0.1:8080"
    timeout_seconds: float = 5.0
    swm_path_template: str = "/auc/swm/eap_aka/plmn/{plmn}/imsi/{imsi}"
    oam_ping_path: str = "/oam/ping"


@dataclass
class AAAConfig:
    backend: str = "pyhss_api"
    origin_host: str = "epdg.localdomain"
    origin_realm: str = "localdomain"
    destination_host: str = "hss.localdomain"
    destination_realm: str = "localdomain"
    eap_max_rounds: int = 4
    allow_unknown_imsi: bool = False
    pyhss_api: PyHSSAPIConfig = field(default_factory=PyHSSAPIConfig)


@dataclass
class PLMNConfig:
    mcc: str = "001"
    mnc: str = "001"


@dataclass
class SWuConfig:
    local_address: str = "127.0.0.1"
    ike_port: int = 500
    natt_port: int = 4500


@dataclass
class SWmConfig:
    peer_host: str = "127.0.0.8"
    realm: str = "localdomain"
    port: int = 3868


@dataclass
class S2bConfig:
    backend: str = "noop"
    pgw_address: str = "127.0.0.4"
    gtpv2_port: int = 2123
    timeout_seconds: float = 2.0


@dataclass
class ProtocolConfig:
    plmn: PLMNConfig = field(default_factory=PLMNConfig)
    swu: SWuConfig = field(default_factory=SWuConfig)
    swm: SWmConfig = field(default_factory=SWmConfig)
    s2b: S2bConfig = field(default_factory=S2bConfig)


@dataclass
class Config:
    node_id: str = "epdg.local"
    http: HTTPConfig = field(default_factory=HTTPConfig)
    ipsec: IPSecConfig = field(default_factory=IPSecConfig)
    aaa: AAAConfig = field(default_factory=AAAConfig)
    protocol: ProtocolConfig = field(default_factory=ProtocolConfig)


def _merge_dataclass(instance: Any, data: dict[str, Any]) -> Any:
    for key, value in data.items():
        if not hasattr(instance, key):
            continue
        current = getattr(instance, key)
        if dataclass_is_instance(current) and isinstance(value, dict):
            _merge_dataclass(current, value)
        else:
            setattr(instance, key, value)
    return instance


def dataclass_is_instance(value: Any) -> bool:
    return hasattr(value, "__dataclass_fields__")


def load(path: str | Path) -> Config:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    cfg = Config()
    if isinstance(raw, dict):
        _merge_dataclass(cfg, raw)
    return cfg
