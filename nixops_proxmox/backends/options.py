import subprocess
from typing import Optional, Sequence, Mapping, Literal, Union

from nixops.backends import MachineOptions
from nixops.resources import ResourceOptions


class IPOptions(ResourceOptions):
    gateway: Optional[str]
    address: str
    prefixLength: Optional[int]


class NetworkOptions(ResourceOptions):
    model: str
    bridge: str
    tag: Optional[int]
    trunks: Sequence[str]
    ip: Mapping[Union[Literal["v4"], Literal["v6"]],
    IPOptions]


class DiskOptions(ResourceOptions):
    volume: str
    label: Optional[str]
    size: str
    aio: Optional[str]
    enableSSDEmulation: bool
    enableDiscard: bool


class UefiOptions(ResourceOptions):
    enable: bool
    volume: str


class SecretOptions(ResourceOptions):
    text: Optional[str]
    command: Optional[str]


class ProxmoxOptions(ResourceOptions):
    profile: Optional[str]
    serverUrl: Optional[str]
    username: SecretOptions
    password: SecretOptions
    tokenName: SecretOptions
    tokenValue: SecretOptions
    useSSH: bool
    verifySSL: bool
    usePrivateIPAddress: bool
    node: Optional[str]
    pool: Optional[str]

    network: Sequence[NetworkOptions]

    partitions: str
    disks: Sequence[DiskOptions]

    uefi: UefiOptions

    sockets: int
    cores: int
    memory: int

    startOnBoot: bool
    terminationProtection: bool
    hotplugFeatures: Optional[str]
    cpuLimit: Optional[str]
    cpuUnits: Optional[str]
    cpuType: str
    arch: Optional[Union[Literal["aarch64"], Literal["x86_64"]]]

    expertArgs: Optional[str]
    vmid: Optional[str]
    installISO: str


class ProxmoxMachineOptions(MachineOptions):
    proxmox: ProxmoxOptions
