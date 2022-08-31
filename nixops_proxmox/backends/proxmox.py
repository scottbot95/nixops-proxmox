from typing import Type, Optional, Union, List, Callable, Any, Mapping

import nixops.util
import nixops.known_hosts
from nixops.backends import MachineDefinition, MachineState, MachineDefinitionType
from nixops.resources import ResourceDefinition, ResourceDefinitionType

from .options import ProxmoxMachineOptions


class VirtualMachineDefinition(MachineDefinition):
    """Definition of a Proxmox QEMU VM"""

    config: ProxmoxMachineOptions

    @classmethod
    def get_type(cls: Type[ResourceDefinition]) -> str:
        return "proxmox"

    def __int__(self, name: str, config):
        super().__init__(name, config)

        for key in ('profile', 'serverUrl', 'username', 'tokenName',
                    'tokenValue', 'password', 'useSSH', 'disks',
                    'node', 'pool', 'nbCpus', 'nbCores', 'memory',
                    'startOnBoot', 'protectVM', 'hotplugFeatures',
                    'cpuLimit', 'cpuUnits', 'cpuType', 'arch',
                    'vmid',
                    'postPartitioningLocalCommands',
                    'partitions', 'expertArgs', 'installISO', 'network',
                    'uefi', 'useSSH', 'usePrivateIPAddress'):
            setattr(self, key, getattr(self.config.proxmox, key))

    def show_type(self) -> str:
        return "{0} [{1}]".format(self.get_type(), self.config.proxmox.serverUrl)

    def host_key_type(self) -> str:
        return (
            "ed25519"
            if nixops.util.parse_nixos_version(self.config.nixosRelease) >= ["15", "09"]
            else "dsa"
        )


class VirtualMachineState(MachineState[VirtualMachineDefinition]):
    """State of a Proxmox VM"""

    @classmethod
    def get_type(cls) -> str:
        return "proxmox"

    state = nixops.util.attr_property("state", MachineState.MISSING, int)

    public_ipv4 = nixops.util.attr_property("publicIPv4", None)
    public_ipv6 = nixops.util.attr_property("publicIPv6", None)
    private_ipv4 = nixops.util.attr_property("privateIPv4", None)
    private_ipv6 = nixops.util.attr_property("privateIPv6", None)

    public_dns_name = nixops.util.attr_property("publicDNSName", None)

    use_private_ip_address = nixops.util.attr_property(
        "proxmox.usePrivateIPAddress",
        False,
        type=bool
    )

    serverUrl = nixops.util.attr_property("proxmox.serverUrl", None)
    node = nixops.util.attr_property("proxmox.node", None)
    username = nixops.util.attr_property("proxmox.username", None)
    password = nixops.util.attr_property("proxmox.password", None)

    tokenName = nixops.util.attr_property("proxmox.tokenName", None)
    tokenValue = nixops.util.attr_property("proxmox.tokenValue", None)

    useSSH = nixops.util.attr_property("proxmox.useSSH", False)

    verifySSL = nixops.util.attr_property("proxmox.verifySSL", False)

    partitions = nixops.util.attr_property("proxmox.partitions", None)

    public_host_key = nixops.util.attr_property("proxmox.publicHostKey", None)
    private_host_key = nixops.util.attr_property("proxmox.privateHostKey", None)

    first_boot = nixops.util.attr_property(
        "proxmox.firstBoot",
        True,
        type=bool
    )
    installed = nixops.util.attr_property(
        "proxmox.installed",
        False,
        type=bool)
    partitioned = nixops.util.attr_property(
        "proxmox.partitioned",
        False,
        type=bool)

    def __init__(self, depl, name, id):
        super().__init__(depl, name, id)
        self._conn = None
        self._node = None
        self._vm = None
        self._cached_instance = None

    def _reset_state(self):
        with self.depl.db:
            self.state = MachineState.MISSING
            self.vm_id = None
            self._reset_network_knowledge()
            self.public_host_key = None
            self.private_host_key = None
            self._conn = None
            self._node = None
            self._vm = None
            self._cached_instance = None

    def _reset_network_knowledge(self):
        for ip in (self.public_ipv4,
                   self.public_ipv6,
                   self.private_ipv4,
                   self.private_ipv6):
            if ip and self.public_host_key:
                nixops.known_hosts.remove(
                    ip,
                    self.public_host_key)

        with self.depl.db:
            self.public_ipv4 = None
            self.public_ipv6 = None
            self.private_ipv4 = None
            self.private_ipv6 = None

    def _learn_known_hosts(self, public_key: Optional[str] = None):
        if public_key is None:
            public_key = self.public_host_key
        for ip in (self.public_ipv4, self.public_ipv6,
                   self.private_ipv4, self.private_ipv6):
            if ip:
                nixops.known_hosts.add(ip, public_key)

    def create(self, defn: ResourceDefinitionType, check: bool, allow_reboot: bool, allow_recreate: bool) -> None:
        pass
