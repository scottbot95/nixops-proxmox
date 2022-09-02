import time
from collections import defaultdict
from ipaddress import IPv6Address, IPv4Address, ip_address
from itertools import chain
from typing import Type, Optional, List, Any, Mapping, Dict

import nixops.util
import nixops.known_hosts
from nixops.backends import MachineDefinition, MachineState, CheckResult
from nixops.deployment import Deployment
from nixops.nix_expr import RawValue, Function, py2nix
from nixops.resources import ResourceDefinition, ResourceEval
from nixops.ssh_util import SSHCommandFailed
from nixops.state import RecordId
from proxmoxer import ProxmoxAPI, ProxmoxResource, ResourceException

import nixops_proxmox.proxmox_utils
from .options import ProxmoxMachineOptions
from nixops_proxmox.proxmox_utils import to_prox_bool, can_reach, first_reachable_or_none


class VirtualMachineDefinition(MachineDefinition):
    """Definition of a Proxmox QEMU VM"""

    config: ProxmoxMachineOptions

    @classmethod
    def get_type(cls: Type[ResourceDefinition]) -> str:
        return 'proxmox'

    def __int__(self, name: str, config: ResourceEval):
        super().__init__(name, config)

        # for key in ('profile', 'serverUrl', 'username', 'credentials', 'useSSH', 'disks',
        #             'node', 'pool', 'sockets', 'cores', 'memory',
        #             'startOnBoot', 'protectVM', 'hotplugFeatures',
        #             'cpuLimit', 'cpuUnits', 'cpuType', 'arch',
        #             'vmid', 'postPartitioningLocalCommands',
        #             'partitions', 'expertArgs', 'installISO', 'network',
        #             'uefi', 'usePrivateIPAddress'):
        #     setattr(self, key, getattr(self.config.proxmox, key))

    def show_type(self) -> str:
        return '{0} [{1}]'.format(self.get_type(), self.config.proxmox.serverUrl)

    def host_key_type(self) -> str:
        return (
            'ed25519'
            if nixops.util.parse_nixos_version(self.config.nixosRelease) >= ['15', '09']
            else 'dsa'
        )


class VirtualMachineState(MachineState[VirtualMachineDefinition]):
    """State of a Proxmox VM"""

    @classmethod
    def get_type(cls) -> str:
        return 'proxmox'

    state = nixops.util.attr_property('state', MachineState.MISSING, int)

    public_ipv4 = nixops.util.attr_property('publicIPv4', None)
    public_ipv6 = nixops.util.attr_property('publicIPv6', None)
    private_ipv4 = nixops.util.attr_property('privateIPv4', None)
    private_ipv6 = nixops.util.attr_property('privateIPv6', None)

    public_dns_name = nixops.util.attr_property('publicDNSName', None)

    use_private_ip_address = nixops.util.attr_property(
        'proxmox.usePrivateIPAddress',
        False,
        type=bool
    )

    serverUrl = nixops.util.attr_property('proxmox.serverUrl', None)
    node = nixops.util.attr_property('proxmox.node', None)
    username = nixops.util.attr_property('proxmox.username', None)
    credentials = nixops.util.attr_property('proxmox.credentials', None, 'json')

    useSSH = nixops.util.attr_property('proxmox.useSSH', False)

    verifySSL = nixops.util.attr_property('proxmox.verifySSL', False)

    partitions = nixops.util.attr_property('proxmox.partitions', None)

    public_host_key = nixops.util.attr_property('proxmox.publicHostKey', None)
    private_host_key = nixops.util.attr_property('proxmox.privateHostKey', None)

    first_boot = nixops.util.attr_property(
        'proxmox.firstBoot',
        True,
        type=bool
    )
    installed = nixops.util.attr_property(
        'proxmox.installed',
        False,
        type=bool)
    partitioned = nixops.util.attr_property(
        'proxmox.partitioned',
        False,
        type=bool)

    def __init__(self, depl: Deployment, name: str, id: RecordId):
        super().__init__(depl, name, id)
        self.cores = None
        self.cpus = None
        self.memory = None
        self.profile: Optional[str] = None
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

    @property
    def public_ip(self) -> Optional[str]:
        return self.public_ipv6 or self.public_ipv4

    @property
    def private_ip(self) -> Optional[str]:
        return self.private_ipv6 or self.private_ipv4

    @property
    def resource_id(self):
        return self.vm_id

    @property
    def _client(self) -> ProxmoxAPI:
        if self._conn:
            return self._conn
        self._conn = nixops_proxmox.proxmox_utils.connect(
            self.serverUrl, self.username,
            credentials=self.credentials,
            use_ssh=self.useSSH,
            verify_ssl=self.verifySSL
        )
        return self._conn

    @property
    def _node_client(self, node: Optional[str] = None) -> ProxmoxResource:
        return self._client.nodes(node or self.node)

    @property
    def _vm_client(self, vm_id: Optional[int] = None) -> ProxmoxResource:
        return self._node_client.qemu(vm_id or self.resource_id)

    def _get_instance(self, instance_id: Optional[int] = None, *, allow_missing: bool = False,
                      force_update: bool = False):
        self._vm_client.get()
        if not instance_id:
            instance_id = self.resource_id

        assert instance_id, 'Cannot get instance of a VM that has not been created yet'
        if not self._cached_instance or force_update:

            # noinspection PyBroadException
            try:
                instance = self._vm_client(instance_id).status.current.get()
            except Exception:
                if allow_missing:
                    instance = None
                else:
                    raise

            self._cached_instance = instance

        return self._cached_instance

    def has_temporary_key(self) -> bool:
        return 'NixOps auto-generated key' in self.public_host_key

    def _get_free_vmid(self):
        return self._client.cluster.nextid.get()

    def _allocate_disk_image(self, filename: str, size: str, volume: str, vmid: int) -> str:
        try:
            return self._node_client.storage(volume).content.post(
                filename=filename,
                size=size,
                vmid=vmid
            )
        except ResourceException as e:
            if 'already exists' in str(e):
                return f'{volume}:{filename}'
            else:
                raise e

    def _create_instance(self, defn: VirtualMachineDefinition, vmid: int) -> Any:
        if not self.public_host_key or self.provision_ssh_key:
            self.log_start('Generating new SSH key pair...')
            (private, public) = nixops.util.create_key_pair(type=defn.host_key_type())

            with self.depl.db:
                self.public_host_key = public
                self.private_host_key = private

            self.log_end('done')

        config = defn.config.proxmox
        options = {
            'vmid': vmid,
            'name': defn.name,
            'agent': 'enabled=1,type=virtio',
            'vga': 'qxl',
            'args': config.expertArgs,
            'bios': 'ovmf' if config.uefi.enable else 'seabios',
            'sockets': config.sockets or 1,
            'cores': config.cores or 1,
            'cpu': config.cpuType or 'kvm64',
            'cpulimit': config.cpuLimit or 0,
            'cpuunits': config.cpuUnits or 1024,
            'memory': config.memory,
            'description': 'NixOps-managed VM',
            'pool': config.pool,
            'hotplug': config.hotplugFeatures or '1',
            'onboot': to_prox_bool(config.startOnBoot),
            'ostype': 'l26',
            'protection': to_prox_bool(config.terminationProtection),
            'cdrom': config.installISO,
            'serial0': 'socket',
            'scsihw': 'virtio-scsi-pci',
            'start': 1,
            'unique': 1,
            'archive': 0,
        }

        if config.arch is not None:
            options['arch'] = config.arch

        # networks
        for i, net in enumerate(config.network):
            options[f"net{i}"] = (",".join(
                [
                    f"model={net.model}",
                    f"bridge={net.bridge}"
                ]
                + ([f"tag={net.tag}"] if net.tag else [])
                + ([f"trunks={';'.join(net.trunks)}"] if net.trunks else [])))

            if net.ip:
                ipConfig = []
                if net.ip["v4"]:
                    ipConfig.append(f'gw={net.ip["v4"].gateway}')
                    ipConfig.append(f'ip={net.ip["v4"].address}/{net.ip["v4"].prefixLength}')
                if net.ip["v6"]:
                    ipConfig.append(f'gw6={net.ip["v6"].gateway}')
                    ipConfig.append(f'ip6={net.ip["v6"].address}/{net.ip["v6"].prefixLength}')

                if len(ipConfig) > 0:
                    options[f'ipconfig{i}'] = ','.join(ipConfig)

        # disks
        max_indexes = defaultdict(lambda: 0)
        for i, disk in enumerate(config.disks):
            filename = f'vm-{vmid}-disk-{i}'
            options[f'scsi{i}'] = (','.join([
                                                f'file={disk.volume}:{filename}',
                                                f'size={disk.size}',
                                                f'ssd={1 if disk.enableSSDEmulation else 0}',
                                                f"discard={'on' if disk.enableDiscard else 'ignore'}"
                                            ]
                                            + ([f'aio={disk.aio}'] if disk.aio else [])))
            self._allocate_disk_image(filename, disk.size, disk.volume, vmid)
            max_indexes[disk.volume] += 1

        # uefi
        if config.uefi and config.uefi.enable:
            filename = f'vm-{vmid}-disk-{max_indexes[config.uefi.volume] + 1}'
            options['efidisk0'] = f'{config.uefi.volume}:{filename}'
            self._allocate_disk_image(filename, '4M', config.uefi.volume, vmid)

        try:
            self.logger.log_start('Creating proxmox VM...')
            result = self._node_client.qemu.post(**options)
        finally:
            self.logger.log_end('done')

        return result

    def _execute_command_with_agent(self, command: str, stdin_data: str = '', *, instance_id: Optional[int] = None):
        result = self._vm_client(instance_id).agent.exec.post(**{
            'command': command,
            'input-data': stdin_data
        })

        def get_status():
            return self._vm_client(instance_id).agent('exec-status').get(pid=int(result['pid']))

        current_status = get_status()
        while not current_status['exited']:
            current_status = get_status()

        return current_status['exitcode'], current_status.get('out-data', '')

    @property
    def _is_in_live_cd(self) -> bool:
        return bool(self._execute_command_with_agent('test -e /.install_status')[0])

    def _qemu_agent_is_running(self):
        try:
            self._execute_command_with_agent('true')
            return True
        except Exception as e:
            if 'not running' in str(e):
                return False
            else:
                raise e

    def _wait_for_qemu_agent(self):
        def _qemu_agent_is_running():
            if not self._qemu_agent_is_running():
                raise ValueError("Did not return True")

        nixops.util.wait_for_success(_qemu_agent_is_running)

    def _provision_ssh_key_through_agent(self):
        self.log_start('Provisioning SSH key through QEMU Agent...')
        self._execute_command_with_agent('mkdir -p /root/.ssh')
        self._vm_client.agent('file-write').post(
            content=f'# This was generated by NixOps during initial installation phase.\n' +
                    f'# Do not edit.\n{self.public_host_key}',
            file='/root/.ssh/authorized_keys'
        )
        self._execute_command_with_agent('chown -R root /root/.ssh')
        self._execute_command_with_agent('chmod 755 /root/.ssh/authorized_keys')
        self.log_end('Provisioned')

    def _partition_disks(self, partitions):
        self.log_start('Partitioning disks...')
        try:
            self.run_command('umount -R /mnt || true')

            self._vm_client.agent('file-write').post(
                content=f'#!/run/current-system/sw/bin/bash\n{partitions}',
                file='/tmp/partition.sh'
            )
            self.run_command('chmod +x /tmp/partition.sh')
            out = self.run_command('/tmp/partition.sh', capture_stdout=True)
        except SSHCommandFailed as failed_command:
            if failed_command.exitcode == 100:  # Reboot requried
                self.log(failed_command.message)
                self.reboot()
                return
            else:
                raise

        self.log_end('Partitioned')
        with self.depl.db:
            self.partitions = partitions
            self.fs_info = out
            self.partitioned = True

        return out

    def _configure_initial_nix(self, uefi: bool):
        self.log_start('Generating the initial configuration...')

        # 1. Generate the HW configuration and the standard configuration
        self.run_command('nixos-generate-config --root /mnt', capture_stdout=True)

        # 2. Add overrides to configuration.nix
        nixos_cfg = {
            'imports': [RawValue('./hardware-configuration.nix')],
            ('boot', 'kernelParams'): ['console=ttyS0'],
            ('services', 'openssh', 'enable'): True,
            ('services', 'qemuGuest', 'enable'): True,
            ('systemd', 'services', 'qemu-guest-agent', 'serviceConfig'): {
                'RuntimeDirectory': 'qemu-ga',
                'ExecStart': RawValue('lib.mkForce "\\${pkgs.qemu.ga}/bin/qemu-ga -t /var/run/qemu-ga"')
            },
            ('services', 'getty', 'autologinUser'): 'root',
            ('networking', 'firewall', 'allowedTCPPorts'): [22],
            ('users', 'users', 'root'): {
                ('openssh', 'authorizedKeys', 'keys'): [self.public_host_key],
                'initialPassword': ''
            },
            ('users', 'mutableUsers'): False
        }

        if uefi:
            nixos_cfg[('boot', 'loader')] = {
                ('efi', 'canTouchEfiVariables'): True,
                ('systemd-boot', 'enable'): True,
            }
        else:
            nixos_cfg[('boot', 'loader', 'grub', 'devices')] = ['/dev/sda']

        nixos_initial_postinstall_conf = py2nix(Function('{ config, pkgs, lib, ... }', nixos_cfg))
        self.run_command(f'cat <<EOF > /mnt/etc/nixos/configuration.nix\n{nixos_initial_postinstall_conf}\nEOF')
        self.run_command('echo preinstall > /mnt/.install_status')
        self.log_end('Initial configuration generated')
        self.log_start('Installing NixOS...')
        self.run_command('nixos-install --no-root-passwd', capture_stdout=True)
        self.log_end('NixOS installed')
        self.run_command('echo installed > /mnt/.install_status')

    def _reinstall_host_key(self, key_type, *, max_attempts: int = 10):
        self.log_start('Reinstalling new host keys...')
        attempts = 0

        while True:
            try:
                exitcode, new_key = self._execute_command_with_agent(f'cat /etc/ssh/ssh_host_{key_type}_key.pub')
                new_key = str(new_key).rstrip()
                if exitcode != 0:
                    raise Exception(f'Failed to read SSH host key from VM {self.name} during re-installation')
                break
            except Exception as e:
                attempts += 1
                if attempts >= max_attempts:
                    raise e
                self.log(f'Failed to read SSH host key (attempt {attempts}/{max_attempts}), retrying...')
                time.sleep(1)

        self._learn_known_hosts(new_key)
        self.log_end('Installed...')

    def _post_install(self, host_key_type: str, check: bool):
        self._wait_for_ip()

        self._reinstall_host_key(host_key_type)
        self.write_ssh_private_key(self.private_host_key)

        self.wait_for_ssh(check=check)
        self.run_command('echo postinstall > /.install_status')

        self.installed = True
        self.state = self.UP

    def create(self, defn: VirtualMachineDefinition, check: bool, allow_reboot: bool, allow_recreate: bool) -> None:
        if self.state != self.UP:
            check = True

        config = defn.config.proxmox

        self.set_common_state(defn)

        self.profile = config.profile
        self.serverUrl = config.serverUrl
        self.username = config.username
        self.credentials = config.credentials
        self.useSSH = config.useSSH

        assert self.serverUrl is not None, \
            "There is no Proxmox server URL set," + \
            " set `deployment.proxmox.serverUrl` or a valid `deployment.proxmox.profile`"
        self.use_private_ip_address = config.usePrivateIPAddress

        nodes = self._client.nodes.get()
        if len(nodes) == 0:
            raise Exception('No nodes found in Proxmox cluster')
        if len(nodes) > 1 and (config.node is None):
            raise Exception('Multiple nodes in Proxmox cluster. Please specify deployment.proxmox.node')
        self.node = config.node or nodes[0]['node']

        pools = self._client.pools.get()
        assert config.pool is None or config.pool in [pool['poolid'] for pool in pools], \
            f'There is no pool named `{config.pool}`, ensure you set `deployment.proxmox.pool` to a valid value ' \
            "or verify your Proxmox user permissions or cluster."

        if self.resource_id and allow_reboot:
            self.stop()
            check = True

        if self.vm_id and check:
            instance = self._get_instance(allow_missing=True)

            if instance is None:
                if not allow_recreate:
                    raise Exception(f"Proxmox VM '{self.name}' doesn't exist. use --allow-recreate to create a new one")

                self.log(f"Proxmox VM '{self.name}' doesn't exist "
                         f"(status: {instance['status'] if instance else 'gone'}). "
                         f"Will re-create")
                self._reset_state()
            elif instance['status'] == 'stopped':
                self.log(f"Proxmox VM '{self.name}' was stopped, restarting...")
                # Change the memory allocation
                self._reset_network_knowledge()
                self.start()

        # Create the QEMU
        if not self.resource_id:
            has_user_vmid = config.vmid is not None
            while True:
                vmid = config.vmid or self._get_free_vmid()
                self.log(f'Creating VM in {self.node} ID: {vmid} with {config.memory} memory')
                try:
                    instance = self._create_instance(defn, vmid)
                    break
                except Exception as e:
                    if 'already exists' in str(e):
                        if has_user_vmid:
                            raise Exception(f'Specified VM is not free.')
                        else:
                            self.log(f'vmid collision, trying another one.')
                    else:
                        print('Failure', e)

            with self.depl.db:
                self.vm_id = vmid
                self.memory = config.memory
                self.cpus = config.sockets
                self.cores = config.cores
                self.state = self.RESCUE

        if self.state not in (self.UP, self.RESCUE) or check:
            while True:
                if self._get_instance(allow_missing=True):
                    break
                self.log(f"Proxmox VM instance '{self.vm_id}' not known yet, waiting...")
                time.sleep(3)

        instance = self._get_instance

        self._wait_for_qemu_agent()
        self.state = self.RESCUE if self._is_in_live_cd else self.UP

        # If using live cd, provision ourselves through the agent
        if self.state == self.RESCUE:
            self.log("In live CD (rescue mode)")
        self._provision_ssh_key_through_agent()
        self.write_ssh_private_key(self.private_host_key)
        time.sleep(1)  # Give some time for it to pick up the SSH key

        if self.public_ip or (self.use_private_ip_address and not self.private_ip) or check:
            self._wait_for_ip()
        time.sleep(1)

        if self.state == self.RESCUE:
            self.log('Initial installation in rescue mode')
            old_ssh_user = self.ssh_user
            self.ssh_user = 'root'
            self.wait_for_ssh(check=check)
            # partitions don't match
            if self.partitions and self.partitions != config.partitions:
                if self.depl.logger.confirm('Partition table changed, re-run partitioning phase?'):
                    self.partitioned = False

            if self.partitioned:
                self._partition_disks(config.partitions)
            else:
                if self._partition_disks(config.partitions):
                    time.sleep(1)
                    self._provision_ssh_key_through_agent()
                    self.write_ssh_private_key(self.private_host_key)
                    self.wait_for_ssh(check=check)
            self._configure_initial_nix(config.uefi.enable)
            self.reboot()
            self._wait_for_qemu_agent()
            self._post_install(defn.host_key_type(), check)
            self.ssh_user = old_ssh_user

        # Check if a previous installation failed
        if self.state != self.RESCUE and not self.installed:
            self.log_start('Resuming the post-installation...')
            old_ssh_user = self.ssh_user
            self.ssh_user = 'root'
            self._post_install(defn.host_key_type(), check)
            self.log_end('Post-install finished')
            self.ssh_user = old_ssh_user

        if self.first_boot and self.installed:
            self.first_boot = False

        self.write_ssh_private_key(self.private_host_key)

    def destroy(self, wipe: bool = False) -> bool:
        if not self.vm_id:
            return True

        if not self.depl.logger.confirm(f"Are you sure you want to destroy Proxmox VM '{self.vm_id}'"):
            return False

        if wipe:
            self.warn('Wipe is not currently supported on Proxmox')

        instance = None
        if self.vm_id:
            instance = self._get_instance(allow_missing=True)

        if instance:
            self._vm_client.status.stop.post()

            instance = self._get_instance(force_update=True)
            while instance['status'] != 'stopped':
                self.log_continue(f"[{instance['status']}]")
                time.sleep(2.5)
                instance = self._get_instance(force_update=True)

            self._vm_client.delete(purge=1)

        self.log_end('')
        self._reset_network_knowledge()

        return True

    def stop(self, hard: bool = False) -> None:
        if not self.depl.logger.confirm(f"Are you sure you want to stop machine '{self.name}'"):
            return

        self.log_start('Stopping Proxmox VM...')

        self._vm_client.status.shutdown.post()
        self.state = self.STOPPING

        # Wait until it's really stopped
        def check_stopped() -> bool:
            instance = self._get_instance(force_update=True)
            cur_state = instance['state']
            self.log_continue(f"[{cur_state}]")

            if cur_state == 'stopped':
                return True
            if cur_state != 'running':
                raise Exception(f"Proxmox VM '{self.vm_id}' failed to stop (state is '{cur_state}')")
            return False

        if not nixops.util.check_wait(check_stopped, initial=3, max_tries=300, exception=False):
            self.log_end('(timed out)')
            self.log_start('force-stopping Proxmox VM...')
            self._vm_client.status.stop.post()
            nixops.util.check_wait(check_stopped, initial=3, max_tries=100)

        self.log_end('')
        self.state = self.STOPPED
        self.ssh._ssh_master = None

    def start(self) -> None:
        self.log(f"Starting Proxmox VM '{self.vm_id}'")

        self._vm_client.status.start.post()
        self.state = self.STARTING

        self._wait_for_ip()
        self.wait_for_ssh()
        self.send_keys()

    def restore(self, defn, backup_id: Optional[str], devices: List[str] = []):
        # TODO
        super().restore(defn, backup_id, devices)

    def remove_backup(self, backup_id, keep_physical=False):
        # TODO
        super().remove_backup(backup_id, keep_physical)

    def get_backups(self) -> Mapping[str, Mapping[str, Any]]:
        # TODO
        return super().get_backups()

    def backup(self, defn, backup_id: str, devices: List[str] = []) -> None:
        # TODO
        super().backup(defn, backup_id, devices)

    def reboot(self, hard: bool = False) -> None:
        self.logger.log('Rebooting Proxmox VM...')
        if hard:
            self._vm_client.status.reset.post()
        else:
            self._vm_client.status.reboot.post()

        self.state = self.STARTING

    def reboot_sync(self, hard: bool = False) -> None:
        # FIXME Do we need to do something special here?
        super().reboot_sync(hard)

    def get_ssh_flags(self, *args, **kwargs) -> List[str]:
        file = self.get_ssh_private_key_file()
        super_flags = super(VirtualMachineState, self).get_ssh_flags(*args, **kwargs)

        return super_flags + (['-i', file] if file else []) + (
            ['-o', 'StrictHostKeyChecking=accept-new'] if self.has_temporary_key() else [])

    def get_ssh_name(self) -> str:
        if self.use_private_ip_address:
            if not self.private_ip:
                raise Exception(f"Proxmox machine '{self.name}' does not have a private (v4 or v6) address (yet)")
            return self.private_ip
        else:
            if not self.public_ip:
                raise Exception(f"Proxmox machine '{self.name}' does not have a public (v4 or v6) address (yet)")
            return self.public_ip  # User IP v6 by default

    def get_ssh_private_key_file(self) -> Optional[str]:
        if self._ssh_private_key_file:
            return self._ssh_private_key_file

    def get_console_output(self) -> str:
        # TODO capture serial output somehow
        return super().get_console_output()

    def _check(self, res: CheckResult):
        if not self.vm_id:
            res.exists = False
            return

        instance = self._get_instance(allow_missing=False)

        if instance is None:
            self.state = self.MISSING
            self.vm_id = None
            return

        res.exists = True

        if instance['status'] == 'running':
            res.is_up = True
            res.disks_ok = True
            super()._check(res)
        elif instance['status'] == 'stopped':
            res.is_up = False
            self.state = self.STOPPED

    def _wait_for_ip(self):
        self.log_start("waiting for at least a reachable IP address... ")

        def _instance_ip_ready(interfaces):
            potential_ips = []
            for name, if_ in interfaces.items():
                if name == "lo":
                    continue

                potential_ips.extend(if_.get('ip-addresses', []))

            if not potential_ips:
                return False

            return any((can_reach(self.logger, i['ip-address'], self.ssh_user) for i in potential_ips))

        while True:
            instance = self._get_instance(force_update=True)
            self.log_continue(f"[{instance['status']}]")

            if instance['status'] == 'running':
                net_ifs = self._get_network_interfaces()
                if net_ifs:
                    self.log_continue(f"[{', '.join(net_ifs.keys())}]")
            else:
                net_ifs = {}

            if instance['status'] == "stopped":
                raise Exception(
                    f"Proxmox VM '{self.resource_id}' failed to start (state is '{instance['status']}')"
                )

            if _instance_ip_ready(net_ifs):
                break

            time.sleep(3)

        ip_addresses = list(chain.from_iterable(
            map(lambda i: ip_address(i['ip-address']), if_['ip-addresses']) for name, if_ in net_ifs.items() if
            if_['ip-addresses'] and name != "lo"))
        private_ips = {str(ip) for ip in ip_addresses if ip.is_private and not ip.is_link_local}
        public_ips = {str(ip) for ip in ip_addresses if not ip.is_private}
        ip_v6 = {str(ip) for ip in ip_addresses if isinstance(ip, IPv6Address)}
        ip_v4 = {str(ip) for ip in ip_addresses if isinstance(ip, IPv4Address)}

        with self.depl.db:
            self.private_ipv4 = first_reachable_or_none(self.logger, private_ips & ip_v4)
            self.public_ipv4 = first_reachable_or_none(self.logger, public_ips & ip_v4)
            self.private_ipv6 = first_reachable_or_none(self.logger, private_ips & ip_v6)
            self.public_ipv6 = first_reachable_or_none(self.logger, public_ips & ip_v6)
            self.ssh_pinged = False

        self.log_end(
            f"[IPv4: {self.public_ipv4} / {self.private_ipv4}][IPv6: {self.public_ipv6} / {self.private_ipv6}]")

        if not self.has_temporary_key():
            self._learn_known_hosts()

    def _get_network_interfaces(self, instance_id: Optional[int] = None) -> Dict[str, Any]:
        if not instance_id:
            instance_id = self.resource_id

        assert instance_id, "Cannot get instance of a non-created virtual machine!"
        ins = self._get_instance(instance_id, force_update=True)

        assert bool(ins['agent']), "Cannot get network interfaces without QEMU Agent!"
        try:
            net_interfaces = {interface["name"]: interface for interface in
                              self._vm_client.agent.get("network-get-interfaces").get("result")}
            assert net_interfaces.get("lo") is not None, "No loopback interface in the result!"
        except Exception as e:
            return {}

        return net_interfaces
