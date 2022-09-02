from functools import partial
from ipaddress import ip_address

import nixops.util
import proxmoxer.backends.https
from nixops.ssh_util import SSH
from proxmoxer import ProxmoxAPI

from nixops_proxmox.backends.options import CredentialsOptions, PasswordCredentialsOptions, AuthTokenOptions


class EmptyClusterError(Exception):
    def __init__(self, msg):
        super(EmptyClusterError, self).__init__(msg)
        self.msg = msg

    def __str__(self):
        return self.msg

    def __repr__(self):
        return self.__str__()


def to_prox_bool(val):
    return 1 if val else 0


def connect(
        server_url: str,
        username: str,
        *,
        credentials: CredentialsOptions,
        verify_ssl: bool = False,
        use_ssh: bool = False) -> ProxmoxAPI:
    kwargs = {
        "host": server_url,
        "user": username,
        "backend": "ssh_paramiko" if use_ssh else "https"
    }

    if isinstance(credentials, PasswordCredentialsOptions):
        kwargs["password"] = credentials.password
    elif isinstance(credentials, AuthTokenOptions):
        kwargs["token_name"] = credentials.tokenName
        kwargs["token_value"] = credentials.tokenValue

    if not use_ssh:
        kwargs["verify_ssl"] = verify_ssl

    api = ProxmoxAPI(**kwargs)

    # Verify API works
    try:
        nodes = api.nodes.get()
        if not nodes:
            raise EmptyClusterError("Proxmox cluster must have at least one node")
    except (proxmoxer.backends.https.AuthenticationError, EmptyClusterError) as error:
        raise Exception(
            f"Failed to connect to Proxmox server '{server_url}@{username}'. {type(error).__name__}: {error}"
        )

    return api


def try_ssh(user, ip, logger) -> bool:
    ssh = SSH(logger)
    ssh.register_host_fun(lambda: ip)
    ssh.register_flag_fun(lambda: ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])
    # TODO: such hacky, wow.
    ssh.register_passwd_fun(lambda: "")
    try:
        ssh.run_command("true", user, logged=False, timeout=3)
        return True
    except Exception:
        return False


def can_reach(logger, ip:str, user: str = "root", timeout: int = 10, callback=None):
    # TODO: in that case, we need to determine the correct link, is there a way?
    if ip_address(ip).is_link_local:
        return False

    return nixops.util.wait_for_success(partial(try_ssh, user, ip, logger), timeout, callback)


def first_reachable_or_none(logger, ips, user: str = "root", timeout_per_ip: int = 10, callback=None):
    for ip in ips:
        logger.log("testing {}".format(ip))
        if can_reach(logger, ip, user, timeout_per_ip, callback):
            return ip
