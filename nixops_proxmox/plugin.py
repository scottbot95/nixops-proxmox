import os.path
from typing import List

from nixops.plugins import Plugin
import nixops.plugins


# noinspection PyMethodOverriding
class ProxmoxPlugin(Plugin):

    @staticmethod
    def nixexprs() -> List[str]:
        return [os.path.dirname(os.path.abspath(__file__)) + "/nix"]

    @staticmethod
    def load():
        return [
            "nixops_proxmox.backends.proxmox"
        ]


@nixops.plugins.hookimpl
def plugin():
    return ProxmoxPlugin()
