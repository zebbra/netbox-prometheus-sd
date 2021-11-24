from enum import Enum
from typing import List
import logging


class HostType(Enum):
    VIRTUAL_MACHINE = "vm"
    DEVICE = "device"
    IP_ADDRESS = "ip_address"


class Host:
    """ Represents a virtual machine or device in netbox """

    hostname: str
    ip_address: str
    id: int
    host_type: str
    labels: dict[str, str]

    def __init__(self, id, hostname, ip_address, host_type: HostType):
        self.hostname = hostname
        self.ip_address = ip_address
        self.id = id
        self.host_type = host_type
        self.labels = {}
        self.labels["ip"] = ip_address
        self.labels["name"] = hostname
        self.labels["type"] = host_type.value
        self.labels["id"] = str(id)

    def add_label(self, key, value):
        """ Add a netbox prefixed meta label to the host """
        key = key.replace("-", "_").replace(" ", "_")
        logging.debug(f"Add label '{key}' with value '{value}'")

        if value == None: value = ""
        if value == True: value = "true"
        if value == False: value = "false"

        self.labels[key] = str(value)

    def to_sd_json(self):
        prefixed_labels = {f"__meta_netbox_{label}": value for (label, value) in self.labels.items()}
        return {"targets": [self.ip_address], "labels": prefixed_labels}

class HostList:
    """ Collection of host objects """

    hosts: list[Host]

    def __init__(self):
        self.hosts = []

    def clear(self):
        self.hosts = []

    def add_host(self, host: Host):
        if not self.host_exists(host):
            self.hosts.append(host)

    def host_exists(self, host: Host):
        """ Check if a host is already in the list by id and type """
        for current in self.hosts:
            if current.host_type == host.host_type and current.id == host.id:
                return True
        return False
