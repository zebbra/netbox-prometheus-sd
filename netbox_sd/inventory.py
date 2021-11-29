import logging
import sys
import os
import json
import argparse
import time

import netaddr
from netaddr.ip import IPAddress

from pynetbox.core.api import Api
from pynetbox.core.response import Record
from pynetbox import RequestError
from pynetbox.models.dcim import Devices
from pynetbox.models.virtualization import VirtualMachines
from requests.exceptions import ConnectionError

from prometheus_client import Summary, Gauge, Counter

from pprint import pprint

from .writer import PrometheusSDWriter
from .model import Host, HostType, HostList

POPULATION_TIME = Summary(
    "netbox_sd_populate_seconds", "Time spent populating the inventory from netbox"
)
HOST_GAUGE = Gauge("netbox_sd_hosts", "Number of hosts discovered by netbox-sd")
NETBOX_REQUEST_COUNT_TOTAL = Counter(
    "netbox_sd_requests_total", "Total count of requests to netbox API"
)
NETBOX_REQUEST_COUNT_ERROR_TOTAL = Counter(
    "netbox_sd_requests_error_total", "Total count of failed requests to netbox API"
)


class NetboxInventory:
    netbox: Api
    host_list: HostList

    def __init__(self, netbox: Api):
        self.netbox = netbox
        self.host_list = HostList()

    @POPULATION_TIME.time()
    def populate(self, filter, netbox_objects):
        self.host_list.clear()
        # filter = {"status": "active"}
        logging.debug(f"Filter is :{filter}")

        if 'vm' in netbox_objects:
            NETBOX_REQUEST_COUNT_TOTAL.inc()
            vm_list = self.netbox.virtualization.virtual_machines.filter(**filter)
            logging.debug(f"Found {len(vm_list)} active virtual machines")

            for vm in vm_list:
                # filter vms without primary ip
                if not getattr(vm, "primary_ip"):
                    logging.debug(f"Drop vm '{vm.name}' due to missing primary IP")
                    continue
                host = self._populate_target_from_netbox(vm, HostType.VIRTUAL_MACHINE)
                # Add services
                self._get_service_list_for_host(host, virtual_machine_id=vm.id)
                self.host_list.add_host(host)
        else:
            logging.debug(f"skip vm population")

        if 'device' in netbox_objects:
            # Get all active devices
            NETBOX_REQUEST_COUNT_TOTAL.inc()
            device_list = self.netbox.dcim.devices.filter(**filter)
            logging.debug(f"Found {len(device_list)} active devices")
            for device in device_list:
                # filter devices without primary ip
                if not getattr(device, "primary_ip"):
                    logging.debug(
                        f"Drop device '{device.name}' due to missing primary IP"
                    )
                    continue
                host = self._populate_target_from_netbox(device, HostType.DEVICE)
                # Add services
                self._get_service_list_for_host(host, device_id=device.id)
                self.host_list.add_host(host)
        else:
            logging.debug(f"skip device population")

        if 'ip_address' in netbox_objects:
            if len(netbox_objects) > 1:
                logging.warn(f"NETBOX_OBJECTS is set to {netbox_objects} which will lead to duplicated entries in the Prometheus servive discovery")
            # Get all active devices
            NETBOX_REQUEST_COUNT_TOTAL.inc()
            ip_addresses_list = self.netbox.ipam.ip_addresses.filter(**filter)
            logging.debug(f"Found {len(ip_addresses_list)} active ip addresses")
            for ip_address in ip_addresses_list:
                host = self._populate_target_from_netbox(ip_address, HostType.IP_ADDRESS)
                self.host_list.add_host(host)
        else:
            logging.debug(f"skip ip_addresses population")

        HOST_GAUGE.set(len(self.host_list.hosts))



    def _populate_target_from_netbox(self, data: Record, host_type: HostType):
        # if not data.has_details:
        #     data.full_details()

        """
        Map values from netbox Records containing a virtual machine or device to a host object.
        See https://pynetbox.readthedocs.io/en/latest/response.html for more details on records.
        """

        ip = self._get_ip_from_record(data, host_type)
        name = self._get_name_from_record(data, host_type)
        host = Host(data.id, name, ip, host_type=host_type)

        if host.host_type == HostType.DEVICE:
            self._populate_device_labels_from_netbox(data, host)

        if host.host_type == HostType.VIRTUAL_MACHINE:
            self._populate_vm_labels_from_netbox(data, host)

        if host.host_type == HostType.IP_ADDRESS:
            self._populate_ip_address_labels_from_netbox(data, host)

        # Add common attributes for all objects
        if getattr(data, "status", None):
            host.add_label("status", data.status.value)

        if getattr(data, "tenant", None):
            host.add_label("tenant", data.tenant.name)
            host.add_label("tenant_slug", data.tenant.slug)
            if data.tenant.group:
                host.add_label("tenant_group", data.tenant.group.name)
                host.add_label("tenant_group_slug", data.tenant.group.slug)

        if getattr(data, "platform", None):
            host.add_label("platform", data.platform.name)
            host.add_label("platform_slug", data.platform.slug)

        # Add custom attributes
        if getattr(data, "custom_fields", None):
            for key, value in data["custom_fields"].items():
                host.add_label("custom_field_" + key, value)

        # Add Tags as comma separated list
        if getattr(data, "tags", None):
            host.add_label("tags", ",".join([t.name for t in data.tags]))
            host.add_label("tag_slugs", ",".join([t.slug for t in data.tags]))


        return host

    def _find_assigned_host_for_ip_address(self, ip_address: IPAddress):
        host_id = None
        host_type = None

        if ip_address.assigned_object_type == "virtualization.vminterface":
            host_id = ip_address.assigned_object.virtual_machine.id
            host_type = HostType.VIRTUAL_MACHINE
        elif ip_address.assigned_object_type == "dcim.interface":
            host_id = ip_address.assigned_object.device.id
            host_type = HostType.DEVICE
        else:
            return None

        for host in self.host_list.hosts:
            if host.id == host_id and host.host_type == host_type:
                return host

    def _populate_ip_address_labels_from_netbox(self, ip_address: IPAddress, host: Host):
        assigned_object = self._find_assigned_host_for_ip_address(ip_address)

        if assigned_object is not None:
            for (label, value) in assigned_object.labels.items():
                host.add_label(f"assigned_object_{label}", value)

    def _populate_device_labels_from_netbox(self, device: Devices, host: Host):
        if getattr(device, "site", None):
            host.add_label("site", device.site.name)
            host.add_label("site_slug", device.site.slug)
        if getattr(device, "device_role", None):
            host.add_label("role", device.device_role.name)
            host.add_label("role_slug", device.device_role.slug)
        if getattr(device, "device_type", None):
            host.add_label("device_type", device.device_type.model)
            host.add_label("device_type_slug", device.device_type.slug)

    def _populate_vm_labels_from_netbox(self, vm: VirtualMachines, host: Host):
        if getattr(vm, "role", None):
            host.add_label("role", vm.role.name)
            host.add_label("role_slug", vm.role.slug)

        if getattr(vm, "cluster", None):
            host.add_label("cluster", vm.cluster.name)
            # Add site from cluster if type is a VM
            if getattr(vm.cluster, "site", None):
                host.add_label("site", vm.cluster.site.name)
                host.add_label("site_slug", vm.cluster.site.slug)


    def _get_service_list_for_host(self, host, virtual_machine_id=None, device_id=None):
        NETBOX_REQUEST_COUNT_TOTAL.inc()
        service_list = self.netbox.ipam.services.filter(
            virtual_machine_id=virtual_machine_id, device_id=device_id
        )
        logging.debug(
            f"Found {len(service_list)} services for virtual_machine={virtual_machine_id} or device={device_id}"
        )
        for service in service_list:
            # netbox <= 2.9
            if getattr(service, "port", None):
                host.add_label("service_%s" % service.name, service.port)
            # netbox >= 2.10
            elif getattr(service, "ports", None):
                host.add_label(
                    "service_%s" % service.name, ",".join(str(x) for x in service.ports)
                )


    def _get_ip_from_record(self, data: Record, host_type: HostType):
        """
        Extract IP address from netbox Records containing a virtual machine, device or ip-address.
        See https://pynetbox.readthedocs.io/en/latest/response.html for more details on records.
        """

        if host_type == HostType.VIRTUAL_MACHINE or host_type == HostType.DEVICE:
            if data.primary_ip is not None:
                return str(netaddr.IPNetwork(data.primary_ip.address).ip)

        if host_type == HostType.IP_ADDRESS:
            return str(netaddr.IPNetwork(data.address).ip)

    def _get_name_from_record(self, data: Record, host_type: HostType):
        """
        Extract name used as label __meta_netbox_name from netbox Records containing a virtual machine, device or ip-address.
        See https://pynetbox.readthedocs.io/en/latest/response.html for more details on records.
        """

        if host_type == HostType.VIRTUAL_MACHINE or host_type == HostType.DEVICE:
            return data.name

        if host_type == HostType.IP_ADDRESS:
            if getattr(data, "dns_name", None):
                return data.dns_name
            else:
                return self._get_ip_from_record(data, host_type)
