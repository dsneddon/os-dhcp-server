# -*- coding: utf-8 -*-

# Copyright 2014-2015 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


import logging
import netaddr


logger = logging.getLogger(__name__)


class Route(object):
    """Base class for network routes."""

    def __init__(self, next_hop, ip_netmask="", default=False):
        self.next_hop = next_hop
        self.ip_netmask = ip_netmask
        self.default = default

    @staticmethod
    def from_json(json):
        next_hop = _get_required_field(json, 'next_hop', 'Route')
        ip_netmask = json.get('ip_netmask', "")
        default = strutils.bool_from_string(str(json.get('default', False)))
        return Route(next_hop, ip_netmask, default)


class Subnet(object):
    """Base class for dhcp info for network subnets"""

    def __init__(self, name=None, ip_netmask, gateway, start_ip, end_ip, tftp=None,
                 pxefile=None):
        self.name = name or ''
        network = netaddr.IPNetwork(ip_netmask)
        self.net_addr = str(network.network)
        self.broadcast = str(network.broadcast)
        self.gateway = gateway
        self.start_ip = start_ip
        self.end_ip = end_ip
        self.tftp = tftp or ''
        self.pxefile = pxefile or ''

    @staticmethod
    def from_json(json):
        name = json.get('name')
        ip_netmask = json.get('ip_netmask')
        gateway = json.get('gateway')
        start_ip = json.get('start_ip')
        end_ip = json.get('end_ip')
        tftp = json.get('tftp')
        pxefile = json.get('pxefile')

        return Subnet(name, ip_netmask, gateway, start_ip,
                      end_ip, tftp, pxefile)
