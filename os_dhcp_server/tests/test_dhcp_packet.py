# -*- coding: utf-8 -*-

# Copyright 2014 Red Hat, Inc.
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

from oslo_concurrency import processutils
from os_dhcp_server.tests import base
from os_dhcp_server import dhcp_packet
from os_dhcp_server import globals


_DHCP_PACKET_WITH_OPTIONS = [1, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             99, 130, 83, 99,  # MAGIC_COOKIE
                             1, 4, 255, 255, 255, 0, 3, 4, 10, 0, 0, 1, 255]


class TestDhcpPacket(base.TestCase):

    def setUP(self):
        super(TestDhcpPacket, self).setUp()

    def tearDown(self):
        super(TestDhcpPacket, self).tearDown()

    def test_is_ipv4_list(self):
        ipv4_list = ["192.168.0.1", "10.0.0.0", "192.168.0.2"]
        ipv4_octets = ['\xc0', '\xa8', '\x00', '\x01', # 192.168.0.1 as hex
                       '\n', '\x00', '\x00', '\x00',  # 10.0.0.0 as hex
                       '\xc0', '\xa8', '\x00', '\x02']  # 192.168.0.2 as hex
        self.assertEqual(ipv4_list, dhcp_packet.unpack_ipv4_list(ipv4_octets))

    def test_create_packet(self):
        packet = dhcp_packet.DhcpPacket()
        # Ensure that the packet has a valid Magic Cookie
        self.assertEqual(240, packet.get_option_start())

    def test_init_packet(self):
        packet = dhcp_packet.DhcpPacket([0] * 250)
        # Ensure that a totally blank packet was created
        self.assertEqual([0] * 250, packet.packet_data)
        packet.init_packet()
        # Ensure that the packet has a valid Magic Cookie after running init
        self.assertEqual(240, packet.get_option_start())

    def test_get_option_start(self):
        packet = dhcp_packet.DhcpPacket([0] * 250)
        for byte in globals.MAGIC_COOKIE:
            packet.packet_data.append(byte)
        # Magic Cookie was appended on bytes 250-253, so options start at 254
        self.assertEqual(254, packet.get_option_start())
        pass

    def test_get_dhcp_option(self):
        # First, test getting options from a raw decoded packet
        packet = dhcp_packet.DhcpPacket(_DHCP_PACKET_WITH_OPTIONS)
        dhcp_options = packet.dhcp_options
        print "get_option: %s " % packet.get_option('subnet_mask')
        packet.set_option('router', "10.0.0.2")
        print "DHCP_OPTIONS: %s " % packet.dhcp_options

    def test_set_dhcp_option(self):
        packet = dhcp_packet.DhcpPacket()
        packet.set_option('op', 1)
        self.assertEqual(1, packet.packet_data[0])
        packet.set_option('hops', 4)
        self.assertEqual(4, packet.packet_data[3])
        packet.set_option('router', "10.0.0.1")
        packet.set_option('subnet_mask', "255.255.255.0")
        print packet.dhcp_options
        print packet.encode_packet()
