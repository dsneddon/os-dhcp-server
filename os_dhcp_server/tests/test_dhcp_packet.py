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
import logging


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
                             1, 4, 255, 255, 255, 0, 3, 8, 10, 0, 0, 1, 10, 0,
                             0, 2, 26, 2, 35, 194, 255]


class TestDhcpPacket(base.TestCase):

    def setUP(self):
        super(TestDhcpPacket, self).setUp()

    def tearDown(self):
        super(TestDhcpPacket, self).tearDown()

    def test_pack_ipv4_bytes(self):
        ipv4_list = ["192.168.0.1", "10.0.0.1", "192.168.0.2"]
        ipv4_octets = [192, 168, 0, 1, 10, 0, 0, 1, 192, 168, 0, 2]
        self.assertEqual(ipv4_list, dhcp_packet.unpack_ipv4_bytes(ipv4_octets))

    def test_unpack_ipv4_bytes(self):
        ipv4_list = ["192.168.0.1", "10.0.0.1", "192.168.0.2"]
        ipv4_octets = [192, 168, 0, 1, 10, 0, 0, 1, 192, 168, 0, 2]
        self.assertEqual(ipv4_octets,
                         dhcp_packet.value_to_bytelist('[ipv4]', ipv4_list))

    def test_create_packet(self):
        packet = dhcp_packet.DhcpPacket()
        # Ensure that the packet has a valid Magic Cookie
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
        self.assertEqual(4, packet.get_option('hops'))
        self.assertEqual('10.0.0.1, 10.0.0.2', packet.get_option('router'))
        self.assertEqual('255.255.255.0', packet.get_option('subnet_mask'))
        self.assertEqual(9154, packet.get_option('interface_mtu'))

    def test_set_dhcp_option(self):
        packet = dhcp_packet.DhcpPacket()
        packet.set_option('op', 2)
        self.assertEqual(2, packet.packet_data[0])
        packet.set_option('hops', 4)
        self.assertEqual(4, packet.packet_data[3])
        packet.set_option('router', "10.0.0.1")
        packet.set_option('subnet_mask', "255.255.255.0")
        packet.set_option('interface_mtu', 9154)
        self.assertEqual({'router':'10.0.0.1', 'subnet_mask':'255.255.255.0',
                          'interface_mtu': 9154}, packet.dhcp_options)

    def test_create_dhcp_offer(self):
        packet = dhcp_packet.DhcpOffer("00:01:02:aa:bb:cc")
        self.assertEqual(2, packet.get_option('op'))
        self.assertEqual("00:01:02:aa:bb:cc", packet.chaddr)
        #print(str(packet))
        packet.set_option('chaddr', "00:01:02:aa:bb:cc")
        print("file: {}".format(packet.get_option('file')))
        print("chaddr: {}".format(packet.get_option('chaddr')))
        print packet.str()


    # def test_invalid_packets(self):
    #     packet = dhcp_packet.DhcpPacket()
    #     print packet.str()
    #     for i in range (0,230):
    #         packet.packet_data.pop()
    #     packet.map_options()
    #     print packet.packet_data
    #     print packet.str()
