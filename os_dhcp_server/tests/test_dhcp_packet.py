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


class TestDhcpPacket(base.TestCase):

    def setUP(self):
        super(TestDhcpPacket, self).setUp()

    def tearDown(self):
        super(TestIfcfgNetConfig, self).tearDown()

    def test_is_ipv4_list(self):
        ipv4_list = ["10.0.0.0", "192.168.0.1"]
        ipv4_octets = []
        for ip in ipv4_list:
            for octet in ip.split("."):
                ipv4_octets.append(octet)
        format = str(len(ipv4_octets)) + "c"
        ipv4_encoded_list = map(chr, format)
        pass

    def test_create_packet(self):
        pass

    def test_init_packet(self):
        pass

    def test_get_option_start(self):
        pass

    def test_get_dhcp_option(self):
        pass

    def test_set_dhcp_option(self):
        pass