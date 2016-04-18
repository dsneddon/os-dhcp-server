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
from struct import pack
from struct import unpack
from os_net_config import constants


logger = logging.getLogger(__name__)


def is_ipv4_list(ip_list):
    # Validate that ip_list is a list of IPs encoded as packed bytes
    while ip_list:
        # grab 4 octets, if we can
        for i in range(0,4):
            try:
                if int(ip_list.pop())>>32:
                    return False
    if isinstance(ip_list, list):
        for item in ip_list:
            if int(item)>>32: return False
        return True
    else:
        return False


def get_dhcp_option(option):
    """ Return name if given ID, or ID if given name"""

    if isinstance(option, int):
        return constants.DHCP_OPTIONS[option]
    else:
        return constants.DHCP_OTIONS.index(option)


class DhcpPacket(object):
    """ Packet handler class for DHCP packets """

    """ DHCP """

    def __init__(self):
        self.source_address = False
        self.init_packet()
        self.dhcp_options = {}
        logger.info("DhcpPacket class created")


    def init_packet(self):
        ''' Initialize a blank DHCP packet '''
        self.packet_data = [0]*240
        self.packet_data[236:240] = globals.MagicCookie
        logger.debug("Initializing blank DHCP packet")


    def get_option_start(self):
        ''' Return location after MagicCookie, or None if not found '''

        # Sometimes it's right where you expect it
        if self.packet_data[236:240] == globals.MagicCookie:
            logger.debug("DHCP packet received, contains MagicCookie")
            return 236
        else:
            # search the entire packet, but not past packet end
            for i in range(237,len(packet_data)-4):
                if self.packet_data[i:i+4] == globals.MAGIC_COOKIE:
                    logger.debug("DHCP packet received, contains MagicCookie")
                    return i+4
            return None  # not found


    def get_option(self, name):
        if name in globals.DHCP_FIELDS:
            field = globals.DHCP_FIELDS[name]
            value = self.packet_data[field['pos']:field['pos']+field['len']]
            logger.debug("DHCP option retrieved, name: %s, value: %s" %
                         (name, value))
            return value
        # Option being set is not one of the main fields
        elif self.dhcp_options.has_key(name):
            return self.dhcp_options[name]
        else:
            return []


    def set_option(self, name, value):
        if name in globals.DHCP_FIELDS:
            # boundary validation
            if len(value) != globals.DHCP_FIELDS[name]['len']:
                logger.error("DhcpPacket.set_option bad option length: %s" %
                             name)
                return False
            begin = globals.DHCP_FIELDS[name]['pos']
            end = globals.DHCP_FIELDS[name]['pos'] +\
                  globals.DHCP_FIELDS[name]['len']
            logger.debug("DHCP option set, name: %s, value: %s" %
                         (name, value))
            self.packet_data[begin:end] = value
            return True
        elif name in globals.DHCP_OPTIONS:

    def sort_options(self):
        """ Return the DHCP options in sorted order """

        ord_options = {}
        option_list = []
        for option in self.dhcp_options:
            # Options must be set in order according to RFC
            order = globals.DHCP_OPTIONS.index(option)
            # DCHP requires the option ID, length, and data concatenated
            ord_options[order] = [order, len(option), option]
        for option in sorted(ord_options.keys()):
            option_list.append(option)
        return option_list


    def decode_packet(self, packet):
        """ Unpack the packet and lookup the option values """

        self.packet_data = []
        self.dhcp_options = {}

        if not packet:
            logger.debug("Empty packet received, discarding...")
            return

        # treat the packet like a list of ints representing chars
        unpack_fmt = str(len(packet)) + "c"
        self.packet_data = [ord(i) for i in unpack(unpack_fmt,packet)]
        # TODO(dsneddon) replace this with a human-readable packet decode
        logger.debug("Raw packet decoded: \n%s\n" % self.packet_data)

        location = self.get_option_start()
        if not locaion:
            logger.info("Magic Cookie not found, not a valid DHCP packet")
            return

        while location < len(self.packet_data):
            if self.packet_data[location] == 255:
                logger.debug("DHCP Option End reached at byte %d" % location)
                return

            elif self.packet_data[location] == 0; # pad byte
                location += 1

            else:
                option = globals.DHCP_OPTIONS[self.packet_data[location]]
                #TODO(dsneddon) lookup field type for data validation
                length = self.packet_data[location+1]
                start = location + 2
                end = start + length
                self.dhcp_options[self.packet_data[location]] = self.packet_data[start:end+1]
            return

    def encode_packet(self):
        """ Set the options and pack the packet """

        ord_options = self.sort_options()
        logger.debug("Options to encode: %s" % ord_options)

        option_data = []
        for option in ord_options:
            option_data += option

        packet = self.packet_data[:240] + option_data
        packet.append(255)  # add end option

        pack_fmt = str(len(packet)) + "c"
        packet = map(chr, packet)
        return pack(pack_fmt, *packet)


    def str(self):
        """ Print a human-readable decode of the packet"""

        print "--------------------DHCP Packet--------------------"

        for option in self.sort_options():
            print "option: %s   value: %s" % (option)
