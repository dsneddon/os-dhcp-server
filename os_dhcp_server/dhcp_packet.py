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
from netaddr import IPAddress
from netaddr.core import AddrFormatError
from os_dhcp_server import globals


logger = logging.getLogger(__name__)


def unpack_ipv4_list(byte_pattern):
    """ Given a list of raw bytes, parse out and return a list of IPs

    :param byte_pattern: The raw bytes from the DHCP option containing
        a list of IP addresses. The RFC specifies that an IP list will
        be a list of octets, with each group of 4 octets representing
        one IP address. There are no separators or terminators.
    :returns: a list of IP addresses as strings"""

    ip_list = []
    # reverse the bytes so we can pop them off one at a time
    byte_pattern.reverse()
    while len(byte_pattern) > 3:
        # if there are at least 4 octets, add them as an IP to the list
        ip_string = ''
        for i in range(0,3):
            ip_string += str(ord(byte_pattern.pop())) + "."
        ip_string += str(ord(byte_pattern.pop()))
        ip_list.append(ip_string)
    return ip_list


def get_dhcp_option(option):
    """ Return name if given ID, or ID if given name"""

    if isinstance(option, int):
        return constants.DHCP_OPTIONS[option]
    else:
        return constants.DHCP_OTIONS.index(option)


class DhcpPacket(object):
    """ Packet handler class for DHCP packets """

    """ DHCP """

    def __init__(self, data=None):
        self.source_address = False
        self.init_packet()
        self.dhcp_options = {}
        if data:
            if isinstance(data, list):
                self.packet_data = data
                self.decode_packet()
        else:
            self.init_packet()
        logger.info("DhcpPacket class created")


    def init_packet(self):
        ''' Initialize a blank DHCP packet '''
        self.packet_data = [0]*240
        self.packet_data[236:240] = globals.MAGIC_COOKIE
        logger.debug("Initializing blank DHCP packet")


    def get_option_start(self):
        ''' Return location after MagicCookie, or None if not found '''

        # Sometimes it's right where you expect it
        if self.packet_data[236:240] == globals.MAGIC_COOKIE:
            logger.debug("DHCP packet received, contains MagicCookie")
            return 240
        else:
            # search the entire packet, but not past packet end
            for i in range(237,len(self.packet_data)-3):
                if self.packet_data[i:i+4] == globals.MAGIC_COOKIE:
                    logger.debug("DHCP packet received, contains MagicCookie")
                    return i+4
            return None  # not found


    def int32_to_octets(self, value):
        """ Given an int or long, return a 4-byte array of 8-bit ints."""

        new_value = [int(value >> 24 & 0xFF)]
        new_value.append(int(value >> 16 & 0xFF))
        new_value.append(int(value >> 8 & 0xFF))
        new_value.append(int(value & 0xFF))
        return new_value


    def value_to_bytelist(self, type, value):
        """ Given a field or option type, format the value as a list with a
            length that matches the given type.

        :param type: The object type, which is one of: int, int16, int32, bool,
            char, char+, string, or an RFC-defined type.
        :param value: The value on which to enforce type.

        :returns: value after type enforcement"""
        if type == 'int':
            if isinstance(value, int):
                value = [value]
            if isinstance(value, list):
                if len(value) != 1:
                    return False
                if (not isinstance(i, int)) or (i < 0) or (i > 255):
                    return False
            elif isinstance(value, str):
                if len(value) != 1:
                    return False
                value = [int(value)]
        elif type == 'int16':
            if isinstance(value, int):
                new_value = [int(value >> 8 & 0xFF)]
                new_value.append(int(value & 0xFF))
                value = new_value
            if isinstance(value, list):
                if len(value) != 2:
                    return False
                for i in range(0, 2):
                    if (not isinstance(i, int)) or (i < 0) or (i > 255):
                        return False
            elif isinstance(value, str):
                if len(value) != 2:
                    return False
                new_value = []
                for i in value:
                    new_value.append(int(i))
                value = new_value
        elif type == 'int32':
            if isinstance(value, int):
                value = self.int32_to_octets(value)
            if isinstance(value, list):
                if len(value) != 4:
                    return False
                for i in range(0, 4):
                    if (not isinstance(i, int)) or (i < 0) or (i > 255):
                        return False
            elif isinstance(value, str):
                if len(value) != 4:
                    return False
                new_value = []
                for i in value:
                    new_value.append(int(i))
                value = new_value
        elif type == 'bool':
            if isinstance(value, bool):
                if value:
                    value = [1]
                else:
                    value = [0]
            elif isinstance(value, int):
                value = [value]
            elif isinstance(value, str):
                if value in globals.TRUE_VALUES:
                    value = [1]
                elif value in globals.FALSE_VALUES:
                    value = [0]
                else:
                    return False
        elif type == 'ipv4':
            if isinstance(value, int):
                value = self.int32_to_octets(value)
            if isinstance(value, str):
                try:
                    ip_addr = IPAddress(value.strip())
                except AddrFormatError:
                    return False
                value = self.int32_to_octets(int(ip_addr))
            if isinstance(value, IPAddress):
                value = self.int32_to_octets(int(value))
        elif type == '[ipv4]':
            if isinstance(value, list):
                new_value = []
                for ip in value:
                    ip_octets = self.value_to_type('ipv4', ip)
                    new_value.extend(ip_octets)
                value = new_value
            elif isinstance(value, str):
                new_value = []
                for ip in value.split(','):
                    try:
                        ip_addr = IPAddress(ip.strip())
                    except AddrFormatError:
                        return False
                for octet in self.int32_to_octets(int(ip_addr)):
                    new_value.append(octet)
                value = new_value
            else:
                return False
        return value


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
        """ Set DHCP options (including fields)

            :param name: The name of the option or field to be set
            :param value: The value to set for the field or option. If the
                value is a list, then it will be treated as a series of bytes
                and the length must not be shorter than the min or larger than
                 the max length allowed per option. Depending on the field or
                 option type, a transformation may occur, e.g. if a field type
                 is 'int16', then each byte will be converted to an int before
                 setting the byte value, conversely if the field type is
                 'string', then a string transformation will be done.
                 Booleans will be tested against the TRUE_VALUES and
                 FALSE_VALUES defined in os_dhcp_server.globals.
            :returns: True or False to indicate success, failure will be logged
        """

        if name in globals.DHCP_FIELDS:
            if isinstance(value, list):
                # boundary validation
                if len(value) != globals.DHCP_FIELDS[name]['len']:
                    logger.error("DhcpPacket.set_option option %s bad length: %s" %
                                 (name, value))
                    return False
            begin = globals.DHCP_FIELDS[name]['pos']
            end = globals.DHCP_FIELDS[name]['pos'] +\
                  globals.DHCP_FIELDS[name]['len']
            self.packet_data[begin:end] = [value]
            logger.debug("DHCP field set, name: %s, value: %s" %
                         (name, value))
            return True
        elif name in globals.DHCP_OPTIONS:
            option_number = globals.DHCP_OPTIONS.index(name)
            option = globals.DHCP_OPTION_TYPES[option_number]
            # boundary validation
            byte_values = self.value_to_bytelist(option['type'], value)
            if len(byte_values) < option['min']:
                logger.error("DhcpPacket.set_option option %s too short: %s" %
                             (name, value))
                return False
            elif (option['max'] != 0) and (len(byte_values) > option['max']):
                logger.error("DhcpPacket.set_option option %s too long: %s" %
                             (name, value))
                return False
            self.dhcp_options[name] = self.value_to_bytelist(option['type'],
                                                             value)
            logger.debug("DHCP option set, name: %s, value: %s" %
                         (name, value))


    def sort_options(self):
        """ Return a list of the DHCP options in order by option number """

        option_list = []
        ord_options = {}
        for option in self.dhcp_options.keys():
            # Options must be set in order according to RFC
            order = globals.DHCP_OPTIONS.index(option)
            # DCHP requires the option ID, length, and data concatenated
            ord_options[order] = (option, self.dhcp_options[option])
        for option in sorted(ord_options.keys()):
            option_list.append([option,
                                ord_options[option][0],
                                ord_options[option][1]])
        return option_list


    def pack_packet(self, packet):
        """ Packs the packet using struct.pack to prepare to send on wire """

        pack_fmt = str(len(packet)) + "c"
        packet = map(chr, packet)
        return pack(pack_fmt, *packet)

    def decode_packet(self):
        """ Unpack the packet and lookup the option values """

        self.dhcp_options = {}

        if not self.packet_data:
            logger.debug("Empty packet received, discarding...")
            return

        # treat the packet like a list of ints representing chars
        #unpack_fmt = str(len(self.packet_data)) + "c"
        #self.packet_decoded = [ord(i) for i in unpack(unpack_fmt,
        #                                              self.packet_data)]
        # TODO(dsneddon) replace this with a human-readable packet decode
        #logger.debug("Raw packet decoded: \n%s\n" % self.packet_decoded)

        location = self.get_option_start()
        if not location:
            logger.info("Magic Cookie not found, not a valid DHCP packet")
            return

        while location < len(self.packet_data):
            if self.packet_data[location] == 255:
                logger.debug("DHCP Option End reached at byte %d" % location)
                return

            elif self.packet_data[location] == 0: # pad byte
                location += 1
                break

            else:
                option = globals.DHCP_OPTIONS[self.packet_data[location]]
                #TODO(dsneddon) lookup field type for data validation
                length = self.packet_data[location+1]
                start = location + 2
                end = start + length
                self.dhcp_options[option] = self.packet_data[start:end]
            return


    def encode_packet(self):
        """ Set the options and pack the packet """

        ord_options = self.sort_options()
        logger.debug("Options to encode: %s" % ord_options)

        option_data = []
        logger.debug("DHCP options added to packet: %s" % ord_options)
        for option in ord_options:
            option_data.append(option[0])
            option_data.append(len(option[2]))
            option_data.extend(option[2])

        self.packet_data[240:] = option_data
        self.packet_data.append(255)  # add end option


    def str(self):
        """ Return a human-readable decode of the packet"""

        str_rep = "--------------------DHCP Packet--------------------"

        for option in self.sort_options():
            str_rep += "option: %s   value: %s\n" % (option,
                                              self.dhcp_options[option])
        return str_rep
