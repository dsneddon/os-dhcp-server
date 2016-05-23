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
import re
import binascii
from struct import pack
from struct import unpack
from netaddr import IPAddress
from netaddr.core import AddrFormatError
from os_dhcp_server import globals as dhcp


logger = logging.getLogger(__name__)


def value_to_bytelist(optype, value):
    """ Given a field or option type, format the value as a list with a
        length that matches the given type.

    :param optype: The object type, which is one of: int, int16, int32,
        bool, char, char+, string, or an RFC-defined type.
    :param value: The value on which to enforce type.

    :returns: value after type enforcement"""
    if optype == 'int':
        if isinstance(value, int):
            if (value < 0) or (value > 255):
                return False
            else:
                return [value]
        if isinstance(value, list):
            if len(value) != 1:
                return False
            i = value[0]
            if (not isinstance(i, int)) or (i < 0) or (i > 255):
                return False
            else:
                return value
        elif isinstance(value, str):
            try:
                int_value = int(value)
            except ValueError:
                return False
            if (int_value < 0) or (int_value > 255):
                return False
            else:
                return [int_value]
    elif optype == 'int16':
        if isinstance(value, int):
            return [int(value >> 8 & 0xFF), int(value & 0xFF)]
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
            return new_value
    elif optype == 'int32':
        if isinstance(value, int):
            return int32_to_octets(value)
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
            return new_value
    elif optype == 'bool':
        if (isinstance(value, bool)) or (isinstance(value, int)):
            if value:
                return [1]
            else:
                return [0]
        elif isinstance(value, str):
            if value in dhcp.TRUE_VALUES:
                return [1]
            elif value in dhcp.FALSE_VALUES:
                return [0]
            else:
                return False
    elif optype == 'ipv4':
        if isinstance(value, int):
            return int32_to_octets(value)
        elif isinstance(value, str):
            try:
                ip_addr = IPAddress(value.strip())
            except AddrFormatError:
                logger.error("Could not parse IP address: %s" % value)
                return False
            return int32_to_octets(int(ip_addr))
        elif isinstance(value, IPAddress):
            return int32_to_octets(int(value))
    elif optype == '[ipv4]':
        if isinstance(value, list):
            new_value = []
            for ip in value:
                ip_octets = value_to_bytelist('ipv4', ip)
                new_value.extend(ip_octets)
            return new_value
        elif isinstance(value, str):
            new_value = []
            for ip in value.split(','):
                try:
                    ip_addr = IPAddress(ip.strip())
                except AddrFormatError:
                    return False
            for octet in int32_to_octets(int(ip_addr)):
                new_value.append(octet)
            return new_value
        else:
            return False
    elif optype == 'string':
        return list(str(value))
    elif optype == 'identifier' or optype == 'hwmacaddr':  # see RFC6842
        # Deal with MAC addresses or optype (01 is Ethernet) plus MAC
        if isinstance(value, str):
            macaddr = re.compile(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})',
                                 re.IGNORECASE)
            macaddr_type = re.compile(r'01:([0-9A-F]{2}[:-]){5}'
                                      r'([0-9A-F]{2})', re.IGNORECASE)
            if macaddr.match(value) or macaddr_type.match(value):
                mac_raw = ''.join(value.split(':'))  # strip the colons
                # Convert the remaining hex to bytes
                return [ord(i) for i in binascii.unhexlify(mac_raw)]
            else:
                return [ord(i) for i in value]
        elif isinstance(value, list):
            return value
    logger.error("Type not implemented: %s" % optype)
    return False


def bytelist_to_value(optype, bytelist):
    """ Given a series of bytes, return a human-readable value based on
        the option type. Does the reverse of value_to_bytelist.

    :param optype: The object type, which is one of: int, int16, int32,
        bool, char, char+, string, or an RFC-defined type.
    :param bytelist: The list of bytes to convert to a readable format.

    :returns: value after type conversion"""

    if optype == 'int':
        return int(bytelist[0])
    elif optype == 'int16':
        if len(bytelist) != 2:
            logger.debug("Could not convert %s bytes to int16")
            return False
        new_value = bytelist[0] * 256
        new_value += bytelist[1]
        return new_value
    elif optype == 'int32':
        if len(bytelist) > 4:
            logger.error("Could not convert %s bytes to int32" %
                         len(bytelist))
            return False
        new_value = bytelist[0] * 256 * 256 * 256
        new_value += bytelist[1] * 256 * 256
        new_value += bytelist[2] * 256
        new_value += bytelist[3]
        return new_value
    elif optype == 'bool':
        if bytelist in dhcp.TRUE_VALUES:
            return 'True'
        else:
            return 'False'
    elif optype == 'ipv4':
        if len(bytelist) != 4:
            logger.error("Could not convert %s to IPv4 address" %
                         bytelist)
            return False
        else:
            return '{}.{}.{}.{}'.format((bytelist[0], bytelist[1],
                                         bytelist[2], bytelist[3]))
    elif optype == '[ipv4]':
        if len(bytelist) < 4:
            logger.error("Could not convert %s to a list of IPs" %
                         bytelist)
            return False
        else:
            new_value = ''
            bytelist.reverse()
            while len(bytelist) > 3:
                if new_value:  # if there is already at least 1 IP,
                    new_value += ', '  # append a comma between addresses
                for i in range(0,3):
                    new_value += str(bytelist.pop()) + "."
                new_value += str(bytelist.pop())
            return new_value
    elif optype == 'string':
        return ''.join(chr(byte) for byte in bytelist)
    elif optype == 'identifier':
        if (len(bytelist) == 7) and (bytelist[0] == 1):  # MAC address
            return ':'.join('{:02x}'.format(x) for x in bytelist)
        else:
            return ''.join('{}'.format(chr(x)) for x in bytelist)
    else:
        return bytelist


def unpack_ipv4_bytes(byte_pattern):
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
        for i in range(0, 3):
            ip_string += str(byte_pattern.pop()) + "."
        ip_string += str(byte_pattern.pop())
        ip_list.append(ip_string)
    return ip_list


def int32_to_octets(value):
    """ Given an int or long, return a 4-byte array of 8-bit ints."""

    return [int(value >> 24 & 0xFF), int(value >> 16 & 0xFF),
            int(value >> 8 & 0xFF), int(value & 0xFF)]


def get_option_name_id(option):
    """ Return name if given ID, or ID if given name"""

    if isinstance(option, int):
        return dhcp.DHCP_OPTIONS[option]
    else:
        return dhcp.DHCP_OPTIONS.index(option)


class DhcpPacket(object):
    """ Packet handler class for DHCP packets """

    def __init__(self, data=None):
        self.source_address = False
        self.dhcp_options = {}
        if data:
            if isinstance(data, list):
                self.packet_data = data
            if isinstance(data, str):
                self.raw_packet_data = data
                self.decode_packet()
        else:
            self.init_packet()
        logger.info("DhcpPacket class created")

    def init_packet(self):
        """ Initialize a blank DHCP packet """
        self.packet_data = [0]*240
        self.packet_data[236:240] = dhcp.MAGIC_COOKIE
        logger.debug("Initializing blank DHCP packet")

    def get_option_start(self):
        """ Return location after MagicCookie, or None if not found """

        # Sometimes it's right where you expect it
        if self.packet_data[236:240] == dhcp.MAGIC_COOKIE:
            logger.debug("DHCP packet received, contains MagicCookie")
            return 240
        else:
            # search the entire packet, but not past packet end
            for i in range(237, len(self.packet_data) - 3):
                if self.packet_data[i:i+4] == dhcp.MAGIC_COOKIE:
                    logger.debug("DHCP packet received, contains MagicCookie")
                    return i+4
            return None  # not found


    def get_option_number(self, name):
        """ Get the DHCP option number from the name. """

        return dhcp.DHCP_OPTIONS.index(name)

    def get_option(self, name):
        """ Get DHCP options (including fields)"""
        if name in dhcp.DHCP_FIELDS:
            field = dhcp.DHCP_FIELDS[name]
            value = self.packet_data[field['pos']:field['pos']+field['len']]
            logger.debug("DHCP option retrieved, name: %s, value: %s" %
                         (name, value))
            return value
        # Option being set is not one of the main fields
        elif name in self.dhcp_options:
            option_num = self.get_option_number(name)
            option_type = dhcp.DHCP_OPTION_TYPES[option_num]['type']
            return bytelist_to_value(option_type, self.dhcp_options[name])
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

        if name in dhcp.DHCP_FIELDS:
            if isinstance(value, list):
                # boundary validation
                if len(value) != dhcp.DHCP_FIELDS[name]['len']:
                    logger.error("DhcpPacket option %s bad length: %s" %
                                 (name, value))
                    return False
            begin = dhcp.DHCP_FIELDS[name]['pos']
            end = dhcp.DHCP_FIELDS[name]['pos'] + dhcp.DHCP_FIELDS[name]['len']
            self.packet_data[begin:end] = [value]
            logger.debug("DHCP field set, name: %s, value: %s" %
                         (name, value))
            return True
        elif name in dhcp.DHCP_OPTIONS:
            option_number = dhcp.DHCP_OPTIONS.index(name)
            option = dhcp.DHCP_OPTION_TYPES[option_number]
            # boundary validation
            byte_values = value_to_bytelist(option['type'], value)
            if len(byte_values) < option['min']:
                logger.error("DhcpPacket.set_option option %s too short: %s" %
                             (name, value))
                return False
            elif (option['max'] != 0) and (len(byte_values) > option['max']):
                logger.error("DhcpPacket.set_option option %s too long: %s" %
                             (name, value))
                return False
            self.dhcp_options[name] = value_to_bytelist(option['type'],
                                                             value)
            logger.debug("DHCP option set, name: %s, value: %s" %
                         (name, value))

    def sort_options(self):
        """ Return a list of the DHCP options in order by option number """

        option_list = []
        ord_options = {}
        for option in self.dhcp_options.keys():
            # Options must be set in order according to RFC
            order = dhcp.DHCP_OPTIONS.index(option)
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
        """ Unpack the packet and lookup the option values. An option has the
            format option number (1 byte), length (1 byte), and data. """

        self.dhcp_options = {}

        if not self.raw_packet_data:
            logger.debug("Empty packet received, discarding...")
            return

        # treat the packet like a list of ints representing chars
        unpack_fmt = str(len(self.raw_packet_data)) + "c"
        self.packet_data = [ord(i) for i in unpack(unpack_fmt,
                                                   self.raw_packet_data)]
        # TODO(dsneddon) replace this with a human-readable packet decode
        logger.debug("Raw packet decoded: \n%s\n" % self.packet_data)

    def

        location = self.get_option_start()
        if not location:
            logger.info("Magic Cookie not found, not a valid DHCP packet")
            return

        while location < len(self.packet_data):
            if self.packet_data[location] == 255:
                logger.debug("DHCP Option End reached at byte %d" % location)
                break
            elif self.packet_data[location] == 0:  # pad byte
                location += 1
            else:
                option = dhcp.DHCP_OPTIONS[self.packet_data[location]]
                # TODO(dsneddon) lookup field type for data validation
                length = self.packet_data[location+1]
                start = location + 2
                end = start + length
                #logger.debug("option: %s length: %s data %s" %
                #             (option, length, self.packet_data[start:end]))
                self.dhcp_options[option] = self.packet_data[start:end]
                location = end

        for option in self.dhcp_options:
            logger.debug("option: %s value: %s" %
                         (option, self.get_option(option)))

    def encode_packet(self):
        """ Set the options and pack the packet. An option has an option
            number, followed by length, followed by data. """

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

        str_rep = "--------------------DHCP Packet--------------------\n"

        for option in self.sort_options():
            str_rep += "option: %s   value: %s\n" % (option,
                                                     self.dhcp_options[option])
        return str_rep
