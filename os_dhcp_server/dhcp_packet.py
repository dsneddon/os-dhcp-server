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
                return [value]
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
                else:
                    return value
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
            return value
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
        if len(bytelist) != 4:
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
            __bytelist = bytelist[:]
            __bytelist.reverse()
            new_value = ''
            while len(__bytelist) > 3:
                if new_value:  # if there is already at least 1 IP,
                    new_value += ', '  # append a comma between addresses
                for i in range(0,3):
                    new_value += str(__bytelist.pop()) + "."
                new_value += str(__bytelist.pop())
            return new_value
    elif optype == 'string':
        return ''.join(chr(byte) for byte in bytelist)
    elif optype == 'identifier' or optype == 'hwmacaddr':  # see RFC6842:
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

def field_length_valid(name, length):
    type = dhcp.DHCP_FIELDS[name]['type']
    if type in ['hwmacaddr', 'sname', 'file']:
        if length > dhcp.DHCP_FIELDS[name]['len']:
            return False
        else:
            return True
    else:
        if length == dhcp.DHCP_FIELDS[name]['len']:
            return True
        else:
            return False


class DhcpPacket(object):
    """ Packet handler class for DHCP packets

    :param data: Raw packet data, otherwise packet will be initialized.
    """

    def __init__(self, data=None):
        self.source_address = False
        self.dhcp_options = {}
        if data:
            if isinstance(data, list):
                self.packet_data = data
                self.map_options()
            if isinstance(data, str):
                self.raw_packet_data = data
                self.decode_packet()
        else:
            # Initialize a blank packet
            self.packet_data = [0] * 240
            self.packet_data[236:240] = dhcp.MAGIC_COOKIE
            logger.debug("Initializing blank DHCP packet")
        logger.info("DhcpPacket packet created")

    def get_option_start(self):
        """ Return location after MagicCookie, or None if not found """

        # Sometimes it's right where you expect it
        print "packet_data_length: %s" % len(self.packet_data)
        if len(self.packet_data) > 238:
            if self.packet_data[237:240] == dhcp.MAGIC_COOKIE:
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

    def get_option(self, opt_name):
        """ Get DHCP options (including fields)"""
        if opt_name in dhcp.DHCP_FIELDS:
            field = dhcp.DHCP_FIELDS[opt_name]
            try:
                rawvalue = self.packet_data[
                               field['pos']:field['pos']+field['len']
                           ]
            except IndexError:
                return None
            value = bytelist_to_value(field['type'], rawvalue)
            logger.debug("DHCP field retrieved, opt_name: %s, value: %s" %
                         (opt_name, value))
            return value
        # Option being retrieved is not one of the main fields
        elif opt_name in dhcp.DHCP_OPTIONS:
            opt_num = self.get_option_number(opt_name)
            opt_type = dhcp.DHCP_OPTION_TYPES[opt_num]['type']
            value = bytelist_to_value(opt_type, self.dhcp_options[opt_name])
            logger.debug("DHCP option retreived, opt_name: %s, value: %s" %
                         (opt_name, value))
            return value
        else:
            logger.error("Error: Could not get value for invalid option: %s" %\
                         opt_name)
            return None

    def set_option(self, opt_name, value):
        """ Set DHCP options (including fields)

            :param opt_name: The opt_name of the option or field to be set
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

        if opt_name in dhcp.DHCP_FIELDS:
            type = dhcp.DHCP_FIELDS[opt_name]['type']
            begin = dhcp.DHCP_FIELDS[opt_name]['pos']
            if isinstance(value, int):
                value = [value]
            if isinstance(value, IPAddress):
                # Treat IP addresses like strings below
                value = str(value)
            if isinstance(value, list):
                # boundary validation
                if not field_length_valid(opt_name, len(value)):
                    logger.error("DhcpPacket field %s value wrong length: %s" %
                                 (opt_name, value))
                    return False
                self.packet_data[begin:(begin + len(value))] = value
                logger.debug("DHCP field set, opt_name: %s, value: %s" %
                             (opt_name, value))
                return True
            elif isinstance(value, str):
                # Convert string to an array of bytes as unsigned small ints
                bytelist = value_to_bytelist(type, value)
                if not field_length_valid(opt_name, len(bytelist)):
                    logger.error("DhcpPacket field %s value wrong length: %s" %
                                 (opt_name, value))
                    return False
                self.packet_data[begin:(begin + len(value))] = bytelist
                logger.debug("DHCP field set, opt_name: %s, value: %s" %
                             (opt_name, value))
                return True
            else:
                return False
        elif opt_name in dhcp.DHCP_OPTIONS:
            option = dhcp.DHCP_OPTION_TYPES[dhcp.DHCP_OPTIONS.index(opt_name)]
            # boundary validation
            bytelist = value_to_bytelist(option['type'], value)
            if len(bytelist) < option['min']:
                logger.error("Cannot set option %s, value too short: %s" %
                             (opt_name, value))
                return False
            elif (option['max'] != 0) and (len(bytelist) > option['max']):
                logger.error("Cannot set option %s, value too long: %s" %
                             (opt_name, value))
                return False
            self.dhcp_options[opt_name] = value
            logger.debug("DHCP option set, opt_name: %s, value: %s" %
                         (opt_name, value))
            return True

    def sort_options(self):
        """ Return a list of dicts of DHCP options sorted by option number """

        option_list = []
        ord_options = {}
        for option in self.dhcp_options:
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

    def map_options(self):
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
                self.dhcp_options[option] = self.packet_data[start:end]
                location = end

    def decode_packet(self):
        """ Unpack the packet and lookup the option values. An option has the
            format option number (1 byte), length (1 byte), and data. """

        if not self.raw_packet_data:
            logger.debug("Empty packet received, discarding...")
            return

        # treat the packet like a list of ints representing chars
        unpack_fmt = str(len(self.raw_packet_data)) + "c"
        self.packet_data = [ord(i) for i in unpack(unpack_fmt,
                                                   self.raw_packet_data)]
        # TODO(dsneddon) replace this with a human-readable packet decode
        logger.debug("Raw packet decoded: \n%s\n" % self.packet_data)

        self.map_options()

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

        str_rep = """
+--------------------------DHCP Packet--------------------------+
0                   1                   2                   3   |
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     op ({})    |   htype ({})   |    hlen ({})   |    hops ({})   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   xid ( {:<16} )                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           secs ({})           |           flags ({})            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   ciaddr ( {:<16} )                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   yiaddr ( {:<16} )                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   siaddr ( {:<16} )                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   giaddr ( {:<16} )                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   chaddr ( {:<16} )                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| sname ( {:<51} ) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| file ( {:<52} ) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| <magic cookie> indicates options begin at byte:  {:>12} |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
""".format(self.get_option('op'), self.get_option('htype'),
           self.get_option('hlen'), self.get_option('hops'),
           self.get_option('xid'), self.get_option('secs'),
           self.get_option('flags'), self.get_option('ciaddr'),
           self.get_option('yiaddr'), self.get_option('siaddr'),
           self.get_option('giaddr'), self.get_option('chaddr'),
           self.get_option('sname'), self.get_option('file'),
           self.get_option_start())

        str_rep += "|--------------------------DHCP Options----------------"
        str_rep += "---------|\n"
        for option in self.sort_options():
            str_rep += "| option {:3}: {:<18} {:>30} |\n".format(
                    option[0], str(option[1])[0:18], str(option[2])[0:29])
            if len(str(option[2])) > 30:
                str_rep += "| {:50} |"
        str_rep += "+-----------------------------------------------------"
        str_rep += "----------+"
        return str_rep


class DhcpOffer(DhcpPacket):
    """ Subclass of DHCPPacket specifically for DHCP Offers

    :param chaddr: Client HWAddr (MAC Address)
    :param ip_dest: Unicast destination IP address
    :param data: Raw packet data (otherwise packet will be initialized)
    """

    def __init__(self, chaddr=None, source_address=None, ip_dest=None,
                 data=None):
        super(DhcpOffer, self).__init__(data)
        print "DHCPOffer packet length: %s" % len(self.packet_data)
        self.source_address = source_address
        self.dhcp_options = {}
        self.ip_dest = ip_dest
        self.chaddr = chaddr
        # if data:
        #     if isinstance(data, list):
        #         self.packet_data = data
        #         self.map_options()
        #     if isinstance(data, str):
        #         self.raw_packet_data = data
        #         self.decode_packet()
        # else:
        #     self.init_packet()
        if self.chaddr:
            self.set_option('chaddr', self.chaddr)
        logger.info("DhcpOffer packet created")

        self.set_option('op', 2)
        self.set_option('htype', 1)
        self.set_option('hlen', 6)
        self.set_option('dhcp_message_type',
                        dhcp.DHCP_MESSAGE_LIST.index('DHCP_OFFER'))
        self.set_option('dhcp_message_type', 2)
