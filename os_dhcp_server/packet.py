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

import logger
from struct import pack
from struct import unpack


logger = logging.getLogger(__name__)


""" DHCP Packet format

    First 226 bytes contain standard DHCP fields.
    This is followed by a "Magic Cookie", which is a set of 4 bytes
    in a specific order that signifies the delineator between the
    standard fields and the options.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
    +---------------+---------------+---------------+---------------+
    |                            xid (4)                            |
    +-------------------------------+-------------------------------+
    |           secs (2)            |           flags (2)           |
    +-------------------------------+-------------------------------+
    |                          ciaddr  (4)                          |
    +---------------------------------------------------------------+
    |                          yiaddr  (4)                          |
    +---------------------------------------------------------------+
    |                          siaddr  (4)                          |
    +---------------------------------------------------------------+
    |                          giaddr  (4)                          |
    +---------------------------------------------------------------+
    |                                                               |
    |                          chaddr  (16)                         |
    |                                                               |
    |                                                               |
    +---------------------------------------------------------------+
    |                                                               |
    |                          sname   (64)                         |
    +---------------------------------------------------------------+
    |                                                               |
    |                          file    (128)                        |
    +---------------------------------------------------------------+
    |                                                               |
    |                          options (variable)                   |
    +---------------------------------------------------------------+

    The options immediately follow the Magic Cookie, and are
    presented in the following format: option number (1 byte), length
    (1 byte), and value. The value depends on the type, where type is
    one of the following: ipv4, [ipv4] (list of IPv4 addresses),
    boolean, character (single), character (string), int16, int32,
    identifier, or RFC3397 (encoded domain names). Options are not
    included in DHCP packets by default. Any options which are included
    must be presented in incrementing order of option. IPv4 addresses
    are presented as 4-byte values, each byte representing one octet.
    Lists of IPv4 addresses contain multiple 4-byte values without
    a delimeter. The number of IP addresses in the list is equal to
    the length/4.

    RFC3397 defines an encoding for domain names. The code for this
    option is 119. If the domain name list fits within 255 characters,
    it may be sent as a single message:

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     119       |     Len       |         Searchstring...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Searchstring...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    If the domain name list is longer than 255 characters, it may be
    encoded in a series of repeated 119 options, which are then
    reassembled and concatenated. Below is an example encoding of a
    search list consisting of "eng.apple.com." and
    "marketing.apple.com.":

    +---+---+---+---+---+---+---+---+---+---+---+
    |119| 9 | 3 |'e'|'n'|'g'| 5 |'a'|'p'|'p'|'l'|
    +---+---+---+---+---+---+---+---+---+---+---+
    +---+---+---+---+---+---+---+---+---+---+---+
    |119| 9 |'e'| 3 |'c'|'o'|'m'| 0 | 9 |'m'|'a'|
    +---+---+---+---+---+---+---+---+---+---+---+
    +---+---+---+---+---+---+---+---+---+---+---+
    |119| 9 |'r'|'k'|'e'|'t'|'i'|'n'|'g'|xC0|x04|
    +---+---+---+---+---+---+---+---+---+---+---+

    In the above example, we can see that 'eng.apple.com' is terminated
    with a zero, indicating the end of the name. Also, marketing is
    terminated with a pointer reference to character position 4, which
    is where the 'apple.com' in 'eng.apple.com' starts, so this second
    name resolvs to 'marketing.apple.com'. Names must end with either
    a zero terminator or a pointer reference, or they will be discarded.
    Repeated hosts on the same domain may use either full names or
    pointers.

    __Relay Agent Information Option__
    The format of the Relay Agent Information
    option is:

     Code   Len     Agent Information Field
    +------+------+------+------+------+------+--...-+------+
    |  82  |   N  |  i1  |  i2  |  i3  |  i4  |      |  iN  |
    +------+------+------+------+------+------+--...-+------+

    The length N gives the total number of octets in the Agent
    Information Field.  The Agent Information field consists of a
    sequence of SubOpt/Length/Value tuples for each sub-option, encoded
    in the following manner:

           SubOpt  Len     Sub-option Value
          +------+------+------+------+------+------+--...-+------+
          |  1   |   N  |  s1  |  s2  |  s3  |  s4  |      |  sN  |
          +------+------+------+------+------+------+--...-+------+
           SubOpt  Len     Sub-option Value
          +------+------+------+------+------+------+--...-+------+
          |  2   |   N  |  i1  |  i2  |  i3  |  i4  |      |  iN  |
          +------+------+------+------+------+------+--...-+------+

    No "pad" sub-option is defined, and the Information field shall NOT
    be terminated with a 255 sub-option.  The length N of the DHCP Agent
    Information Option shall include all bytes of the sub-option
    code/length/value tuples.  Since at least one sub-option must be
    defined, the minimum Relay Agent Information length is two (2).  The
    length N of the sub-options shall be the number of octets in only
    that sub-option's value field.  A sub-option length may be zero.  The
    sub-options need not appear in sub-option code order.

    The initial assignment of DHCP Relay Agent Sub-options is as follows:

                 DHCP Agent              Sub-Option Description
                 Sub-option Code
                 ---------------         ----------------------
                     1                   Agent Circuit ID Sub-option
                     2                   Agent Remote ID Sub-option

    DHCP servers claiming to support the Relay Agent Information option
    SHALL echo the entire contents of the Relay Agent Information option
    in all replies.  Servers SHOULD copy the Relay Agent Information
    option as the last DHCP option in the response.  Servers SHALL NOT
    place the echoed Relay Agent Information option in the overloaded
    sname or file fields.  If a server is unable to copy a full Relay
    Agent Information field into a response, it SHALL send the response
    without the Relay Information Field, and SHOULD increment an error
    counter for the situation.
"""


# Header field information taken from:
# https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
_DHCP_FIELDS = {'op':{'pos':0, 'len':1, 'type': 'int'},
                'htype':{'pos':1, 'len':1, 'type': 'int'},
                'hlen':{'pos':2, 'len':1, 'type': 'int'},
                'hops':{'pos':3, 'len':1, 'type': 'int'},
                'xid':{'pos':3, 'len':4, 'type': 'int32'},
                'secs':{'pos':8, 'len':2, 'type': 'int2'},
                'flags':{'pos':10, 'len':2, 'type':'int2'},
                'ciaddr':{'pos':12, 'len':4, 'type':'int32'},
                'yiaddr':{'pos':16, 'len':4, 'type':'int32'},
                'siaddr':{'pos':20, 'len':4, 'type':'int32'},
                'giaddr':{'pos':24, 'len':4, 'type':'int32'},
                'chaddr':{'pos':28, 'len':16, 'type':'hwmacaddr'},
                'sname':{'pos':44, 'len':64, 'type':'str'},
                'file':{'pos':108, 'len':128, 'type':'str'}
               }

_DHCP_OPCODES = { '0': 'ERROR_UNDEF', '1' : 'BOOTREQUEST' , '2' : 'BOOTREPLY'}

_DHCP_MESSAGE_TYPES = { '0': 'ERROR_UNDEF', '1': 'DHCP_DISCOVER',
                        '2': 'DHCP_OFFER', '3' : 'DHCP_REQUEST',
                        '4':'DHCP_DECLINE', '5': 'DHCP_ACK',
                        '6': 'DHCP_NACK', '7': 'DHCP_RELEASE',
                        '8' : 'DHCP_INFORM' }

_DHCP_OPTIONS = ['pad',
                 # Vendor Extension
                 'subnet_mask','time_offset', 'router','time_server',
                 'name_server', 'domain_name_server','log_server',
                 'cookie_server','lpr_server', 'impress_server',
                 'resource_location_server', 'host_name','boot_file',
                 'merit_dump_file', 'domain_name','swap_server','root_path',
                 'extensions_path',
                 # IP layer parameters per host
                 'ip_forwarding','nonlocal_source_rooting', 'policy_filter',
                 'maximum_datagram_reassembly_size', 'default_ip_time-to-live',
                 'path_mtu_aging_timeout', 'path_mtu_table',
                 # IP layer parameters per interface
                 'interface_mtu','all_subnets_are_local', 'broadcast_address',
                 'perform_mask_discovery', 'mask_supplier',
                 'perform_router_discovery', 'routeur_solicitation_address',
                 'static_route',
                 # link layer parameters per interface
                 'trailer_encapsulation','arp_cache_timeout',
                 'ethernet_encapsulation',
                 # TCP parameters
                 'tcp_default_ttl','tcp_keepalive_interval',
                 'tcp_keepalive_garbage',
                 # Applications and service parameters
                 'nis_domain', 'nis_servers', 'ntp_servers', 'vendor_specific',
                 'nbns', 'nbdd','nd_node_type', 'nb_scope',
                 'x_window_system_font_server',
                 'x_window_system_display_manager',
                 # DHCP extensions
                 'request_ip_address', 'ip_address_lease_time', 'overload',
                 'dhcp_message_type', 'server_identifier',
                 'parameter_request_list', 'message',
                 'maximum_dhcp_message_size', 'renewal_time_value',
                 'rebinding_time_value', 'vendor_class', 'client_identifier',
                 # adds from RFC 2132,2242
                 'netware_ip_domain_name', 'netware_ip_sub_options',
                 'nis+_domain', 'nis+_servers', 'tftp_server_name',
                 'bootfile_name', 'mobile_ip_home_agent', 'smtp_servers',
                 'pop_servers', 'nntp_servers', 'default_www_server',
                 'default_finger_server', 'default_irc_server',
                 'streettalk_server', 'streettalk_directory_assistance_server',
                 'user_class','directory_agent','service_scope',
                 'rapid_commit','client_fqdn','relay_agent',
                 'internet_storage_name_service',
                 '84', 'nds_server','nds_tree_name','nds_context',
                 '88','89',
                 #90
                 'authentication',
                 'client_last_transaction_time','associated_ip', #RFC 4388
                 'client_system', 'client_ndi', #RFC 3679
                 'ldap','unassigned','uuid_guid', #RFC 3679
                 'open_group_user_auth', #RFC 2485
                 # 99->115 RFC3679
                 'unassigned','unassigned','unassigned', 'unassigned',
                 'unassigned','unassigned', 'unassigned','unassigned',
                 'unassigned', 'unassigned','unassigned','unassigned',
                 'unassigned','netinfo_address','netinfo_tag', 'url',
                 'unassigned', 'auto_config','name_service_search',
                 'subnet_selection', 'domain_search','sip_servers',
                 'classless_static_route',
                 'cablelabs_client_configuration','geoconf',
                 #124
                 'vendor_class', 'vendor_specific',
                 '126','127','128','129',
                 '130','131','132','133','134','135','136','137','138','139',
                 '140','141','142','143','144','145','146','147','148','149',
                 '150','151','152','153','154','155','156','157','158','159',
                 '160','161','162','163','164','165','166','167','168','169',
                 '170','171','172','173','174','175','176','177','178','179',
                 '180','181','182','183','184','185','186','187','188','189',
                 '190','191','192','193','194','195','196','197','198','199',
                 '200','201','202','203','204','205','206','207','208','209',
                 '210','211','212','213','214','215','216','217','218','219',
                 '220','221','222','223','224','225','226','227','228','229',
                 '230','231','232','233','234','235','236','237','238','239',
                 '240','241','242','243','244','245','246','247','248','249',
                 '250','251','252','253','254'
                ]

_MAGIC_COOKIE = [99,130,83,99]

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
        return _DHCP_OPTIONS[option_number]
    else:
        return _DHCP_OTIONS.index(option)


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
        self.packet_data[236:240] = MagicCookie
        logger.debug("Initializing blank DHCP packet")


    def get_option_start(self):
        ''' Return location after MagicCookie, or None if not found '''

        # Sometimes it's right where you expect it
        if self.packet_data[236:240] == MagicCookie:
            logger.debug("DHCP packet received, contains MagicCookie")
            return 236
        else:
            # search the entire packet, but not past packet end
            for i in range(237,len(packet_data)-4):
                if self.packet_data[i:i+4] == _MAGIC_COOKIE:
                    logger.debug("DHCP packet received, contains MagicCookie")
                    return i+4
            return None  # not found


    def get_option(self, name):
        if name in _DHCP_FIELDS:
            field = _DHCP_FIELDS[name]
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
        if name in _DHCP_FIELDS:
            # boundary validation
            if len(value) != _DHCP_FIELDS[name]['len']:
                logger.error("DhcpPacket.set_option bad option length: %s" %
                             name)
                return False
            begin = _DHCP_FIELDS[name]['pos']
            end = _DHCP_FIELDS[name]['pos'] + _DHCP_FIELDS[name]['len']
            logger.debug("DHCP option set, name: %s, value: %s" %
                         (name, value))
            self.packet_data[begin:end] = value
            return True
        elif name in _DHCP_OPTIONS:


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
                option = _DHCP_OPTIONS[self.packet_data[location]]
                #TODO(dsneddon) lookup field type for data validation
                length = self.packet_data[location+1]
                start = location + 2
                end = start + length
                self.dhcp_options[self.packet_data[location]] = self.packet_data[start:end+1]

    def encode_packet(self):
        """ Set the options and pack the packet """

        ord_options = {}
        for option in self.dhcp_options:
            # Options must be set in order according to RFC
            order = _DHCP_OPTIONS.index(option)
            # DCHP requires the option ID, length, and data concatenated
            ord_options[order] = [ order, len(option), option ]
        logger.debug("Options to encode: %s" % ord_options)

        option_data = []
        for option in sorted(ord_options.keys()):
            option_data += ord_options[option]

        packet = self.packet_data[:240] + option_data
        packet.append(255)  # add end option

        pack_fmt = str(len(packet)) + "c"
        packet = map(chr, packet)
        return pack(pack_fmt, *packet)


    def str(self):
        """ Print a human-readable decode of the packet"""
        print "Not yet implemented."
