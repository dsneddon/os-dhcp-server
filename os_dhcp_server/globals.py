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

TRUE_VALUES = ('True', 'true', '1', 'yes', 'one')

FALSE_VALUES = ('False', 'false', '0', 'no', 'None', 'none', 'zero')

MAGIC_COOKIE = [99,130,83,99]

# Header field information taken from:
# https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
DHCP_FIELDS = {'op':{'pos':0, 'len':1, 'type': 'int'},
                'htype':{'pos':1, 'len':1, 'type': 'int'},
                'hlen':{'pos':2, 'len':1, 'type': 'int'},
                'hops':{'pos':3, 'len':1, 'type': 'int'},
                'xid':{'pos':3, 'len':4, 'type': 'int32'},
                'secs':{'pos':8, 'len':2, 'type': 'int16'},
                'flags':{'pos':10, 'len':2, 'type':'int16'},
                'ciaddr':{'pos':12, 'len':4, 'type':'int32'},
                'yiaddr':{'pos':16, 'len':4, 'type':'int32'},
                'siaddr':{'pos':20, 'len':4, 'type':'int32'},
                'giaddr':{'pos':24, 'len':4, 'type':'int32'},
                'chaddr':{'pos':28, 'len':16, 'type':'hwmacaddr'},
                'sname':{'pos':44, 'len':64, 'type':'string'},
                'file':{'pos':108, 'len':128, 'type':'string'}
               }

DHCP_OPCODES = { '0': 'ERROR_UNDEF', '1' : 'BOOTREQUEST' , '2' : 'BOOTREPLY'}

DHCP_MESSAGE_TYPES = {'0': 'ERROR_UNDEF', '1': 'DHCP_DISCOVER',
                      '2': 'DHCP_OFFER', '3' : 'DHCP_REQUEST',
                      '4':'DHCP_DECLINE', '5': 'DHCP_ACK',
                      '6': 'DHCP_NACK', '7': 'DHCP_RELEASE',
                      '8' : 'DHCP_INFORM' }

DHCP_MESSAGE_LIST = ['ERROR_UNDEF', 'DHCP_DISCOVER', 'DHCP_OFFER',
                     'DHCP_REQUEST', 'DHCP_DECLINE', 'DHCP_ACK',
                     'DHCP_NACK', 'DHCP_RELEASE', 'DHCP_INFORM']

DHCP_OPTIONS = ['pad',
                 # Vendor Extension
                 'subnet_mask','time_offset', 'router','time_server',
                 'name_server', 'domain_name_server','log_server',
                 'cookie_server','lpr_server', 'impress_server',
                 'resource_location_server', 'host_name','boot_file',
                 'merit_dump_file', 'domain_name','swap_server','root_path',
                 'extensions_path',
                 # IP layer parameters per host
                 'ip_forwarding','nonlocal_src_routing', 'policy_filter',
                 'max_dgram_reassem_size', 'default_ip_ttl',
                 'path_mtu_aging_timeout', 'path_mtu_table',
                 # IP layer parameters per interface
                 'interface_mtu','all_subnets_local', 'broadcast_address',
                 'perform_mask_discovery', 'mask_supplier',
                 'perform_rtr_discovery', 'router_sol_address',
                 'static_route',
                 # link layer parameters per interface
                 'trailer_encapsulation','arp_cache_timeout',
                 'ethernet_encapsulation',
                 # TCP parameters
                 'tcp_default_ttl','tcp_keepalive_int',
                 'tcp_keepalive_garbage',
                 # Applications and service parameters
                 'nis_domain', 'nis_servers', 'ntp_servers', 'vendor_specific',
                 'nbns', 'nbdd','nd_node_type', 'nb_scope',
                 'x__font_server',
                 'x_display_manager',
                 # DHCP extensions
                 'request_ip_address', 'ip_address_lease_time', 'overload',
                 'dhcp_message_type', 'server_identifier',
                 'param_request_list', 'message',
                 'max_dhcp_msg_size', 'renewal_time_value',
                 'rebinding_time_val', 'vendor_class', 'client_identifier',
                 # adds from RFC 2132,2242
                 'netware_ip_domain', 'netware_ip_sub_opts',
                 'nis+_domain', 'nis+_servers', 'tftp_server_name',
                 'bootfile_name', 'mobile_ip_home_agent', 'smtp_servers',
                 'pop_servers', 'nntp_servers', 'default_www_server',
                 'default_finger_server', 'default_irc_server',
                 'streettalk_server', 'streettalk_directory',
                 'user_class','directory_agent','service_scope',
                 'rapid_commit','client_fqdn','relay_agent',
                 'internet_storage_ns',
                 '84', 'nds_server','nds_tree_name','nds_context',
                 '88','89',
                 #90
                 'authentication',
                 'client_last_trans_time','associated_ip', #RFC 4388
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
                 'cidr_static_route',
                 'cablelabs_client','geoconf',
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

# TODO(dsneddon) - create type for policy_filter, which is multiples of 8 bytes
DHCP_OPTION_TYPES = {
    0: {'max': 0, 'type': 'none', 'name': 'pad', 'min': 0},
    1: {'max': 4, 'type': '[ipv4]', 'name': 'subnet_mask', 'min': 4},
    2: {'max': 4, 'type': 'int32', 'name': 'time_offset', 'min': 4},
    3: {'max': 0, 'type': '[ipv4]', 'name': 'router', 'min': 4},
    4: {'max': 0, 'type': '[ipv4]', 'name': 'time_server', 'min': 4},
    5: {'max': 0, 'type': '[ipv4]', 'name': 'name_server', 'min': 4},
    6: {'max': 0, 'type': '[ipv4]', 'name': 'domain_name_server', 'min': 4},
    7: {'max': 0, 'type': '[ipv4]', 'name': 'log_server', 'min': 4},
    8: {'max': 0, 'type': '[ipv4]', 'name': 'cookie_server', 'min': 4},
    9: {'max': 0, 'type': '[ipv4]', 'name': 'lpr_server', 'min': 4},
    10: {'max': 0, 'type': '[ipv4]', 'name': 'impress_server', 'min': 4},
    11: {'max': 0, 'type': '[ipv4]', 'name': 'resource_location_server',
         'min': 4},
    12: {'max': 0, 'type': 'string', 'name': 'host_name', 'min': 1},
    13: {'max': 2, 'type': 'int16', 'name': 'boot_file', 'min': 2},
    14: {'max': 0, 'type': 'string', 'name': 'merit_dump_file', 'min': 1},
    15: {'max': 0, 'type': 'string', 'name': 'domain_name', 'min': 1},
    16: {'max': 4, 'type': 'int32', 'name': 'swap_server', 'min': 4},
    17: {'max': 0, 'type': 'string', 'name': 'root_path', 'min': 1},
    18: {'max': 0, 'type': 'string', 'name': 'extensions_path', 'min': 1},
    19: {'max': 1, 'type': 'bool', 'name': 'ip_forwarding', 'min': 1},
    20: {'max': 1, 'type': 'bool', 'name': 'nonlocal_src_routing', 'min': 1},
    21: {'max': 0, 'type': 'ipv4', 'name': 'policy_filter', 'min': 8},
    22: {'max': 2, 'type': 'int16', 'name': 'max_dgram_reassem_size',
         'min': 2},
    23: {'max': 0, 'type': 'char', 'name': 'default_ip_ttl', 'min': 0},
    24: {'max': 4, 'type': 'int32', 'name': 'path_mtu_aging_timeout',
         'min': 4},
    25: {'max': 2, 'type': 'int16', 'name': 'path_mtu_table', 'min': 2},
    26: {'max': 2, 'type': 'int16', 'name': 'interface_mtu', 'min': 2},
    27: {'max': 1, 'type': 'bool', 'name': 'all_subnets_local', 'min': 1},
    28: {'max': 4, 'type': 'int32', 'name': 'broadcast_address', 'min': 4},
    29: {'max': 1, 'type': 'bool', 'name': 'perform_mask_discovery', 'min': 1},
    30: {'max': 1, 'type': 'bool', 'name': 'mask_supplier', 'min': 1},
    31: {'max': 1, 'type': 'bool', 'name': 'perform_rtr_discovery', 'min': 1},
    32: {'max': 4, 'type': 'int32', 'name': 'router_sol_address', 'min': 4},
    33: {'max': 4, 'type': 'ipv4', 'name': 'static_route', 'min': 4},
    34: {'max': 1, 'type': 'bool', 'name': 'trailer_encapsulation', 'min': 1},
    35: {'max': 4, 'type': 'int32', 'name': 'arp_cache_timeout', 'min': 4},
    36: {'max': 1, 'type': 'bool', 'name': 'ethernet_encapsulation', 'min': 1},
    37: {'max': 0, 'type': 'char', 'name': 'tcp_default_ttl', 'min': 0},
    38: {'max': 4, 'type': 'int32', 'name': 'tcp_keepalive_int', 'min': 4},
    39: {'max': 1, 'type': 'bool', 'name': 'tcp_keepalive_garbage', 'min': 1},
    40: {'max': 0, 'type': 'string', 'name': 'nis_domain', 'min': 1},
    41: {'max': 4, 'type': 'ipv4', 'name': 'nis_servers', 'min': 4},
    42: {'max': 4, 'type': 'ipv4', 'name': 'ntp_servers', 'min': 4},
    43: {'max': 0, 'type': 'string', 'name': 'vendor_specific', 'min': 1},
    44: {'max': 4, 'type': 'ipv4', 'name': 'nbns', 'min': 4},
    45: {'max': 4, 'type': 'ipv4', 'name': 'nbdd', 'min': 4},
    46: {'max': 0, 'type': 'char', 'name': 'nd_node_type', 'min': 0},
    47: {'max': 0, 'type': 'string', 'name': 'nb_scope', 'min': 1},
    48: {'max': 4, 'type': 'ipv4', 'name': 'x__font_server', 'min': 4},
    49: {'max': 4, 'type': 'ipv4', 'name': 'x_display_manager', 'min': 4},
    50: {'max': 4, 'type': 'int32', 'name': 'request_ip_address', 'min': 4},
    51: {'max': 4, 'type': 'int32', 'name': 'ip_address_lease_time', 'min': 4},
    52: {'max': 0, 'type': 'char', 'name': 'overload', 'min': 0},
    53: {'max': 0, 'type': 'int', 'name': 'dhcp_message_type', 'min': 0},
    54: {'max': 4, 'type': 'int32', 'name': 'server_identifier', 'min': 4},
    55: {'max': 0, 'type': 'char+', 'name': 'param_request_list', 'min': 0},
    56: {'max': 0, 'type': 'string', 'name': 'message', 'min': 1},
    57: {'max': 2, 'type': 'int16', 'name': 'max_dhcp_msg_size', 'min': 2},
    58: {'max': 4, 'type': 'int32', 'name': 'renewal_time_value', 'min': 4},
    59: {'max': 4, 'type': 'int32', 'name': 'rebinding_time_val', 'min': 4},
    60: {'max': 0, 'type': 'string', 'name': 'vendor_class', 'min': 1},
    61: {'max': 0, 'type': 'identifier', 'name': 'client_identifier',
         'min': 0},
    62: {'max': 0, 'type': 'string', 'name': 'netware_ip_domain', 'min': 1},
    63: {'max': 0, 'type': 'RFC2242', 'name': 'netware_ip_sub_opts', 'min': 0},
    64: {'max': 0, 'type': 'string', 'name': 'nis+_domain', 'min': 1},
    65: {'max': 4, 'type': 'ipv4', 'name': 'nis+_servers', 'min': 4},
    66: {'max': 0, 'type': 'string', 'name': 'tftp_server_name', 'min': 1},
    67: {'max': 0, 'type': 'string', 'name': 'bootfile_name', 'min': 1},
    68: {'max': 4, 'type': 'int32', 'name': 'mobile_ip_home_agent', 'min': 4},
    69: {'max': 4, 'type': 'ipv4', 'name': 'smtp_servers', 'min': 4},
    70: {'max': 4, 'type': 'ipv4', 'name': 'pop_servers', 'min': 4},
    71: {'max': 4, 'type': 'ipv4', 'name': 'nntp_servers', 'min': 4},
    72: {'max': 4, 'type': 'ipv4', 'name': 'default_www_server', 'min': 4},
    73: {'max': 4, 'type': 'ipv4', 'name': 'default_finger_server', 'min': 4},
    74: {'max': 4, 'type': 'ipv4', 'name': 'default_irc_server', 'min': 4},
    75: {'max': 4, 'type': 'ipv4', 'name': 'streettalk_server', 'min': 4},
    76: {'max': 4, 'type': 'ipv4', 'name': 'streettalk_directory', 'min': 4},
    77: {'max': 0, 'type': 'RFC3004', 'name': 'user_class', 'min': 0},
    78: {'max': 0, 'type': 'RFC2610', 'name': 'directory_agent', 'min': 0},
    79: {'max': 0, 'type': 'RFC2610', 'name': 'service_scope', 'min': 0},
    80: {'max': 0, 'type': 'null', 'name': 'rapid_commit', 'min': 0},
    81: {'max': 0, 'type': 'string', 'name': 'client_fqdn', 'min': 1},
    82: {'max': 0, 'type': 'RFC3046', 'name': 'relay_agent', 'min': 0},
    83: {'max': 0, 'type': 'RFC4174', 'name': 'internet_storage_ns', 'min': 0},
    84: {'max': 0, 'type': 'None', 'name': '84', 'min': 0},
    85: {'max': 4, 'type': 'ipv4', 'name': 'nds_server', 'min': 4},
    86: {'max': 0, 'type': 'RFC2241', 'name': 'nds_tree_name', 'min': 0},
    87: {'max': 0, 'type': 'RFC2241', 'name': 'nds_context', 'min': 0},
    88: {'max': 0, 'type': 'None', 'name': '88', 'min': 0},
    89: {'max': 0, 'type': 'None', 'name': '89', 'min': 0},
    90: {'max': 0, 'type': 'RFC3118', 'name': 'authentication', 'min': 0},
    91: {'max': 0, 'type': 'RFC4388', 'name': 'client_last_trans_time',
         'min': 0},
    92: {'max': 4, 'type': 'ipv4', 'name': 'associated_ip', 'min': 4},
    93: {'max': 0, 'type': 'None', 'name': 'client_system', 'min': 0},
    94: {'max': 0, 'type': 'None', 'name': 'client_ndi', 'min': 0},
    95: {'max': 0, 'type': 'None', 'name': 'ldap', 'min': 0},
    96: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    97: {'max': 0, 'type': 'None', 'name': 'uuid_guid', 'min': 0},
    98: {'max': 0, 'type': 'string', 'name': 'open_group_user_auth', 'min': 1},
    99: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    100: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    101: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    102: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    103: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    104: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    105: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    106: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    107: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    108: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    109: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    110: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    111: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    112: {'max': 0, 'type': 'None', 'name': 'netinfo_address', 'min': 0},
    113: {'max': 0, 'type': 'None', 'name': 'netinfo_tag', 'min': 0},
    114: {'max': 0, 'type': 'None', 'name': 'url', 'min': 0},
    115: {'max': 0, 'type': 'None', 'name': 'unassigned', 'min': 0},
    116: {'max': 0, 'type': 'char', 'name': 'auto_config', 'min': 0},
    117: {'max': 0, 'type': 'RFC2937', 'name': 'name_service_search',
          'min': 0},
    118: {'max': 4, 'type': 'int32', 'name': 'subnet_selection', 'min': 4},
    119: {'max': 0, 'type': 'RFC3397', 'name': 'domain_search', 'min': 0},
    120: {'max': 0, 'type': 'RFC3361', 'name': 'sip_servers', 'min': 0},
    121: {'max': 0, 'type': 'None', 'name': 'cidr_static_route', 'min': 0},
    122: {'max': 0, 'type': 'None', 'name': 'cablelabs_client', 'min': 0},
    123: {'max': 0, 'type': 'None', 'name': 'geoconf', 'min': 0},
    124: {'max': 0, 'type': 'None', 'name': 'vendor_class', 'min': 0},
    125: {'max': 0, 'type': 'None', 'name': 'vendor_specific', 'min': 0},
    126: {'max': 0, 'type': 'None', 'name': '126', 'min': 0},
    127: {'max': 0, 'type': 'None', 'name': '127', 'min': 0},
    128: {'max': 0, 'type': 'None', 'name': '128', 'min': 0},
    129: {'max': 0, 'type': 'None', 'name': '129', 'min': 0},
    130: {'max': 0, 'type': 'None', 'name': '130', 'min': 0},
    131: {'max': 0, 'type': 'None', 'name': '131', 'min': 0},
    132: {'max': 0, 'type': 'None', 'name': '132', 'min': 0},
    133: {'max': 0, 'type': 'None', 'name': '133', 'min': 0},
    134: {'max': 0, 'type': 'None', 'name': '134', 'min': 0},
    135: {'max': 0, 'type': 'None', 'name': '135', 'min': 0},
    136: {'max': 0, 'type': 'None', 'name': '136', 'min': 0},
    137: {'max': 0, 'type': 'None', 'name': '137', 'min': 0},
    138: {'max': 0, 'type': 'None', 'name': '138', 'min': 0},
    139: {'max': 0, 'type': 'None', 'name': '139', 'min': 0},
    140: {'max': 0, 'type': 'None', 'name': '140', 'min': 0},
    141: {'max': 0, 'type': 'None', 'name': '141', 'min': 0},
    142: {'max': 0, 'type': 'None', 'name': '142', 'min': 0},
    143: {'max': 0, 'type': 'None', 'name': '143', 'min': 0},
    144: {'max': 0, 'type': 'None', 'name': '144', 'min': 0},
    145: {'max': 0, 'type': 'None', 'name': '145', 'min': 0},
    146: {'max': 0, 'type': 'None', 'name': '146', 'min': 0},
    147: {'max': 0, 'type': 'None', 'name': '147', 'min': 0},
    148: {'max': 0, 'type': 'None', 'name': '148', 'min': 0},
    149: {'max': 0, 'type': 'None', 'name': '149', 'min': 0},
    150: {'max': 0, 'type': 'None', 'name': '150', 'min': 0},
    151: {'max': 0, 'type': 'None', 'name': '151', 'min': 0},
    152: {'max': 0, 'type': 'None', 'name': '152', 'min': 0},
    153: {'max': 0, 'type': 'None', 'name': '153', 'min': 0},
    154: {'max': 0, 'type': 'None', 'name': '154', 'min': 0},
    155: {'max': 0, 'type': 'None', 'name': '155', 'min': 0},
    156: {'max': 0, 'type': 'None', 'name': '156', 'min': 0},
    157: {'max': 0, 'type': 'None', 'name': '157', 'min': 0},
    158: {'max': 0, 'type': 'None', 'name': '158', 'min': 0},
    159: {'max': 0, 'type': 'None', 'name': '159', 'min': 0},
    160: {'max': 0, 'type': 'None', 'name': '160', 'min': 0},
    161: {'max': 0, 'type': 'None', 'name': '161', 'min': 0},
    162: {'max': 0, 'type': 'None', 'name': '162', 'min': 0},
    163: {'max': 0, 'type': 'None', 'name': '163', 'min': 0},
    164: {'max': 0, 'type': 'None', 'name': '164', 'min': 0},
    165: {'max': 0, 'type': 'None', 'name': '165', 'min': 0},
    166: {'max': 0, 'type': 'None', 'name': '166', 'min': 0},
    167: {'max': 0, 'type': 'None', 'name': '167', 'min': 0},
    168: {'max': 0, 'type': 'None', 'name': '168', 'min': 0},
    169: {'max': 0, 'type': 'None', 'name': '169', 'min': 0},
    170: {'max': 0, 'type': 'None', 'name': '170', 'min': 0},
    171: {'max': 0, 'type': 'None', 'name': '171', 'min': 0},
    172: {'max': 0, 'type': 'None', 'name': '172', 'min': 0},
    173: {'max': 0, 'type': 'None', 'name': '173', 'min': 0},
    174: {'max': 0, 'type': 'None', 'name': '174', 'min': 0},
    175: {'max': 0, 'type': 'None', 'name': '175', 'min': 0},
    176: {'max': 0, 'type': 'None', 'name': '176', 'min': 0},
    177: {'max': 0, 'type': 'None', 'name': '177', 'min': 0},
    178: {'max': 0, 'type': 'None', 'name': '178', 'min': 0},
    179: {'max': 0, 'type': 'None', 'name': '179', 'min': 0},
    180: {'max': 0, 'type': 'None', 'name': '180', 'min': 0},
    181: {'max': 0, 'type': 'None', 'name': '181', 'min': 0},
    182: {'max': 0, 'type': 'None', 'name': '182', 'min': 0},
    183: {'max': 0, 'type': 'None', 'name': '183', 'min': 0},
    184: {'max': 0, 'type': 'None', 'name': '184', 'min': 0},
    185: {'max': 0, 'type': 'None', 'name': '185', 'min': 0},
    186: {'max': 0, 'type': 'None', 'name': '186', 'min': 0},
    187: {'max': 0, 'type': 'None', 'name': '187', 'min': 0},
    188: {'max': 0, 'type': 'None', 'name': '188', 'min': 0},
    189: {'max': 0, 'type': 'None', 'name': '189', 'min': 0},
    190: {'max': 0, 'type': 'None', 'name': '190', 'min': 0},
    191: {'max': 0, 'type': 'None', 'name': '191', 'min': 0},
    192: {'max': 0, 'type': 'None', 'name': '192', 'min': 0},
    193: {'max': 0, 'type': 'None', 'name': '193', 'min': 0},
    194: {'max': 0, 'type': 'None', 'name': '194', 'min': 0},
    195: {'max': 0, 'type': 'None', 'name': '195', 'min': 0},
    196: {'max': 0, 'type': 'None', 'name': '196', 'min': 0},
    197: {'max': 0, 'type': 'None', 'name': '197', 'min': 0},
    198: {'max': 0, 'type': 'None', 'name': '198', 'min': 0},
    199: {'max': 0, 'type': 'None', 'name': '199', 'min': 0},
    200: {'max': 0, 'type': 'None', 'name': '200', 'min': 0},
    201: {'max': 0, 'type': 'None', 'name': '201', 'min': 0},
    202: {'max': 0, 'type': 'None', 'name': '202', 'min': 0},
    203: {'max': 0, 'type': 'None', 'name': '203', 'min': 0},
    204: {'max': 0, 'type': 'None', 'name': '204', 'min': 0},
    205: {'max': 0, 'type': 'None', 'name': '205', 'min': 0},
    206: {'max': 0, 'type': 'None', 'name': '206', 'min': 0},
    207: {'max': 0, 'type': 'None', 'name': '207', 'min': 0},
    208: {'max': 0, 'type': 'None', 'name': '208', 'min': 0},
    209: {'max': 0, 'type': 'None', 'name': '209', 'min': 0},
    210: {'max': 0, 'type': 'None', 'name': '210', 'min': 0},
    211: {'max': 0, 'type': 'None', 'name': '211', 'min': 0},
    212: {'max': 0, 'type': 'None', 'name': '212', 'min': 0},
    213: {'max': 0, 'type': 'None', 'name': '213', 'min': 0},
    214: {'max': 0, 'type': 'None', 'name': '214', 'min': 0},
    215: {'max': 0, 'type': 'None', 'name': '215', 'min': 0},
    216: {'max': 0, 'type': 'None', 'name': '216', 'min': 0},
    217: {'max': 0, 'type': 'None', 'name': '217', 'min': 0},
    218: {'max': 0, 'type': 'None', 'name': '218', 'min': 0},
    219: {'max': 0, 'type': 'None', 'name': '219', 'min': 0},
    220: {'max': 0, 'type': 'None', 'name': '220', 'min': 0},
    221: {'max': 0, 'type': 'None', 'name': '221', 'min': 0},
    222: {'max': 0, 'type': 'None', 'name': '222', 'min': 0},
    223: {'max': 0, 'type': 'None', 'name': '223', 'min': 0},
    224: {'max': 0, 'type': 'None', 'name': '224', 'min': 0},
    225: {'max': 0, 'type': 'None', 'name': '225', 'min': 0},
    226: {'max': 0, 'type': 'None', 'name': '226', 'min': 0},
    227: {'max': 0, 'type': 'None', 'name': '227', 'min': 0},
    228: {'max': 0, 'type': 'None', 'name': '228', 'min': 0},
    229: {'max': 0, 'type': 'None', 'name': '229', 'min': 0},
    230: {'max': 0, 'type': 'None', 'name': '230', 'min': 0},
    231: {'max': 0, 'type': 'None', 'name': '231', 'min': 0},
    232: {'max': 0, 'type': 'None', 'name': '232', 'min': 0},
    233: {'max': 0, 'type': 'None', 'name': '233', 'min': 0},
    234: {'max': 0, 'type': 'None', 'name': '234', 'min': 0},
    235: {'max': 0, 'type': 'None', 'name': '235', 'min': 0},
    236: {'max': 0, 'type': 'None', 'name': '236', 'min': 0},
    237: {'max': 0, 'type': 'None', 'name': '237', 'min': 0},
    238: {'max': 0, 'type': 'None', 'name': '238', 'min': 0},
    239: {'max': 0, 'type': 'None', 'name': '239', 'min': 0},
    240: {'max': 0, 'type': 'None', 'name': '240', 'min': 0},
    241: {'max': 0, 'type': 'None', 'name': '241', 'min': 0},
    242: {'max': 0, 'type': 'None', 'name': '242', 'min': 0},
    243: {'max': 0, 'type': 'None', 'name': '243', 'min': 0},
    244: {'max': 0, 'type': 'None', 'name': '244', 'min': 0},
    245: {'max': 0, 'type': 'None', 'name': '245', 'min': 0}
}
