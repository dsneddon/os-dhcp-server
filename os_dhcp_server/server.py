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

import os
import sys
import IN
import socket
import logging

from os_net_config import utils

logger = logging.getLogger(__name__)


def reqparse(message): #handles either DHCPDiscover or DHCPRequest
    #using info from http://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
    #the tables titled DHCPDISCOVER and DHCPOFFER
    data=None
    dhcpfields=[1,1,1,1,4,2,2,4,4,4,4,6,10,192,4,"msg.rfind('\xff')",1,None]
    #send: boolean as to whether to send data back, and data: data to send, if any
    #print len(message)
    hexmessage=binascii.hexlify(message)
    messagesplit=[binascii.hexlify(x) for x in slicendice(message,dhcpfields)]
    dhcpopt=messagesplit[15][:6] #hope DHCP type is first. Should be.
    if dhcpopt == '350101':
        #DHCPDiscover
        #craft DHCPOffer
        #DHCPOFFER creation:
        #options = \xcode \xlength \xdata
        lease=getlease(messagesplit[11])
        print 'Leased:',lease
        data='\x02\x01\x06\x00'+binascii.unhexlify(messagesplit[4])+'\x00\x04'
        data+='\x80\x00'+'\x00'*4+socket.inet_aton(lease)
        data+=socket.inet_aton(address)+'\x00'*4
        data+=binascii.unhexlify(messagesplit[11])+'\x00'*10+'\x00'*192
        data+='\x63\x82\x53\x63'+'\x35\x01\x02'+'\x01\x04'
        data+=socket.inet_aton(netmask)+'\x36\x04'+socket.inet_aton(address)
        data+='\x1c\x04'+socket.inet_aton(broadcast)+'\x03\x04'
        data+=socket.inet_aton(gateway)+'\x06\x04'+socket.inet_aton(dns)
        data+='\x33\x04'+binascii.unhexlify(hex(leasetime)[2:].rjust(8,'0'))
        data+='\x42'+binascii.unhexlify(hex(len(tftp))[2:].rjust(2,'0'))+tftp
        data+='\x43'+binascii.unhexlify(hex(len(pxefilename)+1)[2:].rjust(2,'0'))
        data+=pxefilename+'\x00\xff'
    elif dhcpopt == '350103':
        #DHCPRequest
        #craft DHCPACK
        data='\x02\x01\x06\x00'+binascii.unhexlify(messagesplit[4])+'\x00'*8
        data+=binascii.unhexlify(messagesplit[15][messagesplit[15].find('3204')+4:messagesplit[15].find('3204')+12])
        data+=socket.inet_aton(address)+'\x00'*4
        data+=binascii.unhexlify(messagesplit[11])+'\x00'*202
        data+='\x63\x82\x53\x63'+'\x35\x01\05'+'\x36\x04'+socket.inet_aton(address)
        data+='\x01\x04'+socket.inet_aton(netmask)+'\x03\x04'
        data+=socket.inet_aton(address)+'\x33\x04'
        data+=binascii.unhexlify(hex(leasetime)[2:].rjust(8,'0'))
        data+='\x42'+binascii.unhexlify(hex(len(tftp))[2:].rjust(2,'0'))
        data+=tftp+'\x43'+binascii.unhexlify(hex(len(pxefilename)+1)[2:].rjust(2,'0'))
        data+=pxefilename+'\x00\xff'
    return data


class DhcpServer(object):
    """DHCP Server object for listening and sending DHCP requests and offers"""

    def __init__(self, ip_address, listen_port, verbose, debug):
        self.ip_address = ip_address
        self.listen_port = listen_port
        self.verbose = verbose
        self.debug = debug

    if self.listen_port < 1024:
        if not os.geteuid() == 0:
            sys.exit(os.path.basename(__file__) + ": root permitions are necessary to bind to port " + str(
                port) + ", use -p to specify a non privileged port or run as root.")

    def listen(self):
        if self.verbose or self.debug:
            print  "Starting os-dhcp-server..."
            if not self.ip_address or self.ip_address == '0.0.0.0':
                print "  address: all interfaces"
            else:
                print "  address:      " + address
            print   "  tftp:         " + str(tftp)
            print   "  gateway:      " + str(gateway)
            print   "  dns:          " + str(dns)
            print   "  netmask:      " + str(netmask)
            print   "  port:         " + str(self.listen_port)
            print   "  pxe filename: " + str(pxefilename)
            print   "  pid:          " + str(os.getpid())
            print   "  serving:      " + str(offerfrom) + " - " + str(offerto)
            print   "Press <Ctrl-C> to exit.\n"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, interface + '\0')  # experimental
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind((self.ip_address, self.listen_port))

        while 1:  # main loop
            try:
                message, addressf = s.recvfrom(8192)
                if not message.startswith('\x01') and not addressf[0] == '0.0.0.0':
                    continue  # only serve if a dhcp request
                data = reqparse(message)  # handle request
                if data:
                    s.sendto(data, ('<broadcast>', 68))  # reply
                release()  # update releases table
            except KeyboardInterrupt:
                return 0
