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
import select
import binascii
import logging
from os_dhcp_server import dhcp_packet
from os_dhcp_server import utils


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

    def __init__(self, ip_address, listen_port, reuseaddr=True, broadcast=True,
                 verbose, debug):
        self.ip_address = ip_address
        self.listen_port = listen_port
        self.reuseaddr = reuseaddr
        self.broadcast = broadcast
        self.verbose = verbose
        self.debug = debug
        self.dhcp_socket = None

    if self.listen_port < 1024:
        if not os.geteuid() == 0:
            sys.exit("%s must be run as root to use ports <1024. Exiting." %
                     os.path.basename(__file__))

    def create_socket(self):
        """Open a socket for listening to DHCP requests"""
        logger.info("Creating os-dhcp-server socket...")
        if not self.ip_address or self.ip_address == '0.0.0.0':
            logger.debug("  address: all interfaces")
        else:
            logger.debug("  address:      %s" % address )
            logger.debug("  tftp:         %s" % str(tftp) )
            logger.debug("  gateway:      %s" % str(gateway) )
            logger.debug("  dns:          %s" % str(dns) )
            logger.debug("  netmask:      %s" % str(netmask) )
            logger.debug("  port:         %s" % str(self.listen_port) )
            logger.debug("  pxe filename: %s" % str(pxefilename) )
            logger.debug("  pid:          %s" % str(os.getpid()) )
            logger.debug("  serving:      %s - %s" % (str(offerfrom),
                                                      str(offerto)))
        try:
            self.dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error as err:
            logger.error("Error creating DHCP server socket: %s" % err)
            return False
        try:
            if self.reuseaddr:
                self.dhcp_socket.setsockopt(socket.SOL_SOCKET,
                                            socket.SO_REUSEADDR, 1)
        except socket.error as err:
            logger.error("Error setting socket option SO_REUSEADDR: %s" % err)
            return False
        try:
            if self.broadcast:
                self.dhcp_socket.setsockopt(socket.SOL_SOCKET,
                                            socket.SO_BROADCAST, 1)
        except socket.error as err:
            logger.error("Error setting socket option SO_BROADCAST: %s" % err)
            return False

    def bind_socket(self):
        """Bind the socket to the IP address and port"""
        if self.verbose or self.debug:
            logger.info("Attempting to bind DHCP server to %s:%s" % \
                        (self.ip_address, self.listen_port))
        try:
            s.bind((self.ip_address, self.listen_port))
        except socket.error as err:
            logger.error("Error binding to socket: %s" % err)
            return False

        while 1:  # main loop
            try:
                # original listen block from sdhcpd.py
                #message, addressf = s.recvfrom(8192)
                #if not message.startswith('\x01') and not addressf[0] == '0.0.0.0':
                #    continue  # only serve if a dhcp request
                #data = reqparse(message)  # handle request
                #if data:
                #    s.sendto(data, ('<broadcast>', 68))  # reply
                #release()  # update releases table
                packet = self.receive()
                if not packet:
                    logger.error('Error processing received packet, '+
                                 'no data received')
                packet.decode_packet()
            except KeyboardInterrupt:
                return 0

    def receive(self):
        """Main loop for processing DHCP packets"""
        data_in, data_out, data_except = select.select([self.dhcp_socket],
                                                       [], [], timeout)

        if (data_in != []):
            (data, source_address) = self.dhcp_socket.recvfrom(8192)
        else:
            return None

        if data:
            packet = dhcp_packet.DhcpPacket(data)
            packet.source_address = source_address
        return packet