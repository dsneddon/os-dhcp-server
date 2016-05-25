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
import socket
import select
import logging
from os_dhcp_server import dhcp_packet
from os_dhcp_server import utils


logger = logging.getLogger(__name__)



class DhcpServer(object):
    """DHCP Server object for listening and sending DHCP requests and offers"""

    def __init__(self, ip_address, listen_port, verbose, debug, reuseaddr=True,
                 broadcast=True):
        self.ip_address = ip_address
        self.listen_port = listen_port
        self.reuseaddr = reuseaddr
        self.broadcast = broadcast
        self.verbose = verbose
        self.debug = debug
        self.dhcp_socket = None

        if self.listen_port < 1024:
            if not os.geteuid() == 0:
                sys.exit("Error, %s must be run as root to use ports <1024." %
                         os.path.basename(__file__))

    def create_socket(self):
        """Open a socket for listening to DHCP requests"""
        logger.info("Creating os-dhcp-server socket...")
        if not self.ip_address or self.ip_address == '0.0.0.0':
            logger.debug("  address: all interfaces")
        logger.debug("  address:      %s" % self.ip_address )
        #logger.debug("  tftp:         %s" % str(tftp) )
        #logger.debug("  gateway:      %s" % str(gateway) )
        #logger.debug("  dns:          %s" % str(dns) )
        #logger.debug("  netmask:      %s" % str(netmask) )
        logger.debug("  port:         %s" % str(self.listen_port) )
        #logger.debug("  pxe filename: %s" % str(pxefilename) )
        logger.debug("  pid:          %s" % str(os.getpid()) )
        #logger.debug("  serving:      %s - %s" % (str(offerfrom),
        #                                              str(offerto)))
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
            self.dhcp_socket.bind((self.ip_address, self.listen_port))
        except socket.error as err:
            logger.error("Error binding to socket: %s" % err)
            return False

    def receive(self):
        """Main loop for processing DHCP packets"""
        data_in, data_out, data_except = select.select([self.dhcp_socket],
                                                       [], [])

        if (data_in != []):
            (data, source_address) = self.dhcp_socket.recvfrom(8192)
        else:
            return None

        if data:
            packet = dhcp_packet.DhcpPacket(data)
            packet.source_address = source_address
            logger.debug(packet.str())
        return packet

    def listen(self):

        while 1:  # main loop
            try:
                packet = self.receive()
                if not packet:
                    logger.error('Error processing received packet, ' +
                                 'no data received')
                else:
                    packet.decode_packet()
            except KeyboardInterrupt:
                return 0