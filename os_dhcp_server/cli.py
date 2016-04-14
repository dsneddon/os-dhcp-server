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


import argparse
import logging
import sys
import yaml

from os_dhcp_server import version
from os_dhcp_server import network
from os_dhcp_server import utils

logger = logging.getLogger(__name__)


def parse_opts(argv):
    parser = argparse.ArgumentParser(
        description='DHCP server for OpenStack TripleO')
    parser.add_argument('-c', '--config-file', metavar='CONFIG_FILE',
                        help="""path to the configuration file.""",
                        default='/etc/os-dhcp-server/config.yaml')
    parser.add_argument('-i', '--interface', metavar='INTERFACE',
                        help="""Interface to listen on (default all)""",
                        default='')
    parser.add_argument('-r', '--root-dir', metavar='ROOT_DIR',
                        help="""The root directory of the filesystem.""",
                        default='')
    parser.add_argument('-p', '--port', metavar='LISTEN_PORT',
                        help="""The port to use to listen for DHCP requests""",
                        default='67')
    parser.add_argument(
        '-d', '--debug',
        dest="debug",
        action='store_true',
        help="Print debugging output.",
        required=False)
    parser.add_argument(
        '-v', '--verbose',
        dest="verbose",
        action='store_true',
        help="Print verbose output.",
        required=False)
    parser.add_argument('--version', action='version',
                        version=version.version_info.version_string())

    opts = parser.parse_args(argv[1:])

    return opts


def configure_logger(verbose=False, debug=False):
    LOG_FORMAT = '[%(asctime)s] [%(levelname)s] %(message)s'
    DATE_FORMAT = '%Y/%m/%d %I:%M:%S %p'
    log_level = logging.WARN

    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO

    logging.basicConfig(format=LOG_FORMAT, datefmt=DATE_FORMAT,
                        level=log_level)


def main(argv=sys.argv):
    opts = parse_opts(argv)
    configure_logger(opts.verbose, opts.debug)
    logger.info('Using config file at: %s' % opts.config_file)

    # Read config file containing network configs to apply
    if os.path.exists(opts.config_file):
        with open(opts.config_file) as cf:
            subnet_array = yaml.load(cf.read()).get("subnets")
            logger.debug('subnets JSON: %s' % str(iface_array))
    else:
        logger.error('No config file exists at: %s' % opts.config_file)
        return 1

    if not isinstance(subnet_array, list):
        logger.error('No subnets defined in config: %s' % opts.config_file)
        return 1

    dhcp_server = server.DhcpServer('0.0.0.0', 67, subnet, opts.verbose, opts.debug)

    return dhcp_server(listen)


    if __name__ == '__main__':
        sys.exit(main(sys.argv))