===============================
os-dhcp-server
===============================

dhcp server with relay support for use in cloud networking

An implementation of a dhcp server for use in implementing the ideas presented in
the 'TripleO Leaf and Spine (Clos) Architecture' spec @
https://etherpad.openstack.org/p/TripleO_Leaf-and-Spine_Clos_Architecture
The intention is for this code to be moved under the tripleo project in due
course.

* Free software: Apache license
# TODO (dsneddon) Create URLs for following:
* Documentation:
* Source: https://github.com/dsneddon/os-dhcp-server
* Bugs:

Features
--------

The goal of this project is to provide a utility daemon which will provide
DHCP services for use in cloud network deployments where servers are to be
deployed in multiple routed subnets with DHCP relays or proxies.

 * A listener daemon which accepts relayed DHCP requests from routers
   or other devices providing DHCP relay or proxy services. The daemon
   responds to DHCP requests with DHCP offers and PXE boot services.
   The server supports booting servers with an Ironic introspection
   image or a deployment image, depending on which phase of the deployment
   is underway.

 * A python library which provides configuration via an object model.

YAML Config Examples
--------------------
 * Configure a set of subnets and address ranges

.. code-block:: yaml

  subnet_config:
    - 
      type: ipv4_subnet
      name: provisioning-1
      use_dhcp: true
      ip_netmask: 192.168.2.0/24
      gateway: 192.168.2.254
      address_ranges:
        -
          start: 192.168.2.10
          end: 192.168.2.50

..


 * Configure an image for PXE boot

.. code-block:: yaml

  boot_config:
    - 
       type: pxe_image
       name: ironic-introspection
       url: http://192.168.0.1:8000/

..

