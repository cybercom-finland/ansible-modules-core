#!/usr/bin/python
#coding: utf-8 -*-

# (c) 2014, Toni Ylenius <toni.ylenius@cybercom.com>
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

try:
    try:
        from neutronclient.neutron import client
    except ImportError:
        from quantumclient.quantum import client
    from keystoneclient.v2_0 import client as ksclient
except ImportError:
    print("failed=True msg='quantumclient (or neutronclient) and keystoneclient are required'")

DOCUMENTATION = '''
---
module: quantum_port
short_description: Add/remove port from a network
description:
   - Add/remove port from a network
options:
   login_username:
     description:
        - login username to authenticate to keystone
     required: true
     default: admin
   login_password:
     description:
        - Password of login user
     required: true
     default: True
   login_tenant_name:
     description:
        - The tenant name of the login user
     required: true
     default: True
   auth_url:
     description:
        - The keystone URL for authentication
     required: false
     default: 'http://127.0.0.1:35357/v2.0/'
   region_name:
     description:
        - Name of the region
     required: false
     default: None
   state:
     description:
        - Indicate desired state of the resource
     choices: ['present', 'absent']
     default: present
   name:
     description:
        - Name of the port
     required: false
     default: None
   fixed_ips:
     description:
        - The fixed ips dictionary that defines subnet and/or ip_address for the port
     required: false
     default: None
   tenant_name:
     description:
        - The name of the tenant for whom the port should be created
     required: false
     default: None
   network_name:
     description:
        - Name of the network to which the port should be attached
     required: false
     default: None
requirements: ["quantumclient", "neutronclient", "keystoneclient"]
'''

EXAMPLES = '''
- quantum_port:
       state: present
       login_username: admin
       login_password: admin
       login_tenant_name: admin
       tenant_name: tenant1
       network_name: network1
       name: testport

# You can also define the IP address
- quantum_port:
       state: present
       login_username: admin
       login_password: admin
       login_tenant_name: admin
       name: testport
       tenant_name: tenant1
       network_name: network1
       fixed_ips:
         - ip_address: 192.168.0.2
'''

_os_keystone   = None
_os_tenant_id  = None
_os_network_id = None

def _get_ksclient(module, kwargs):
    global _os_keystone
    try:
        kclient = ksclient.Client(username=kwargs.get('login_username'),
                                 password=kwargs.get('login_password'),
                                 tenant_name=kwargs.get('login_tenant_name'),
                                 auth_url=kwargs.get('auth_url'))
    except Exception, e:
        module.fail_json(msg = "Error authenticating to the keystone: %s" %e.message)
    _os_keystone = kclient
    return kclient


def _get_endpoint(module, ksclient):
    try:
        endpoint = ksclient.service_catalog.url_for(service_type='network', endpoint_type='publicURL')
    except Exception, e:
        module.fail_json(msg = "Error getting network endpoint: %s" % e.message)
    return endpoint

def _get_neutron_client(module, kwargs):
    _ksclient = _get_ksclient(module, kwargs)
    token     = _ksclient.auth_token
    endpoint  = _get_endpoint(module, _ksclient)
    kwargs = {
            'token':        token,
            'endpoint_url': endpoint
    }
    try:
        neutron = client.Client('2.0', **kwargs)
    except Exception, e:
        module.fail_json(msg = " Error in connecting to neutron: %s" % e.message)
    return neutron

def _set_tenant_id(module):
    global _os_tenant_id
    if not module.params['tenant_name']:
        tenant_name = module.params['login_tenant_name']
    else:
        tenant_name = module.params['tenant_name']

    for tenant in _os_keystone.tenants.list():
        if tenant.name == tenant_name:
            _os_tenant_id = tenant.id
            break
    if not _os_tenant_id:
            module.fail_json(msg = "The tenant id cannot be found, please check the parameters")

def _set_network_id(neutron, module):
    global _os_network_id
    _os_network_id = _get_net_id(neutron, module)
    if not _os_network_id:
        module.fail_json(msg = "The network id of network not found, please check the parameters")

def _get_net_id(neutron, module):
    kwargs = {
        'tenant_id': _os_tenant_id,
        'name': module.params['network_name'],
    }
    try:
        networks = neutron.list_networks(**kwargs)
    except Exception, e:
        module.fail_json(msg="Error in listing neutron networks: %s" % e.message)
    if not networks['networks']:
            return None
    return networks['networks'][0]['id']

def _format_fixed_ips(fixed_ips_input):
    if fixed_ips_input is None:
        return None
    fixed_ips = []
    if not isinstance(fixed_ips_input, (list, tuple)):
        fixed_ips_input = [fixed_ips_input] 
    for item in fixed_ips_input:
        for key, value in item.iteritems():
            fixed_ips.append("%s=%s" % (key, value))
    return fixed_ips

def _get_port_id(neutron, module):
    kwargs = {
        'tenant_id': _os_tenant_id,
        'fixed_ips': _format_fixed_ips(module.params.get('fixed_ips')),
        'name': module.params.get('name'),
    }
    for key in kwargs.keys():
        if kwargs[key] is None:
            kwargs.pop(key)

    try:
        ports = neutron.list_ports(**kwargs)
    except Exception, e:
        module.fail_json(msg="Error in listing neutron ports: %s" % e.message)
    if not ports['ports']:
            return None
    return ports['ports'][0]['id']


def _ensure_port(module, neutron):
    old_port_id = _get_port_id(neutron, module)
    if old_port_id:
        return False, old_port_id

    if module.check_mode:
        return True, None

    port = {
            'name':            module.params.get('name'),
            'tenant_id':       _os_tenant_id,
            'fixed_ips':       module.params.get('fixed_ips'),
            'network_id':      _os_network_id,
    }
    for key in port.keys():
        if port[key] is None:
            port.pop(key)

    try:
        new_port = neutron.create_port(dict(port=port))
    except Exception, e:
        module.fail_json(msg = "Failure in creating port: %s" % e.message)

    return True, new_port['port']['id']


def _delete_port(module, neutron):
    old_port_id = _get_port_id(neutron, module)
    if not old_port_id:
        return False

    if module.check_mode:
        return True

    try:
        neutron.delete_port(old_port_id)
    except Exception, e:
        module.fail_json( msg = "Error in deleting port: %s" % e.message)

    return True


def main():

    argument_spec = openstack_argument_spec()
    argument_spec.update(dict(
            name                    = dict(required=False),
            network_name            = dict(required=True),
            fixed_ips               = dict(required=False),
            tenant_name             = dict(default=None),
            state                   = dict(default='present', choices=['absent', 'present']),
        ))
    module = AnsibleModule(argument_spec=argument_spec,
            supports_check_mode=True)

    neutron = _get_neutron_client(module, module.params)
    neutron.format = 'json'
    _set_tenant_id(module)
    _set_network_id(neutron, module)

    if not module.params['name'] and not module.params['fixed_ips']:
        module.fail_json(msg = "Provide name and/or fixed_ips.")

    if module.params['state'] == 'present':
        changed, port_id = _ensure_port(module, neutron)
        module.exit_json(changed = changed, id = port_id)
    else:
        changed = _delete_port(module, neutron)
        module.exit_json(changed = changed, id = None)

# this is magic, see lib/ansible/module.params['common.py
from ansible.module_utils.basic import *
from ansible.module_utils.openstack import *
main()

