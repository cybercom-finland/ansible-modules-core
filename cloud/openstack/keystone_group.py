#!/usr/bin/python
# -*- coding: utf-8 -*-

# Based on Jimmy Tang's implementation

DOCUMENTATION = '''
---
module: keystone_group
short_description: Manage OpenStack Identity (keystone) group roles
description:
   - Manage group roles in OpenStack. Possibly will be extended to manage
     groups also.
options:
   login_user:
     description:
        - login username to authenticate to keystone
     required: false
     default: admin
   login_password:
     description:
        - Password of login user
     required: false
     default: 'yes'
   login_tenant_name:
     description:
        - The tenant login_user belongs to
     required: false
     default: None
   token:
     description:
        - The token to be uses in case the password is not specified
     required: false
     default: None
   endpoint:
     description:
        - The keystone url for authentication
     required: false
     default: 'http://127.0.0.1:35357/v3/'
   group:
     description:
        - The name of the group that has to added/removed from OpenStack
     required: false
     default: None
   tenant:
     description:
        - The tenant name on which role is assigned
     required: false
     default: None
   role:
     description:
        - The name of the role to be assigned or created
     required: false
     default: None
   state:
     description:
        - Indicate desired state of the resource
     choices: ['present', 'absent']
     default: present
requirements: [ python-keystoneclient ]
'''

EXAMPLES = '''
# Apply the admin role to the admins group in the demo tenant
- keystone_group: role=admin group=admins tenant=demo
'''

try:
    from keystoneclient.v3 import client
except ImportError:
    keystoneclient_found = False
else:
    keystoneclient_found = True


def authenticate(endpoint, token, login_user, login_password, login_tenant_name):
    """Return a keystone client object"""

    if token:
        return client.Client(endpoint=endpoint, token=token)
    else:
        return client.Client(auth_url=endpoint, username=login_user,
                             password=login_password, tenant_name=login_tenant_name)

def get_tenant(keystone, name):
    """ Retrieve a tenant by name"""
    tenants = [x for x in keystone.projects.list() if x.name == name]
    count = len(tenants)
    if count == 0:
        raise KeyError("No keystone tenants with name %s" % name)
    elif count > 1:
        raise ValueError("%d tenants with name %s" % (count, name))
    else:
        return tenants[0]

def get_group(keystone, name):
    """ Retrieve a group by name"""
    groups = [x for x in keystone.groups.list() if x.name == name]
    count = len(groups)
    if count == 0:
        raise KeyError("No keystone groups with name %s" % name)
    elif count > 1:
        raise ValueError("%d groups with name %s" % (count, name))
    else:
        return groups[0]

def get_role(keystone, name):
    """ Retrieve a role by name"""
    roles = [x for x in keystone.roles.list() if x.name == name]
    count = len(roles)
    if count == 0:
        raise KeyError("No keystone roles with name %s" % name)
    elif count > 1:
        raise ValueError("%d roles with name %s" % (count, name))
    else:
        return roles[0]

def ensure_role_exists(keystone, group_name, tenant_name, role_name,
                       check_mode):
    """ Check if role exists

        Return (True, id) if a new role was created or if the role was newly
        assigned to the group for the tenant. (False, id) if the role already
        exists and was already assigned to the group ofr the tenant.

    """
    # Check if the group has the role in the tenant
    group = get_group(keystone, group_name)
    tenant = get_tenant(keystone, tenant_name)
    roles = [x for x in keystone.roles.list(group=group, project=tenant)
                     if x.name == role_name]
    count = len(roles)

    if count == 1:
        # If the role is in there, we are done
        role = roles[0]
        return (False, role.id)
    elif count > 1:
        # Too many roles with the same name, throw an error
        raise ValueError("%d roles with name %s" % (count, role_name))

    # At this point, we know we will need to make changes
    if check_mode:
        return (True, None)

    # Get the role if it exists
    try:
        role = get_role(keystone, role_name)
    except KeyError:
        # Role doesn't exist yet
        role = keystone.roles.create(role_name)

    # Associate the role with the group in the admin
    keystone.roles.grant(group=group, role=role, project=tenant)
    return (True, role.id)


def ensure_role_absent(keystone, group_name, tenant_name, role_name,
        check_mode):
    """ Remove role from groups (can't remove role currently)

        Return True if the role was removed. False if the role
        didn't exist or wasn't already assigned to the group of the tenant.

    """
    # Check if the group has the role in the tenant
    group = get_group(keystone, group_name)
    tenant = get_tenant(keystone, tenant_name)
    roles = [x for x in keystone.roles.list(group=group, project=tenant)
                     if x.name == role_name]
    count = len(roles)

    role = None
    if count == 1:
        role = roles[0]
    elif count == 0:
        return False
    elif count > 1:
        # Too many roles with the same name, throw an error
        raise ValueError("%d roles with name %s" % (count, role_name))

    # At this point, we know we will need to make changes
    if check_mode:
        return True

    # Remove the grant
    keystone.roles.revoke(group=group, role=role, project=tenant)

    return True


def main():

    argument_spec = openstack_argument_spec()
    argument_spec.update(dict(
            group=dict(required=False),
            tenant=dict(required=False),
            role=dict(required=False),
            state=dict(default='present', choices=['present', 'absent']),
            endpoint=dict(required=False,
                          default="http://127.0.0.1:35357/v3"),
            token=dict(required=False),
            login_user=dict(required=False),
            login_password=dict(required=False),
            login_tenant_name=dict(required=False)
    ))
    # keystone operations themselves take an endpoint, not a keystone auth_url
    del(argument_spec['auth_url'])
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[['token', 'login_user'],
                            ['token', 'login_password'],
                            ['token', 'login_tenant_name']]
    )

    if not keystoneclient_found:
        module.fail_json(msg="the python-keystoneclient module is required")

    group = module.params['group']
    tenant = module.params['tenant']
    role = module.params['role']
    state = module.params['state']
    endpoint = module.params['endpoint']
    token = module.params['token']
    login_user = module.params['login_user']
    login_password = module.params['login_password']
    login_tenant_name = module.params['login_tenant_name']

    keystone = authenticate(endpoint, token, login_user, login_password, login_tenant_name)
    check_mode = module.check_mode

    try:
        d = dispatch(keystone, group, tenant, role,
                     state, endpoint, token, login_user,
                     login_password, check_mode)
    except Exception, e:
        if check_mode:
            # If we have a failure in check mode
            module.exit_json(changed=True,
                             msg="exception: %s" % e)
        else:
            module.fail_json(msg="exception: %s" % e)
    else:
        module.exit_json(**d)


def dispatch(keystone, group=None, tenant=None, role=None,
             state="present", endpoint=None, token=None, login_user=None,
             login_password=None, check_mode=False):
    """ Dispatch to the appropriate method.

        Returns a dict that will be passed to exit_json

        tenant  group role   state
        ------  ----  ----  --------
          X      X     X     present     ensure_role_exists
          X      X     X     absent      ensure_role_absent


        """
    changed = False
    id = None
    if tenant and group and role and state == "present":
        changed, id = ensure_role_exists(keystone, group, tenant, role,
                                         check_mode)
    elif tenant and group and role and state == "absent":
        changed = ensure_role_absent(keystone, group, tenant, role, check_mode)
    else:
        raise ValueError("We need tenant, role and group")

    return dict(changed=changed, id=id)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.openstack import *
if __name__ == '__main__':
    main()
