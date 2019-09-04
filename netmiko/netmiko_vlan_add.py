#!/usr/bin/env python3

'''Netmiko script to configure a trunk interface on a Cisco IOS switch
with a new VLAN. The VLAN is first created if necessary, and an SVI is
also created and assigned an IPv4 address. Finally, the newly added IPv4
subnet is included in an OSPF router instance.
'''

import sys
import re
import logging
import ipaddress
import netrc
from netmiko import Netmiko

# Login credentials are stored in ~/.netrc
#
# .netrc entries look like this:
#
# machine 192.168.1.110 login my_login_id password l0gin_pa$$w0rd account ena6le_pa$$w0rd
# machine access_switch login my_login_id password l0gin_pa$$w0rd
#
# In the first example above, the machine is specified by its IP address.
# The enable password is given against the 'account' field (which is really a
# hack).
# In the second example above, the machine is specified by its name, and it
# has no enable password (hence the absence of the 'account' field).
#
# Ensure .netrc is protected by appropriate r/w permissions

DESIRED_SETTINGS = {'device':    '192.168.1.110',   # device to configure; must
                                                    # be specified in ~/.netrc
                    'vlan':      '520',             # the vlan to be added
                    'name':      'voip-black',      # the vlan name
                    'trunk':     'FastEthernet0/5', #
                    'ip':        '10.1.52.1/24',    # New SVI IP address
                    'ospf_rtr':  '100',             # IOS OSPF process id
                    'ospf_area': '0'}               # OSPF area to

def main():
    '''Main program logic
    '''

    logging.basicConfig(level=logging.WARNING,
                        format='%(asctime)s %(levelname)s: %(message)s',
                        stream=sys.stdout)

    device = make_connection_to_device()

    # Get the list of currently configured VLANs
    current_vlan_list = get_vlan_list(device)
    if not current_vlan_list:
        print('Failed to read current vlan list, aborting', file=sys.stderr)
        device.disconnect()
        sys.exit(-1)

    # Complain and exit if the VLAN already exists
    new_vlan = DESIRED_SETTINGS['vlan']
    if new_vlan in current_vlan_list:
        print('Unexpected state: VLAN {} already exists'.format(new_vlan),
              file=sys.stderr)
        device.disconnect()
        sys.exit(-1)

    # Get the list of interfaces currently configured
    current_interface_list = get_interface_list(device)
    if not current_interface_list:
        print('Failed to read current interface list, aborting',
              file=sys.stderr)
        device.disconnect()
        sys.exit(-1)

    # Complain and exit if the SVI already exists
    svi_name = 'Vlan{}'.format(new_vlan)
    if svi_name in current_interface_list:
        print('Unexpected state: interface {} already exists'.format(svi_name),
              file=sys.stderr)
        device.disconnect()
        sys.exit(-1)

    # The list of commands to be pushed
    config_commands = []
    config_commands.append('vlan {}'.format(new_vlan))
    config_commands.append(' name {}'.format(DESIRED_SETTINGS['name']))
    config_commands.append(' exit')

    config_commands.append('interface {}'.format(DESIRED_SETTINGS['trunk']))
    config_commands.append(' switchport mode trunk')

    # Get the current configuration of the desired trunk interface
    current_trunk_cfg = get_current_interface_running_config(
        device, DESIRED_SETTINGS['trunk'])

    # See if it already has an "allowed vlans" config
    vlans_existing = False
    for line in current_trunk_cfg:
        if line.strip().startswith('switchport trunk allow'):
            vlans_existing = True

    if vlans_existing:
        config_commands.append(
            ' switchport trunk allowed vlan add {}'.format(new_vlan))
    else:
        config_commands.append(
            ' switchport trunk allowed vlan {}'.format(new_vlan))

    config_commands.append(' exit')

    config_commands.append('interface {}'.format(svi_name))
    config_commands.append(' description IPv4 gateway '
                           'for {} vlan'.format(DESIRED_SETTINGS['name']))
    config_commands.append(' no shutdown')

    ipn = ipaddress.ip_network(DESIRED_SETTINGS['ip'], strict=False)
    ipa = DESIRED_SETTINGS['ip'].split('/')[0]
    config_commands.append(' ip address {} {}'.format(ipa, ipn.netmask))
    config_commands.append(' exit')

    config_commands.append(
        'router ospf {}'.format(DESIRED_SETTINGS['ospf_rtr']))
    config_commands.append(' network {} {} area {}'.format(
        ipn.network_address, ipn.hostmask, DESIRED_SETTINGS['ospf_area']))
    config_commands.append(' passive-interface default')
    config_commands.append(' no passive-interface {}'.format(svi_name))
    config_commands.append(' exit')

    print('The following configuration will be applied:')
    print('------------------------------')
    for _ in config_commands:
        print(_)
    print('------------------------------')

    config_result = device.send_config_set(config_commands)
    print('Configuration result:')
    print('------------------------------')
    print(config_result)
    print('------------------------------')

    print('Done, disconnecting from device.')

    device.disconnect()
    sys.exit(0)
#---

def get_vlan_list(device):
    '''Return a list of currently configured VLANs on the switch
    '''

    # Lines in the 'show vlan brief' output look like this:
    #
    # "VLAN Name                             Status    Ports"
    # "---- -------------------------------- --------- -------------------------------"
    # "1    default                          active    Fa0/1, Fa0/2, Fa0/3, Fa0/4, Fa0/5, Fa0/6, Fa0/7, Fa0/8, Gi0/1"
    # "17   VLAN0017                         active    "
    # "517  VLAN0517                         active    "
    # "519  VLAN0519                         active    "
    # "1002 fddi-default                     act/unsup "
    # "1003 token-ring-default               act/unsup "
    #
    # The following regular expression extracts the integer at the beginning
    # of the line

    re_vlan_id = re.compile(r'^(\d+) .+$')

    # Gather the output of 'show vlan brief' and pass each line through the
    # regular expression. Ignore non-matching lines. For matching lines,
    # store the extracted vlan_id into the list that we will eventually return.

    vlan_list = []
    sh_op = device.send_command('show vlan brief')
    for line in sh_op.split('\n'):
        match_obj = re_vlan_id.search(line)
        if match_obj:
            vlan_list.append(match_obj.group(1))

    return vlan_list
#---

def get_interface_list(device):
    '''Return a list of currently configured interfaces on the device
    '''

    # Lines in the 'show interface summary' look like this:
    #
    # *: interface is up
    # IHQ: pkts in input hold queue     IQD: pkts dropped from input queue
    # OHQ: pkts in output hold queue    OQD: pkts dropped from output queue
    # RXBS: rx rate (bits/sec)          RXPS: rx rate (pkts/sec)
    # TXBS: tx rate (bits/sec)          TXPS: tx rate (pkts/sec)
    # TRTL: throttle count
    #
    #  Interface               IHQ   IQD  OHQ   OQD  RXBS RXPS  TXBS TXPS TRTL
    #-------------------------------------------------------------------------
    #* Vlan1                    0     0    0     0     0    0     0    0    0
    #* FastEthernet0/1          0     0    0     0     0    0     0    0    0
    #  FastEthernet0/2          0     0    0     0     0    0     0    0    0

    # regex to match the header separator
    re_header_separator = re.compile(r'^-{50}.*$') # At least 50 '-' characters

    # regex to extract the interface name
    re_intf_line = re.compile(r'''^          # start of line
                                  \*?        # there may be a '*' char
                                  \s+        # one or more spaces
                                  ([^\s]+)\s # All nonspace chars until a space
                                  .*$''',    # Ignore the rest of the line
                              re.VERBOSE)

    # beginning of the string
    # there may be a single '*'
    # one or more spaces
    # grab everything that's not a space, followed by a space
    # don't care about anything after that
    # till the end of the string

    interface_list = []
    header_finished = False

    sh_op = device.send_command('show interface summary')
    for line in sh_op.split('\n'):
        # Ignore all lines until we see the '------' header separator
        if not header_finished:
            match_obj = re_header_separator.search(line)
            if match_obj:
                header_finished = True
            continue

        match_obj = re_intf_line.search(line)
        if match_obj:
            interface_list.append(match_obj.group(1))

    return interface_list
#---

def get_current_interface_running_config(device, interface):
    '''Return a list of lines containing the given interface's running
    configuration'''

    interface_config = []
    sh_cmd_op = device.send_command('show run interface {}'.format(interface))
    for line in sh_cmd_op.split('\n'):
        # Ignore uninteresting lines
        if not line:
            continue
        if line == 'Building configuration...':
            continue
        if line == '!':
            continue
        if line == 'end':
            break
        interface_config.append(line)

    return interface_config
#---

def make_connection_to_device():
    '''Helper invoked from main() to set up a netmiko connection to the
    device, and put it into enable mode'''

    # access the netrc to read the credentials
    try:
        rc = netrc.netrc()
    except FileNotFoundError as e:
        print('(Failed to access netrc file for gathering ',
              'login credentials: {})'.format(str(e)), file=sys.stderr)
        sys.exit(-1)

    netmiko_device_info = {}
    netmiko_device_info['host'] = DESIRED_SETTINGS['device']
    netmiko_device_info['device_type'] = 'cisco_ios'

    try:
        host = netmiko_device_info['host']
        (login, enable_password, password) = rc.authenticators(host)
    except TypeError:
        print('No entry in netrc file for device "{}", and no default '
              'either.'.format(netmiko_device_info['host']), file=sys.stderr)
        sys.exit(-1)

    # Fill in the user name / password / enable password device_info
    # attributes from the info we read from .netrc
    netmiko_device_info['username'] = login
    netmiko_device_info['password'] = password
    if enable_password:
        netmiko_device_info['secret'] = enable_password

    print('Connecting to device_info "{}"...'.format(
        netmiko_device_info['host']), end='', flush=True)

    device = Netmiko(**netmiko_device_info)
    print('connected.')

    print('Entering enable mode...', end='', flush=True)
    device.enable()
    print('done.')

    prompt = device.find_prompt()
    print('Prompt is "{}"'.format(prompt))

    return device

if __name__ == '__main__':
    main()
