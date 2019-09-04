# network-automation-demos
Demonstration code for performing a specific network modification using different Network Automation techniques.

This is the companion GitHub repository for the Network Automation article I wrote at (link coming soon). The article takes a specific, simple Enterprise network task - adding a new VLAN in a distribution switch and configuring various related L2/L3 parameters related to this new VLAN - and then explains how that specific task can be automated using different automation software tools.

## Netmiko

The `netmiko/` directory contains a single Python program that uses Netmiko to apply the configuration change.

Switch credentials are stored in the `~/.netrc file`, protected with appropriate permissions. Entries look like this:

    machine 192.168.1.110 login my_login_id password l0gin_pa$$w0rd account ena6le_pa$$w0rd
    machine access_switch login my_login_id password l0gin_pa$$w0rd

Note that the `"account"` field of the `.netrc` line is repurposed for storing the privileged access password (aka enable password).

The desired settings are stored in the `DESIRED_SETTINGS` dictionary variable at the beginning of the script:

    DESIRED_SETTINGS = {'device':    '192.168.1.110',   # device to configure; must
                                                        # be specified in ~/.netrc
                        'vlan':      '520',             # the vlan to be added
                        'name':      'voip-black',      # the vlan name
                        'trunk':     'FastEthernet0/5', #
                        'ip':        '10.1.52.1/24',    # New SVI IP address
                        'ospf_rtr':  '100',             # IOS OSPF process id
                        'ospf_area': '0'}               # OSPF area

## NETCONF + YANG

The `netconf-yang/` directory contains a single Python program that uses the `ncclient` module to send NETCONF requests to apply the configuration change. The program uses Cisco YANG models for NXOS, and as such can only be used on that OS.

The desired settings are specified in the main() function:

    # The device to operate on
    device = {}
    device['host'] = '10.10.20.100'
    device['netconf_port'] = 830
    device['user'] = 'netconf-user'
    device['password'] = 'secret-netconf-password'

    # The settings to apply
    settings = {}
    settings['vlan_id'] = '162'
    settings['vlan_name'] = 'Vendor VLAN Black'
    settings['interface'] = 'Gi1/0/13'
    settings['ip_address'] = '10.3.162.1'
    settings['ip_network'] = '10.3.162.0'
    settings['ip_subnet'] = '255.255.255.0'
    settings['ip_ospf_router'] = '38'
    settings['ip_ospf_mask'] = '0.0.0.255'
    settings['ospf_area'] = '0'


The target device needs to have NETCONF enabled, and the NETCONF credentials must be in your possession.

## Chef

The `ent_dist_switch.rb` recipe under the `chef/` directory was written for a Cisco NXOS device. [This Cisco document](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/7-x/programmability/guide/b_Cisco_Nexus_9000_Series_NX-OS_Programmability_Guide_7x/b_Cisco_Nexus_9000_Series_NX-OS_Programmability_Guide_7x_chapter_01110.html) provides information on running Chef with NXOS devices.

The `ent_dist_switch.rb` recipe depends on the Chef `cisco-cookbook`, available on the Chef Supermarket. The `ent_dist_switch.rb` recipe has to be placed under the `cisco-cookbook-x.x.x/recipes/` directory. This recipe installs the VLAN and does the associated L2/L3 configuration for our example network automation scenario.

The following invocation of `knife bootstrap` command from the Chef workstation includes the `ent_dist_switch.rb` recipe in the *run-list* of our distribution switch located at management IP 10.10.20.100:

    vnetman@mint:~$ knife bootstrap 10.10.20.100 --ssh-user admin --sudo --identity-file ~/.ssh/id_rsa_admin_guestshell_chef_server --node-name dist_switch_nxos_01 --run-list 'recipe[cisco-cookbook::ent_dist_switch]'
    Node dist_switch_nxos_01 exists, overwrite it? (Y/N) Y
    Client dist_switch_nxos_01 exists, overwrite it? (Y/N) Y
    Creating new client for dist_switch_nxos_01
    Creating new node for dist_switch_nxos_01
    Connecting to 10.10.20.100
    10.10.20.100 -----> Existing Chef installation detected
    10.10.20.100 Starting the first Chef Client run...
    10.10.20.100 [2018-12-16T10:26:26+00:00] WARN: Please install an English UTF-8 locale for Chef to use, falling back to C locale and disabling UTF-8 support.
    10.10.20.100 Starting Chef Client, version 12.7.2
    10.10.20.100 resolving cookbooks for run list: ["cisco-cookbook::ent_dist_switch"]
    10.10.20.100 Synchronizing Cookbooks:
    10.10.20.100   - cisco-cookbook (1.2.4)
    10.10.20.100 Compiling Cookbooks...
    10.10.20.100 Converging 3 resources
    10.10.20.100 Recipe: cisco-cookbook::ent_dist_switch
    10.10.20.100   * cisco_vlan[220] action create
    10.10.20.100     - update vlan_name 'VLAN0220' => '3rd-floor-vendor-lab'
    10.10.20.100   * cisco_interface[ethernet1/4] action create
    10.10.20.100     - update switchport_mode access => trunk
    10.10.20.100     - update switchport_trunk_allowed_vlan '1-4094' => '218,219,220'
    10.10.20.100   * cisco_interface[vlan220] action create
    10.10.20.100     - create interface 'vlan220'
    10.10.20.100     - update description '' => 'vlan for 3rd floor vendor lab'
    10.10.20.100     - update shutdown 'true' => 'false'
    10.10.20.100     - update svi_autostate 'true' => 'false'
    10.10.20.100     - update svi_management 'false' => 'true'
    10.10.20.100     - update ipv4_address/netmask '/' => 192.168.220.1/24
    10.10.20.100 
    10.10.20.100 Running handlers:
    10.10.20.100 Running handlers complete
    10.10.20.100 Chef Client finished, 3/3 resources updated in 02 minutes 07 seconds
    vnetman@mint:~$ 

## Puppet

The `puppet/` directory contains the puppet site manifest for our distribution switch, as well as the code for the `dist_nxos::new_vlan` class that the site manifest refers to. As the name suggests, this code is intended to execute on a Cisco NXOS device. It depends upon the `ciscopuppet` module, available on Puppet Forge.

Upon installing and running the Puppet Agent on the Cisco NXOS device, the device pulls the site manifest, and then runs the `dist_nxos::new_vlan` class code, which configures the VLAN and associated L2/L3 configuration elements on the distribution switch.

## Ansible

The code in the `ansible/` directory contains an Ansible playbook that applies the configuration from our example scenario. The `ansible/` directory also contains inventory files, arranged in the directory layout that Ansible expects.

The playbook is expected to be run with extra variables provided on the command line. For our example scenario, the playbook run ouput is reproduced below. Pay attention to the fact that the interface is referred to not by its name (*Ethernet1/34*), but rather by its description (*3rd_floor_vendor*).

    vnetman@mint:~/work/ansible$ ansible-playbook playbook.yml -e 'extr_vlan_id=221 extr_vlan_descr="vlan-for-221" extr_downlink_key="3rd_floor_vendor"' 

    PLAY [distribution_switches] ***************************************************

    TASK [debug] *******************************************************************
    ok: [cisco-devnet-n9k -> localhost] => {
        "msg": "ospf_dist_router"
    }

    TASK [Ensure SVI does not already exist (delete it if it does)] ****************
    ok: [cisco-devnet-n9k]

    TASK [Ensure vlan does not already exist (delete it if it does)] ***************
    ok: [cisco-devnet-n9k]

    TASK [Ensure OSPF instance exists (create it if it doesn't)] *******************
    ok: [cisco-devnet-n9k]

    TASK [Create the vlan] *********************************************************
    changed: [cisco-devnet-n9k]

    TASK [Ensure downlink interface is an L2 trunk, and is trunking the new vlan] ***
    ok: [cisco-devnet-n9k]

    TASK [Create the SVI] **********************************************************
    changed: [cisco-devnet-n9k]

    TASK [Assign IPv4 address to the SVI] ******************************************
    changed: [cisco-devnet-n9k]

    TASK [Add the newly created network in OSPF] ***********************************
    changed: [cisco-devnet-n9k]

    PLAY RECAP *********************************************************************
    cisco-devnet-n9k           : ok=9    changed=4    unreachable=0    failed=0   

    vnetman@mint:~/work/ansible$
