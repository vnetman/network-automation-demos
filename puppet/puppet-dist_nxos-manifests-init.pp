class dist_nxos::new_vlan (
  $vlan_id,
  $vlan_name,
  $downlink,
) {
  require ciscopuppet::install

  cisco_vlan { $vlan_id :
    ensure    => present,
    vlan_name => $vlan_name,
    state     => 'active',
    shutdown  => false,
  }

  $svi_name = "Vlan${vlan_id}"
  $ipv4_address = "192.168.${vlan_id}.1"
  
  cisco_interface { $svi_name :
    ensure              => present,
    interface           => $svi_name,
    shutdown            => false,
    description         => "SVI for $vlan_name",
    mtu                 => 9216,
    ipv4_forwarding     => false,
    ipv4_address        => $ipv4_address,
    ipv4_netmask_length => 24,
    svi_autostate       => false,
  }

  cisco_interface { $downlink :
    ensure                        => present,
    shutdown                      => false,
    switchport_mode               => 'trunk',
    switchport_trunk_allowed_vlan => $vlan_id,
  }

  $ospf_name = "dist_vlans"
  $ospf_name_vrf = "${ospf_name}_default"

  cisco_ospf { "$ospf_name_vrf" :
    ensure => present,
  }

  $ospf_interface_name = "${svi_name} ${ospf_name}"
  cisco_interface_ospf { $ospf_interface_name :
    ensure => present,
    area   => 200,
  }
}
