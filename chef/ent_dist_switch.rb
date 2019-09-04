Chef::Log.info('adding vlan 220 on distribution switch')

cisco_vlan '220' do
  action    :create
  vlan_name '3rd-floor-vendor-lab'
  shutdown  false
  state     'active'
end

cisco_interface 'Ethernet1/4' do
  description 'Downlink to 3rd floor'
  switchport_mode 'trunk'
  switchport_trunk_allowed_vlan '218, 219, 220'
end

cisco_interface 'Vlan220' do
  description         'vlan for 3rd floor vendor lab'
  shutdown            false
  ipv4_address        '192.168.220.1'
  ipv4_netmask_length 24
  svi_autostate       false
  svi_management      true
end

cisco_ospf 'main' do
  action :create
end

cisco_interface_ospf 'Vlan220' do
  action                         :create
  ospf                           'main'
  area                           1
  passive_interface              true
end
