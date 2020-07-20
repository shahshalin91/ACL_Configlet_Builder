import requests, json, re
from collections import OrderedDict
import ssl
from pprint import pprint as pp
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context


acl_configlet_content='''
ip access-list BlueBypassHosts
   10 permit ip host 192.168.1.10 any
!
ip access-list EncapBlueFirewallHosts
   10 permit vxlan host 192.168.1.10 any
!
ip access-list BluePrefix
   10 permit ip any 192.168.1.0/24
   20 permit ip any 192.168.2.0/24
!
ip access-list BlueFirewallHostsIn
   10 permit ip host 192.168.1.10 any
!
interface Ethernet52/1
   ip access-group BlueFirewallHostsIn out
!
interface Ethernet1
   ip access-group BluePrefix in
!
interface vlan29
   ip access-group EncapBlueFirewallHosts  out
!
'''

configlet_details = {"ACL Definitions": None, "Interface Details": None}

config_sections = [section.strip() for section in acl_configlet_content.split("!") ]
acls = OrderedDict()
interface_details = OrderedDict()

for config_section in config_sections:
    # print config_section
    acl_match = re.match(r'ip\s+access-list\s+(\S+)', config_section.split("\n")[0])
    if acl_match:
        acl_content = OrderedDict()
        for statement in config_section.split("\n")[1:]:
            acl_content[int(statement.lstrip().split(" ")[0])] = " ".join(statement.lstrip().split(" ")[1:])
        # print acl_match.group(1)
        acls[acl_match.group(1)] = acl_content
    # print acl_content
    # print acls
    break

#vlan, vlan_desc,vlan, vni,vrf_name,vrf_vni,asn,vlan,loopback0,vni,vni,vni
# user defined : vlan, vlan_desc, vrf_name
# query the switch: loopback0, asn
# calculated: vni

vlan_vrf_configlet_content = '''
!
vlan 400
   name Test
!
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789
   vxlan vlan 400 vni 4000
   vxlan vrf BLAN-2 vni 4002
!   
router bgp 64829
   vlan 400
      rd 10.230.128.18:4000
      route-target both 4000:4000
      redistribute learned
!
exit
exit
!
  
!
vlan 37
   name MCDC-Videoframe_A
!
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789
   vxlan vlan 37 vni 370
   vxlan vrf BLAN-2 vni 4002
!   
router bgp 64829
   vlan 37
      rd 10.230.128.18:370
      route-target both 370:370
      redistribute learned
!
exit
exit
!
'''

config_sections = [section.strip() for section in vlan_vrf_configlet_content.split("\nexit\nexit\n!")]

vlan_data = OrderedDict()

for config_section in config_sections:
	#print config_section
	#print config_section.lstrip("!\n")
	#check = re.match(r"vlan\s+(\S+)",config_section.lstrip("!\n"))
	#print vlan_num
	vlan_values= OrderedDict()
	check = re.match(r"!\s+vlan\s+(\d+)\s+name\s+(\S+)\s+!\s+interface Vxlan1\s+vxlan\s+source-interface\s+\S+\s+vxlan\s+udp-port\s+4789\s+vxlan\s+vlan\s+\d+\s+vni\s+(\d+)\s+vxlan\s+vrf\s+(\S+)\s+vni\s+(\d+)\s!\s+router\s+bgp\s+(\d+)\s+vlan\s+\d+\s+rd\s+(\S+):\d+\s+route-target\s+both\s+\S+\s+redistribute\s+learned\s+!",config_section)
	if check:
		vlan_values["vlan_name"] = check.group(2)
		vlan_values["vni"] = check.group(3)
		vlan_values["vrf"] = check.group(4)
		vlan_values["vrf_vlan"] = check.group(5)
		vlan_values["asn"] = check.group(6)
		vlan_values["loopback1"] = check.group(7)
		vlan_data[check.group(1)] = vlan_values
#print vlan_data
print(json.dumps(vlan_data, indent=4))


		



'''
!\s+vlan\s+(\d+)\s+name\s+(\S+)\s+!\s+interface Vxlan1\s+vxlan\s+source-interface\s+\S+\s+vxlan\s+udp-port\s+4789\s+vxlan\s+vlan\s+(\d+)\s+vni\s+(\d+)\s+vxlan\s+vrf\s+(\S+)\s+vni\s+(\d+)\s!\s+router\s+bgp\s+(\d+)\s+vlan\s+\d+\s+rd\s+(\S+):\d+\s+route-target\s+both\s+\S+\s+redistribute\s+learned\s+!
'''