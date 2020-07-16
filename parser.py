import re
from collections import OrderedDict

import json

def acl_configlet_parser(acl_configlet_content):
    configlet_details = {"ACL Definitions": None, "Interface Details": None}
    config_sections = [section.strip() for section in acl_configlet_content.split("!") ]
    acls = OrderedDict()
    interface_details = OrderedDict()
    for config_section in config_sections:
        acl_match = re.match(r'ip\s+access-list\s+(\S+)', config_section.split("\n")[0])
        if acl_match:
            acl_content = OrderedDict()
            for statement in config_section.split("\n")[1:]:
                acl_content[statement.lstrip().split(" ")[0]] = " ".join(statement.lstrip().split(" ")[1:])
            acls[acl_match.group(1)] = acl_content

        interface_match = re.match(r'interface\s+(.+)', config_section.split("\n")[0])
        if interface_match:
            interface_acl_statements = []
            for statement in config_section.split("\n")[1:]:
                acl_interface_application_match = re.match(r'ip\s+access-group\s+(\S+)\s+(in|out)', statement.strip())
                if acl_interface_application_match:
                    interface_acl_statements.append(statement.strip())
            
            interface_details[interface_match.group(1)] = interface_acl_statements


    configlet_details["ACL Definitions"] = acls
    configlet_details["Interface Details"] = interface_details

    return configlet_details


if __name__ == "__main__":
    acl_configlet_content = '''ip access-list BlueBypassHosts
   10 permit ip host 192.168.1.10 any
!
ip access-list BlueFirewallHosts
   10 permit ip any host 192.168.1.10
!
ip access-list BlueFirewallHostsIn
   10 permit ip host 192.168.1.10 any
!
ip access-list BluePrefix
   10 permit ip any 192.168.1.0/24
   20 permit ip any 192.168.2.0/24
!
ip access-list EncapBlueFirewallHosts
   10 permit vxlan host 192.168.1.10 any
!
ip access-list citi
   10 permit ip host 1.0.0.1 any
!
interface Ethernet1
   ip access-group BluePrefix in
!
interface Ethernet52/1
   ip access-group BlueFirewallHostsIn out
!
interface Vlan15
   ip access-group citi out
   ip access-group citi in
!
   '''
    acl_configlet_parser(acl_configlet_content)