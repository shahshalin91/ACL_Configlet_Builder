from collections import OrderedDict

def buildACLConfiglet(acl_configlet_details):
    acl_configlet_content = ""
    for acl, statement_dict in acl_configlet_details["ACL Definitions"].items():
        acl_configlet_content += "ip access-list {}\n".format(acl)
        for sequence_number, statement in statement_dict.items():
            acl_configlet_content += "   {} {}\n".format(sequence_number, statement)
        acl_configlet_content += "!\n"
    for interface, interface_statements in acl_configlet_details["Interface Details"].items():
        acl_configlet_content += "interface {}\n".format(interface)
        for statement in interface_statements:
            acl_configlet_content += "   {}\n".format(statement)
        acl_configlet_content += "!\n"
    return acl_configlet_content


def DeleteACL(acl_name, acl_configlet_details):

    for key in acl_configlet_details["ACL Definitions"].keys():
        if acl_name == key:
            del acl_configlet_details["ACL Definitions"][key]
    for key,values in acl_configlet_details["Interface Details"].items():
        for value in values:
            if acl_name in value:
                del acl_configlet_details["Interface Details"][key]
                break
    return acl_configlet_details



acl_configlet_details = {
  "ACL Definitions": {
    "BlueBypassHosts": {
      "10": "permit ip host 192.168.1.10 any"
    }, 
    "BlueFirewallHosts": {
      "10": "permit ip any host 192.168.1.10"
    }, 
    "BlueFirewallHostsIn": {
      "10": "permit ip host 192.168.1.10 any"
    }, 
    "BluePrefix": {
      "10": "permit ip any 192.168.1.0/24", 
      "20": "permit ip any 192.168.2.0/24"
    }, 
    "EncapBlueFirewallHosts": {
      "10": "permit vxlan host 192.168.1.10 any"
    }, 
    "citi": {
      "10": "permit ip host 1.0.0.1 any"
    }
  }, 
  "Interface Details": {
    "Ethernet1": [
      "ip access-group BluePrefix in"
    ], 
    "Ethernet52/1": [
      "ip access-group BlueFirewallHostsIn out"
    ], 
    "Vlan15": [
      "ip access-group citi out", 
      "ip access-group citi in"
    ]
  }
}


#print buildACLConfiglet(acl_configlet_details)
#deleted_acl_configlet = DeleteACL("BluePrefix",acl_configlet_details)
#print buildACLConfiglet(deleted_acl_configlet)