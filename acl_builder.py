import json, re
from collections import OrderedDict
from cvplibrary import CVPGlobalVariables, GlobalVariableNames, SSHClient
from cvplibrary import RestClient
from cvplibrary import Form
from cvplibrary import Device
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

def getConfiglet(configlet):
  # setup request to get device list configlet
  url='https://localhost/cvpservice/configlet/getConfigletByName.do?queryparam=&name=%s' % configlet;
  method= 'GET';
  client= RestClient(url,method);
  if client.connect():
    # extract the config from configlet and convert to json data (dict)
    response = json.loads(client.getResponse())
    if "errorCode" in response:
      print "! Problem Loading:%s - %s" %(configlet, response['errorMessage'])
      return False
    else:
      return response

def modifyACL(acl_name, modify_action, acl_statements, acl_interface_application, acl_interface, acl_direction, device_ips):
    if modify_action == "Create/Update":
        CreateOrUpdateACL(acl_name, acl_statements, acl_interface_application, acl_interface, acl_direction, device_ips)
    elif modify_action == "Delete":
        DeleteACL(acl_name, device_ips)

def CreateOrUpdateACL(acl_name, acl_statements, acl_interface_application, acl_interface, acl_direction, device_ips):
    '''
    When creating ACL configlet, write ACL definition and ACL detail configuration first then write application of ACL to interface configuration second
    '''
    
    #for each device 
    #Get device object via CVP API call


    #Check for existing acl configlet for that device - <hostname>-ACLs
    if existing_acl_configlet:
        #Parse configlet for acl_name
        if acl_name_exists:
            #Parse and update acl_name

        else:
            #Create acl in configlet with acl_name, acl_statements, acl_interface, and acl_direction

    else:
        #Create configlet with acl_name, acl_statements, acl_interface, and acl_direction

def DeleteACL(acl_name, device_ips):
    #for each device 
    #Get device object via CVP API call

    #Check for existing acl configlet for that device - <hostname>-ACLs
    if existing_acl_configlet:
        #Parse configlet for acl_name
        if acl_name_exists:
            #Parse and delete acl_name

        else:
            #Nothing to do config wise. Just throw message

    else:
        #Nothing to do config wise. Just throw message


acl_option = Form.getFieldById('acl_option').value

show_details_acl_name = Form.getFieldById('show_details_acl_name').value

modify_acl_name = Form.getFieldById('modify_acl_name').value

#acl_name will be name of acl we are working with
if show_details_acl_name is not None:
  acl_name = show_details_acl_name
elif modify_acl_name is not None:
  acl_name = modify_acl_name
else:
  acl_name = None

modify_action = Form.getFieldById('modify_action').value

add_acl_statements = [statement.strip() for statement in Form.getFieldById('add_acl_statements').value.split("\n") ] if Form.getFieldById('add_acl_statements').value is not None else None

remove_acl_statements = [statement.strip() for statement in Form.getFieldById('remove_acl_statements').value.split("\n") ] if Form.getFieldById('remove_acl_statements').value is not None else None

#'acl_statements' will be name of the statements we are either removing or adding
acl_statements = {"Add": None, "Delete": None}
if add_acl_statements is not None:
  acl_statements["Add"] = add_acl_statements
if remove_acl_statements is not None:
    acl_statements["Delete"] = remove_acl_statements

#'acl_interface_application' will be either 'Apply' or 'Remove'
acl_interface_application = Form.getFieldById('acl_interface_application').value


apply_interface = Form.getFieldById('apply_interface').value()
#List containing 'In' and/or 'Out' 
apply_direction = Form.getFieldById('apply_direction').value()

remove_interface = Form.getFieldById('remove_interface').value()
#List containing 'In' and/or 'Out' 
remove_direction = Form.getFieldById('remove_direction').value()

if apply_interface is not None:
  acl_interface = apply_interface
elif remove_interface is not None:
  acl_interface = remove_interface
else:
  acl_interface = None
  
if apply_direction is not None:
  acl_direction = apply_direction
elif remove_direction is not None:
  acl_direction = remove_direction
else:
  acl_direction = None
  

multiple_devices_flag = Form.getFieldById('multiple_devices_flag').value()
if multiple_devices_flag is None or multiple_devices_flag == "No":
    device_ips = [ CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP) ]
else:
    device_ips = [ip.strip() for ip in Form.getFieldById('ip_addresses').value().split("\n") ] if Form.getFieldById('ip_addresses').value() is not None else None




if acl_option == "Show ACL Names":
    showAclNames(device_ips)
elif acl_option == "Show ACL Details":
    showAclDetails(device_ips, acl_name)
else:
    modifyACL(acl_name, modify_action, acl_statements, acl_interface_application, acl_interface, acl_direction, device_ips)

