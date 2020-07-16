import json, re
from cvplibrary import CVPGlobalVariables, GlobalVariableNames
from cvplibrary import RestClient
from cvplibrary import Form
import jinja2
from jinja2 import Template
from jinja2 import Environment, PackageLoader
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
if add_acl_statements is not None:
  acl_statements = add_acl_statements
elif remove_acl_statements is not None:
  acl_statements = remove_acl_statements
else:
  acl_statements = None

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
device_ips = [ip.strip() for ip in Form.getFieldById('ip_addresses').value().split("\n") ] if Form.getFieldById('ip_addresses').value() is not None else None




if acl_option == "Show ACL Names":
    showAclNames()
elif acl_option == "Show ACL Details":
    showAclDetails()
else:
    modifyACL(acl_name, modify_action, acl_statements, acl_interface_application, acl_interface, acl_direction, devices)

