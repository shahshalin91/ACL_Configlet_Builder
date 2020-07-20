import requests, json, re
from collections import OrderedDict
import cvp
<<<<<<< HEAD
from cvplibrary import CVPGlobalVariables, GlobalVariableNames, SSHClient, SSHClientUser
=======
from cvplibrary import CVPGlobalVariables, GlobalVariableNames,  SSHClient, SSHClientUser
>>>>>>> MasterCB/master
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

class CVP():
    """
    Class to act as a CVP object.  Leverages REST API to execute CVP functions. 
    """
    def __init__(self, ip_address, username, password):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.cvp_sesh = None

    def login(self):
        """
        Returns a cvp session
        """
        payload = json.dumps({"userID": self.username, "password": self.password})
        self.cvp_sesh = requests.Session()
        self.cvp_sesh.post("https://{}/cvpservice/login/authenticate.do".format(self.ip_address), data=payload, verify=False)
        return self.cvp_sesh

    def logout(self):
        """
        Logs out fof a cvp session
        """
        self.cvp_sesh.post("https://{}/cvpservice/login/logout.do".format(self.ip_address), verify=False)
        return self.cvp_sesh

    def getInventory(self, provisioned=False):
        """
        Returns the inventory

            provisioned ( bool ): Flag that will signal whether to retrieve the entire inventory or just provisioned devices

        """
        if provisioned == True:
            provisioned = "true"
        else:
            provisioned = "false"
        response = self.cvp_sesh.get("https://{}/cvpservice/inventory/devices?provisioned={}".format(self.ip_address, provisioned), verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            print("Error retrieving inventory.")
            print(response.text)
            return None

    def addConfiglet(self, configlet_name, config):
        data = {"config": config, "name": configlet_name}
        self.cvp_sesh.post("https://{}/cvpservice/configlet/addConfiglet.do".format(self.ip_address), verify=False, data=json.dumps(data))

    def updateConfiglet(self, configlet_key, configlet_name, config):
        data = {"config": config, "name": configlet_name, "key": configlet_key, "waitForTaskIds":False, "reconciled":False}
        self.cvp_sesh.post("https://{}/cvpservice/configlet/updateConfiglet.do".format(self.ip_address), verify=False, data=json.dumps(data))

    def getConfiglet(self, configlet_name):
        response = self.cvp_sesh.get("https://{}/cvpservice/configlet/getConfigletByName.do?name={}".format(self.ip_address, configlet_name), verify=False)
        if response.status_code == 200:
            if 'errorCode' in response.text:
                return None
            return response.json()
        else:
            print("Error retrieving configlet.")
            print(response.text)
            return None

    def getConfigletsAppliedToDevice(self, device_id):
        response = self.cvp_sesh.get("https://{}/cvpservice/provisioning/getConfigletsByNetElementId.do?netElementId={}&startIndex=0&endIndex=0".format(self.ip_address, device_id), verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            print("Error retrieving configlets for {}.".format(device_id))
            print(response.text)
            return None
    
    def applyConfiglets(self, dev, new_configlets, create_task=True):
        # Get all the configlets assigned to the device.
        configlets = self.getConfigletsAppliedToDevice(dev['systemMacAddress'])["configletList"]

        # Get a list of the names and keys of the configlets
        cnames = []
        ckeys = []
        for configlet in configlets:
            cnames.append(configlet['name'])
            ckeys.append(configlet['key'])

        # Add the new configlets to the end of the arrays
        for entry in new_configlets:
            cnames.append(entry['name'])
            ckeys.append(entry['key'])

        info = '%s: Configlet Assign: to Device %s' % ('Created by ACL Configlet Builder', dev['fqdn'])
        info_preview = '<b>Configlet Assign:</b> to Device' + dev['fqdn']
        data = {'data': [{'info': info,
                          'infoPreview': info_preview,
                          'note': '',
                          'action': 'associate',
                          'nodeType': 'configlet',
                          'nodeId': '',
                          'configletList': ckeys,
                          'configletNamesList': cnames,
                          'ignoreConfigletNamesList': [],
                          'ignoreConfigletList': [],
                          'configletBuilderList': [],
                          'configletBuilderNamesList': [],
                          'ignoreConfigletBuilderList': [],
                          'ignoreConfigletBuilderNamesList': [],
                          'toId': dev['systemMacAddress'],
                          'toIdType': 'netelement',
                          'fromId': '',
                          'nodeName': '',
                          'fromName': '',
                          'toName': dev['fqdn'],
                          'nodeIpAddress': dev['ipAddress'],
                          'nodeTargetIpAddress': dev['ipAddress'],
                          'childTasks': [],
                          'parentTask': ''}]}
        self._add_temp_action(data)
        if create_task:
            return self._save_topology_v2([])
        return None

    def _add_temp_action(self, data):
        ''' Adds temp action that requires a saveTopology call to take effect.

            Args:
                data (dict): a data dict with a specific format for the
                    desired action.

                    Base Ex: data = {'data': [{specific key/value pairs}]}
        '''
        url = 'https://{}/cvpservice/provisioning/addTempAction.do?format=topology&queryParam=&nodeId=root'.format(self.ip_address)
        self.cvp_sesh.post(url, data=json.dumps(data))

    def _save_topology_v2(self, data):
        ''' Confirms a previously created temp action.

            Args:
                data (list): a list that contains a dict with a specific
                    format for the desired action. Our primary use case is for
                    confirming existing temp actions so we most often send an
                    empty list to confirm an existing temp action.

            Returns:
                response (dict): A dict that contains a status and a list of
                    task ids created (if any).

                    Ex: {u'data': {u'status': u'success', u'taskIds': []}}
        '''
        url = 'https://{}/cvpservice/provisioning/v2/saveTopology.do'.format(self.ip_address)
        return self.cvp_sesh.post(url, data=json.dumps(data))

def parseACLConfiglet(acl_configlet_content):
    configlet_details = {"ACL Definitions": None, "Interface Details": None}
    config_sections = [section.strip() for section in acl_configlet_content.split("!") ]
    acls = OrderedDict()
    interface_details = OrderedDict()
    for config_section in config_sections:
        acl_match = re.match(r'ip\s+access-list\s+(\S+)', config_section.split("\n")[0])
        if acl_match:
            acl_content = OrderedDict()
            for statement in config_section.split("\n")[1:]:
                acl_content[int(statement.lstrip().split(" ")[0])] = " ".join(statement.lstrip().split(" ")[1:])
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


def buildACLConfiglet(acl_configlet_details):
    acl_configlet_content = ""
    for acl, statement_dict in acl_configlet_details["ACL Definitions"].items():
        acl_configlet_content += "ip access-list {}\n".format(acl)
        for sequence_number, statement in OrderedDict(sorted(statement_dict.items())).items():
            acl_configlet_content += "   {} {}\n".format(sequence_number, statement)
        acl_configlet_content += "!\n"
    for interface, interface_statements in acl_configlet_details["Interface Details"].items():
        acl_configlet_content += "interface {}\n".format(interface)
        for statement in interface_statements:
            acl_configlet_content += "   {}\n".format(statement)
        acl_configlet_content += "!\n"
    return acl_configlet_content

<<<<<<< HEAD
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

def showAclNames():
  user = SSHClientUser(CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME), CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD))
  sshclient = SSHClient(user, CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP))
  cmd = 'sh ip access-lists | json'
  resp = sshclient.executeCommand( cmd )
  resp_json = json.loads(resp)
  for i in  range(len(resp_json["aclList"])-1):
    print(resp_json["aclList"][i]["name"])

def showAclDetails(acl_name):
  user = SSHClientUser(CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME), CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD))
  sshclient = SSHClient(user, CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP))
  cmd = 'sh ip access-lists %s' %(acl_name)
  resp = sshclient.executeCommand( cmd )
  return resp

def modifyACL(acl_name, modify_action, acl_statements, acl_interface_application, acl_interface, acl_direction, device_ips):
    server = cvp.Cvp('localhost')
    server.authenticate(CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME), CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD))
    if modify_action == "Create/Update":
        CreateOrUpdateACL(acl_name, acl_statements, acl_interface_application, acl_interface, acl_direction, device_ips,server)
=======
def showAclNames(device_ips):
    user = SSHClientUser(CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME), CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD))
    sshclient = SSHClient(user, device_ips[0])
    cmd = 'sh ip access-lists | json'
    resp = sshclient.executeCommand( cmd )
    resp_json = json.loads(resp)
    acl_names = []
    for acl in  resp_json["aclList"]:
        if acl["dynamic"] == False and acl["readonly"] == False:
            acl_names.append( acl["name"] )
    
    if len(acl_names) == 0:
        print "No configured ACLs found"
    for name in acl_names:
        print name


def showAclDetails(device_ips, acl_name):
    output = ""
    user = SSHClientUser(CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME), CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD))
    sshclient = SSHClient(user, device_ips[0])
    cmd = 'sh ip access-lists %s' %(acl_name)
    resp = sshclient.executeCommand( cmd )
    output += resp
    cmd = 'sh ip access-lists %s summary | json' %(acl_name)
    resp = json.loads(sshclient.executeCommand( cmd ) )
    configured_egress_interfaces = []
    configured_ingress_interfaces = []
    for iface in resp["aclList"][0]["configuredEgressIntfs"]:
        configured_egress_interfaces.append(iface["name"])
    for iface in resp["aclList"][0]["configuredIngressIntfs"]:
        configured_ingress_interfaces.append(iface["name"])

    output += "Configured Egress Interfaces\n"
    if len(configured_egress_interfaces) == 0:
        output += "   None\n"
    for iface in configured_egress_interfaces:
        output += "  - {}\n".format(iface)
    output += "\n"
    output += "Configured Ingress Interfaces\n"
    if len(configured_ingress_interfaces) == 0:
        output += "   None\n"
    for iface in configured_ingress_interfaces:
        output += "  - {}\n".format(iface)
    output += "\n"

    print output

def modifyACL(acl_name, modify_action, acl_statements, acl_interface_application, apply_interface, remove_interface, apply_directions, remove_directions, device_ips, preview_or_apply):
    username = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME)
    password = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD)
    server = CVP('localhost', username, password)
    server.login()
    if modify_action == "Create/Update" or acl_interface_application is not None:
        CreateOrUpdateACL(acl_name, acl_statements, acl_interface_application, apply_interface, remove_interface, apply_directions, remove_directions, device_ips, preview_or_apply, server)
>>>>>>> MasterCB/master
    elif modify_action == "Delete":
        DeleteACL(acl_name, device_ips, preview_or_apply, server)
    server.logout()

def CreateOrUpdateACL(acl_name, acl_statements, acl_interface_application, apply_interface, remove_interface, apply_directions, remove_directions, device_ips, preview_or_apply, server):
    '''
    When creating ACL configlet, write ACL definition and ACL detail configuration first then write application of ACL to interface configuration second
    '''
    target_switches = []
    devices = server.getInventory()
    for device in devices:
        if device["ipAddress"] in device_ips:
            target_switches.append(device)

    #for each device 
    for switch in target_switches:
        #Check for existing <hostname>-ACLs configlet
        try:
            #Configlet exists
            configlet = server.getConfiglet("{}-ACLs".format(switch["hostname"]))
        except:
            #configlet does not exist
            configlet = None

        if configlet is not None:
        #Parse configlet for acl_name
            configlet_details_dict = parseACLConfiglet(configlet["config"])

            if acl_name in configlet_details_dict["ACL Definitions"].keys():
                #Parse and update acl_name
                #Delete statements from ACL
                if acl_statements["Delete"] is not None:
                    for k, v in acl_statements["Delete"].items():
                        if k in configlet_details_dict["ACL Definitions"][acl_name].keys():
                            if configlet_details_dict["ACL Definitions"][acl_name][k] == v:
                                del configlet_details_dict["ACL Definitions"][acl_name][k]
                        else:
                            print "Could not find statement '{} {}' within {} ACL in {}-ACLs".format(k, v, acl_name, switch["hostname"])
                #Add statements to ACL
                if acl_statements["Add"] is not None:
                    for k, v in acl_statements["Add"].items():
                        if k not in configlet_details_dict["ACL Definitions"][acl_name]:
                            configlet_details_dict["ACL Definitions"][acl_name][k] = v
                        else:
                            print "Error: Sequence number {} is already being used in {} for {}".format(k, acl_name, switch["hostname"])
                            return

            else:
                #Create acl in configlet with acl_name, acl_statements, acl_interface, and acl_direction
                if acl_statements["Add"] is not None:
                    configlet_details_dict["ACL Definitions"][acl_name] = acl_statements["Add"]

            #Take care of interface details
            interface_statements = []

            if acl_interface_application == "Apply":
                #Add to list of interface statements
                for direction in apply_directions:
                    interface_statements.append("ip access-group {} {}".format(acl_name, direction))
                
                #If interface we are applying statements to is not in interface details dict, create dict for it with statements
                if apply_interface not in configlet_details_dict["Interface Details"].keys():
                    configlet_details_dict["Interface Details"][apply_interface] = interface_statements
                
                #If interface is already in interface details dict
                else:
                    for iface_statement in interface_statements:
                        #Check to see if statement in interface details for interface and add to it if its not
                        if iface_statement not in configlet_details_dict["Interface Details"][apply_interface]:
                            configlet_details_dict["Interface Details"][apply_interface].append(iface_statement)

            elif acl_interface_application == "Remove" and remove_interface in configlet_details_dict["Interface Details"].keys():
                #Remove from interface
                #Add to list of interface statements
                for direction in remove_directions:
                    interface_statements.append("ip access-group {} {}".format(acl_name, direction))   

                #Remove interface statement from interface details if statement is in details
                for statement in interface_statements:
                    if statement in configlet_details_dict["Interface Details"][remove_interface]:
                        configlet_details_dict["Interface Details"][remove_interface].remove(statement)

                #If there are no more statements for a an interface detail, delete interface from interface details kets
                if len(configlet_details_dict["Interface Details"][remove_interface]) == 0:
                    del configlet_details_dict["Interface Details"][remove_interface]

            configlet_content = buildACLConfiglet(configlet_details_dict)
            if preview_or_apply == "Apply":
                #Update ACL Configlet
                server.updateConfiglet(configlet["key"], configlet["name"], configlet_content)
                print "Updated {} configlet".format("{}-ACLs".format(switch["hostname"]))
                # configlet = server.getConfiglet(configlet["name"])
                # server.applyConfiglets(switch, [configlet])
            print "-"*30
            print configlet_content
            print "-"*30
        else:
            #Create configlet with acl_name, acl_statements, acl_interface, and acl_direction
            configlet_details_dict = {"ACL Definitions": {}, "Interface Details": {}}
            #Create acl in configlet with acl_name, acl_statements, acl_interface, and acl_direction
            if acl_statements["Add"] is not None:
                configlet_details_dict["ACL Definitions"][acl_name] = acl_statements["Add"]
            if apply_interface is not None:
                interface_statements = []
                for direction in apply_directions:
                    interface_statements.append("ip access-group {} {}".format(acl_name, direction))
                configlet_details_dict["Interface Details"][apply_interface] = interface_statements
            configlet_content = buildACLConfiglet(configlet_details_dict)
            if preview_or_apply == "Apply":
                #Add and apply ACL Configlet
                server.addConfiglet("{}-ACLs".format(switch["hostname"]), configlet_content)
                print "Added {} to Configlets".format("{}-ACLs".format(switch["hostname"]))
                configlet = server.getConfiglet(configlet["name"])
                server.applyConfiglets(switch, [configlet])
            print "-"*30
            print configlet_content
            print "-"*30

def DeleteACL(acl_name, device_ips, preview_or_apply, server):
    target_switches = []
    devices = server.getInventory()
    for device in devices:
        if device["ipAddress"] in device_ips:
            target_switches.append(device)

<<<<<<< HEAD
def DeleteACL(acl_name, device_ips, server):
    target_switches = []
    devices = server.cvpService.getInventory()[0]
    for device in devices:
        if device["ipAddress"] in device_ips:
            target_switches.append(device)
            

=======
>>>>>>> MasterCB/master
    #for each device 
    for switch in target_switches:
        acl_to_delete = False
        #Check for existing <hostname>-ACLs configlet
        try:
            #Configlet exists
            configlet = server.getConfiglet("{}-ACLs".format(switch["hostname"]))
        except:
            #configlet does not exist
            configlet = None

        if configlet is not None:
        #Parse configlet for acl_name
<<<<<<< HEAD
            configlet_details_dict = parseACLConfiglet(configlet.config)
            for key in configlet_details_dict["ACL Definitions"].keys():
                if acl_name == key:
                    acl_to_delete = True
                    del configlet_details_dict["ACL Definitions"][key]
=======
            configlet_details_dict = parseACLConfiglet(configlet["config"])
            if acl_name in configlet_details_dict["ACL Definitions"].keys():
                acl_to_delete = True
                del configlet_details_dict["ACL Definitions"][acl_name]
>>>>>>> MasterCB/master
            for key,values in configlet_details_dict["Interface Details"].items():
                for value in values:
                    value = value.split(" ")[2]
                    if acl_name == value:
                        acl_to_delete = True
<<<<<<< HEAD
                        del configlet_details_dict["Interface Details"][key]
                        break
            #print json.dumps(configlet_details_dict, indent=2)
            if acl_to_delete:
                configlet_content = buildACLConfiglet(configlet_details_dict)
                configlet.config = configlet_content
                #print configlet.config
                #Delete ACL Configlet
                server.updateConfiglet(configlet)
                print "Deleted ACL {} from {} configlet".format(acl_name , "{}-ACLs".format(switch["hostname"]))
            else:
                print "ACL  {} doesn't exist in {} configlet".format(acl_name , "{}-ACLs".format(switch["hostname"]))
        else:
            print "Configlet does not exist for {} ".format(device["hostname"])

=======
                        configlet_details_dict["Interface Details"][key].remove(value)
            #print json.dumps(configlet_details_dict, indent=2)
            if acl_to_delete:
                configlet_content = buildACLConfiglet(configlet_details_dict)
                if preview_or_apply == "Apply":
                    #Delete ACL Configlet
                    server.updateConfiglet(configlet["key"], configlet["name"], configlet_content)
                    print "Deleted ACL {} from {} configlet".format(acl_name , "{}-ACLs".format(switch["hostname"]))
                print "-"*30
                print configlet_content
                print "-"*30
            else:
                print "ACL {} doesn't exist in {} configlet".format(acl_name , "{}-ACLs".format(switch["hostname"]))
        else:
            print "Configlet does not exist for {} ".format(switch["hostname"])
>>>>>>> MasterCB/master


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
    add_acl_statements_dict = {}
    for statement in add_acl_statements:
        add_acl_statements_dict[int(statement.split(" ")[0])] = " ".join(statement.split(" ")[1:])
    acl_statements["Add"] = add_acl_statements_dict
if remove_acl_statements is not None:
    remove_acl_statements_dict = {}
    for statement in remove_acl_statements:
        remove_acl_statements_dict[int(statement.split(" ")[0])] = " ".join(statement.split(" ")[1:])
    acl_statements["Delete"] = remove_acl_statements_dict

#'acl_interface_application' will be either 'Apply' or 'Remove'
acl_interface_application = Form.getFieldById('acl_interface_application').value


apply_interface = None
apply_direction = None
remove_interface= None
remove_direction = None

if acl_interface_application == "Apply":
  apply_interface = Form.getFieldById('apply_interface').value
  #List containing 'In' and/or 'Out' 
  apply_direction = Form.getFieldById('apply_direction').value
elif acl_interface_application == "Remove":
  remove_interface = Form.getFieldById('remove_interface').value
  #List containing 'In' and/or 'Out' 
  remove_direction = Form.getFieldById('remove_direction').value
else:
  ""

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

multiple_devices_flag = None

if acl_option == "Modify ACL":
  multiple_devices_flag = Form.getFieldById('multiple_devices_flag').value

<<<<<<< HEAD
if multiple_devices_flag is None or multiple_devices_flag == "No":
  device_ips = [ CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP) ]
else:
  device_ips = [ip.strip() for ip in Form.getFieldById('ip_addresses').value.split("\n") ] if Form.getFieldById('ip_addresses').value is not None else None


=======
preview_or_apply = Form.getFieldById('preview_or_apply').value
multiple_devices_flag = Form.getFieldById('multiple_devices_flag').value

if multiple_devices_flag is None or "No" in multiple_devices_flag:
    device_ips = [ CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP) ]
else:
    device_ips = [ip.strip() for ip in Form.getFieldById('ip_addresses').value.split("\n") ] if Form.getFieldById('ip_addresses').value is not None else None
>>>>>>> MasterCB/master

if acl_option == "Show ACL Names":
  showAclNames()
elif acl_option == "Show ACL Details":
  print showAclDetails(acl_name)
else:
<<<<<<< HEAD
  modifyACL(acl_name, modify_action, acl_statements, acl_interface_application, acl_interface, acl_direction, device_ips)
    
=======
    modifyACL(acl_name, modify_action, acl_statements, acl_interface_application, apply_interface, remove_interface, apply_directions, remove_directions, device_ips, preview_or_apply)

>>>>>>> MasterCB/master
