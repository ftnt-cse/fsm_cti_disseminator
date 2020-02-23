#!/usr/bin/env python2
# Blacklist on FortiSandbox a list of specific FortiSIEM malware Haches list
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND

import pg8000 as dbapi
import sys
import json
from   base64 import b64encode, b64decode
import hashlib # For SHA-256 Encoding
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# User Settings
MAX_IOC_COUNT='50000'
QUARANTINE_SECONDS=86400 # 1 day

# Internal Settings
db_username='phoenix'
db_password=''

#sys args
mIncidentXML 	= sys.argv[1]
mUser 			= sys.argv[2]
mPassword 		= sys.argv[3]
mSuperPassword	= sys.argv[4]
mAccessIp 		= sys.argv[5]

def pg_query(username,password,query,host='127.0.0.1',database='phoenixdb',port=5432):
	records=[]
	try:
		conn=dbapi.connect(database=database,host=host, port=port,user=username ,password=password,ssl=False)
		curr=conn.cursor()
		curr.execute(query)
		return list(curr.fetchall())

	except Exception as err:
		print('DB Query failed',err)
		exit()


def fsa_json_login(server,username,password):
	json = { 
		"method": "exec",
		"params": [
			{
				"url": "/sys/login/user",
				"data": [
					{
						"user": username,
						"passwd": password
					}
				]  
			}
		], 
		"id": 1,
		"ver": "2.0"
	}


	r = requests.post("http://" + server + "/jsonrpc", json=json, verify=False, timeout=300).json()

	code = r['result']['status']['code']
	message = r['result']['status']['message']

	if code != 0:
		print("cannot login to %s using credentials [%s:%s]: %s",server, username, password, message)
		exit()

	session = r['session']
		
	#print("%s: successfully logged %s using credentials [%s:%s]", session, server, username, password)
	return session

def json_fsa_logout(server,session):
	json = {
		"method": "exec",
		"params": [
			{
				"url": "/sys/logout",
			}
		],
		"session":session,
		"id": 2,
		"ver": "2.0"
	}

	r = requests.post("http://" + server + "/jsonrpc", json = json, verify=False, timeout=300).json()

	code = r['result']['status']['code']
	message = r['result']['status']['message']

	if code != 0:
		print("Cannot logout from :", server, message)
		return
	#print("%s: disconnected from %s: %s", session, server, message)


def json_fsa_white_black_list_update(server,username, password, algorithm, encoded_hashes, action):

	session = fsa_json_login(server,username, password)	
	if session == None:
		print('Cannot establish a session with FSA',server)
		sys.exit(1)

	json = {
		"method": "post",
		"params": [
		{
				"url": "/scan/policy/black-white-list",
				"list_type": "black",
				"checksum_type": algorithm,
				"action": action,
				"upload_file": encoded_hashes
		}
		],
				"session":session,
				"id": 25,
				"ver": "2.5"
		}
	r = requests.post("http://" + server + "/jsonrpc", json=json, verify=False, timeout=300).json()
	code = r['result']['status']['code']
	message = r['result']['status']['message']
	if code != 0:
		print("Cannot update Black/white list: ", message)
		return
	else:
		print('Successfully updated Black/White List',str(len(encoded_hashes)),algorithm,'Byte written')
	json_fsa_logout(mAccessIp,session)


def main():

	# Query DB for hash list
	json_records={'md5':[],'sha1':[],'sha256':[]}
	records=pg_query(db_username,db_password,"select algorithm,hash,asn from ph_malware_hash where asn='1492' LIMIT " + MAX_IOC_COUNT)
	if len(records) <= 1:
		print('No records found, make sure you have a malware group populated in FSM')
		exit()
	# Process Algorithms and create groups
	for record in records:
		algorithm = record[0].replace('-','').replace('_','').replace('.','').lower()
		json_records[algorithm].append(record[1])
	# Submit to FSA
	for hash_type in json_records:
		if len(json_records[hash_type]) >= 1:
			encoded_hashes=b64encode('\n'.join(json_records[hash_type]))
			json_fsa_white_black_list_update(mAccessIp,mUser,mPassword,hash_type,encoded_hashes,'append')

if __name__ == "__main__":
	main()
