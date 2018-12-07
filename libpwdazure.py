#!/usr/bin/env python
import binascii
from samba.auth import system_session
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs
from ConfigParser import SafeConfigParser
from azure.common.credentials import ServicePrincipalCredentials
from azure.common.credentials import UserPassCredentials
from azure.graphrbac.models import PasswordProfile, UserUpdateParameters
from azure.graphrbac import GraphRbacManagementClient
import os
import json
import syslog

## Get confgiruation
config = SafeConfigParser()
config.read('/etc/synchro-office-password/synchro.conf')

## Open connection to Syslog ##
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)

filename = config.get('common', 'path_pwdlastset_file')
dict_mail_pwdlastset={}
if os.path.isfile(filename):
    dict_mail_pwdlastset = json.loads(open(filename,'r').read())

def update_password(mail, pwd, pwdlastset):
    credentials = UserPassCredentials(
        config.get('azure', 'admin_email'), config.get('azure', 'admin_password'), resource="https://graph.windows.net"
    )

    tenant_id = config.get('azure', 'tenant_id')

    graphrbac_client = GraphRbacManagementClient(
       credentials,
       tenant_id
    )

    param =         UserUpdateParameters(
                    password_profile=PasswordProfile(
                    password=pwd,
                    force_change_password_next_login=False)
                    )                   

    try: 
        graphrbac_client.users.update(mail, param)
        service.users().update(userKey = mail, body=user).execute()
        syslog.syslog(syslog.LOG_WARNING, '[NOTICE] Updated password for %s' % mail)
        dict_mail_pwdlastset[str(mail)]=str(pwdlastset)
        open(filename,'w').write(json.dumps(dict_mail_pwdlastset))
        #TODO CLEAR PASSWORD IN AD
    except Exception as e:
        syslog.syslog(syslog.LOG_WARNING, '[ERROR] %s : %s' % (mail,str(e)))
    finally:
        graphrbac_client = None

def run():

    param_samba = {
    'basedn' : config.get('samba', 'path'),
    'pathsamdb':'%s/sam.ldb' % config.get('samba', 'private'),
    'adbase': config.get('samba', 'base')
    }

    # SAMDB
    lp = LoadParm()
    creds = Credentials()
    creds.guess(lp)
    samdb_loc = SamDB(url=param_samba['pathsamdb'], session_info=system_session(),credentials=creds, lp=lp)
    allmail = {}

    # Search all users
    for user in samdb_loc.search(base=param_samba['adbase'], expression="(&(objectClass=user)(mail=*))", attrs=["mail","sAMAccountName","pwdLastSet"]):
        mail = str(user["mail"])

        #replace mail if replace_domain in config
        if config.getboolean('common', 'replace_domain'):
            mail = mail.split('@')[0] + '@' + config.get('common', 'domain')

        pwdlastset = user.get('pwdLastSet','')

        #add mail in all mail
        allmail[mail] = None

        if str(pwdlastset) != dict_mail_pwdlastset.get(mail,''):

            for user in samdb_loc.search(base=param_samba['basedn'], expression="(&(objectClass=user)(mail=*))", attrs=["mail","sAMAccountName","supplementalCredentials"]):
                scb = ndr_unpack(drsblobs.supplementalCredentialsBlob, str(user["supplementalCredentials"]))
                password = False
                for p in scb.sub.packages:
                    if p.name == 'Primary:CLEARTEXT' :
                        password =  binascii.unhexlify(p.data).decode("utf16")
                if not password:
                    continue
                update_password(mail, password, pwdlastset)

    #delete user found in dict mail pwdlastset but not found in samba
    listdelete = []
    for user in dict_mail_pwdlastset :
        if not user in allmail:
            listdelete.append(user)

    for user in listdelete:
        del dict_mail_pwdlastset[user]

    #write new json dict mail password
    if listdelete:
        open(filename,'w').write(json.dumps(dict_mail_pwdlastset))



