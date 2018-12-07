#!/usr/bin/env python
import binascii
import ldb
from samba.auth import system_session
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB
from ConfigParser import SafeConfigParser
from samba.netcmd.user import GetPasswordCommand
from azure.common.credentials import ServicePrincipalCredentials
from azure.common.credentials import UserPassCredentials
from azure.graphrbac.models import PasswordProfile, UserUpdateParameters
from azure.graphrbac import GraphRbacManagementClient
import os
import json
import syslog
import time

## Get confgiruation
config = SafeConfigParser()
config.read('/etc/synchro-office-password/synchro.conf')

## Open connection to Syslog ##
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)


filename = config.get('common', 'path_pwdlastset_file')


def disable_clear_password(pwd,uac,dn,sama,samdb_loc):
    ldif_data = """dn: %s
changetype: modify
replace: userAccountControl
userAccountControl: 512
""" % (dn)
    samdb_loc.modify_ldif(ldif_data)

    samdb_loc.setpassword('(sAMAccountName=%s)' % sama,pwd)

    ldif_data = """dn: %s
changetype: modify
replace: userAccountControl
userAccountControl: %s
""" % (dn,uac)
    samdb_loc.modify_ldif(ldif_data)


def update_password(mail,pwd,uac,dn,sama,samdb_loc):
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
        disable_clear_password(pwd,uac,dn,sama,samdb_loc)
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
    testpawd = GetPasswordCommand()
    testpawd.lp = lp
    allmail = {}

    # Search all users
    for user in samdb_loc.search(base=param_samba['adbase'], expression="(&(objectClass=user)(mail=*))", attrs=["mail","sAMAccountName",'userAccountControl','distinguishedName']):
        mail = str(user["mail"])

        #replace mail if replace_domain in config
        if config.getboolean('common', 'replace_domain'):
            mail = mail.split('@')[0] + '@' + config.get('common', 'domain')
        uac = user['userAccountControl']
        username = str(user["sAMAccountName"])
        dn = str(user["distinguishedName"])

        #add mail in all mail
        allmail[mail] = None

        password = testpawd.get_account_attributes(samdb_loc,None,param_samba['basedn'],filter="(sAMAccountName=%s)" % (username),scope=ldb.SCOPE_SUBTREE,attrs=['virtualClearTextUTF8'],decrypt=True)
        if not 'virtualClearTextUTF8' in password:
            continue
        password = str(password['virtualClearTextUTF8'])
        update_password(mail, password, uac,dn,username,samdb_loc)
