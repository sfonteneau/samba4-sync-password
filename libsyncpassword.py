#!/usr/bin/python3
import ldb
import os
import json
import syslog
import time
import binascii
import base64
import configparser
import subprocess
import traceback
import os.path
from Crypto import Random
from samba.auth import system_session
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.netcmd.user import GetPasswordCommand

## Get configuration
config = configparser.ConfigParser()
config.read('/etc/syncpassword/synchro.conf')


## Open connection to Syslog ##
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)

filename = config.get('common', 'path_pwdlastset_file')
mailattr = config.get('common', 'mail_attr')

if os.path.exists(filename):
    dict_mail_pwdlastset = json.loads(open(filename,'r').read())
else:
    dict_mail_pwdlastset = {}

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


def update_password(mail,pwd,uac,dn,sama,samdb_loc,pwdlastset):
    script = config.get('common', 'external_script_password')
    b64password = base64.b64encode(pwd).decode('utf-8')
    try: 
        subprocess.check_output('%s %s %s' % (script,mail,b64password),shell=True, stderr=subprocess.STDOUT)
        dict_mail_pwdlastset[str(mail)]=str(pwdlastset)
        syslog.syslog(syslog.LOG_WARNING, '[INFO] Updated password for %s' % mail)
        disable_clear_password(pwd,uac,dn,sama,samdb_loc)
        open(filename,'w').write(json.dumps(dict_mail_pwdlastset))
    except subprocess.CalledProcessError as e:
        er = e.output.decode('utf-8').replace(b64password,'##B64PASSWORD##')
        syslog.syslog(syslog.LOG_WARNING, '[ERROR] %s : %s' % (mail,er))


def run():
    allmail = {}

    # Search all users
    for user in samdb_loc.search(base=param_samba['adbase'], expression="(&(objectClass=user)(!(objectClass=computer)))", attrs=[mailattr,"sAMAccountName",'userAccountControl','distinguishedName','pwdLastSet']):
        pwdlastset = user.get('pwdLastSet','')
        mail = str(user.get(mailattr,''))

        if str(pwdlastset) == dict_mail_pwdlastset.get(mail,''):
            continue

        allmail[mail] = None

        if not mail:
            continue

        uac = user['userAccountControl']
        username = str(user["sAMAccountName"])
        dn = str(user["distinguishedName"])

        #add mail in all mail
        allmail[mail] = None
        Random.atfork()
        password = testpawd.get_account_attributes(samdb_loc,None,param_samba['basedn'],filter="(sAMAccountName=%s)" % (username),scope=ldb.SCOPE_SUBTREE,attrs=['virtualClearTextUTF8'],decrypt=False)
        if not 'virtualClearTextUTF8' in password:
            continue
        password = password['virtualClearTextUTF8'][0]
        update_password(mail, password, uac,dn,username,samdb_loc,pwdlastset)

    open(filename,'w').write(json.dumps(dict_mail_pwdlastset))

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
