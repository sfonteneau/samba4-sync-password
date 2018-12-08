Password Sync for Samba4
==================================

That this solution requires you to enable plaintext passwords:

samba-tool domain passwordsettings set --store-plaintext=on
and check "Store password using reersible encryption" in user account.

Reads from your Samba4 AD and send user,email and password in script

If the script returns a good exit code, the password in plain text in samba4 is removed.

Python Dependencies
============================

- daemon
- syslog
- samba


Installation
==============
- mkdir /opt/syncpassword/
- mkdir /etc/syncpassword
- cd /opt/syncpassword/
- git clone https://github.com/sfonteneau/samba4-sync-password.git
- cp -f syncho.conf /etc/syncpassword/
- Configure synchro.conf with your samba settings 
- Start sync with "python syncpassword.py start"

	Note :

	- The script gets the different arguments in this way:    script.sh samaccountname mail password
	- replace_domain : This makes it possible to replace the domain of the email field with another domain (that of the domain field of the configuration file)


