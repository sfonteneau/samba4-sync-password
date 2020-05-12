Password Sync for Samba4
==================================

That this solution requires you to enable plaintext passwords:

samba-tool domain passwordsettings set --store-plaintext=on
and check "Store password using reersible encryption" in user account.

Reads from your Samba4 AD and send user,email and password in script

If the script returns a good exit code, the password in plain text in samba4 is removed.

Python Dependencies
============================

- syslog
- samba


Installation
==============

- git clone https://github.com/sfonteneau/samba4-sync-password.git
- mv samba4-sync-password /opt/syncpassword
- mkdir /etc/syncpassword
- cd /opt/syncpassword/
- mkdir /etc/syncpassword/
- cp -f syncho.conf /etc/syncpassword/
- Configure /etc/syncpassword/synchro.conf with your samba settings 
- Start with "python3 /opt/syncpassword/syncpassword.py"

Note :

    - The script gets the different arguments in this way:  script.sh mail password (password encode in base64)
    - Create a systemctl service for the script
