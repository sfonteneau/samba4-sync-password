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

