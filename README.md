Google Apps Password Sync for Samba4
===========

Reads from your Samba4 AD and updates passwords in Azure AD

Note that this solution requires you to enable plaintext passwords:

samba-tool domain passwordsettings set --store-plaintext=on

Python Dependencies
===========

- daemon
- syslog
- samba
- azure-sdk-for-python

azure-sdk-for-python API must be installed with pip:
pip install --upgrade google-api-python-client

   git clone git://github.com/Azure/azure-sdk-for-python.git
   cd azure-sdk-for-python
   python setup.py install

