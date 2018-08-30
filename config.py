"""Configuration settings for running the Python auth samples locally.

In a production deployment, this information should be saved in a database or
other secure storage mechanism.
"""

# Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
# See LICENSE in the project root for license information.

CLIENT_ID = '47f1ad04-97a5-4b58-8729-e889eaccfedb'
CLIENT_SECRET = 'ckpUJERC72*;tjiaCC240}~'
REDIRECT_URI = 'https://alert-isg-tool.westus.cloudapp.azure.com/login/authorized'

# AUTHORITY_URL ending determines type of account that can be authenticated:
# /organizations = organizational accounts only
# /consumers = MSAs only (Microsoft Accounts - Live.com, Hotmail.com, etc.)
# /common = allow both types of accounts
AUTHORITY_URL = 'https://login.microsoftonline.com/common'

AUTH_ENDPOINT = '/oauth2/v2.0/authorize'
TOKEN_ENDPOINT = '/oauth2/v2.0/token'

#RESOURCE = 'https://security-isg.westus.cloudapp.azure.com/'
RESOURCE = 'https://graph.microsoft.com/'
API_VERSION = 'v1.0'
#API_VERSION = ''
ISG_VERSION = 'testSecuritydev'
#ISG_VERSION = ''
ISG_URL = RESOURCE + ISG_VERSION + '/security/'
SCOPES = ['User.Read', 'User.ReadBasic.All', 'SecurityEvents.Read.All', 'SecurityEvents.ReadWrite.All'] # Add other scopes/permissions as needed.

# Basic Key Authorization is sent encoded as base64, so the key is encoded into base64 bytes and then
# decoded from bytes into a utf-8 string
import base64

BASIC_TEST_KEY = base64.b64encode("illumio-shared-secret-key".encode()).decode()

## values used to validate JWT actor tokens from the Secuirty Graph
ALGORITHMS = ['RS256']

VENDOR_NAME = "illumio"
PROVIDER_NAME = "illumio"

# This code can be removed after configuring CLIENT_ID and CLIENT_SECRET above.
if 'ENTER_YOUR' in CLIENT_ID or 'ENTER_YOUR' in CLIENT_SECRET:
    print('ERROR: config.py does not contain valid CLIENT_ID and CLIENT_SECRET')
    import sys
    sys.exit(1)
