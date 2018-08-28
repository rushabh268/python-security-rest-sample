"""sample for Microsoft Graph ISG"""
# Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license.
# See LICENSE in the project root for license information.
import base64
import mimetypes
import pprint
import uuid
import datetime
import time
import urllib
import json
from functools import wraps

import flask
from flask_oauthlib.client import OAuth

import config

APP = flask.Flask(__name__, template_folder='static/templates')
APP.debug = True
APP.secret_key = 'development'
OAUTH = OAuth(APP)
MSGRAPH = OAUTH.remote_app(
    'microsoft',
    consumer_key=config.CLIENT_ID,
    consumer_secret=config.CLIENT_SECRET,
    request_token_params={'scope': config.SCOPES},
    base_url=config.RESOURCE + config.API_VERSION + '/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url=config.AUTHORITY_URL + config.TOKEN_ENDPOINT,
    authorize_url=config.AUTHORITY_URL + config.AUTH_ENDPOINT)
VIEW_DATA = {} #used to store items that should be rendered in the HTML

@APP.route('/')
def homepage():
    """Render the home page."""
    if 'access_token' in flask.session:
        if 'email' not in flask.session or 'username' not in flask.session :
            return flask.redirect(flask.url_for('get_my_email_address'))
        if 'SecurityEvents.Read.All' not in flask.session['scopes'] or 'SecurityEvents.ReadWrite.All' not in flask.session['scopes']:
            return flask.render_template('Admin_consent.html', Title="Microsoft Security Graph API demo web application"
                                 ,Year=datetime.date.today().strftime("%Y")
                                 ,ViewData=VIEW_DATA, Config=config)
    return flask.render_template('Graph.html', Title="Microsoft Security Graph API demo web application"
                                 ,Year=datetime.date.today().strftime("%Y")
                                 ,ViewData=VIEW_DATA, Config=config)

@APP.route('/login')
def login():
    """Prompt user to authenticate."""
    VIEW_DATA.clear()
    flask.session.clear()
    flask.session['state'] = str(uuid.uuid4())
    return MSGRAPH.authorize(callback=config.REDIRECT_URI, state=flask.session['state'])

@APP.route('/login/authorized')
def authorized():
    """Handler for the application's Redirect Uri."""
    # redirected admin consent flow
    if flask.request.args.get('error') :
        if flask.request.args.get('error_subcode'):
            error_description = flask.request.args.get('error_subcode')
        else :
            error_description = flask.request.args['error_description']
        message = '<strong>Error:</strong> ' + flask.request.args['error'] + '</br> <strong>Reason:</strong> ' + error_description
        flask.flash(message, category='danger')
        return flask.redirect('/')
    elif flask.request.args.get('admin_consent') :
        message = '<strong>Success</strong> Tenant: ' + flask.request.args['tenant'] + ' has given this application admin consent.'
        flask.flash(message, category='success')
        flask.session.pop('access_token', None) 
        VIEW_DATA.clear()
        return flask.redirect('/')
    # redirected from authentication
    if str(flask.session['state']) != str(flask.request.args['state']):
        raise Exception('state returned to redirect URL does not match!')
    response = MSGRAPH.authorized_response()
    #print("authorized response : ", response)
    flask.session['access_token'] = response['access_token']
    flask.session['scopes'] = response['scope'].split()
    flask.session['providers'] = get_providers()
    return flask.redirect('/')

def get_providers():
    top_alerts = get_top_security_alert()
    providers = []
    print(top_alerts)
    for alert in top_alerts.get('value'):
        providers.append(alert.get("vendorInformation").get("provider"))
    return providers


@APP.route('/logout')
def logout():
    """signs out the current user from the session."""
    #flask.session.pop('access_token', None) 
    flask.session.clear()
    VIEW_DATA.clear()
    return flask.redirect(flask.url_for('homepage'))

#Used to decorate methods that require authentication.
def requires_auth(f):
  """Wrapper function to prompt user to authenticate."""
  @wraps(f)
  def decorated(*args, **kwargs):
    if 'access_token' not in flask.session:
      # Redirect to Login page
      return flask.redirect('/login')
    return f(*args, **kwargs)
  return decorated

@APP.route('/GetMyEmailAddress')
@requires_auth
def get_my_email_address():
    """Make Rest API call to graph for current users email"""
    VIEW_DATA.clear() # reset data passed to the Graph.html
    user_profile = MSGRAPH.get('me', headers=request_headers()).data
    if 'error' in user_profile: ### Access token has expired!
        #print(user_profile)
        if user_profile['error']['code'] == 'InvalidAuthenticationToken':
            return flask.redirect(flask.url_for('login'))
       
    flask.session['email'] = user_profile['userPrincipalName']
    flask.session['username'] = user_profile['displayName']
    return flask.redirect(flask.url_for('homepage'))

@APP.route('/GetAlerts', methods = ['POST', 'GET'])
@requires_auth
def get_alerts():
    """Make Rest API call to security graph for alerts"""
    if flask.request.method == 'POST':
        result = flask.request.form
        alert_data = {}
        VIEW_DATA.clear()
        for key in result:
            alert_data[key] = result[key]
        flask.session['alertData'] = alert_data
         
        filteredAlerts = get_alerts_from_graph()
        if b'' in filteredAlerts:
            print("Please Sign-in using a on.microsoft.com account for demo data")
            filteredAlerts = "Incorrect Tenant Account"
        elif 'error' in filteredAlerts:
            if filteredAlerts['error']['code'] == 'InvalidAuthenticationToken':

                return flask.redirect(flask.url_for('login'))

        VIEW_DATA['GetAlertResults'] = filteredAlerts

        #MSGRAPH.base_url = config.RESOURCE + config.API_VERSION + '/'
        MSGRAPH.base_url = config.RESOURCE + '/'
    return flask.redirect(flask.url_for('homepage'))

def get_alerts_from_graph():
    """Helper to Make Rest API call to graph by building the query"""
    MSGRAPH.base_url = config.ISG_URL
    alert_data = flask.session['alertData']
    filteredQuery = ""
    if 'AssignedToMe' in alert_data :
        filteredQuery += "assignedTo eq '" + flask.session['email'] +"'"
    if not alert_data:
        VIEW_DATA['QueryDetails'] = "REST query: '" + MSGRAPH.base_url + 'alerts/?$top=5' + "'"
        return MSGRAPH.get('alerts/?$top=5', headers=request_headers()).data
    else:
        if (alert_data['Category'] != "All"):
            filteredQuery += 'category eq ' if (len(filteredQuery) == 0) else '&category eq '
            filteredQuery += "'{}'".format(alert_data['Category'])
        if (alert_data['Provider'] != "All"):
            filteredQuery += 'vendorInformation/provider eq ' if (len(filteredQuery) == 0) else '&vendorInformation/provider eq '
            filteredQuery += "'{}'".format(alert_data['Provider'])
        if (alert_data['Status'] != "All"):
            filteredQuery += 'Status eq ' if (len(filteredQuery) == 0) else '&Status eq '
            filteredQuery += "'{}'".format(alert_data['Status'])
        if (alert_data['Severity'] != "All"):
            filteredQuery += 'Severity eq ' if (len(filteredQuery) == 0) else '&Severity eq '
            filteredQuery += "'{}'".format(alert_data['Severity'])
        if (alert_data['HostFqdn'] != ""):
            filteredQuery += 'hostState/fqdn eq ' if (len(filteredQuery) == 0) else '&hostState/fqdn eq '
            filteredQuery += "'{}'".format(alert_data['HostFqdn'])
        if (alert_data['Upn'] != ""):
            filteredQuery += 'userPrincipalName eq ' if (len(filteredQuery) == 0) else '&userPrincipalName eq '
            filteredQuery += "'{}'".format(alert_data['Upn'])
        filteredQuery += '$top=' if (len(filteredQuery) == 0) else '&$top='
        filteredQuery += alert_data['Top']

    addFilter = ""
    if filteredQuery != ("$top=" + alert_data['Top']):
        addFilter = '$filter='

    query = "alerts/?" + addFilter + filteredQuery
    VIEW_DATA['QueryDetails'] = query
    query = urllib.parse.quote(query,safe="/?$='&") #cleans up the url
    return MSGRAPH.get(query, headers=request_headers()).data

@APP.route('/DisplayAlert/<alertId>')
@requires_auth
def display_alert(alertId):
    """Renders the alert page"""
    alert = get_alert_by_id(alertId)
    jsonAlert = json.dumps(alert, sort_keys=True, indent=4, separators=(',', ': '))
    return flask.render_template('alert.html', Title="Alert Details"
                                ,Year=datetime.date.today().strftime("%Y")
                                ,Alert=jsonAlert, AlertId=alertId, Config=config)

def get_alert_by_id(alertId):
    """Helper function to get a security alert by ID
    
    alertId      = The Alert ID to be updated

    Returns the response from Graph
    """
    MSGRAPH.base_url = config.ISG_URL
    alert = MSGRAPH.get('alerts/' + alertId, headers=request_headers()).data
    if b'' in alert:
       print("Please Sign-in using a on.microsoft.com account for demo data")
       alert = None
    elif 'error' in alert:
        alert = None
    MSGRAPH.base_url = config.RESOURCE + config.API_VERSION + '/'
    return alert

def update_security_alert(alertId, newData):
    """Helper to Update a security graph alert.

    alertId      = The Alert ID to be updated
    newData      = The json body of the PATCH rest call
    """
    MSGRAPH.base_url = config.ISG_URL
    _ = MSGRAPH.patch('alerts/' + alertId, data=newData, headers=request_headers(),  format='json')
    MSGRAPH.base_url = config.RESOURCE + config.API_VERSION + '/'
    return

def get_top_security_alert():
    """Helper to get the most recent security graph alert."""
    MSGRAPH.base_url = config.ISG_URL
    print('MSGRAPH.base_url:', MSGRAPH.base_url)
    most_recent_alert = MSGRAPH.get('alerts/?$top=1', headers=request_headers()).data
    if b'' in most_recent_alert:
        print("Please Sign-in using a on.microsoft.com account for demo data")
        most_recent_alert = None
    elif 'error' in most_recent_alert:
        most_recent_alert = None
    MSGRAPH.base_url = config.RESOURCE + config.API_VERSION + '/'
    return most_recent_alert


@APP.route('/UpdateAlert', methods = ['POST', 'GET'])
@requires_auth
def update_alert():
    """ Make Rest API call to security graph to update an alert """
    if flask.request.method == 'POST':
        flask.session.pop('UpdateAlertData', None)
        result = flask.request.form
        VIEW_DATA.clear()
        alert_data = {_:result[_] for _ in result} #Iterate over html form POST from Graph.html
        if alert_data.get('AlertId'): # Id form was not empty
            alert_data['AlertId'] = alert_data.get('AlertId').strip(' ')
        else:
            VIEW_DATA['UpdateAlertError'] = "Please enter valid alert Id"
            return flask.redirect(flask.url_for('homepage'))
        alertId = alert_data['AlertId']
        old_alert = get_alert_by_id(alertId) # store old alert before updating it
        if not old_alert: # alert not found
            VIEW_DATA['UpdateAlertError'] = "No alert matching this ID " + alertId + " was found"
            return flask.redirect(flask.url_for('homepage'))
        else: 
            VIEW_DATA['OldAlert'] = old_alert
            properties_to_update = {}
            properties_to_update["assignedTo"] = flask.session['email']
            if alert_data.get("SelectStatusToUpdate") != "Unknown":
                properties_to_update["status"] = alert_data.get("SelectStatusToUpdate")
            if alert_data.get("SelectFeedbackToUpdate") != "Unknown":
                properties_to_update["feedback"] = alert_data.get("SelectFeedbackToUpdate")
            if alert_data.get("Comments") != "":
                properties_to_update["comments"] = alert_data.get("Comments")
            # include the required vendor information in the body of the PATCH
            properties_to_update["vendorInformation"] = old_alert.get("vendorInformation")
            # update the alert
            update_security_alert(alertId, properties_to_update)
            # make another call to graph to get the updated alert
            updated_alert = get_alert_by_id(alertId)
            #store the alert to be rendered in the table in Graph.html
            VIEW_DATA['UpdateAlertResults'] = updated_alert
            VIEW_DATA['UpdateQueryDetails'] = "REST query PATCH: '" + config.ISG_URL +"alerts/" + alertId + "'"
            VIEW_DATA['UpdateQueryBody'] = "Request Body: " + json.dumps(properties_to_update, sort_keys=True, indent=4, separators=(',', ': '))
        flask.session['UpdateAlertData'] = alert_data
    return flask.redirect(flask.url_for('homepage'))

@APP.route('/EmailAlert', methods = ['POST', 'GET'])
@requires_auth
def email_alert():
    """Handler for email_alert route."""
    if flask.request.method == 'POST':
        VIEW_DATA.clear()
        emails = flask.request.form   
        VIEW_DATA['EmailRecipients'] = emails.get('recipients')
        if not emails.get('recipients'):
            VIEW_DATA['EmailResults'] = "Please enter an email address."
            return flask.redirect(flask.url_for('homepage'))
        else:
            most_recent_alert = get_top_security_alert()
            if most_recent_alert:
                most_recent_alert = most_recent_alert.get('value')
            if most_recent_alert:
                most_recent_alert = most_recent_alert[0]

                # build the email message
                message_subject = "New Alert - '" + most_recent_alert['title'] + "' of Category '" + most_recent_alert['category'] + "' from Provider '" + most_recent_alert.get('vendorInformation')['provider'] + "'"
                message_body = "<p>Alert Created: " + most_recent_alert['createdDateTime']  + "</p>" \
                            + "<p>Description: " + most_recent_alert['description'] + "</p>" \
                            + "<p>Alert Id: " + most_recent_alert['id']  + "</p>" \
                            + "<p>MS Graph Explorer URL '" + config.ISG_URL + "alerts/" +  most_recent_alert['id'] + "'</p>"
                # send the email 
                response = sendmail(client=MSGRAPH,
                                subject=message_subject,
                                recipients=emails.get('recipients').split(','),
                                body=message_body)
                response_json = pprint.pformat(response.data)
                if response_json != "b''": # the email message was not sent
                    return flask.redirect(flask.url_for('login'))
                VIEW_DATA['EmailResults'] = "Email sent to " + emails.get('recipients') + "."
            else:
                VIEW_DATA['EmailResults'] = "No alert to send"
    return flask.redirect(flask.url_for('homepage'))


@MSGRAPH.tokengetter
def get_token():
    """Called by flask_oauthlib.client to retrieve current access token."""
    return (flask.session.get('access_token'), '')


def request_headers(headers=None):
    """Return dictionary of default HTTP headers for Graph API calls.
    Optional argument is other headers to merge/override defaults."""
    default_headers = {'SdkVersion': 'sample-python-flask',
                       'x-client-SKU': 'sample-python-flask',
                       'client-request-id': str(uuid.uuid4()),
                       'return-client-request-id': 'true'}
    if headers:
        default_headers.update(headers)
    return default_headers


def sendmail(client, subject=None, recipients=None, body='', content_type='HTML', attachments=None):
    """Helper to send email from current user.

    client       = user-authenticated flask-oauthlib client instance
    subject      = email subject (required)
    recipients   = list of recipient email addresses (required)
    body         = body of the message
    content_type = content type (default is 'HTML')
    attachments  = list of file attachments (local filenames)

    Returns the response from the POST to the sendmail API.
    """

    # Verify that required arguments have been passed.
    if not all([client, subject, recipients]):
        raise ValueError('sendmail(): required arguments missing')

    #print('recipients : ', recipients )

    # Create recipient list in required format.
    recipient_list = [{'EmailAddress': {'Address': address.strip()}}
                      for address in recipients]

    # Create list of attachments in required format.
    attached_files = []
    if attachments:
        for filename in attachments:
            b64_content = base64.b64encode(open(filename, 'rb').read())
            mime_type = mimetypes.guess_type(filename)[0]
            mime_type = mime_type if mime_type else ''
            attached_files.append( \
                {'@odata.type': '#microsoft.graph.fileAttachment',
                 'ContentBytes': b64_content.decode('utf-8'),
                 'ContentType': mime_type,
                 'Name': filename})

    # Create email message in required format.
    email_msg = {'Message': {'Subject': subject,
                             'Body': {'ContentType': content_type, 'Content': body},
                             'ToRecipients': recipient_list,
                             'Attachments': attached_files},
                 'SaveToSentItems': 'true'}

    # Do a POST to Graph's sendMail API and return the response.
    return client.post('me/microsoft.graph.sendMail',
                       headers=request_headers(),
                       data=email_msg,
                       format='json')


if __name__ == '__main__':
    APP.run(host='10.0.0.5', port=5000)
