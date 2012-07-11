# encoding: utf-8
"""

Created by Pete Aykroyd on 2010-06-21.
Copyright (c) 2010 Spring Partners. All rights reserved.

Visit http://springpad.com/api/oauth-register-app to get your developer tokens

PRE-REQUISITES: 
  ensure that you easy_install httplib2, json
  and also install: http://pypi.python.org/pypi/oauth/1.0.1 

EXAMPLE:
  # without a token
  import spring
  c = spring.Client(consumer_key, consumer_secret, None)
  req_token = c.get_request_token()
  # direct user to authorize page
  # ...
  # when this is done:
  acc_token = c.get_access_token(req_token)
  c.get_user('me')

  # with a token
  import spring
  from oauth import oauth
  tkn = oauth.OAuthToken.from_string(access_token_string_repr)
  c = spring.Client(consumer_key, consumer_secret, tkn)
  c.get_user('aykroyd')
"""

import  httplib2, uuid, json
import oauth.oauth as oauth
from datetime import datetime
from time import mktime

BASE_API_URL = 'http://springpad.com/api/'

class SecurityError(BaseException):
  pass


class Client:
  """Provides access to Springpad's API functions."""
  
  def __init__(self, 
               consumer_key=None,
               consumer_secret=None,
               access_token=None,
               username=None,
               password=None,
               default_headers=None,
               client_name='Python'):
    if (not consumer_key and not consumer_secret) and (not username and not password):
      raise ValueError('Must provide either consumer_key and secret or username and password.')

    if consumer_key and consumer_secret:
      self.consumer = oauth.OAuthConsumer(consumer_key, consumer_secret)
      self.access_token = access_token
      self.sig_method = oauth.OAuthSignatureMethod_HMAC_SHA1()
    else:
      self.consumer = None
      self.access_token = None
      self.sig_method = None
    self.client_name = client_name
    self._user_uuid = None
    self.username=username
    self.password=password

  def using_oauth(self):
    return self.consumer

  def using_simple_auth(self):
    return self.username and self.password

  def get_request_token(self):
    """Starts the oauth auth process by getting a request token from Springpad.
        
       You can get the URL to direct the user do:
             "http://springpad.com/api/oauth-authorize%?s" % request_token

       After the user approves access at the given url, your application's callback
       url will be requested by Springpad with the request token as a query parameter.
       When that happens, you can request the access token with the get_access_token call.
    """
    data = self._fetch('oauth-request-token', as_json=False)
    return oauth.OAuthToken.from_string(data)

  def get_access_token(self, request_token):
    """Fetches the access token from Springpad to allow you to make valid API calls. 
      
       This method has the side-effect of setting the access_token on this client. So that
       subsequent calls to Springpad will be signed with token.
    """
    data = self._fetch('oauth-access-token', token=request_token, as_json=False)
    self.access_token = oauth.OAuthToken.from_string(data)
    return self.access_token

  def get_block(self, uuid):
    """returns a block by the uuid"""
    return self._fetch("users/me/blocks/%s" % uuid)

  def get_blocks(self, type_filter=None, sort='created', order='desc', filter_string=None, limit=10, start=0, \
            format='full', parameters=None):
    """returns some blocks"""
    params = {'sort':sort, 'order':order, 'limit':limit, 'start':start, 'format':format}
    if parameters:
      params.update(parameters)
    if type_filter: 
      params['type'] = type_filter
    if filter_string: 
      params['filter'] = filter_string
    
    results = self._fetch("users/me/blocks", parameters=params)
    return results

  def get_counts(self, facet):
    """gets a map of counts for a specific facet"""
    results = self._fetch("users/me/blocks/count/%s" % facet)
    return results

  def get_parent_attachments(self, uuid):
    return self._fetch("blocks/%s/parent-attachments" % uuid)

  def get_more_action_links(self, uuid):
    return self._fetch("blocks/%s/more-action-links" % uuid)
  
  def get_more_actions(self, uuid):
    return self._fetch("blocks/%s/more-actions" % uuid)


  def follow_user(self, userId):
    """ follows the requested user """
    return self._fetch("users/me/follow/%s" % userId, method='POST') != None

  def find_new_blocks(self, type_filter=None, text=None, location=None, limit=10):
    """
    searches springpad and the web for new blocks matching the parameters
    Arguments:
    - `type_filter`: name of the type or None
    - `text`: text to search for in the name or properties of the block
    - `location`: if specified, this can either be a string (e.g., Cambridge, MA) or a dict contain lat/lng information
    - `limit`: maximum number of results to return
    - `resp_format`: desired format of the response
    """
    params = {'limit':limit, 'text':text}
    
    if isinstance(location, str):
      if text is None:
        params['text'] = location
      else:
        params['text'] = text + ' ' + location
    elif isinstance(location, dict):
      params['lat'] = locations['lat']
      params['lng'] = locations['lng']
    
    if type_filter is None:
      return self._fetch("blocks/all", parameters=params)
    else:
      return self._fetch("blocks/types/%s/all" % type_filter, parameters=params)

  def attach_file(self, uuid, bytes, filename=None, description=None):
    import base64
    encoded = base64.b64encode(bytes)

    # the ',%s' % encoded bit is a hack to work-around a bug in springpad as of July 11, 2012.
    # should be fixed by next week
    data = self._fetch("users/me/blocks/%s/files" % uuid, post_data=',%s' % encoded, \
                   parameters = {'filename':filename, 'description':description, 'encoding': 'base64'},
                   method='POST')
    return True

  def attach_photo(self, uuid, bytes, type='png', filename=None, description=None):
    import base64
    encoded = base64.b64encode(bytes)

    data = self._fetch("users/me/blocks/%s/photos" % uuid, post_data='data:image/%s;base64,%s' % (type,encoded), \
                   parameters = {'filename':filename, 'description':description, 'encoding': 'base64'},
                   method='POST')
    return True
      
  def get_user(self, user_id):
    """Takes either the username, or email and fetches info about the user from springpad."""
    return self._fetch("users/%s" % user_id)

  def new_uuid(self):
    """Convenience method that returns a properly formed UUID for the current user.
       
       Warning: the first time this is called it will make a Springpad request to get
       the current user's UUID. So the first call will be slow. All subsequent ones will be 
       quick.
    """
    if not self._user_uuid:
      self._user_uuid = parse_uuid(self.get_user('me')['uuid'])
    uuid_str = str(uuid.uuid4())
    return self._user_uuid[:2] + '3' + uuid_str[3:]
    
  def execute_commands(self, commands):
    """executes commands on the server"""
    self._fetch('users/me/commands', method='POST', post_data=json.dumps(commands))

  def _fetch(self, path, method='GET', parameters=None, post_data=None, headers=None, token=None, as_json=True):
    token = token or self.access_token
    url = BASE_API_URL + path
    headers = headers or {}

    # add required headers
    headers.update({'X-Spring-Client': self.client_name, 'Content-Type': 'application/json; charset=UTF-8'})

    if self.using_oauth():
      request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=token, http_url=url,
                                                           http_method=method, parameters=parameters)

      request.sign_request(self.sig_method, self.consumer, token)
      url = request.to_url()
#      print url
    else:
      headers.update({'X-Spring-Username': self.username, 'X-Spring-Password': self.password})

    resp, data = httplib2.Http().request(url, method=method, body=post_data, headers=headers) 

    if resp.status == 403:
      raise SecurityError, "Failed to authenticate. Ensure that tokens are setup. HTTP: (%d) %s" % (resp.status, resp.reason)
    elif resp.status != 200:
      raise Exception, "Error fulfilling request. HTTP: (%d) %s" % (resp.status, resp.reason)

    if as_json:
      return json.loads(data)
    else:
      return data

def parse_uuid(json_uuid):
  """parses a json uuid in the /UUID(...)/ format"""
  return json_uuid[6:len(json_uuid) - 2]
  
def parse_type(json_type):
  """parses out the type name to return"""
  return json_type[6:len(json_type) - 2]
  
def parse_date(json_date):
  """parses out the date in the json string and returns a python date object"""
  dateStr = json_date[6:len(json_date) - 2]
  return datetime.fromtimestamp(int(dateStr) / 1000)
  
def isuuid(val):
  """tests whether this is a uuid string"""
  return (isinstance(val, str) or isinstance(val, unicode)) and len(val) == 36 and val[8] == '-' and val[13] == '-' and val[18] == '-' and val[23] == '-'

def get_json_value(value):
  """returns a python value properly formatted for json"""
  if isuuid(value):
    return "/UUID(%s)/" % value
  elif isinstance(value, datetime):
    return "/Date(%i)/" % int(mktime(value.timetuple()) * 1000)
  elif isinstance(value, Block):
    return get_json_value(value.uuid)
  else:
    return value
    
