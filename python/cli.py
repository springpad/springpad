#!/usr/bin/env python
# encoding: utf-8
import uuid, ConfigParser, os, sys, json
from optparse import OptionParser
from oauth import oauth
from spring import Client, BASE_API_URL, isuuid

def print_as_json(obj):
  """Takes object, converts it to JSON, and then pretty prints it."""
  print json.dumps(obj, indent=4)


def main():
  usage = """ ./cli.py [options] command args
    register [consumer-key] [consumer-secret]     Stores OAuth data in the config for the app to use
    auth                                          Starts the user authentication process. Repeated calls will overwrite access tokens
    get [uuid1, uuid2, ...]                       Prints blocks by UUID. Use -f to get specific fields from the block
    user [username]                               Prints the user specified. Using 'me' will print the current user
    search                                        Prints blocks matching the criteria. (e.g., type with --type)
    find                                          Prints blocks from the Web and the user's friends maching search. Use with --type and --text
    delete [uuid1, uuid2, ...]                    Deletes blocks
    execute [command]                             Takes a JSON commands string and executes it
    attach [path]                                 Attaches a file to a block. Use with --uuid to specify the block
    
    Examples:

    Start by registring your OAuth keys (visit http://springpadit.com/developers for more information)
    ./cli.py register 343413412343 3413412kk1344

    Authenticate by running this and then follow the instructions on the screen:
    ./cli.py auth

    Then run queries like:

    ./cli.py user me
    ./cli.py user aykroyd
    ./cli.py -l 1 -s 3 --type=Task search
    ./cli.py execute "[['set', '/UUID(4234d039-1bad-cef3-a8de-88bab513cdd8)/', 'name', 'Make a cool integration with springpad!']]"
    ./cli.py get 4234d039-1bad-cef3-a8de-88bab513cdd8
    
    """

  parser = OptionParser(usage=usage)
  parser.add_option("-F", "--field", action="append", type="string", dest="field", 
      help="Specify a field to retrieve. Dotted (properties.date) fields supported", metavar="FIELD")
  parser.add_option("-n", "--type", type="string", dest="type", help="specifies a type name for block queries")
  parser.add_option("-t", "--text", type="string", help="text to search for")
  parser.add_option("-i", "--uuid", type="string", metavar="UUID", help="specifies a uuid for other calls")
  parser.add_option("-l", "--limit", dest="limit", default=5, help="limits the number of results returned by the query")
  parser.add_option("-s", "--start", dest="start", default=0, help="start results with the nth matching result")

  (options, args) = parser.parse_args(sys.argv[1:])

  if len(args) == 0:
    parser.print_help()
    exit(1)
  
  command = args[0]

  config = ConfigParser.ConfigParser()
  config.read([os.path.expanduser('~/.springpad')])
  # get consumer key and secret
  if config.has_section('access'):
    consumer_key = config.get('access', 'key')
    consumer_secret = config.get('access', 'secret')
  else:
    consumer_key = None
    consumer_secret = None

  if config.has_option('access', 'token'):
    token = oauth.OAuthToken.from_string(config.get('access', 'token'))
  else:
    token = None

  service = Client(consumer_key, consumer_secret, access_token=token)

  if command == 'register':
    if len(args) != 3:
      print "USAGE: ./cli.py register [consumer-key] [consumer-secret]"
    else:
      config.add_section('access')
      config.set('access', 'key', args[1])
      config.set('access', 'secret', args[2])          
      with open(os.path.expanduser('~/.springpad'), 'w') as fh:
        config.write(fh)
  
  elif command == 'auth':
    token = None
    service.access_token = None
    request_token = service.get_request_token()
    url = BASE_API_URL + 'oauth-authorize?' + str(request_token)
    print "Please go to the following URL and click the authorize button:\n\n%s\n" % url
    raw_input('<<<press enter after you hit the authorize button on the webpage>>>')
    access_token = service.get_access_token(request_token)
    if access_token:
      config.set('access', 'token', "%s" % access_token)
      with open(os.path.expanduser('~/.springpad'), 'w') as fh:
        config.write(fh)
      print "You will by authorized for that account from now on."
    else:
      print "Failed to authenticate your account."

  # fetches a block by uuid or path
  elif command == 'get':
    raw=True
    if options.field:
      raw=False

    for uuid in args[1:]:
      if isuuid(uuid):
        response = service.get_block(uuid)
      else:
        print "Error: get expect a UUID but got %s" % uuid
        sys.exit(0)

      if options.field:
        # fields support bean style access
        for field in options.field:
          parts = field.split('.')
          root = response
          for part in parts:
            value = root.get(part)
            root = value

          if isinstance(value, time.struct_time):
            value = time.strftime('%a, %d %b %Y %H:%M:%S +0000', value)

          print value
      else:
        print_as_json(response)

  elif command == 'user':
    if len(args) == 1:
      parser.print_help()
    else:
      print_as_json(service.get_user(args[1]))
  elif command == 'search':
    response = service.get_blocks(type_filter=options.type, start=options.start, limit=options.limit)
    print_as_json(response)

  elif command == 'find':
    print_as_json(service.find_new_blocks(type_filter=options.type, text=options.text))

  elif command == 'execute':
    if len(args) == 1:
      print 'Need to provide commands to execute.'
    else:
      try:
        cmds = json.loads(args[1])
        service.execute_commands(cmds)
      except ValueError:
        print "Unable to parse JSON commands: %s" % args[1]
      except Exception as e:
        print "Error executing commands: %s" % e

  elif command == 'delete':
      for option in args[1:]:
        service.execute_commands([['delete', "/UUID(%s)/" % option]])
      print "Delete successful"

  elif command == 'attach':
    if len(args) == 1:
      print "USAGE ./cli.py attach /path/to/file"
    else:
      uuid = options.uuid
      path = args[1] 
      with open(path, "rb") as fh:
        import re
        bytes = fh.read()
        if re.match(".*\.(jpg|jpeg)$", path):
          service.attach_photo(uuid, bytes, filename=path[path.rfind("/"):])
        else:
          service.attach_file(uuid, bytes, filename=path[path.rfind("/"):])

  else:
    parser.print_help()

  sys.exit(1)


if __name__ == "__main__":
  main()
