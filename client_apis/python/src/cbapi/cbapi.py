#
# CARBON BLACK API
# Copyright Bit9, Inc. 2014
# support@carbonblack.com
#

import json
import time
import requests
import shutil

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass

class CbApi(object):
    """ Python bindings for Carbon Black API 
    Example:

    import cbapi
    cb = cbapi.CbApi("http://cb.example.com", token="apitoken")
    # get metadata for all svchost.exe's not from c:\\windows
    procs = cb.process_search(r"process_name:svchost.exe -path:c:\\windows\\")  
    for proc in procs['results']:
        proc_detail = cb.process(proc['id'])
        print proc_detail['process']['start'], proc_detail['process']['hostname'], proc_detail['process']['path']
    """
    def __init__(self, server, ssl_verify=True, token=None, client_validation_enabled=True, ignore_system_proxy=False,
                 use_https_proxy=None, use_http_proxy=None):
        """ Requires:
                server -    URL to the Carbon Black server.  Usually the same as 
                            the web GUI.
                ssl_verify - verify server SSL certificate
                token - this is for CLI API interface
        """

        if not server.startswith("http"):
            raise TypeError("Server must be URL: e.g, http://cb.example.com")

        if token is None:
            raise TypeError("Missing required authentication token.")

        self.server = server.rstrip("/")
        self.ssl_verify = ssl_verify
        self.token = token
        self.token_header = {'X-Auth-Token': self.token}
        self.session = requests.Session()
        self.client_validation_enabled = client_validation_enabled

        self.proxies = {}
        if ignore_system_proxy:         # see https://github.com/kennethreitz/requests/issues/879
            self.proxies = {
                'no': 'pass'
            }
        else:
            if use_http_proxy:
                self.proxies['http'] = use_http_proxy
            if use_https_proxy:
                self.proxies['https'] = use_https_proxy

    def info(self):
        """ Provide high-level information about the Carbon Black Enterprise Server.

            **NOTE** This function is provided for convenience and may change in
                     future versions of the Carbon Black API

            Returns a python dictionary with the following field:
                - version - version of the Carbon Black Enterprise Server
        """
        r = self.cbapi_get("%s/api/info" % self.server)
        r.raise_for_status()
        return json.loads(r.content)

    def license_status(self):
        """ Provide a summary of the current applied license
        """
        r = self.cbapi_get("%s/api/v1/license" % (self.server,))
        r.raise_for_status()
        return json.loads(r.content)

    def apply_license(self, license):
        """ Apply a new license to the server
        """
        r = self.cbapi_post("%s/api/v1/license" % (self.server,),
                            data=json.dumps({'license': license}))
        r.raise_for_status()

    def concurrent_license_info(self, start_date, end_date):
        """
        Get the concurrent license info for a given date range
        :param start_date: the start date
        :param end_date: the end date
        """
        url = "{0}/api/concurrent_license_info/{1:%Y%m%d}/{2:%Y%m%d}".format(self.server, start_date, end_date)
        r = requests.get(url=url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def communication_settings(self):
        """
        Get the current communication settings
        """
        url = "%s/api/communication_settings" % self.server
        r = requests.get(url=url,  headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def communication_settings_modify(
        self,
        settings=None,
        enabled=None,
        statistics=None,
        community_participation=None,
        mail_server_type=None,
        smtp_connection_type=None,
        smtp_server=None,
        smtp_port=None,
        smtp_username=None,
        smtp_password=None
    ):
        """
        Update communication settings. Settings can be updated individually or as a part of one settings dictionary
        :param settings: the full communication settings dictionary
        :param enabled: is Alliance communication enabled
        :param statistics: are performance statistics enabled
        :param community_participation: support the Alliance Threat Intelligence Community
        :param mail_server_type: one of ("own", "cb", or "none"). "own" requires smtp_* arguments to be populated
        :param smtp_connection_type: one of ("tls", "ssl", or "insecure")
        :param smtp_server: the name of the user's own mail server
        :param smtp_port: the port of the user's own mail server
        :param smtp_username: the username for the user's own mail server
        :param smtp_password: the password for the user's own mail server
        """

        request = settings or {}

        if enabled is not None:
            request["enabled"] = enabled

        if statistics is not None:
            request["statistics"] = statistics

        if community_participation is not None:
            request["community_participation"] = community_participation

        if mail_server_type is not None:
            request["mail_server_type"] = mail_server_type

        if smtp_connection_type is not None:
            request["smtp_connection_type"] = smtp_connection_type

        if smtp_server is not None:
            request["smtp_server"] = smtp_server

        if smtp_port is not None:
            request["smtp_port"] = smtp_port

        if smtp_username is not None:
            request["smtp_username"] = smtp_username

        if smtp_password is not None:
            request["smtp_password"] = smtp_password

        if self.client_validation_enabled:
            for key in ["enabled", "statistics", "community_participation"]:
                if key in request and request[key] is None:
                    raise ValueError("%s cannot be None" % key)

            if "mail_server_type" in request:
                if request["mail_server_type"] not in ["cb", "own", "none", ""]:  # "none" and "" both mean disabled
                    raise ValueError("Invalid mail_server_type: %s" % request["mail_server_type"])

                if request["mail_server_type"] == "own":
                    for key in ["smtp_connection_type", "smtp_server", "smtp_port", "smtp_username", "smtp_pasword"]:
                        if key in request and request[key] is None:
                            raise ValueError("%s is required when mail_server_type is \"own\"" % key)

                    if request["smtp_connection_type"] not in ["tls", "ssl", "insecure"]:
                        raise ValueError("Invalid smtp_connection_type: %s" % request["smtp_connection_type"])

        url = "%s/api/communication_settings" % self.server
        r = requests.post(url=url,  headers=self.token_header, data=json.dumps(request), verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def check_for_new_feeds(self):
        """
        Check for new alliance feeds
        """
        url = "%s/api/internal/alliance" % self.server
        r = requests.post(url=url,  headers=self.token_header, data=json.dumps({}), verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def alliance_status(self):
        """
        Get the alliance status
        """
        url = "%s/api/v1/alliance_status" % self.server
        r = requests.get(url=url,  headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def get_platform_server_config(self):
        """ Get Bit9 Platform Server configuration
            This includes server address and authentication information

            Must authenticate as a global administrator for this data to be available

            Note: the secret is never available (via query) for remote callers, although
                  it can be applied
        """
        r = self.cbapi_get("%s/api/v1/settings/global/platformserver" % (self.server,))
        r.raise_for_status()
        return json.loads(r.content)

    def set_platform_server_config(self, platform_server_config):
        """ Sets the Bit9 Platform Server configuration
            This includes the server address, username, and password

            Must authenticate as a global administrator to have the rights to set this config

            platform_server_config is expected to be a python dictionary with the following keys:
                username : username for authentication
                password : password for authentication
                server   : server address
        """
        r = self.cbapi_post("%s/api/v1/settings/global/platformserver" % (self.server,),
                            data=json.dumps(platform_server_config))

    def test_platform_server_config(self):
        """
        Tests the current Bit9 Platform Server configuration
        This includes the server address, username, and password

        Must authenticate as a global administrator to have the rights to set this config
        """
        url = "%s/api/v1/settings/global/platformserver/test" % self.server
        r = requests.get(url=url, headers=self.token_header)
        r.raise_for_status()

    def process_search(self, query_string, start=0, rows=10, sort="last_update desc", facet_enable=True):
        """ Search for processes.  Arguments:

            query_string -      The Cb query string; this is the same string used in the
                                "main search box" on the process search page.  "Contains text..."
                                See Cb Query Syntax for a description of options.

            start -             Defaulted to 0.  Will retrieve records starting at this offset.
            rows -              Defaulted to 10. Will retrieve this many rows.
            sort -              Default to last_update desc.  Must include a field and a sort
                                order; results will be sorted by this param.
            facet_enable -      Enable facets on the result set. Defaults to enable facets (True)

            Returns a python dictionary with the following primary fields:
                - results - a list of dictionaries describing each matching process
                - total_results - the total number of matches
                - elapsed - how long this search took
                - terms - a list of strings describing how the query was parsed
                - facets - a dictionary of the facet results for this search
        """

        # setup the object to be used as the JSON object sent as a payload
        # to the endpoint

        if facet_enable:
            facet_param = ['true', 'true']
        else:
            facet_param = ['false', 'false']

        params = {
            'sort': sort,
            'facet': facet_param,
            'rows': rows,
            'cb.urlver': ['1'],
            'start': start}

        # a q (query) param only needs to be specified if a query is present
        # to search for all processes, provide an empty string for q
        #
        if len(query_string) > 0:
            params['q'] = [query_string]

        # HTTP POST and HTTP GET are both supported for process search
        # HTTP POST allows for longer query strings
        #
        r = self.cbapi_post("%s/api/v1/process" % self.server, data=json.dumps(params))
        r.raise_for_status()
        return r.json()

    def process_summary(self, id, segment, children_count=15):
        """ get the detailed metadata for a process.  Requires the 'id' field from a process
            search result, as well as a segment, also found from a process search result.
            The results will be limited to children_count children metadata structures.

            Returns a python dictionary with the following primary fields:
                - process - metadata for this process
                - parent -  metadata for the parent process
                - children - a list of metadata structures for child processes
                - siblings - a list of metadata structures for sibling processes
        """
        r = self.cbapi_get("%s/api/v1/process/%s/%s?children=%d" % (self.server, id, segment, children_count))
        r.raise_for_status()
        return r.json()

    def process_events(self, id, segment):
        """ get all the events (filemods, regmods, etc) for a process.  Requires the 'id' and 'segment_id' fields
            from a process search result"""
        r = self.cbapi_get("%s/api/v1/process/%s/%s/event" % (self.server, id, segment))
        r.raise_for_status()
        return r.json()

    def process_report(self, id, segment=0):
        """ download a "report" package describing the process
            the format of this report is subject to change"""
        r = self.cbapi_get("%s/api/v1/process/%s/%s/report" % (self.server, id, segment))
        r.raise_for_status() 
        return r.content

    def binary_search(self, query_string, start=0, rows=10, sort="server_added_timestamp desc", facet_enable=True):
        """ Search for binaries.  Arguments:


            query_string -      The Cb query string; this is the same string used in the
                                "main search box" on the binary search page.  "Contains text..."
                                See Cb Query Syntax for a description of options.

            start -             Defaulted to 0.  Will retrieve records starting at this offset.

            rows -              Defaulted to 10. Will retrieve this many rows.
            sort -              Default to server_added_timestamp desc.  Must include a field and a sort
                                order; results will be sorted by this param.
            facet_enable -      Enable facets on the result set. Defaults to enable facets (True)

            Returns a python dictionary with the following primary fields:
                - results - a list of dictionaries describing each matching binary
                - total_results - the total number of matches
                - elapsed - how long this search took
                - terms - a list of strings describing how the query was parsed
                - facets - a dictionary of the facet results for this saerch
        """
        if facet_enable:
            facet_param = ['true', 'true']
        else:
            facet_param = ['false', 'false']

        # setup the object to be used as the JSON object sent as a payload
        # to the endpoint
        params = {
            'sort': sort,
            'facet': facet_param,
            'rows': rows,
            'cb.urlver': ['1'],
            'start': start}

        # a q (query) param only needs to be specified if a query is present
        # to search for all binaries, provide an empty string for q
        if len(query_string) > 0:
            params['q'] = [query_string]

        # do a post request since the URL can get long
        # @note GET is also supported through the use of a query string
        r = self.cbapi_post("%s/api/v1/binary" % self.server, data=json.dumps(params))
        r.raise_for_status()
        return r.json()

    def binary_enum(self):
        '''
        Retrieves all the binary files stored in the server
        '''
        url = "%s/api/v1/binary" % (self.server,)

        r = requests.get(url, headers=self.token_header,verify = self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def binary_summary(self, md5):
        """ get the metadata for a binary.  Requires the md5 of the binary.

            Returns a python dictionary with the binary metadata. """
        r = self.cbapi_get("%s/api/v1/binary/%s/summary" % (self.server, md5))
        r.raise_for_status()
        return r.json()

    def binary(self, md5hash):
        """
        download binary based on md5hash
        """

        r = self.cbapi_get("%s/api/v1/binary/%s" % (self.server, md5hash))

        r.raise_for_status()
        return r._content

    def binary_info(self, md5hash):
        '''
        download binary based on md5hash
        '''

        r = requests.get("%s/api/v1/binary/%s" % (self.server, md5hash),
                         headers=self.token_header, verify=self.ssl_verify, stream = True)
        r.raise_for_status()
        shutil.copy(r, "~/Downloads")

    def binary_hits_enum(self, md5):
        '''
        Enumerates all binary threat_intel_hits
        '''

        r = requests.get("%s/api/v1/binary/%s/threat_intel_hits" % (self.server,md5),
                         headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()


    def binary_hits_add(self):
        '''
        Adds a binary threat_intel_hit to the Carbon Black server
        '''


    def sensor(self, sensor_id):
        """
        get information about a single sensor, as specified by sensor id
        """

        r = self.cbapi_get("%s/api/v1/sensor/%s" % (self.server, sensor_id))
        r.raise_for_status()
        return r.json()

    def sensors(self, query_parameters={}):
        """
        get sensors, optionally specifying search criteria

        as of this writing, supported search criteria are:
          ip - any portion of an ip address
          hostname - any portion of a hostname, case sensitive
          groupid - the sensor group id; must be numeric

        returns a list of 0 or more matching sensors
        """

        url = "%s/api/v1/sensor?" % (self.server,)
        for query_parameter in query_parameters.keys():
            url += "%s=%s&" % (query_parameter, query_parameters[query_parameter])

        r = self.cbapi_get(url)
        r.raise_for_status()
        return r.json()

    def sensor_installer(self, type, group_id=1):
        """
        get sensor installer package for a specified sensor group

        group_id - the group_id to download an installer for; defaults to 1 "Default Group"
        type - the sensor installer type.  [WindowsEXE|WindowsMSI|OSX|Linux]
        """

        # set up a mapping of types to REST endpoints
        #
        mapping = {\
                    'WindowsEXE': '/api/v1/group/%s/installer/windows/exe' % (group_id,),\
                    'WindowsMSI': '/api/v1/group/%s/installer/windows/msi' % (group_id,),\
                    'OSX':        '/api/v1/group/%s/installer/osx' % (group_id,),\
                    'Linux':      '/api/v1/group/%s/installer/linux' % (group_id,),\
                  }

        if self.client_validation_enabled:
            # verify that the type parameter is a known value
            #
            if not mapping.has_key(type):
                raise ValueError("Unrecognized type '%s'; should be one of 'WindowsEXE', 'WindowsMSI', 'OSX', or 'Linux'" % (type,))

        # build the fully-qualified URL
        #
        url = "%s%s" % (self.server, mapping[type])
        
        r = self.cbapi_get(url)
        r.raise_for_status()
       
        return r.content 

    def sensor_backlog(self):
        """
        retrieves a summary of aggregate sensor backlog across all active sensors
        """

        url = "%s/api/v1/sensor/statistics" % (self.server,)

        r = self.cbapi_get(url)
        r.raise_for_status()

        return r.json()

    def sensor_force_sync(self, sensor_id, group_id, event_log_flush_time):
        '''
        Force a single sensor to sync via the API
        :param sensor_id: the sensor id
        :param group_id: the id of the group this sensor belongs to
        :param event_log_flush_time:
        :return:
        '''

        url = "%s/api/v1/sensor/%s" % (self.server, sensor_id)
        request = {\
            "event_log_flush_time": event_log_flush_time,\
            "group_id": group_id,\
        }

        r = requests.put(url, headers=self.token_header, verify=self.ssl_verify, data = json.dumps(request))
        r.raise_for_status()

    def server_enum(self):
        """
        Get all server nodes in the environment
        """
        url = "%s/api/server" % self.server

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def server_modify(self, server_id, server):
        """
        Update a server
        :param server_id: The ID of the server to update
        :param server: The modified server object
        """
        url = "%s/api/server/%s" % (self.server, server_id)

        r = requests.put(url, headers=self.token_header, data=json.dumps(server), verify=self.ssl_verify)
        r.raise_for_status()
        return

    def watchlist(self, id=None):
        """
        get all watchlists or a single watchlist
        """

        url = "%s/api/v1/watchlist" % (self.server)
        if id is not None:
            url = url + "/%s" % (id,)

        r = self.cbapi_get(url)
        r.raise_for_status()
        return r.json()

    def watchlist_add(self, type, name, search_query, id=None, readonly=False, basic_query_validation=True):
        """
        adds a new watchlist
        """

        # as directed by the caller, provide basic parameter validation
        if basic_query_validation:

            # ensure that the index type is either events or modules
            if "events" != type and "modules" != type:
                raise ValueError("type must be one of events or modules")

            # ensure that the query begins with q=
            if not "q=" in search_query:
                raise ValueError("watchlist queries must be of the form: cb.urlver=1&q=<query>")

            # ensure that a cb url version is included
            if "cb.urlver" not in search_query:
                search_query = "cb.urlver=1&" + search_query

            # ensure that the query itself is properly encoded
            for kvpair in search_query.split('&'):
                if len(kvpair.split('=')) != 2:
                    continue
                if kvpair.split('=')[0] != 'q':
                    continue

                # the query itself must be percent-encoded
                # verify there are only non-reserved characters present
                # no logic to detect unescaped '%' characters
                for c in kvpair.split('=')[1]:
                    if c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~%":
                        raise ValueError("Unescaped non-reserved character '%s' found in query; use percent-encoding" % c)

        request = {\
                      'index_type': type,\
                      'name': name,\
                      'search_query': search_query,\
                      'readonly': readonly\
                  }

        if id is not None:
            request['id'] = id

        url = "%s/api/v1/watchlist" % (self.server,)

        r = self.cbapi_post(url, data=json.dumps(request))
        r.raise_for_status()

        return r.json()

    def watchlist_del(self, id):
        """
        deletes a watchlist
        """
        request = {'id': id}

        url = "%s/api/v1/watchlist/%s" % (self.server, id)
        
        r = self.cbapi_delete(url, data=json.dumps(request))
        r.raise_for_status()

        return r.json()

    def watchlist_modify(self, id, watchlist):
        """
        updates a watchlist
        """
        url = "%s/api/v1/watchlist/%s" % (self.server, id)

        r = self.cbapi_put(url, data=json.dumps(watchlist))
        r.raise_for_status()

        return r.json()

    def watchlist_action_get(self, watchlist_id):
        """
        gets actions for a watchlist
        :param watchlist_id: the ID of the watchlist
        :return: an array of actions associated with the watchlist
        """

        url = "%s/api/v1/watchlist/%s/action" % (self.server, watchlist_id)

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def watchlist_action_add(self, watchlist_id, action_type_id, email_recipient_user_ids=[]):
        """
        add an action to a watchlist
        :param watchlist_id: the ID of the watchlist
        :param action_type_id: the ID of the action type
        :param email_recipient_user_id: the ID of the user who will receive email
        :return: a dictionary with the new action ID in "action_id"
        """

        request = {
            "action_data": "{\"email_recipients\":[%s]}" % (",".join(str(user_id) for user_id in email_recipient_user_ids)),
            "action_type": action_type_id,
            "group_id": watchlist_id,
            "watchlist_id": watchlist_id
        }

        url = "%s/api/v1/watchlist/%s/action" % (self.server, watchlist_id)

        r = requests.post(url, headers=self.token_header, data=json.dumps(request), verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def watchlist_action_modify(self, watchlist_id, action_id, action):
        """
        modify an action for a watchlist
        :param watchlist_id: the ID of the watchlist
        :param action_id: the ID of the action on the watchlist
        :param action: a dictionary representing the modified action
        :return: a dictionary with the request status in "result"
        """

        url = "%s/api/v1/watchlist/%s/action/%s" % (self.server, watchlist_id, action_id)

        r = requests.put(url, headers=self.token_header, data=json.dumps(action), verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def watchlist_action_del(self, watchlist_id, action_id):
        """
        delete an action for a watchlist
        :param watchlist_id: the ID of the watchlist
        :param action_id: the ID of the action on the watchlist
        :return: a dictionary with the request status in "result"
        """

        url = "%s/api/v1/watchlist/%s/action/%s" % (self.server, watchlist_id, action_id)

        r = requests.delete(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def feed_add_from_url(self, feed_url, enabled=True, validate_server_cert=False, use_proxy=False,
                          feed_username=None, feed_password=None, ssl_client_crt=None, ssl_client_key=None):
        """
        add a new feed to the Carbon Black server, as specified by URL
        """
        request = {
                      'use_proxy': use_proxy,
                      'validate_server_cert': validate_server_cert,
                      'feed_url': feed_url,
                      'enabled': enabled,
                  }

        if feed_username:
            request['username'] = feed_username
        if feed_password:
            request['password'] = feed_password

        if ssl_client_crt:
            request['ssl_client_crt'] = ssl_client_crt
        if ssl_client_key:
            request['ssl_client_key'] = ssl_client_key

        url = "%s/api/v1/feed" % (self.server,)
        
        r = self.cbapi_post(url, data=json.dumps(request))
        r.raise_for_status()

        return r.json()

    def user_add_from_data(self, username, first_name, last_name, password, confirm_password, global_admin, teams, email):
        """
        add a new user to the server
        """
        request = {
            'username': username,
            'first_name': first_name,
            'last_name': last_name,
            'password': password,
            'confirm_password': confirm_password,
            'global_admin': global_admin,
            'teams': teams,
            'email': email,
        }
        url = "%s/api/user" % (self.server,)
       
        r = self.cbapi_post(url, data = json.dumps(request))
        r.raise_for_status()

        return r.json()

    def feed_get_id_by_name(self, name):
        """
        helper function to find the feed id given the feed name
        """

        for feed in self.feed_enum():
            if feed['name'].lower() == name.lower():
                return feed['id']

        # did not find it
        #
        return None

    def feed_enum(self):
        """
        enumerate all configured feeds
        """

        url = "%s/api/v1/feed" % (self.server,)

        r = self.cbapi_get(url)
        r.raise_for_status()

        return r.json()

    def user_enum(self):
        """
        enumerate all users
        """

        url = "%s/api/users" % (self.server,)

        r = self.cbapi_get(url)
        r.raise_for_status()

        return r.json()

    def team_enum(self):
        """
        enumerate all teams
        """

        url = "%s/api/teams" % (self.server,)
        
        r = self.cbapi_get(url)
        r.raise_for_status()

        return r.json()

    def feed_info(self, id):
        """
        retrieve information about an existing feed, as specified by id

        note: the endpoint /api/v1/feed/<id> is not supported as of CB server 5.0
        """
        feeds = self.feed_enum()
        for feed in feeds:
          if str(feed['id']) == str(id):
              return feed
    
    def user_info_from_list(self, username):
        """
        retrieve information about an existing user, as specified by username

        note: the endpoint /api/users/<id> is not supported as of CB server 5.0
        """
        users = self.user_enum()
        for user in users:
          if user['username'] == username:
              return user

    def team_get_id_by_name(self, name):
        """
        retrieve information about an existing team, specified by name
        """

        teams = self.team_enum()
        for team in teams:
            if team['name'] == name:
                return team['id']

    def team_info(self, id):
        """
        retrieve information about an existing team, specified by id
        """

        teams = self.team_enum()
        for team in teams:
            if team['id'] == id:
                return team

    def output_user_activity(self):
        """
        retrieve all user activity from server
        """

        url = "%s/api/useractivity" % (self.server,)
    
        r = self.cbapi_get(url)
        r.raise_for_status()

        useractivity = r.json()

        print "%-12s| %-14s | %-12s | %-5s | %-20s" %("Username", "Timestamp", "Remote Ip", "Result", "Description")
        for attempt in useractivity:
            print "%-12s| %-14s | %-12s | %-5s | %-20s" % (attempt['username'], attempt['timestamp'], attempt['ip_address'], attempt['http_status'], attempt['http_description'])

    def output_user_activity_success(self):
        """
        retrieve all user activity from server and filter out successful attempts
        """

        url = "%s/api/useractivity" % (self.server,)
        
        r = self.cbapi_get(url)
        r.raise_for_status()

        useractivity = r.json()

        successes = []
        for attempt in useractivity:
            if attempt['http_status'] == 200:
                successes.append(attempt)

        print "%-12s| %-14s | %-12s | %-5s | %-20s" %("Username", "Timestamp", "Remote Ip", "Result", "Description")
        for attempt in successes:
            print "%-12s| %-14s | %-12s | %-5s | %-20s" % (attempt['username'], attempt['timestamp'], attempt['ip_address'], attempt['http_status'], attempt['http_description'])

    def output_user_activity_failure(self):
        """
        retrieve all user activity from server and filter out successful attempts
        """

        url = "%s/api/useractivity" % (self.server,)
        
        r = self.cbapi_get(url)
        r.raise_for_status()

        useractivity = r.json()

        failures = []
        for attempt in useractivity:
            if attempt['http_status'] == 403:
                failures.append(attempt)

        print "%-12s| %-14s | %-12s | %-5s | %-20s" %("Username", "Timestamp", "Remote Ip", "Result", "Description")
        for attempt in failures:
            print "%-12s| %-14s | %-12s | %-5s | %-20s" % (attempt['username'], attempt['timestamp'], attempt['ip_address'], attempt['http_status'], attempt['http_description'])

    def feed_modify(self, id, feed):
        '''
        updates a feed
        '''
        url = "%s/api/v1/feed/%s" % (self.server, id)

        r = requests.put(url, headers=self.token_header, data=json.dumps(feed), verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def feed_del(self, id):
        """
        delete a feed, as specified by id
        """
        url = "%s/api/v1/feed/%s" % (self.server, id)

        r = self.cbapi_delete(url)
        r.raise_for_status()

        return r.json()
    
    def user_del(self,username):


        url = "%s/api/user/%s" % (self.server, username)
        
        r = self.cbapi_delete(url)
        r.raise_for_status()

        return r.json()

    def feed_synchronize(self, name, full_sync=True):
        """
        force the synchronization of a feed

        this triggers the CB server to refresh the feed.  it does not result in immediate
        tagging of any existing process or binary documents that match the feed.  it does result
        in any new incoming data from sensors being tagged on ingress.
        """

        feed_request = self.cbapi_get("%s/api/v1/feed" % self.server)
        feed_request.raise_for_status()

        for feed in feed_request.json():
            if feed['name'] == name:
                sync_request = self.cbapi_post("%s/api/v1/feed/%s/synchronize" % (self.server, feed["id"]),
                                               data=json.dumps({"full_sync": full_sync}))
                if sync_request.status_code == 200:
                    return {"result": True}
                elif sync_request.status_code == 409:
                    return {"result": False, "reason": "feed disabled"}
                else:
                    raise Exception("Unexpected response from /api/v1/feed/%s/synchronize: %s"
                                    % (feed['id'], sync_request.status_code))

        return {"result": False, "reason": "feed not found"}

    def feed_report_enum(self, id):
        '''
        enumerate all reports for an existing feed

        note that this will enumerate only the reports that are available on
        the Carbon Black server.  If the feed source has changed since the
        last time the feed was synchronized, these reports may be out-of-date.

        use feed_synchronize to force a feed synchronization
        '''

        url = "%s/api/v1/feed/%s/report" % (self.server, id)

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def feed_report_info(self, feedid, reportid):
        """
        retrieve a single report from a feed
        """

        url = "%s/api/v1/feed/%s/report/%s" % (self.server, feedid, reportid,)

        r = self.cbapi_get(url)
        r.raise_for_status()

        return r.json()

    def user_info(self, username):
        '''
        retrieve information about an existing user, as specified by username
        '''

        url = "%s/api/user/%s" % (self.server, username)

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def user_get_user_by_name(self, first_name, last_name):
        '''
        helper function to find the username given a user's first and last name
        '''

        for user in self.user_enum():
            if user['first_name'].lower() == first_name.lower() and user['last_name'].lower() == last_name.lower():
                return user

        # did not find it
        #
        return None

    def user_activity(self):
        '''
        retrieve all user activity from server
        '''

        url = "%s/api/useractivity" % (self.server,)

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def team_del(self, id):
        '''
        deletes a team, as specified by id
        '''

        url = "%s/api/team/%s" % (self.server, id)

        r = requests.delete(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def team_add_from_data(self, team_name,groups):

        '''
        Adds a new team
        '''

        request = {\
            'group_access' : groups, \
            'name' : team_name, \
        }

        url = "%s/api/team" % (self.server,)


        r = requests.post(url, headers=self.token_header, data = json.dumps(request), verify=self.ssl_verify)

        r.raise_for_status()


        return r.json()

    def team_get_team_by_name(self, name):
        '''
        retrieve an existing team, specified by name
        '''


        teams = self.team_enum()
        for team in teams:
            if team['name'] == name:
                return team

        #did not find it
        return None


    def team_modify(self, id, team):
        """
        Updates a team
        :param id: The ID of the team to modify
        :param team: The modified team object
        :return: a JSON object indicating a successful result
        """

        url = "%s/api/team/%s" % (self.server, id)

        r = requests.put(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    
    def group_enum(self):
        '''
        enumerate all sensor groups
        '''
        
        url = "%s/api/group" % (self.server,)
        
        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        
        return r.json()

    def group_info(self, id):
        '''
        retrieve information about an existing group, specified by id
        '''

        url = "%s/api/group/%s" % (self.server, id)

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        group_list = r.json() #returns a list of length one with the group data

        if not group_list:
            return None
        else:
            return group_list[0] #return the only element in the list of length one

    def group_del(self, id):
        '''
        deletes a group, as specified by id
        '''

        url = "%s/api/group/%s" % (self.server, id)

        r = requests.delete(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def group_add_from_data(self, alert_criticality, banning_enabled, collect_cross_procs, collect_emet_events,
                            collect_filemods, collect_filewritemd5s, collect_moduleinfo, collect_moduleloads,
                            collect_netconns, collect_nonbinary_filewrites, collect_processes, collect_regmods,
                            collect_storefiles, collect_usercontext, datastore_server, max_licenses, name,
                            quota_eventlog_bytes, quota_eventlog_percent, quota_storefile_bytes, quota_storefile_percent,
                            sensor_exe_name, sensor_version, sensorbackend_server, site_id, tamper_level,
                            team_access, vdi_enabled):
        '''
        adds a new group to the server
        '''

        request = {\
            'alert_criticality' : alert_criticality, \
            'banning_enabled' : banning_enabled, \
            'collect_cross_procs' : collect_cross_procs, \
            'collect_emet_events' : collect_emet_events, \
            'collect_filemods' : collect_filemods, \
            'collect_filewritemd5s' : collect_filewritemd5s, \
            'collect_moduleinfo' : collect_moduleinfo, \
            'collect_moduleloads' : collect_moduleloads, \
            'collect_netconns' : collect_netconns, \
            'collect_nonbinary_filewrites' : collect_nonbinary_filewrites, \
            'collect_processes' : collect_processes, \
            'collect_regmods' : collect_regmods, \
            'collect_storefiles' : collect_storefiles, \
            'collect_usercontext' : collect_usercontext, \
            'datastore_server' :datastore_server, \
            'max_licenses' : max_licenses, \
            'name' : name, \
            'quota_eventlog_bytes' : quota_eventlog_bytes, \
            'quota_eventlog_percent' : quota_eventlog_percent, \
            'quota_storefile_bytes': quota_storefile_bytes, \
            'quota_storefile_percent' : quota_storefile_percent, \
            'sensor_exe_name' : sensor_exe_name, \
            'sensor_version' : sensor_version, \
            'sensorbackend_server' : sensorbackend_server, \
            'site_id' : site_id, \
            'tamper_level' : tamper_level, \
            'team_access' : team_access, \
            'vdi_enabled' : vdi_enabled, \
        }

        url = "%s/api/group" % (self.server,)


        r = requests.post(url, headers=self.token_header, data = json.dumps(request), verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def group_get_group_by_name(self,name):
        '''
        retrieve an existing group, specified by group name
        '''

        groups = self.group_enum()
        for group in groups:
            if group['name'] == name:
                return group

        return None


    def threat_report_search(self, query_string, start=0, rows=10, sort="severity_score desc"):
        """ Search for threat reports.  Arguments:

            query_string -      The Cb query string; this is the same string used in the
                                "main search box" on the process search page.  "Contains text..."
                                See Cb Query Syntax for a description of options.

            start -             Defaulted to 0.  Will retrieve records starting at this offset.
            rows -              Defaulted to 10. Will retrieve this many rows.
            sort -              Default to last_update desc.  Must include a field and a sort
                                order; results will be sorted by this param.

            Returns a python dictionary with the following primary fields:
                - results - a list of dictionaries describing each matching process
                - total_results - the total number of matches
                - elapsed - how long this search took
                - terms - a list of strings describing how the query was parsed
                - facets - a dictionary of the facet results for this saerch
        """

        # setup the object to be used as the JSON object sent as a payload
        # to the endpoint
        params = {
            'sort': sort,
            'facet': ['true', 'true'],
            'rows': rows,
            'cb.urlver': ['1'],
            'start': start}

        # a q (query) param only needs to be specified if a query is present
        # to search for all processes, provide an empty string for q
        #
        if len(query_string) > 0:
            params['q'] = [query_string]

        # HTTP POST and HTTP GET are both supported for process search
        # HTTP POST allows for longer query strings
        #
        r = self.cbapi_get("%s/api/v1/threat_report" % self.server, params=params)
        r.raise_for_status()
        return r.json()



    def feed_report_stats(self, feed_id, report_id):
        """
        Get feed report stats
        """

        url = "%s/api/v1/feed/%s/report/%s/stats" % (self.server, feed_id, report_id)

        r = self.cbapi_get(url)
        r.raise_for_status()

        return r.json()

    def feed_action_enum(self,id):
        """
        Gets the actions for a certain feed from the Carbon Black Server
        :param id: the id of the feed
        :return: the actions associated with that feed
        """

        url = "%s/api/v1/feed/%s/action" % (self.server, id)

        r = self.cbapi_get(url)
        r.raise_for_status()

        return r.json()

    def feed_action_add(self, id, action_type_id, email_recipient_user_ids):
        """
        enables one of the three pre-determined actions to be performed
        upon hits for feeds: email, create alert, and write to syslog
        :param id: the id of the feed
        :param action_type_id: the id for the type of action
        :param email_recipient_user_ids: ids of users who will be emailed upon a hit
        :return: the added action
        """
        url = "%s/api/v1/feed/%s/action" % (self.server, id)

        request = {
            "action_data": "{\"email_recipients\":[%s]}" % (",".join(str(user_id) for user_id in email_recipient_user_ids)),
            "action_type": action_type_id,
            "group_id": id, #feed id
            "watchlist_id": None
        }

        r = self.cbapi_post(url, data=json.dumps(request))
        r.raise_for_status()
        return r.json()

    def feed_action_update(self, id , action_id, action_type_id):
        """
        updates a feed action
        :param id: the feed id
        :param action_id: the action id
        :param action_type_id: the action type id
        :return: the updated feed
        """
        url = "%s/api/v1/feed/%s/action/%s" % (self.server, id, action_id)

        old_actions = self.feed_action_enum(id)
        for action in old_actions:
            if int(action['id']) == int(action_id):
                curr_action = action

        request = {
            "action_data": curr_action['action_data'],
            "action_type": action_type_id,
            "group_id": curr_action['group_id'],
            "id" : curr_action['id'],
            "watchlist_id": curr_action['watchlist_id']
        }

        r = self.cbapi_put(url, data=json.dumps(request))
        r.raise_for_status()
        return r.json()

    def feed_action_del(self, id, action_id):
        """
        Deletes a feed action
        :param id: the id of the feed
        :param action_id: the id of the action
        :return: whether successful or not
        """
        url =  "%s/api/v1/feed/%s/action/%s" % (self.server, id, action_id)
        r = self.cbapi_delete(url)
        r.raise_for_status()

        return r.json()

    def feed_requirements(self, id):
        """
        Get feed requirements
        """

        url = "%s/api/v1/feed/%s/requirements" % (self.server, id)

        r = self.cbapi_get(url)
        r.raise_for_status()

        return r.json()

    def alert_search(self, query_string, sort="created_time desc", rows=10, start=0, facet_enable=True):
        """ Search for processes.  Arguments: 

            query_string -      The Alert query string; this is the same string used in the
                                "main search box" on the alert search page.  "Contains text..."
                                See Cb Query Syntax for a description of options.

            start -             Defaulted to 0.  Will retrieve records starting at this offset.
            rows -              Defaulted to 10. Will retrieve this many rows.
            sort -              Default to created_time desc.  Must include a field and a sort
                                order; results will be sorted by this param.

            Returns a list of python dictionaries with the following primary fields:
                - results - a list of dictionaries describing each matching process
                - total_results - the total number of matches
                - elapsed - how long this search took
                - terms - a list of strings describing how the query was parsed
                - facets - a dictionary of the facet results for this saerch
        """

        if facet_enable:
            facet_param = ['true', 'true']
        else:
            facet_param = ['false', 'false']

        params = {
            'sort': sort,
            'facet': facet_param,
            'rows': rows,
            'cb.urlver': ['1'],
            'start': start}

        if len(query_string) > 0:
            params['q'] = [query_string]

        r = self.cbapi_get("%s/api/v1/alert" % self.server, params=params)
        r.raise_for_status()
        return r.json()

    def alert_update(self, alert):
        r = self.cbapi_post("%s/api/v1/alert/%s" % (self.server, alert['unique_id']), data=json.dumps(alert))
        r.raise_for_status()
        return r.json()

    def binary_search_iter(self, query_string, start=0, rows=10, **kwargs):
        """
        A generator for doing a binary search so you can say for results in binary_search_iter
        so that you can keep iterating through all the results.
        :param query_string:
        :param start:
        :param rows:
        :param sort:
        :return:
        """
        our_start = start
        while True:
            resp = self.binary_search(query_string, start=our_start, rows=rows, **kwargs)
            results = resp.get('results')
            for binary in results:
                yield binary
            our_start += len(results)
            if len(results) < rows:
                break

    def process_search_iter(self, query_string, start=0, rows=10, **kwargs):
        """
        A generator for doing a process search so you can say for results in process_search_iter
        so that you can keep going through all the results.

        :param cbapi_inst:
        :param query_string:
        :param start:
        :param rows:
        :param sort:
        :return:
        """
        our_start = start
        while True:
            resp = self.process_search(query_string, start=our_start, rows=rows, **kwargs)
            results = resp.get('results')
            for proc in results:
                yield proc
            our_start += len(results)
            if len(results) < rows:
                break

    def process_search_and_detail_iter(self, query):
        """

        :param query:
        :return:
        """
        for proc in self.process_search_iter(query, start=0, rows=200):
            details = self.process_summary(proc.get('id'), proc.get('segment_id'))
            parent_details = details.get('parent')
            proc_details = details.get('process')
            yield (proc, proc_details, parent_details)

    def process_search_and_events_iter(self, query):
        """

        :param query:
        :return:
        """
        for proc in self.process_search_iter(query, start=0, rows=200):
            events = self.process_events(proc['id'], proc['segment_id']).get('process', [])
            yield (proc, events)


    # class ActionType:
    #     Email=0
    #     Syslog=1
    #     HTTPPost=2
    #     Alert=3
    def watchlist_enable_action(self, watchlist_id, action_type=3, action_data=None):
        """
        Enable an action like create an alert, use syslog, or use email on watchlist hit.
        """
        data = {'action_type': action_type}
        if action_data:
            data['action_data'] = action_data
            data['watchlist_id'] = watchlist_id

        url = "%s/util/v1/watchlist/%d/action" % (self.server, watchlist_id)
        r = self.cbapi_post(url, data=json.dumps(data), timeout=120)
        r.raise_for_status()

        return r.json()

    def live_response_session_list(self):
        url = "%s/api/v1/cblr/session" % (self.server)
        r = self.cbapi_get(url, timeout=120)
        r.raise_for_status()
        return r.json()

    def live_response_session_create(self, sensor_id):
        target_session = None
        for session in self.live_response_session_list():
            if session.get('sensor_id') == sensor_id and session.get('status') == "active":
                target_session = session
                break

        if not target_session:
            url = "%s/api/v1/cblr/session" % (self.server)
            data = {"sensor_id": sensor_id}
            r = self.cbapi_post(url, data=json.dumps(data), timeout=120)
            r.raise_for_status()
            target_session = r.json()
        return target_session

    def live_response_session_status(self, session_id):
        url = "%s/api/v1/cblr/session/%d" % (self.server, session_id)
        r = self.cbapi_get(url, timeout=120)
        r.raise_for_status()
        return r.json()

    def live_response_session_command_post(self, session_id, command, command_object=None):
        url = "%s/api/v1/cblr/session/%d/command" % (self.server, session_id)
        data = {"session_id": session_id, "name": command}
        if type(command_object) is list:
            data['object'] = command_object[0]
            data.update(command_object[1])
        else:
            data['object'] = command_object
        r = self.cbapi_post(url, data=json.dumps(data), timeout=120)
        r.raise_for_status()
        return r.json()

    def live_response_session_command_get(self, session_id, command_id, wait=False):
        url = "%s/api/v1/cblr/session/%d/command/%d" % (self.server, session_id, command_id)
        if wait:
            params = {'wait':'true'}
        else:
            params = {}
        r = self.cbapi_get(url, params=params, timeout=120)
        r.raise_for_status()
        return r.json()

    def live_response_session_command_get_file(self, session_id, file_id):
        url = "%s/api/v1/cblr/session/%d/file/%d/content" % (self.server, session_id, file_id)
        r = self.cbapi_get(url, params={}, timeout=120)
        r.raise_for_status()
        return r.content


    def live_response_session_command_put_file(self, session_id, filepath):
        fin = open(filepath, "rb")
        fpost = {'file': fin}

        url = '%s/api/v1/cblr/session/%d/file' % (self.server, session_id)

        headers = {'X-Auth-Token': self.token}

        r = self.cbapi_post(url, files=fpost, timeout=120)

        r.raise_for_status()
        ret = json.loads(r.content)
        fileid = ret["id"]
        return fileid


    def live_response_session_keep_alive(self, session_id):
        url = '%s/api/v1/cblr/session/%d/keepalive' % (self.server, session_id)
        r = self.cbapi_get(url, timeout=120)
        r.raise_for_status()
        return r.json()

    def sensor_toggle_isolation(self, sensor_id, do_isolation):
        data = self.sensor(sensor_id)

        data["network_isolation_enabled"] = do_isolation

        r = self.cbapi_put("%s/api/v1/sensor/%s" % (self.server, sensor_id),
                           data=json.dumps(data), timeout=120)
        r.raise_for_status()
        return r.status_code == 200

    def sensor_flush_current(self, sensor_id):
        # move it forward 1 day because this should get reset regardless once the sensor is current
        flush_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 86400))
        return self.sensor_flush(sensor_id, flush_time)

    def sensor_flush(self, sensor_id, flush_time):
        data = self.sensor(sensor_id)
        data["event_log_flush_time"] = flush_time #"Wed, 01 Jan 2020 00:00:00 GMT"

        r = self.cbapi_put("%s/api/v1/sensor/%s" % (self.server, sensor_id),
                           data=json.dumps(data), timeout=120)
        r.raise_for_status()
        return r.status_code == 200

    def move_sensor_to_group(self, sensor_id, new_group_id):
        data = self.sensor(sensor_id)
        data["group_id"] = new_group_id

        r = self.cbapi_put("%s/api/v1/sensor/%s" % (self.server, sensor_id),
                           data=json.dumps(data), timeout=120)
        r.raise_for_status()
        return r.status_code == 200

    def event_add(self, investigation_id, description, start_date):
        """
        Adds a tagged_event to an investigation on the server
        :investigation_id: the id of the investigation to add the event to
        :param description: description of the event
        :param start_date: start date of the event
        :return: the added event
        """
        event_data = {
            'description': description,
        }

        request = {
            'investigation_id': investigation_id,
            'event_data': event_data,
            'start_date': start_date
        }

        url = "%s/api/tagged_event" % self.server

        r = self.cbapi_post(url, data=json.dumps(request))
        r.raise_for_status()

        return r.json()

    def event_info(self, investigation_id):
        """
        Enumerates the tagged_events for a certain investigation and gives their information
        :param id: the id of the investigation this tagged_event is for
        """
        url = "%s/api/tagged_event/%s" % (self.server, investigation_id)
        r = self.cbapi_get(url)
        r.raise_for_status()
        return r.json()

    def event_update(self, id, new_description):
        """
        Updates the description of an event on the server
        :param id: the updated event's investigation id
        :return: the updated event
        """

        #be able to target a single event
        old_event_as_list = self.event_info(id)
        old_event = old_event_as_list[0]
        old_event_data = old_event['event_data']
        new_event_data = {\
            'description' : new_description,\
            }

        request = {\

           'start_date' : old_event['start_date'],\
           'event_data' : {\
                            # set every other event_data field to the old_event value
                            'description' : new_description
                          },\
                  }

        url = "%s/api/tagged_event/%s" % (self.server, id)

        r = self.cbapi_put(url, data=json.dumps(request))
        r.raise_for_status()

        return r.json()

    def event_del(self, id):
        """
        Deletes a tagged_event from the server
        :param id: id of the event to be deleted
        :return: success or failure
        """
        # Way to deal with selecting boxes on the UI
        url = "%s/api/tagged_event/%s" % (self.server, id)
        r = self.cbapi_delete(url)
        r.raise_for_status()

        return r.json()


    def event_by_process_id(self, proc_id):
        """
        Retrieves a tagged_event specified by its process_id
        :param proc_id: the process_id of the event
        :return: the tagged_event
        """

        url = "%s/api/tagged_events/%s" % (self.server, proc_id)
        r = self.cbapi_get(url)
        r.raise_for_status()

        return r.json()

    def get_builds(self):
        """
        Gets the build versions from the Carbon Black server
        """
        url = "%s/api/builds" % self.server
        r = self.cbapi_get(url)
        r.raise_for_status()

        return r.json()

    def get_login_caps(self):
        """
        Gets login-caps from Carbon Black server
        """
        url = "%s/api/login-caps" % self.server
        r = self.cbapi_get(url)
        r.raise_for_status()

        return r.json()

    def group_datasharing_enum(self, group_id):
        """
        Enumerates the datasharing settings for the group with id "group_id"
        from Carbon Black server
        """
        url = "%s/api/v1/group/%s/datasharing" % (self.server, group_id)
        r = self.cbapi_get(url)
        r.raise_for_status()

        return r.json()

    # this probably needs something like add_from_data, also look at line
    # that Jeremiah sent you that updated the datasharing settings
    def group_datasharing_add(self, group_id, who, what):
        """
        Add a new datasharing configuration to a sensor group in the CB server
        :param group_id: the sensor group id
        :param what: the type of data being shared i.e. "binaries" or "hashes" etc.
        :param who: What company the data is being shared with
        :return: the added configuration
        """
        request = {
            'group_id': group_id,
            'who': who,
            'what': what,
        }

        url = "%s/api/v1/group/%s/datasharing" % (self.server, group_id)

        r = self.cbapi_post(url, data=json.dumps(request))
        r.raise_for_status()

        return r.json()

    def group_datasharing_del_all(self, group_id):
        """
        Deletes all datasharing configurations for the group with id "group_id"
        from the Carbon Black server
        """
        url = "%s/api/v1/group/%s/datasharing" % (self.server, group_id)
        r = self.cbapi_delete(url)
        r.raise_for_status()

        return r.json()

    def group_datasharing_info(self, group_id, config_id):
        """
        Retrieves a specific datasharing configuration of a sensor group
        :param group_id: id of sensor group
        :param config_id: id of specific datasharing configuration
        :return: the datasharing info for one configuration of a group
        """
        url = "%s/api/v1/group/%s/datasharing/%s" % (self.server,group_id,config_id)
        r = self.cbapi_get(url)
        r.raise_for_status()

        return r.json()

    def group_datasharing_del(self, group_id, config_id):
        """
        Deletes a specific datasharing configuration of a sensor group from the
        Carbon Black server
        :param group_id: id of sensor group
        :param config_id: id of specific datasharing configuration
        :return: the deleted configuration
        """
        url = "%s/api/v1/group/%s/datasharing/%s" % (self.server,group_id,config_id)
        r = self.cbapi_delete(url)
        r.raise_for_status()

        return r.json()

    def alert_add(self, query_string, rows, start, sort, facets):
        '''
        adds a new alert to the Carbon Black server
        '''

        request = {\
            'query_string' : query_string,\
            'rows' : rows,\
            'start' : start,\
            'sort' : sort,\
            'facets' : facets,\
        }

        url = "%s/api/v1/alert" % (self.server,)

        r = requests.post(url, headers=self.token_header, data = json.dumps(request), verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def banning_enum(self):
        '''
        Enumerates all banned hashes
        '''

        url = "%s/api/v1/banning/blacklist" % (self.server,)

        r = requests.get(url, headers=self.token_header,verify = self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def banning_info(self, md5):
        '''
        Retrieves the information of one banned hash, specified by md5hash
        '''

        url = "%s/api/v1/banning/blacklist/%s" % (self.server, md5)

        r = requests.get(url,headers=self.token_header,verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def banning_update(self,md5, text):
        '''
        updates the Notes field of a banned hash
        '''
        url = "%s/api/v1/banning/blacklist/%s" % (self.server, md5)

        r = requests.get(url, headers=self.token_header, verify = self.ssl_verify)
        r.raise_for_status()

        banned_hash = r.json()

        request = {\
            'username' : banned_hash['username'],\
            'audit' : banned_hash['audit'],\
            'block_count' : banned_hash['block_count'],\
            'user_id' : banned_hash['user_id'],\
            'timestamp' : banned_hash['timestamp'],\
            'text' : text,\
            'md5hash' : banned_hash['md5hash'],\
            'enabled' : banned_hash['enabled'],\
            'last_block_time' : banned_hash['last_block_time'],\
            'last_block_sensor_id' :banned_hash['last_block_sensor_id'],\
            'last_block_hostname' : banned_hash['last_block_hostname'],\

            }

        s = requests.put(url,headers=self.token_header,data = json.dumps(request),verify=self.ssl_verify)
        s.raise_for_status()
        return s.json()

    def banning_add(self, md5):
        '''
        adds a new banned hash to the Carbon Black server or enables a pre-existing one
        '''
        url = "%s/api/v1/banning/blacklist" % (self.server,)

        request = {\
            'md5hash' : md5,\
            }

        r = requests.post(url,headers=self.token_header, data = json.dumps(request), verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def disable_ban(self, md5):
        '''
        disables a current banned hash on the server
        '''
        url = "%s/api/v1/banning/blacklist/%s" % (self.server, md5)

        r = requests.delete(url,headers=self.token_header,verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def banning_restrictions(self):
        '''
        retrieves the restrictions for banning from the server
        '''
        url = "%s/api/v1/banning/restrictions" % (self.server,)

        r = requests.get(url,headers=self.token_header,verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def banning_whitelist(self):
        '''
        retrieves the whitelist for banning from the server
        '''
        url = "%s/api/v1/banning/whitelist" % (self.server,)

        r = requests.get(url,headers=self.token_header,verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()


    def site_enum(self):
        """
        Get all sites
        """

        url = "%s/api/site" % self.server

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def site_info(self, site_id):
        """
        Get info for a site
        :param site_id: the ID of the site
        """
        url = "%s/api/site/%s" % (self.server, site_id)
        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def site_add(self, name, group_ids=[]):
        """
        Get info for a site
        :param site: the site object to add
        """

        site = {
            "name": name
        }

        for group_id in group_ids:
            site["group_%s" % group_id] = group_id

        url = "%s/api/site" % self.server
        r = requests.post(url, headers=self.token_header, data=json.dumps(site), verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def site_modify(self, site_id, site):
        """
        Get info for a site
        :param site: the site object to add
        """
        url = "%s/api/site/%s" % (self.server, site_id)
        r = requests.post(url, headers=self.token_header, data=json.dumps(site), verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def site_del(self, site_id):
        """
        Get info for a site
        :param site: the site object to add
        """
        url = "%s/api/site/%s" % (self.server, site_id)
        r = requests.delete(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def dashboard_alliance(self):
        '''
        Enumerates the info for the alliance_client of the Carbon Black server
        '''

        url = "%s/api/v1/dashboard/alliance" % self.server
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def dashboard_hosts(self):
        '''
        Enumerates the hosts on the Carbon Black server
        '''

        url = "%s/api/v1/dashboard/hosts" % self.server
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def dashboard_statistics(self):
        '''
        Enumerates the statistics for the Carbon Black Server
        '''

        url = "%s/api/v1/dashboard/statistics" % self.server
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()


    def detect_feed_unresolvedalertsbyseverity(self, feed_name, count, sort):
        '''
        Enumerates "count" of unresolved alerts by severity on the Carbon Black Server, sorted in
        either ascending or descending order given a feed name, count, and sorting order "sort"
        count defaults to 10 and sort defaults to descending
        '''

        url = "%s/api/v1/detect/report/%s/unresolvedalertsbyseverity/%s/%s" % (self.server, feed_name, count, sort)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()


    def detect_feed_unresolvedalertsbytime(self, feed_name, count, sort):
        '''
        Enumerates "count" of unresolved alerts by time on the Carbon Black Server, sorted in
        either ascending or descending order given a feed name, count, and sorting order "sort"
        count defaults to 10 and sort defaults to descending
        '''

        url = "%s/api/v1/detect/report/%s/unresolvedalertsbyseverity/%s/%s" % (self.server, feed_name, count, sort)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_feed_unresolvedalerttrend(self, feed_name, days):
        '''
        Enumerates unresolved alert trend for the given feed_name
        for the past "days" amount of days. "days" defaults to 30
        '''

        url = "%s/api/v1/detect/report/%s/unresolvedalerttrend/%s" % (self.server, feed_name, days)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_adminsbyalertsresolved(self, count, sort):
        '''
        Enumerates "count" of admins by alerts resolved on the Carbon Black Server, sorted in
        either ascending or descending order given a count, and sorting order "sort"
        count defaults to 10 and sort defaults to descending
        '''

        url = "%s/api/v1/detect/report/adminsbyalertsresolved/%s/%s" % (self.server, count, sort)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_adminsbyresolvedtime(self, count, sort):
        '''
        Enumerates "count" of admins by alerts resolved on the Carbon Black Server, sorted in
        either ascending or descending order given a count, and sorting order "sort"
        count defaults to 10 and sort defaults to descending
        '''

        url = "%s/api/v1/detect/report/adminsbyresolvedtimecd/%s/%s" % (self.server, count, sort)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_alertresolutionaverage(self, days):
        '''
        Enumerates resolution times for the last "days" number of days.
        "days" defaults to 30 if not supplied
        '''

        url = "%s/api/v1/detect/report/alertresolutionaverage/%s" % (self.server, days)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_binarydwell(self, days):
        '''
        Enumerates the binary dwell for the last "day" number of days
        '''

        url = "%s/api/v1/detect/report/binarydwell/%s" % (self.server, days)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_currentalertstatus(self):
        '''
        Returns the current alert status from the Carbon Black Server
        '''

        url = "%s/api/v1/detect/report/currentalertstatus" % self.server
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_currentmonitoringstatus(self):
        '''
        Returns the current monitoring status from the Carbon Black Server
        '''

        url = "%s/api/v1/detect/report/currentmonitoringstatus" % self.server
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_hosthygiene(self, days):
        '''
        Returns the host hygiene from the Carbon Black Server
        '''

        url = "%s/api/v1/detect/report/hosthygiene/%s" % (self.server, days)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_unresolvedalertsbyseverity(self, count, sort):
        '''
        Enumerates "count" of unresolved alerts by severity on the Carbon Black Server, sorted in
        either ascending or descending order given a count, and sorting order "sort"
        count defaults to 10 and sort defaults to descending
        '''

        url = "%s/api/v1/detect/report/unresolvedalertsbyseverity/%s/%s" % (self.server, count, sort)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_unresolvedalertsbytime(self, count, sort):
        '''
        Enumerates "count" of unresolved alerts by time on the Carbon Black Server, sorted in
        either ascending or descending order given a count, and sorting order "sort"
        count defaults to 10 and sort defaults to descending
        '''

        url = "%s/api/v1/detect/report/unresolvedalertsbyseverity/%s/%s" % (self.server, count, sort)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_unresolvedalerttrend(self, days):
        '''
        Enumerates unresolved alert trend for the past "days" amount of days. "days" defaults to 30
        '''

        url = "%s/api/v1/detect/report/unresolvedalerttrend/%s" % (self.server, days)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_unresolvedhostsbyseverity(self, count, sort):
        '''
        Retrieves the unresolved hosts from the server. Retrieves "count" number of the hosts and
        organizes them in "sort" order (asc or desc) by severity. "count" defaults to 10 and "sort" defaults to desc
        '''

        url = "%s/api/v1/detect/report/unresolvedhostsbyseverity/%s/%s" % (self.server, count, sort)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_unresolvedhostsbytime(self, count, sort):
        '''
        Retrieves the unresolved hosts from the server. Retrieves "count" number of the hosts and
        organizes them in "sort" order (asc or desc) by time. "count" defaults to 10 and "sort" defaults to desc
        '''

        url = "%s/api/v1/detect/report/unresolvedhostsbytime/%s/%s" % (self.server, count, sort)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_unresolvedusersbyseverity(self, count, sort):
        '''
        Retrieves the unresolved users from the server. Retrieves "count" number of the users and
        organizes them in "sort" order (asc or desc) by severity. "count" defaults to 10 and "sort" defaults to desc
        '''

        url = "%s/api/v1/detect/report/unresolvedusersbyseverity/%s/%s" % (self.server, count, sort)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def detect_unresolvedusersbytime(self, count, sort):
        '''
        Retrieves the unresolved users from the server. Retrieves "count" number of the users and
        organizes them in "sort" order (asc or desc) by time. "count" defaults to 10 and "sort" defaults to desc
        '''

        url = "%s/api/v1/detect/report/unresolvedusersbytime/%s/%s" % (self.server, count, sort)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def event_enum(self, investigation_id):
        '''
        Enumerates the tagged_events for a certain investigation and gives their information
        :param id: the id of the investigation this tagged_event is for
        '''
        url = "%s/api/tagged_event/%s" % (self.server, investigation_id)
        r = requests.get(url, headers = self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def event_update_old (self, id, tagged_event_id, new_description):
        '''
        Updates the description of an event on the server
        :param id: the updated event's investigation id
        :param tagged_event_id the id of the specific tagged event to be updated
        :return: the updated event
        '''

        #use tagged_event_id to get the exact event out of all tagged events for this investigation
        #
        events = self.event_enum(id)
        for event in events:
            if int(event['id']) == int(tagged_event_id):
                old_event = event
        old_event_data = old_event['event_data']

        #add each of the existing fields from old_event_data into new_event_data,
        #with the exception of description which is being updated
        #

        new_event_data = {}
        for item in old_event_data:
            if str(item) == 'description':
                new_event_data.udpate({'description' : new_event_data})
            else:
                new_event_data.update({item : old_event_data[str(item)]})

        #form request with existing fields of old_event, with the exception of
        #event_data being replaced with new_event_data
        #
        request = {}
        for item in old_event.keys():
            if item == 'description':
                new_event_data['description'] = new_description
            else:
                new_event_data[item] = old_event_data[item]

        url = "%s/api/tagged_event/%s" % (self.server, id)

        r = requests.put(url, headers=self.token_header, data=json.dumps(request), verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()


    def cbapi_get(self, url, **kwargs):
        headers = kwargs.pop('headers', None) or self.token_header
        verify_ssl = kwargs.pop('verify', None) or self.ssl_verify
        proxies = kwargs.pop('proxies', None) or self.proxies

        return self.session.get(url, headers=headers, verify=verify_ssl, proxies=proxies, **kwargs)

    def cbapi_post(self, url, **kwargs):
        headers = kwargs.pop('headers', None) or self.token_header
        verify_ssl = kwargs.pop('verify', None) or self.ssl_verify
        proxies = kwargs.pop('proxies', None) or self.proxies

        return self.session.post(url, headers=headers, verify=verify_ssl, proxies=proxies, **kwargs)

    def cbapi_put(self, url, **kwargs):
        headers = kwargs.pop('headers', None) or self.token_header
        verify_ssl = kwargs.pop('verify', None) or self.ssl_verify
        proxies = kwargs.pop('proxies', None) or self.proxies

        return self.session.put(url, headers=headers, verify=verify_ssl, proxies=proxies, **kwargs)

    def cbapi_delete(self, url, **kwargs):
        headers = kwargs.pop('headers', None) or self.token_header
        verify_ssl = kwargs.pop('verify', None) or self.ssl_verify
        proxies = kwargs.pop('proxies', None) or self.proxies

        return self.session.delete(url, headers=headers, verify=verify_ssl, proxies=proxies, **kwargs)