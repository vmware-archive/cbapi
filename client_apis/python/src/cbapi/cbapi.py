#
# CARBON BLACK API
# Copyright Bit9, Inc. 2014 
# support@carbonblack.com
#

import json
import requests


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
    def __init__(self, server, ssl_verify=True, token=None, client_validation_enabled=True):
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
        self.client_validation_enabled = client_validation_enabled

    def info(self):
        """ Provide high-level information about the Carbon Black Enterprise Server.

            **NOTE** This function is provided for convenience and may change in
                     future versions of the Carbon Black API

            Returns a python dictionary with the following field:
                - version - version of the Carbon Black Enterprise Server
        """
        print self.ssl_verify
        r = requests.get("%s/api/info" % self.server, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return json.loads(r.content)

    def license_status(self):
        """ Provide a summary of the current applied license
        """
        r = requests.get("%s/api/v1/license" % (self.server,),  headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return json.loads(r.content)

    def apply_license(self, license):
        """ Apply a new license to the server
        """
        r = requests.post("%s/api/v1/license" % (self.server,), headers=self.token_header, \
                data=json.dumps({'license': license}), \
                verify=self.ssl_verify)
        r.raise_for_status()

    def concurrent_license_info(self, start_date, end_date):
        """
        Get the concurrent license info for a given date range
        :param start_date: the start date
        :param end_date: the end date
        """
        url = "{}/api/concurrent_license_info/{:%Y%m%d}/{:%Y%m%d}".format(self.server, start_date, end_date)
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
        r = requests.get("%s/api/v1/settings/global/platformserver" % (self.server,), \
                                                                       headers=self.token_header, \
                                                                       verify=self.ssl_verify)
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
        r = requests.post("%s/api/v1/settings/global/platformserver" % (self.server,), \
                                                                        headers=self.token_header, \
                                                                        data = json.dumps(platform_server_config), \
                                                                        verify=self.ssl_verify)

    def test_platform_server_config(self):
        """
        Tests the current Bit9 Platform Server configuration
        This includes the server address, username, and password

        Must authenticate as a global administrator to have the rights to set this config
        """
        url = "%s/api/v1/settings/global/platformserver/test" % self.server
        r = requests.get(url=url, headers=self.token_header)
        r.raise_for_status()

    def process_search(self, query_string, start=0, rows=10, sort="last_update desc"):
        """ Search for processes.  Arguments: 

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
        r = requests.post("%s/api/v1/process" % self.server, headers=self.token_header,
                          data=json.dumps(params), verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def process_summary(self, id, segment, children_count=15):
        """ get the detailed metadata for a process.  Requires the 'id' field from a process
            search result, as well as a segement, also found from a process search result.
            The results will be limited to children_count children metadata structures.

            Returns a python dictionary with the following primary fields:
                - process - metadata for this process
                - parent -  metadata for the parent process
                - children - a list of metadata structures for child processes
                - siblings - a list of metadata structures for sibling processes
        """
        r = requests.get("%s/api/v1/process/%s/%s?children=%d" % (self.server, id, segment, children_count), headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def process_events(self, id, segment):
        """ get all the events (filemods, regmods, etc) for a process.  Requires the 'id' and 'segment_id' fields
            from a process search result"""
        r = requests.get("%s/api/v1/process/%s/%s/event" % (self.server, id, segment), headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def process_report(self, id, segment=0):
        """ download a "report" package describing the process
            the format of this report is subject to change"""
        r = requests.get("%s/api/v1/process/%s/%s/report" % (self.server, id, segment), headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status() 
        return r.content

    def binary_search(self, query_string, start=0, rows=10, sort="server_added_timestamp desc"):
        """ Search for binaries.  Arguments: 


            query_string -      The Cb query string; this is the same string used in the
                                "main search box" on the binary search page.  "Contains text..."
                                See Cb Query Syntax for a description of options.

            start -             Defaulted to 0.  Will retrieve records starting at this offset.

            rows -              Defaulted to 10. Will retrieve this many rows. 
            sort -              Default to server_added_timestamp desc.  Must include a field and a sort
                                order; results will be sorted by this param.

            Returns a python dictionary with the following primary fields:
                - results - a list of dictionaries describing each matching binary
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
        # to search for all binaries, provide an empty string for q
        if len(query_string) > 0:
            params['q'] = [query_string]

        # do a post request since the URL can get long
        # @note GET is also supported through the use of a query string
        r = requests.post("%s/api/v1/binary" % self.server, headers=self.token_header,
                          data=json.dumps(params), verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def binary_summary(self, md5):
        """ get the metadata for a binary.  Requires the md5 of the binary.

            Returns a python dictionary with the binary metadata. """
        r = requests.get("%s/api/v1/binary/%s/summary" % (self.server, md5),
                             headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def binary(self, md5hash):
        '''
        download binary based on md5hash
        '''

        r = requests.get("%s/api/v1/binary/%s" % (self.server, md5hash),
                         headers=self.token_header, verify=self.ssl_verify)

        r.raise_for_status()
        return r._content

    def sensor(self, sensor_id):
        '''
        get information about a single sensor, as specified by sensor id
        '''

        r = requests.get("%s/api/v1/sensor/%s" % (self.server, sensor_id),
                         headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def sensors(self, query_parameters={}):
        '''
        get sensors, optionally specifying search criteria

        as of this writing, supported search criteria are:
          ip - any portion of an ip address
          hostname - any portion of a hostname, case sensitive

        returns a list of 0 or more matching sensors
        '''

        url = "%s/api/v1/sensor?" % (self.server,)
        for query_parameter in query_parameters.keys():
            url += "%s=%s&" % (query_parameter, query_parameters[query_parameter])

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
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
        
        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
       
        return r.content 

    def sensor_backlog(self):
        """
        retrieves a summary of aggregate sensor backlog across all active sensors
        """

        url = "%s/api/v1/sensor/statistics" % (self.server,)

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
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
        '''
        get all watchlists or a single watchlist
        '''

        url = "%s/api/v1/watchlist" % (self.server)
        if id is not None:
            url = url + "/%s" % (id,)

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def watchlist_add(self, type, name, search_query, id=None, readonly=False):
        '''
        adds a new watchlist
        '''

        # as directed by the caller, provide basic feed validation
        if "cb.urlver" not in search_query:
            search_query = "cb.urlver=1&" + search_query

        if self.client_validation_enabled:
            if type not in ["modules", "events"]:
                raise ValueError("Unexpected type. Should be one of (\"modules\", \"events\")")

            if not "q=" in search_query:
                raise ValueError("watchlist queries must be of the form: cb.urlver=1&q=<query>")

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

        r = requests.post(url, headers=self.token_header, data=json.dumps(request), verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()  

    def watchlist_del(self, id):
        '''
        deletes a watchlist
        '''
        request = {'id': id}

        url = "%s/api/v1/watchlist/%s" % (self.server, id)
        
        r = requests.delete(url, headers=self.token_header, data=json.dumps(request), verify=self.ssl_verify)
        r.raise_for_status()

        return r.json() 

    def watchlist_modify(self, id, watchlist):
        '''
        updates a watchlist
        '''
        url = "%s/api/v1/watchlist/%s" % (self.server, id)

        r = requests.put(url, headers=self.token_header, data=json.dumps(watchlist), verify=self.ssl_verify)
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

    def feed_enum(self):
        '''
        enumerate all configured feeds
        '''

        url = "%s/api/v1/feed" % (self.server,)

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def feed_info(self, id):
        '''
        retrieve information about an existing feed, as specified by id

        note: the endpoint /api/v1/feed/<id> is not supported as of CB server 5.0
        '''
        url = "%s/api/v1/feed/%s" % (self.server, id)
        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def feed_modify(self, id, feed):
        '''
        updates a feed
        '''
        url = "%s/api/v1/feed/%s" % (self.server, id)

        r = requests.put(url, headers=self.token_header, data=json.dumps(feed), verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def feed_del(self, id):
        '''
        delete a feed, as specified by id
        '''

        url = "%s/api/v1/feed/%s" % (self.server, id)

        r = requests.delete(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()


    def feed_add_from_url(self, feed_url, enabled, validate_server_cert, use_proxy):
        '''
        add a new feed to the Carbon Black server, as specified by URL
        '''
        request = {\
                      'use_proxy': use_proxy,\
                      'validate_server_cert': validate_server_cert,\
                      'feed_url': feed_url,\
                      'enabled': enabled,\
                  }

        url = "%s/api/v1/feed" % (self.server,)

        r = requests.post(url, headers=self.token_header, data=json.dumps(request), verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def feed_get_id_by_name(self, name):
        '''
        helper function to find the feed id given the feed name
        '''

        for feed in self.feed_enum():
            if feed['name'].lower() == name.lower():
                return feed['id']

        # did not find it
        #
        return None

    def feed_synchronize(self, name, full_sync=True):
        '''
        force the synchronization of a feed

        this triggers the CB server to refresh the feed.  it does not result in immediate
        tagging of any existing process or binary documents that match the feed.  it does result
        in any new incoming data from sensors being tagged on ingress.
        '''

        feed_request = requests.get("%s/api/v1/feed" % self.server, headers=self.token_header, verify=self.ssl_verify)
        feed_request.raise_for_status()

        for feed in feed_request.json():
            if feed['name'] == name:
                sync_request = requests.post("%s/api/v1/feed/%s/synchronize" % (self.server, feed["id"]),
                                             headers=self.token_header,
                                             verify=self.ssl_verify,
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
        '''
        retrieve a single report from a feed
        '''

        url = "%s/api/v1/feed/%s/report/%s" % (self.server, feedid, reportid,)

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def user_enum(self):
        '''
        enumerate all users
        '''

        url = "%s/api/users" % (self.server,)

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
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

    def user_del(self, username):
        '''
        deletes a user, as specified by username
        '''

        url = "%s/api/user/%s" % (self.server, username)

        r = requests.delete(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

    def user_add_from_data(self, username, first_name, last_name, password, confirm_password, global_admin, teams, email):
        '''
        add a new user to the Carbon Black server
        '''
        request = {\
                    'username' : username,\
                    'first_name' : first_name,\
                    'last_name' : last_name,\
                    'password' : password,\
                    'confirm_password' : confirm_password,\
                    'global_admin' : global_admin,\
                    'teams' : teams,\
                    'email' : email,\
                  }
        url = "%s/api/user" % (self.server,)

        r = requests.post(url, headers=self.token_header, data = json.dumps(request), verify=self.ssl_verify)
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

    def team_enum(self):
        '''
        enumerate all teams
        '''
        
        url = "%s/api/teams" % (self.server,)
        
        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()   
        
        return r.json()

    def team_info(self, id):
        '''
        retrieve information about an existing team, specified by id
        '''

        url = "%s/api/team/%s" % (self.server, id)
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

    def alert_search(self, query_string, sort="created_time desc", rows=10, start=0):
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
        params = {
            'sort': sort,
            'facet': ['true', 'true'],
            'rows': rows,
            'cb.urlver': ['1'],
            'start': start}

        if len(query_string) > 0:
            params['q'] = [query_string]

        r = requests.get("%s/api/v1/alert" % self.server, headers=self.token_header,
                          params=params, verify=self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def alert_update(self, alert): 
        r = requests.post("%s/api/v1/alert/%s" % (self.server, alert['unique_id']), headers=self.token_header,
                          data=json.dumps(alert), verify=self.ssl_verify)
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

    def binary_enum(self):
        '''
        Retrieves all the binary files stored in the server
        '''
        url = "%s/api/v1/binary" % (self.server,)

        r = requests.get(url, headers=self.token_header,verify = self.ssl_verify)
        r.raise_for_status()
        return r.json()

    def binary_info(self, md5):
        '''
        Retrieves a specific binary file from the Carbon Black server, specified by md5
        '''
        url = "%s/api/v1/binary/%s/summary" % (self.server, md5)

        r = requests.get(url, headers=self.token_header,verify = self.ssl_verify)
        r.raise_for_status()

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

