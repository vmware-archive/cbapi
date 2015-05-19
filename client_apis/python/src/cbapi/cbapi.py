#
# CARBON BLACK API
# Copyright Bit9, Inc. 2014 
# support@carbonblack.com
#

import json
import time
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
    def __init__(self, server, ssl_verify=True, token=None):
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
                                                                        data = json.dumps(platform_server_config))
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
          groupid - the sensor group id; must be numeric

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

    def watchlist_add(self, type, name, search_query, id=None, readonly=False, basic_query_validation=True):
        '''
        adds a new watchlist
        '''

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
                print kvpair
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
    
    def user_add_from_data(self, username, first_name, last_name, password, confirm_password, global_admin, teams, email):
        '''
        add a new user to the server
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
        a = requests.get(url)
        print a.data['teams']
        
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

    def user_get_username_by_name(self, first_name, last_name):
        '''
        helper function to find the username given a user's first and last name
        '''

        for user in self.user_enum():
            if user['first_name'].lower() == first_name.lower() and user['last_name'].lower() == last_name.lower():
                return user['username']

        # did not find it
        #
        return None
	
    def feed_enum(self):
        '''
        enumerate all configured feeds
        '''

        url = "%s/api/v1/feed" % (self.server,)

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
    
    def team_enum(self):
        '''
        enumerate all teams
        '''
        
        url = "%s/api/teams" % (self.server,)
        
        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        
        return r.json() 
    
    def group_enum(self):
        return 
        
    def feed_info(self, id):
        '''
        retrieve information about an existing feed, as specified by id 
        
        note: the endpoint /api/v1/feed/<id> is not supported as of CB server 5.0
        '''
        feeds = self.feed_enum()
        for feed in feeds:
          if str(feed['id']) == str(id):
              return feed 

    def user_info(self, username):
        '''
        retrieve information about an existing user, as specified by username 
        
        note: the endpoint /api/users/<id> is not supported as of CB server 5.0
        '''
        users = self.user_enum()
        for user in users:
          if user['username'] == username:
              return user 
          
    def team_get_id_by_name(self, name):
        '''
        retrieve information about an existing team, specified by name
        '''
        
        teams = self.team_enum()
        for team in teams:
            if team['name'] == name:
                return team['id']
    
    def team_info(self, id):
        '''
        retrieve information about an existing team, specified by id
        '''
        
        teams = self.team_enum()
        for team in teams:
            print type(id)
            print type(team['id'])
            if team['id'] == id:
                return team
        
    def output_user_activity(self):
        '''
        retrieve all user activity from server
        '''
        
        url = "%s/api/useractivity" % (self.server,)
    
        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
    
        useractivity = r.json()
        
        print "%-12s| %-14s | %-12s | %-5s | %-20s" %("Username", "Timestamp", "Remote Ip", "Result", "Description")
        for attempt in useractivity:
            print "%-12s| %-14s | %-12s | %-5s | %-20s" % (attempt['username'], attempt['timestamp'], attempt['ip_address'], attempt['http_status'], attempt['http_description'])
    
    def output_user_activity_success(self):
        '''
        retrieve all user activity from server and filter out successful attempts
        '''
        
        url = "%s/api/useractivity" % (self.server,)
        
        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
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
        '''
        retrieve all user activity from server and filter out successful attempts
        '''
        
        url = "%s/api/useractivity" % (self.server,)
        
        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        
        useractivity = r.json()
        
        failures = []
        for attempt in useractivity:
            if attempt['http_status'] == 403:
                failures.append(attempt)
        
        print "%-12s| %-14s | %-12s | %-5s | %-20s" %("Username", "Timestamp", "Remote Ip", "Result", "Description")
        for attempt in failures:
            print "%-12s| %-14s | %-12s | %-5s | %-20s" % (attempt['username'], attempt['timestamp'], attempt['ip_address'], attempt['http_status'], attempt['http_description'])      
    
    def feed_del(self, id):
        '''
        delete a feed, as specified by id
        '''
        url = "%s/api/v1/feed/%s" % (self.server, id)

        r = requests.delete(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()
    
    def user_del(self,username):
        
        
        url = "%s/api/user/%s" % (self.server, username)
        
        r = requests.delete(url, headers=self.token_header, verify=self.ssl_verify)
        r.raise_for_status()
        
        return r.json()        
        
    def feed_modify(self, id, feed):
        '''
        updates a watchlist
        '''
        url = "%s/api/v1/feed/%s" % (self.server, id)

        r = requests.put(url, headers=self.token_header, data=json.dumps(feed), verify=self.ssl_verify)
        r.raise_for_status()

        return r.json()

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
        r = requests.get("%s/api/v1/threat_report" % self.server, headers=self.token_header,
                          params=params, verify=self.ssl_verify)
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

    def binary_search_iter(self, query_string, start=0, rows=10, sort="server_added_timestamp desc"):
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
            resp = self.binary_search(query_string, our_start, rows, sort)
            results = resp.get('results')
            for binary in results:
                yield binary
            our_start += len(results)
            if len(results) < rows:
                break

    def process_search_iter(self, query_string, start=0, rows=10, sort="last_update desc"):
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
            resp = self.process_search(query_string, our_start, rows, sort)
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
        r = requests.post(url, headers=self.token_header, data=json.dumps(data), verify=self.ssl_verify, timeout=120)
        r.raise_for_status()

        return r.json()

    def live_response_session_list(self):
        url = "%s/api/v1/cblr/session" % (self.server)
        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify, timeout=120)
        r.raise_for_status()
        return r.json()

    def live_response_session_create(self, sensor_id):
        target_session = None
        for session in self.live_response_session_list():
            if session.get('sensor_id') == sensor_id and session.get('status') != "close":
                target_session = session
                break

        if not target_session:
            url = "%s/api/v1/cblr/session" % (self.server)
            data = {"sensor_id": sensor_id}
            r = requests.post(url, headers=self.token_header, data=json.dumps(data), verify=self.ssl_verify, timeout=120)
            r.raise_for_status()
            target_session = r.json()
        return target_session

    def live_response_session_status(self, session_id):
        url = "%s/api/v1/cblr/session/%d" % (self.server, session_id)
        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify, timeout=120)
        r.raise_for_status()
        return r.json()

    def live_response_session_command_post(self, session_id, command, command_object=None):
        url = "%s/api/v1/cblr/session/%d/command" % (self.server, session_id)
        data = {"session_id": session_id, "name": command}
        if command_object:
            data['object'] = command_object
        r = requests.post(url, headers=self.token_header, data=json.dumps(data), verify=self.ssl_verify, timeout=120)
        r.raise_for_status()
        return r.json()

    def live_response_session_command_get(self, session_id, command_id, wait=False):
        url = "%s/api/v1/cblr/session/%d/command/%d" % (self.server, session_id, command_id)
        if wait:
            params = {'wait':'true'}
        else:
            params = {}
        r = requests.get(url, headers=self.token_header, params=params, verify=self.ssl_verify, timeout=120)
        r.raise_for_status()
        return r.json()

    def live_response_session_command_get_file(self, session_id, file_id):
        url = "%s/api/v1/cblr/session/%d/file/%d/content" % (self.server, session_id, file_id)
        r = requests.get(url, headers=self.token_header, params={}, verify=self.ssl_verify, timeout=120)
        r.raise_for_status()
        return r.content


    def live_response_session_keep_alive(self, session_id):
        url = '%s/api/v1/cblr/session/%d/keepalive' % (self.server, session_id)
        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify, timeout=120)
        r.raise_for_status()
        return r.json()

    def sensor_toggle_isolation(self, sensor_id, do_isolation):
        data = self.sensor(sensor_id)

        data["network_isolation_enabled"] = do_isolation

        r = requests.put("%s/api/v1/sensor/%s" % (self.server, sensor_id),
                        data=json.dumps(data),
                        headers=self.token_header,
                        verify=self.ssl_verify,
                        timeout=120)
        r.raise_for_status()
        return r.status_code == 200

    def sensor_flush_current(self, sensor_id):
        # move it forward 1 day because this should get reset regardless once the sensor is current
        flush_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 86400))
        return self.sensor_flush(sensor_id, flush_time)

    def sensor_flush(self, sensor_id, flush_time):
        data = self.sensor(sensor_id)
        data["event_log_flush_time"] = flush_time #"Wed, 01 Jan 2020 00:00:00 GMT"

        r = requests.put("%s/api/v1/sensor/%s" % (self.server, sensor_id),
                        data=json.dumps(data),
                        headers=self.token_header,
                        verify=self.ssl_verify,
                        timeout=120)
        r.raise_for_status()
        return r.status_code == 200

