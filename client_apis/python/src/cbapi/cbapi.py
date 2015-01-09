#
# CARBON BLACK API
# Copyright Bit9, Inc. 2014 
# support@carbonblack.com
#

import json
import urllib
import requests

class CbApi(object):
    """ Python bindings for Carbon Black API 
    Example:

    import cbapi
    cb = cbapi.CbApi("http://cb.example.com", token="apitoken")
    # get metadata for all svchost.exe's not from c:\\windows
    procs = cb.processes(r"process_name:svchost.exe -path:c:\\windows\\")  
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
        get information about a single sensor
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
        feeds = self.feed_enum()
        for feed in feeds:
          if str(feed['id']) == str(id):
              return feed 

    def feed_del(self, id):
        '''
        delete a feed, as specified by id
        '''
        url = "%s/api/v1/feed/%s" % (self.server, id)

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
