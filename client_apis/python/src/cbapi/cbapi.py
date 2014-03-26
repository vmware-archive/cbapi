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
        r = requests.get("%s/api/info" % self.server, headers=self.token_header, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return json.loads(r.content)

    def license_status(self):
        """ Provide a summary of the current applied license
        """
        r = requests.get("%s/api/v1/license" % (self.server,),  headers=self.token_header, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))

        return json.loads(r.content)

    def apply_license(self, license):
        """ Apply a new license to the server
        """
        r = requests.post("%s/api/v1/license" % (self.server,), headers=self.token_header, \
                data=json.dumps({'license': license}), \
                verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))

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
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))

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
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))

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
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def process_summary(self, id, segment):
        """ get the detailed metadata for a process.  Requires the 'id' field from a process
            search result, as well as a segement, also found from a process search result.

            Returns a python dictionary with the following primary fields:
                - process - metadata for this process
                - parent -  metadata for the parent process
                - children - a list of metadata structures for child processes
                - siblings - a list of metadata structures for sibling processes
        """
        r = requests.get("%s/api/v1/process/%s/%s" % (self.server, id, segment), headers=self.token_header, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def process_events(self, id, segment):
        """ get all the events (filemods, regmods, etc) for a process.  Requires the 'id' and 'segment_id' fields
            from a process search result"""
        r = requests.get("%s/api/v1/process/%s/%s/event" % (self.server, id, segment), headers=self.token_header, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()


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
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def binary_summary(self, md5):
        """ get the metadata for a binary.  Requires the md5 of the binary.

            Returns a python dictionary with the binary metadata. """
        r = requests.get("%s/api/v1/binary/%s/summary" % (self.server, md5),
                             headers=self.token_header, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def binary(self, md5hash):
        '''
        download binary based on md5hash
        '''

        r = requests.get("%s/api/v1/binary/%s" % (self.server, md5hash),
                         headers=self.token_header, verify=self.ssl_verify)

        if r.status_code != 200:
            raise Exception("Unexpected response from /api/v1/binary: %s" % (r.status_code))
        return r._content

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
        if r.status_code != 200:   
            raise Exception("Unexpected response from /api/sensor: %s" % (r.status_code))
        return r.json()

    def watchlist(self, id=None):
        '''
        get all watchlists or a single watchlist
        '''

        url = "%s/api/v1/watchlist" % (self.server)
        if id is not None:
            url = url + "/%s" % (id,)

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from %s: %s" % (url, r.status_code))

        return r.json()

    def feed_synchronize(self, name):
        '''
        force the synchronization of a feed
        '''

        feed_request = requests.get("%s/api/v1/feed" % self.server, headers=self.token_header, verify=self.ssl_verify)
        if feed_request.status_code != 200:
            raise Exception("Unexpected response from /api/v1/feed: %s" % feed_request.status_code)

        for feed in feed_request.json():
            if feed['name'] == name:
                sync_request = requests.post("%s/api/v1/feed/%s/synchronize" % (self.server, feed["id"]),
                                             headers=self.token_header, verify=self.ssl_verify)
                if sync_request.status_code == 200:
                    return {"result": True}
                elif sync_request.status_code == 409:
                    return {"result": False, "reason": "feed disabled"}
                else:
                    raise Exception("Unexpected response from /api/v1/feed/%s/synchronize: %s"
                                    % (feed['id'], sync_request.status_code))

        return r.json()
