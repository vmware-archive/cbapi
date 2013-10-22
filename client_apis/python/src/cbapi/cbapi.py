#
# CARBON BLACK API
# Copyright, Carbon Black, Inc 2013
# technology-support@carbonblack.com
#

import requests
import urllib
import json
from requests.auth import HTTPDigestAuth

class CbApi(object):
    """ Python bindings for Carbon Black API 
    Example:

    import cbapi
    cb = cbapi.CbApi("http://cb.example.com", "admin", "pa$$w0rd")
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

        # We only want to hit the api/auth endpoint if we are using actual creds.
        if self.token is None:
            self._login()

    def processes(self, query_string, start=0, rows=10, sort="last_update desc"):
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
            'sort': ['start desc'], 
            'facet': ['true', 'true'], 
            'rows': ['10'], 
            'cb.urlver': ['1'], 
            'q': [query_string], 
            'start': ['0']}

        # do a post request since the URL can get long
        r = requests.post("%s/api/v1/process/" % self.server, headers=self.token_header,
                          data=json.dumps(params), verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def process(self, id):
        """ get the detailed metadata for a process.  Requires the 'id' field from a process
            search result.
    
            Returns a python dictionary with the following primary fields:
                - process - metadata for this process
                - parent -  metadata for the parent process
                - children - a list of metadata structures for child processes
                - siblings - a list of metadata structures for sibling processes
        """
        r = requests.post("%s/api/process/%s" % (self.server, id), headers=self.token_header, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def events(self, id):
        """ get all the events (filemods, regmods, etc) for a process.  Requires the 'id' field
            from a process search result"""
        r = requests.get("%s/api/events/%s/" % (self.server, id), headers=self.token_header, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def binaries(self, query_string, start=0):
        """ Search for binaries.  Arguments: 

            query_string -      The Cb query string; this is the same string used in the 
                                "main search box" on the binary search page.  "Contains text..."
                                See Cb Query Syntax for a description of options.

            start -             Defaulted to 0.  Will retrieve records starting at this offset.
            rows -              Defaulted to 10. Will retrieve this many rows. 
            sort -              Default to last_update desc.  Must include a field and a sort
                                order; results will be sorted by this param.

            Returns a python dictionary with the following primary fields:
                - results - a list of dictionaries describing each matching binary
                - total_results - the total number of matches
                - elapsed - how long this search took
                - terms - a list of strings describing how the query was parsed
                - facets - a dictionary of the facet results for this saerch
        """
        args = {"q": query_string, "cburlver": 1, 'start': start}
        query = urllib.urlencode(args)
        r = requests.get("%s/api/search/module/%s/" % (self.server, query),
                             headers=self.token_header, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def binary(self, md5):
        """ get the metadata for a binary.  Requires the md5 of the binary.

            Returns a python dictionary with the binary metadata. """
        r = requests.get("%s/api/module/%s/" % (self.server, md5),
                             headers=self.token_header, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def download_binary(self, md5hash):
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
        get sensors, optionally specifying searchcriteria
        
        as of this writing, supported search criteria are:
          ip - any portion of an ip address
          hostname - any portion of a hostname, case sensitive 
        '''

        url = "%s/api/v1/sensor?" % (self.server,)
        for query_parameter in query_parameters.keys():
            url += "%s=%s&" % (query_parameter, query_parameters[query_parameter])

        r = requests.get(url, headers=self.token_header, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from /api/sensor: %s" % (r.status_code))
        return r.content
