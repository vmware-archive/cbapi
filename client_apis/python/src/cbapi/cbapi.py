#
# CARBON BLACK API
# Copyright, Carbon Black, Inc 2013
# technology-support@carbonblack.com
# last-updated 2013-06-05
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
    def __init__(self, server, username=None, password=None, ssl_verify=True, token=None):
        """ Requires:
                server -    URL to the Carbon Black server.  Usually the same as 
                            the web GUI.
                username -  a Cb GUI username  
                password -  password for the user
                ssl_verify - verify server SSL certificate
                token - this is for CLI API interface
        """

        if not server.startswith("http"): 
            raise TypeError("Server must be URL: e.g, http://cb.example.com")

        self.server = server.rstrip("/")
        self.user = username
        self.password = password
        self.cookies = None         # set in login()
        self.ssl_verify = ssl_verify
        self.token = token
        self.token_header = {'X-Auth-Token': self.token}

        # We only want to hit the api/auth endpoint if we are using actual creds.
        if self.token is None:
            self._login()

    def _login(self):
        r = requests.get("%s/api/auth" % self.server, auth=HTTPDigestAuth(self.user, self.password), verify=self.ssl_verify)

        if r.status_code != 200:
            raise Exception("Error authenticating with CB server: %s" % (r.status_code))
        if not r.cookies["session"]:
            raise Exception("CB /api/auth endpoint did not return session cookie.")
        self.cookies = {"session": r.cookies["session"]}

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
        if self.token:
            r = requests.post("%s/api/v1/process/" % self.server, headers=self.token_header,
                         data=json.dumps(params), verify=self.ssl_verify)
        else:
            r = requests.post("%s/api/v1/process/" % self.server, cookies=self.cookies,
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
        if self.token:
            r = requests.post("%s/api/process/%s" % (self.server, id), headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.post("%s/api/process/%s" % (self.server, id), cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def events(self, id):
        """ get all the events (filemods, regmods, etc) for a process.  Requires the 'id' field
            from a process search result"""
        if self.token:
            r = requests.get("%s/api/events/%s/" % (self.server, id), headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.get("%s/api/events/%s/" % (self.server, id), cookies=self.cookies, verify=self.ssl_verify)
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
        if self.token:
            r = requests.get("%s/api/search/module/%s/" % (self.server, query),
                             headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.get("%s/api/search/module/%s/" % (self.server, query),
                             cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def binary(self, md5):
        """ get the metadata for a binary.  Requires the md5 of the binary.

            Returns a python dictionary with the binary metadata. """
        if self.token:
            r = requests.get("%s/api/module/%s/" % (self.server, md5),
                             headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.get("%s/api/module/%s/" % (self.server, md5), cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def enum_feeds(self):
        """
        Enumerates configured feeds on the Enterprise server.
        """
        if self.token:
            r = requests.get("%s/api/feeds/" % (self.server), headers=self.token_header,
                             verify=self.ssl_verify)
        else:
            r = requests.get("%s/api/feeds/" % (self.server), cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from POST /api/feed endpoint: %s" % (r.status_code))
        return r.json()

    def add_feed(self, name, display_name, summary, technical_data, feed_url, provider_url, enabled, manually_added=True):
        """
        Adds a feed to the Enterprise Server.
        """
        data = {
                'name' : name,
                'display_name' : display_name,
                'summary' : summary,
                'technical_data' : technical_data,
                'feed_url' : feed_url,
                'provider_url' : provider_url,
                'enabled' : enabled,
                'manually_added' : manually_added
               }

        if self.token:
            r = requests.post("%s/api/feed/" % (self.server), data=json.dumps(data),
                              headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.post("%s/api/feed/" % (self.server), data=json.dumps(data),
                              cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from POST /api/feed endpoint: %s" % (r.status_code))
        return r.json()

    def update_feed(self, feed_id, name, display_name, summary, technical_data, feed_url, provider_url, enabled):
        """
        Updates an existing feed
        """
        data = {
                'name' : name,
                'display_name' : display_name,
                'summary' : summary,
                'technical_data' : technical_data,
                'feed_url' : feed_url,
                'provider_url' : provider_url,
                'enabled' : enabled,
               }

        if self.token:
            r = requests.put("%s/api/feed/%d/" % (self.server, feed_id), data=json.dumps(data),
                             headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.put("%s/api/feed/%d/" % (self.server, feed_id), data=json.dumps(data),
                             cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpiected response from PUT /api/feed endpoint: %s" % (r.status_code))
        return r.json()

    def delete_feed(self, feed_id):
        """
        Deletes a feed.  Feeds that are not marked as "manually_added" are not deletable.
        """
        if self.token:
            r = requests.delete("%s/api/feed/%d" % (self.server, feed_id),
                                headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.delete("%s/api/feed/%d" % (self.server, feed_id),
                                cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from DELETE /api/feed endpoint: %s" % (r.status_code))
        return r.json()

    def add_watchlist(self, name, query_string, index_type):
        """
        Adds a watchlist by name, query_string, and index_type.  No real magic here.
        """
        query_data = {"q": query_string, "cb.urlver": 1}
        encoded_query = urllib.urlencode(query_data)

        data = {'name': name, "search_query": encoded_query, "index_type": index_type}

        if self.token:
            r = requests.post("%s/api/watchlist" % (self.server), data=json.dumps(data),
                              headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.post("%s/api/watchlist" % (self.server), data=json.dumps(data),
                              cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from POST /api/watchlist endpoint: %s" % (r.status_code))
        return r.json()

    def delete_watchlist(self, watchlist_id):
        """
        Delete a watchlist by id.  As of this comment, the server returns 500 if you try to delete something
        that doesn't exist.
        """
        if self.token:
            r = requests.delete("%s/api/watchlist/%d" % (self.server, watchlist_id),
                                headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.delete("%s/api/watchlist/%d" % (self.server, watchlist_id),
                                cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from DELETE /api/watchlist endpoint: %s" % (r.status_code))
        return r.json()

    def concurrent_license_info(self, start_date, end_date):
        """
        Query server for sensor license info.
        start_date and end_date must support strftime
        """
        if self.token:
            r = requests.get("%s/api/concurrent_license_info/%s/%s" % (\
                self.server, start_date.strftime("%Y%m%d"), end_date.strftime("%Y%m%d")),\
                headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.get("%s/api/concurrent_license_info/%s/%s" % (\
                self.server, start_date.strftime("%Y%m%d"), end_date.strftime("%Y%m%d")),\
                cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from /api/concurrent_license_info: %s" % (r.status_code))
        return r.json()

    def update_server_license(self, license_str):
        """
        Update server license data.
        """
        data = {"license": license_str}

        if self.token:
            r = requests.post("%s/api/license" % (self.server),\
                data=json.dumps(data), headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.post("%s/api/license" % (self.server),\
                data=json.dumps(data), cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from /api/license: %s" % (r.status_code))
        return r.json()

    def get_license_request(self):
        """
        Get a new license request.
        """
        if self.token:
            r = requests.get("%s/api/license" % (self.server),
                             headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.get("%s/api/license" % (self.server), cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from /api/license: %s" % (r.status_code))
        return r.json()

    def download_binary(self, md5hash):
        '''
        download binary based on md5hash
        '''

        if self.token:
            r = requests.get("%s/api/v1/binary/%s" % (self.server, md5hash),
                             headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.get("%s/api/download/%s" % (self.server, md5hash),
                             cookies=self.cookies, verify=self.ssl_verify)

        if r.status_code != 200:
            raise Exception("Unexpected response from /api/v1/binary: %s" % (r.status_code))
        return r._content
        
    def dashboard(self):
        '''
        get dashboard data, storage, hosts, sensors
        '''
        if self.token:
            r = requests.get("%s/api/dashboard" % (self.server),
                             headers=self.token_header, verify=self.ssl_verify)
        else:
            r = requests.get("%s/api/dashboard" % (self.server), cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from /api/dashboard: %s" % (r.status_code))
        return r._content

    def get_sensors(self, query_parameters={}):
        '''
        get sensors, optionally specifying searchcriteria
        
        as of this writing, supported search criteria are:
          ip - any portion of an ip address
          hostname - any portion of a hostname, case sensitive 
        '''

        url = "%s/api/v1/sensor?" % (self.server,)
        for query_parameter in query_parameters.keys():
            url += "%s=%s&" % (query_parameter, query_parameters[query_parameter])

        r = requests.get(url, cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from /api/sensor: %s" % (r.status_code))
        return r.content
