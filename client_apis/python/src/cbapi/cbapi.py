import requests
import urllib
from requests.auth import HTTPDigestAuth

class CbApi(object):
    """ Python bindings for Carbon Black API 
    Example:

    import cbapi
    cb = cbapi.CbApi("http://cb.example.com", "admin", "pa$$w0rd")
    # get metadata for all svchost.exe's not from c:\\windows
    procs = cb.processes(r"process_name:svchost.exe -path:c:\\windows\\")  
    for proc in procs['results']:
        proc_detail = cb.process(proc['id'], proc['segment_id'])
        print proc_detail['process']['start'], proc_detail['process']['hostname'], proc_detail['process']['path']
    """
    def __init__(self, server, username, password, ssl_verify=True):
        """ Requires:
                server -    URL to the Carbon Black server.  Usually the same as 
                            the web GUI.
                username -  a Cb GUI username  
                password -  password for the user
        """

        if not server.startswith("http"): 
            raise TypeError("Server must be URL: e.g, http://cb.example.com")

        self.server = server.rstrip("/")
        self.user = username
        self.password = password
        self.cookies = None         # set in login()
        self.ssl_verify=ssl_verify
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
        r = requests.get("%s/api/search/" % self.server, cookies=self.cookies, 
                         params={"q": query_string, 'cburlver': 1, 'start': start, 'rows': rows, 'sort': sort}, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def process(self, guid, segment):
        """ get the detailed metadata for a process.  Requires the 'id' and 'segment_id' fields 
            from a process search result.
    
            Returns a python dictionary with the following primary fields:
                - process - metadata for this process
                - parent -  metadata for the parent process
                - children - a list of metadata structures for child processes
                - siblings - a list of metadata structures for sibling processes
        """
        r = requests.get("%s/api/process/%s/%s" % (self.server, guid, segment), cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def events(self, guid, segment_id):
        """ get all the events (filemods, regmods, etc) for a process.  Requires the 'id' and 'segment_id' fields
            from a process search result"""

        r = requests.get("%s/api/events/%s/%s" % (self.server, guid, segment_id), cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def binaries(self, query_string, start=0, rows=10, last_update="server_added_timestamp desc"):
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
        args = {"q": query_string, "cburlver": 1, 'start': start, 'rows': rows, 'sort': sort}
        query = urllib.urlencode(args)
        r = requests.get("%s/api/search/module/%s" % (self.server, query), cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()

    def binary(self, md5):
        """ get the metadata for a binary.  Requires the md5 of the binary.

            Returns a python dictionary with the binary metadata. """
        
        r = requests.get("%s/api/module/%s" % (self.server, md5), cookies=self.cookies, verify=self.ssl_verify)
        if r.status_code != 200:
            raise Exception("Unexpected response from endpoint: %s" % (r.status_code))
        return r.json()
