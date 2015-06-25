#!/usr/bin/env python
#
#The MIT License (MIT)
#
# Copyright (c) 2015 Bit9 + Carbon Black
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# -----------------------------------------------------------------------------
# Wrapper object around CB API that extends it to add functionality
#
# last updated 2015-05-25 by Ben Johnson bjohnson@bit9.com
#

from cbapi import cbapi
import requests
import simplejson as json
import time

class CbExtendedApi(cbapi.CbApi):
    """
    Extends the official CbApi to have more functionality.
    """
    def __init__(self, server, ssl_verify=True, token=None):
        """
        Takes an instantiated cbapi instance as the only argument
        """
        cbapi.CbApi.__init__(self, server, ssl_verify, token)

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

