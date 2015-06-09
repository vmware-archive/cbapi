"""
The flask blueprint for the presentation backend/api
"""
import base64
import cjson
import copy
import cProfile
import cStringIO as StringIO
import csv
import datetime
from flask import session, make_response, abort, Blueprint, request, send_file, g, url_for, current_app
from functools import wraps
import logging
import pstats
import simplejson
import subprocess
import time
import urlparse
from werkzeug.utils import secure_filename
import zipfile

from cb.api import CbApi
from cb.api.process_doc_reader import ProcessDocReader
from cb.api.netconn import NetConnJsonTranslator, NetConnCsvTranslator, NetConnDummyTranslator
from cb.api.queryparser.QueryStringParser import QuerySyntaxError
from cb.api.solr_api.exceptions import SolrApiInvalidParams
from cb.auth import CbFlaskRealmDigestDB, CbTeamDb, AccountLockedException
from cb.core import feeds
from cb.core.banning.exceptions import BanningError
from cb.core.feeds.exceptions import *
from cb.core.notifications.events import Cmd_Feed_Synchronize
from cb.core.notifications.publisher import PublisherContext
from cb.db.core_models import AllianceDataSharingWho, AllianceDataSharingWhat, SensorGroup
import cb.utils
from cb.utils import datetime_from_str
from cb.utils.db import DbSessionContext
from cb.utils.protobuf_to_dict import protobuf_to_dict
from cb.maintenance.jobs.feed_sync import FeedSyncJob
import cb.core.platform.settings as platform_settings
import cb.core.platform.check as platform_check
from cb.flask.api_routes_saml import SamlRoutes


_logger = logging.getLogger(__name__)


def build_blueprint(cfg, sensor_backend, xsrf):
    """
    :param cb.utils.config.Config cfg: CB config object
    """

    blueprint = Blueprint('presentation', __name__)

    cluster_config = sensor_backend.cluster_config

    enable_profiling = cfg.CoreServicesEnableApiProfiling

    # wrapper around the flask make_response method that includes encoding to json
    def make_response_json(data, *args, **kwargs):
        if args or kwargs:
            response = make_response(simplejson.dumps(data, *args, **kwargs))
        else:
            response = make_response(cjson.encode(data))
        response.headers['Content-Type'] = "application/json; charset=utf-8"
        return response

    # we do this often enough to make it a special case
    def make_response_success_json():
        return make_response_json({"result": "success"})

    # this might be a little too sneaky // which part?
    blueprint.api = CbApi(cfg, cluster_config)
    blueprint.cb_engine = sensor_backend

    team_db = CbTeamDb()

    auth_db = CbFlaskRealmDigestDB(cfg, 'CB')
    auth_db._cbcache = sensor_backend._cbcache
    auth_db.xsrf = xsrf

    saml = SamlRoutes(blueprint, xsrf, cfg, auth_db, sensor_backend._cbcache)

    def open_feed_store():
        return feeds.open_feed_store(cfg, cluster_config, g.db_session)


    @blueprint.before_request
    def init_request():
        '''
            A function that is called before a request
            handler gets executed. This is a great spot
            to construct objects needed for requests
            IE: database sessions.
        '''
        g.db_session_context = DbSessionContext(cfg)
        g.db_session = g.db_session_context.get()
        g.publisher_context = PublisherContext()
        g.publisher = g.publisher_context.get()
        g.user = None
        g.token_user = None

        if enable_profiling:
            g.profiling = True
            g.cb_solr_stats = None
            g.cb_prof = cProfile.Profile()
            g.cb_prof.enable()
            g.start_time = time.time()


    @blueprint.after_request
    def cleanup_request(response):
        '''
            A function that gets execute after the request is completed.
            This is a mirror to the init_request function and you should destroy
            anything that is an object specific to the request.
        '''
        if hasattr(g, "db_session_context"):
            g.db_session_context.finish()
            g.db_session = None
        if hasattr(g, "publisher_context"):
            g.publisher_context.finish()
            g.publisher = None
        if hasattr(g, "token_user"):
            g.token_user = None

        if enable_profiling and hasattr(g, "cb_prof"):
            g.cb_prof.disable()
            ios = StringIO.StringIO()
            profstats = pstats.Stats(g.cb_prof, stream=ios).sort_stats("cumulative")
            profstats.print_stats(.2)
            
            profile = ios.getvalue()[:50000]
            elapsed_ms = int(1000* (time.time() - g.start_time))
            data = {'profile': profile, 'local_timing':elapsed_ms}
            if g.cb_solr_stats is not None:
                if 'debug' in g.cb_solr_stats:
                    # REMOVE THIS BECAUSE IT COULD BE HUGE
                    if 'explain' in g.cb_solr_stats['debug']:
                        del g.cb_solr_stats['debug']['explain']
                data['solr'] = g.cb_solr_stats
            response.headers['X-CbPerfStats'] = cjson.encode(data)

        return response

    def use_cache(per_user=False, ttl=600, url_token=None):
         """
             A decorator function that on a GET request will try and pull if it exists in the external cache.
             If not it will fall into the decorated function and the decorator will take the response.data and
             stash it in the external cache.  We take three paramaters, they are described as follows:

             per_user  :  This is a flag to tell us that the stored value is on a per user basis, IE search results.
             ttl       :  How long we want the value in external cache to live.
             url_token :  In some cases a url route can have 0 to N parameters. The function will act differently based
                          on the parameters passed. We delete the value out of cache on anything that is NOT a 'GET'
                          request. Since a route that takes a parameter in order to delete update etc, but accepts no paramaters
                          to return a full list of objects, this can be troublesome.  The data for no paramaters will be come stale.
                          Therefore we provide this as a means of clumping urls with params and without params into one stored value.
                          that way it will get deleted accordingly.
         """
         def wrapper(method):
             @wraps(method)
             def wrapped_f(*args, **kwargs):
                 
                 # if the source caller is a script (as compared to web ui), then avoid
                 # all caching.  Script can be determined via authentication mechanism
                 #
                 # See ENT-2283
                 #
                 if "X-Auth-Token" in request.headers:
                     return method(*args, **kwargs)

                 # the url_token is read-only.  I suspect it has something to do
                 # with wraps.  Therefore construct an object based on its value.
                 #
                 url = request.url if url_token is None else url_token

                 # If we are per user add the user id to the key.
                 # this provides a keyspace for per-request cached data
                 #
                 if per_user:
                     key = "%s-%s?%s" % (session['uid'], url, request.query_string)
                 else:
                     key = "%s?%s" % (url, request.query_string)

                 # redis is the backing store for cached values
                 # redis performance can suffer as key length increases
                 # using 250 as an _entirely arbitrary_ cutoff point, avoid caching
                 # any value with a keyname >= 250 characters
                 #
                 # see ENT-2470
                 # 
                 if len(key) >= 250:
                     response = method(*args, **kwargs)
                     return response

                 # we only really care about GET requests
                 if request.method == "GET":
                     # so if we are in a GET request check to see if we have a key/value pair
                     # in cache
                     payload = blueprint.cb_engine._cbcache.get(key)
                     if payload:
                         # If we do use it.
                         response = make_response(payload)
                         response.headers['Content-Type'] = 'application/json'
                         return response
                     else:
                         # if we don't, call the provided method and return the response provided.
                         response = method(*args, **kwargs)
                         blueprint.cb_engine._cbcache.set(key, response.data, ttl)
                         return response
                 else:
                     # if we are anything other than a GET request call the method
                     # and delete the key from cache because the data is now considered stale.
                     #
                     # this has interesting ramfications if the UI is updated such that the
                     # process search and binary search functions use HTTP POST rather than
                     # GET.  See ENT-2469 and ENT-2031
                     #
                     blueprint.cb_engine._cbcache.delete(key)
                     return method(*args, **kwargs)
             return wrapped_f
         return wrapper


    # @blueprint.errorhandler(IntegrityError)
    # def error_integrity_error(e):
    #     # TODO - wrap this in an if debug: conditional
    #     # TODO - how to rollback correctly/cleanly/consistently?
    #     blueprint.api.db.session.rollback()
    #     traceback.print_exc()
    #     return "Database integrity violation", 409

    @blueprint.errorhandler(BanningError)
    def unhandled_banning_exception(e):
        _logger.exception("Unhandled banning exception from API request: %s" % e)
        return str(e), 409

    @blueprint.errorhandler(Exception)
    def unhandled_exception(e):
        # TODO - how to rollback database exceptions so the session
        # gets closed?
        ## Note - We don't return output to the end user to avoid XSS reflection attacks as well as to avoid revealing
        ## too much information about the database. 
        _logger.exception("Unhandled exception from API request: %s" % e)
        return "Unhandled exception. Check logs for details.", 500

    # IMPORTANT: The format of the @blueprint.route URL is very important. The way flask works is that if you have
    # a trailing slash in the route definition it does not matter if the requesting client has a slash or not.
    # If the requesting client does not provide a trailing slash it will redirect to the correct URL format and
    # everything will in essence be OK.
    #
    # If you do not put a trailing slash in the route definition and the requesting client does add a trailing slash
    # then flask will issue a 404 Not Found.
    #
    # This means that our standard format for URL route definition is to ALWAYS end the URL with a /
    #
    # See: http://flask.pocoo.org/docs/quickstart/#variable-rules
    # Jira ticket: ENT-2084

    # define the URL handlers
    @blueprint.route('/api')
    def index():
        # TODO healthcheck.
        return 'Carbon Black API.'

    @blueprint.route("/api/login-caps", methods=['GET'])
    def get_login_capabilities():
        """
        Returns server's login capabilities

        IMPORTANT: This function must remain authentication-free as it is being used by the
        login dialog box
        """

        payload = {
            # This parameter can be None if SSO is disabled OR if the user does
            # not wish to display the link
            "login_ui_sso_label": saml.saml_link_label,
            "login_ui_sso_link": saml.saml_link
        }

        response = make_response_json(payload)
        return response

    #Api call to get general app info like version number etc.
    @blueprint.route('/api/info')
    @auth_db.requires_auth(allow_auth_token=True)
    @use_cache()
    def info():
        version = ''
        
        try:
            with open('/usr/share/cb/VERSION', 'r') as f:
                version = f.readline().replace('\n', '')
        except IOError:
                version = ''

        payload = {}
        payload["version"] = version

        if cfg.CoreServicesProcessSearchIntervalSeconds is not None:
            payload["searchInterval"] = cfg.CoreServicesProcessSearchIntervalSeconds

        #Parameterization of search order and page size (rows/page)
        #Defaults are set in config.py
        payload["processOrder"] = cfg.CoreServicesProcessSearchOrder
        payload["binaryOrder"] = cfg.CoreServicesBinarySearchOrder
        payload["processPageSize"] = cfg.CoreServicesProcessSearchPageSize
        payload["binaryPageSize"] = cfg.CoreServicesBinarySearchPageSize

        payload["timestampDeltaThreshold"] = cfg.TimestampDeltaThreshold

        #Setting for the number of search results exported out by the search page.
        payload["searchExportCount"] = cfg.SearchExportCount

        payload["vdiGloballyEnabled"] = cfg.NewRegistrationCallbackModulePath is not None and \
                                        cfg.NewRegistrationCallbackClassName is not None

        payload["linuxInstallerExists"] = blueprint.cb_engine.current_linux_installer_exists()
        payload["osxInstallerExists"] = blueprint.cb_engine.current_osx_installer_exists()

        # is CB live response enabled and do we auto attach sessions
        payload["cblrEnabled"] = cfg.CbLREnabled
        payload["liveResponseAutoAttach"] = cfg.LiveResponseAutoAttach

        # maximum search results rows limit
        payload["maxSearchResultRows"] = cfg.MaxSearchResultRows

        payload["banningEnabled"] = cfg.BanningEnabled

        response = make_response_json(payload)
        return response

    @blueprint.route('/api/help')
    @auth_db.requires_auth(allow_auth_token=True)
    def list_routes():
        links = []
        for rule in current_app.url_map.iter_rules():
            try:
                url = url_for(rule.endpoint)
                if url and rule.endpoint:
                    links.append((url, rule.endpoint))
            except:
                pass
        links.sort()
        return make_response_json(links)

    @blueprint.route('/api/v1/process', methods=['GET', 'POST'])
    @auth_db.requires_auth(allow_auth_token=True)
    @use_cache(per_user=True, ttl=120)
    def search():
        current_user = _get_user()
        if not current_user:
            abort(500)
        query = ''

        # process search supports both HTTP GET and POST
        # ENT-2031
        #
        if request.method == "GET":
            query = urlparse.parse_qs(request.query_string)
        elif request.method == "POST":
            query = simplejson.JSONDecoder().decode(request.data)

        try:
            response = make_response_json(blueprint.api.search(query, (current_user, g.db_session)), indent=2)
        except QuerySyntaxError:
            abort(400)

        return response

    @blueprint.route("/api/v1/process/host/count", methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def hostcount():
        if request.method == 'GET':
            query = urlparse.parse_qs(request.query_string)
            response = make_response_json(blueprint.api.solr.hostcount(query))
        else:
            abort(405)

        return response

    @blueprint.route("/api/v1/process/<guid>/<segment>/preview")
    @auth_db.requires_auth(allow_auth_token=True)
    @use_cache(per_user=True, ttl=300)
    def preview(guid, segment):
        if request.method == 'GET':
            current_user = _get_user()
            if not current_user:
                abort(500)

            query = {}
            if request.query_string is not None:
                query = urlparse.parse_qs(request.query_string)
            # preview modifies the dictionary, pass a copy in case we re-request
            results = blueprint.api.solr.preview(guid, segment, copy.deepcopy(query), (current_user, g.db_session) )
            # see ENT-1525. This is to ensure we have great performance.
            # if no key name in the dictionary ends with _complete, then
            if not any([x.endswith("_complete") for x in results.keys()]):
                results = blueprint.api.solr.preview(guid, segment, query, (current_user, g.db_session), preserveMulti=True )

            response = make_response_json(results, indent=2)
            return response
        else:
            abort(405)  # missing required parameter

    @blueprint.route('/api/v1/binary', methods=['GET', 'POST'])
    @auth_db.requires_auth(allow_auth_token=True)
    @use_cache(per_user=True, ttl=120)
    def search_module():

        # binary search supports both HTTP GET and POST
        # ENT-2469
        #
        if request.method == 'GET':
            args = urlparse.parse_qs(request.query_string)
        else:
            args = simplejson.JSONDecoder().decode(request.data)

        try:
            if args.get("cb.solr_api", ["1"])[0] == "1":
                # Orig solr.py call:
                return make_response_json(blueprint.api.modules_index_search(args), indent=2)
            else:
                # New solr_api.py call:
                results = blueprint.api.solr2.binaries.search(args)
                return make_response_json(results.as_cbapi_dict(), indent=2)

        except QuerySyntaxError:
            abort(400)

    @blueprint.route('/api/v1/binary/<md5>/threat_intel_hits', methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    @use_cache(per_user=True, ttl=120)
    def module_tic_hits(md5):
        print cfg.TicEnableMd5Lookups
        if cfg.TicEnableMd5Lookups:
            data = None
            sensor_groups = blueprint.api.solr2.module_queries.groups(md5)
            if sensor_groups:
                # confirm that at least one of the sensor groups have permission to send this to TIC
                require_alliance_perm(sensor_groups, AllianceDataSharingWhat.TIC_EVENT)

                iocs = {"md5": [md5]}
                data = blueprint.api.tic.get_feed_threat_data(iocs)
            else:
                _logger.info("Ignoring TIC query for MD5 not present in system: %s", md5)

            if data is None:
                abort(404)

            return make_response_json(data)
        else:
            _logger.info("Endpoint disabled")
            abort(404)

    @blueprint.route('/api/v1/binary/<md5>/summary')
    @auth_db.requires_auth(allow_auth_token=True)
    def modules(md5):
        if request.method == "GET":
            bytes = blueprint.api.icon(md5).encode('base64', 'strict')
            args = {"q": ["md5:%s" % md5.upper(),]}
            results = blueprint.api.modules_index_search(args)
            if len(results["results"]) == 0: 
                abort(404)
            results["results"][0]["icon"] = bytes

            response = make_response_json(results["results"][0], indent=2)
            return response
        else:
            abort(405)

    @blueprint.route('/api/v1/alert', methods=['GET', 'POST'])
    @auth_db.requires_auth(allow_auth_token=True)
    def search_alerts():
        if request.method == 'GET':
            args = urlparse.parse_qs(request.query_string)
        else:
            args = simplejson.JSONDecoder().decode(request.data)
        try:
            _apply_user_group_search_filter(args)

            results = blueprint.api.solr2.alerts.search(args)
            return make_response_json(results.as_cbapi_dict(), indent=2)
        except QuerySyntaxError:
            abort(400)

    @blueprint.route('/api/v1/alert/<alert_id>', methods=['POST'])
    @auth_db.requires_auth(allow_auth_token=True)
    def update_alert(alert_id):
        request_data = simplejson.JSONDecoder().decode(request.data)
        # This is bad - API call should normally fail if attributes that can not
        # be updated (read-only) are passed. But backbone UI model passes all
        # attributes back with this request, and I am silently dropping read-
        # only ones before passing it to the backend [GA 9/1/2014 ENT-3539]
        update_data = dict()
        update_data["unique_id"] = alert_id

        if "status" in request_data:
            update_data["status"] = request_data["status"]
            if "assigned_to" not in request_data:
                update_data["assigned_to"] = auth_db.get_current_request_user().username
            else:
                update_data["assigned_to"] = request_data["assigned_to"]

        blueprint.api.solr2.alerts.update_alert(update_data)

        if "set_ignored" in request_data and "feed_id" in request_data and "watchlist_id" in request_data:
            # a feed_id other than -1 indicates an Alliance feed, and also indicates that
            # the watchlist_id (and watchlist_name) fields are used for the report_id
            if request_data["feed_id"] != -1:
                blueprint.api.solr2.feeds.update_reports(
                    {"is_ignored": request_data["set_ignored"]},
                    ids={str(request_data["feed_id"]): [request_data["watchlist_id"]]}
                )

        return make_response_success_json()

    @blueprint.route('/api/v1/alerts', methods=['POST'])
    @auth_db.requires_auth(allow_auth_token=True)
    def update_alerts():
        """
        expected json format:
        {
          "query": "cb.urlver=1&cb.fq.status=unresolved&sort=alert_severity%20desc&rows=10",
          "requested_status": "Resolved",
          "set_ignored": true
        }

        where "set_ignored" is optional
        """
        data = simplejson.JSONDecoder().decode(request.data)

        query_args = urlparse.parse_qs(data['query'])
        _apply_user_group_search_filter(query_args)
        if "assigned_to" not in query_args:
            query_args["assigned_to"] = auth_db.get_current_request_user().username

        requested_status = data['requested_status']
        set_ignored = data.get("set_ignored", False)

        try:
            feeds_to_update = blueprint.api.solr2.alerts.update_alerts_by_query(query_args,
                                                                                requested_status,
                                                                                set_ignored)
        except QuerySyntaxError:
            abort(400)

        if feeds_to_update:
            blueprint.api.solr2.feeds.update_reports({"is_ignored": True}, ids=feeds_to_update)

        return make_response_success_json()


    # TODO - should move to /api/v1/process/host/export
    @blueprint.route("/api/hostexport")
    @auth_db.requires_auth()
    def hostexport():
        if request.method == "GET":
            query = urlparse.parse_qs(request.query_string)
            query["cb.hostexport"] = ["true"]
            query["fl"] = ["id"]
            query["facet.field"] = ["hostname"]
            query["facet"] = ["true"]
            query["rows"] = 0
            query["hl"] = ["false"]
            results = blueprint.api.search(query)

            csv = u'\uFEFF'
            for d in results["facets"]["hostname"]:
                csv += "%s,%s\r\n" % (d["name"], d["value"])
           
            response = make_response(csv)
            response.headers['Content-Type'] = "text/csv; charset=utf-8; name='hosts.csv'"
            # TODO smarter filename?
            response.headers['Content-Disposition'] = "attachment; filename='hosts.csv'; size=%s" % (len(csv))
            return response
             
        else:
            abort(405)

    @blueprint.route('/api/v1/process/<guid>', defaults={'segment': 0}, methods=['GET'])
    @blueprint.route('/api/v1/process/<guid>/<segment>', methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def process(guid, segment=0):
        children = int(request.args.get("children", 15))
        # get the process
        proc = blueprint.api.process(guid, segment, children)
        if not proc:
            abort(404)

        # confirm this user has access
        current_user = _get_user()
        restricted_groups = auth_db.get_user_groups(g.db_session, current_user.id, roles=["No Access",])
        if current_user.global_admin == False and "group" in proc["process"] and proc["process"]["group"] in restricted_groups:
            abort(405)

        response = make_response_json(proc, indent=2)
        return response

    @blueprint.route('/api/v2/process/<guid>', defaults={'segment': None}, methods=['GET'])
    @blueprint.route('/api/v2/process/<guid>/<segment>', methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def processv2(guid, segment = None):
        """
        process v2 returns just the metadata for the requested process
        (not the metadata for the process, it's parent, children and sibilings.)
        """
        # get the process
        proc = blueprint.api.solr.get(guid, segment, summary=True)
        if not proc:
            abort(404)

        # confirm this user has access
        current_user = _get_user()
        restricted_groups = auth_db.get_user_groups(g.db_session, current_user.id, roles=["No Access", ])
        if current_user.global_admin == False and "group" in proc and proc["group"] in restricted_groups:
            abort(405)

        response = make_response_json(proc, indent=2)
        return response

    @blueprint.route('/api/v1/<guid>/event', defaults={'segment': 0}, methods=['GET'])
    @blueprint.route('/api/v1/process/<guid>/<segment>/event', methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def events(guid, segment):
        return get_events(guid, segment, NetConnCsvTranslator(delim='|'))

    @blueprint.route('/api/v2/<guid>/event', defaults={'segment': 0}, methods=['GET'])
    @blueprint.route('/api/v2/process/<guid>/<segment>/event', methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def events_v2(guid, segment):
        return get_events(guid, segment, NetConnJsonTranslator())

    def get_events(guid, segment, netconn_translator):
        args = None
        if request.query_string is not None:
            args = urlparse.parse_qs(request.query_string)

        with open_feed_store() as feed_store:
            reader = ProcessDocReader(cfg, blueprint.api.solr, feed_store, netconn_translator, blueprint.api.cbcache)
            events_dict = reader.read(guid, segment, args)

        if events_dict is None:
            abort(404) # ENT-2491

        response = make_response_json(events_dict)
        return response

    @blueprint.route('/api/v1/<guid>/report', defaults={'segment': 0}, methods=['GET'])
    @blueprint.route('/api/v1/process/<guid>/<segment>/report', methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def events_report(guid, segment):
        return get_events_report(guid, segment, _package_report_netconns_csv, NetConnCsvTranslator(delim='|'))

    @blueprint.route('/api/v2/<guid>/report', defaults={'segment': 0}, methods=['GET'])
    @blueprint.route('/api/v2/process/<guid>/<segment>/report', methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def events_report_v2(guid, segment):
        return get_events_report(guid, segment, _package_report_netconns_json, NetConnJsonTranslator())

    def _package_report_netconns_csv(output, netconns):
        # write CSV lines of netconn events
        #
        netconn_csv = u'\uFEFF' + "Timestamp,Ip,Port,Protocol,Domain,Direction\r\n"
        for netconn in netconns:
            netconn_csv += "%s\r\n" % \
                (netconn.to_csv(delim=',', translate_ip=True, translate_proto=True, translate_direction=True))

        # package the csv-encoded netconns in the output zip
        #
        output.writestr("csv/netconn.csv", netconn_csv.encode("utf-8"))

    def _package_report_netconns_json(output, netconns):
        # write json array of netconn events
        #
        output.writestr("json/netconn.json", simplejson.dumps(
            [netconn.to_dict(translate_ip=True, translate_proto=True, translate_direction=True)
                for netconn in netconns]))

    def get_events_report(guid, segment, report_netconn_packager, normalize_process_netconn):
        """ Turns a solr process doc into a zip file containing events separated into csv and json
        formatted fields.

        :param guid: process guid
        :param segment:  process segment
        :param report_netconn_packager:  write a netconn array as a member of the returned report
        :param normalize_process_netconn:  write the netconns back to the returned process similar to solr format
        :return: zip file containing process report
        """
        args = None
        if request.query_string is not None:
            args = urlparse.parse_qs(request.query_string)

        with open_feed_store() as feed_store:
            # use the dummy netconn translator here so we can do multiple translations below
            reader = ProcessDocReader(cfg, blueprint.api.solr, feed_store, NetConnDummyTranslator(),
                                      blueprint.api.cbcache)
            events_dict = reader.read(guid, segment, args)

        if events_dict is None:
            abort(404) # ENT-2491

        # set up a memory-backed zip 
        #
        io = StringIO.StringIO()
        zf = zipfile.ZipFile(io, "w")
        
        # build report summary dictionary
        # this includes top-level process information
        #
        summary = {}
        summary["path"] = events_dict["process"].get("path", "<UNKNOWN>")
        summary["md5"] = events_dict["process"].get("md5", "<UNKNOWN>")
        summary["process_key"] = events_dict["process"].get("id", "<UNKNOWN>")
        summary["start"] = events_dict["process"].get("start", "<UNKNOWN>") 
        summary["hostname"] = events_dict["process"].get("hostname", "<UNKNOWN>")
        summary["sensor_id"] = events_dict["process"].get("sensor_id", "<UNKNOWN>")
        summary["cmdline"] = events_dict["process"].get("cmdline", "<UNKNOWN>")
        summary["segment_id"] = events_dict["process"].get("segment_id", 0)
        summary["host_type"] = events_dict["process"].get("host_type", "<UNKNOWN>")

        # build CSV of filemod events
        #
        # SOLR schema included here for documentation
        #
        # <!-- FILEMODS - expected to be "(TYPE) | (TIME) | (path) | (md5) | filetype " -->
        #
        filemod_types = {"1": "Created", "2": "FirstWrite", "4": "Deleted", "8": "LastWrite"}

        filemod_csv = u'\uFEFF' + "ActionTypeCode,ActionTypeDesc,Timestamp,Path,Md5,FileType\r\n"

        for filemod in events_dict["process"].get("filemod_complete", []):
            fields = filemod.split('|')
            if len(fields) < 5:
                continue
            fm_entry = {}
            fm_entry["actiontype_code"] = fields[0]
            fm_entry["actiontype_desc"] = filemod_types.get(fields[0], "<UNKNOWN>")
            fm_entry["timestamp"] = fields[1]
            fm_entry["path"] = fields[2]
            fm_entry["md5"] = fields[3]
            fm_entry["filetype"] = fields[4] 
        
            filemod_csv += "%s,%s,%s,%s,%s,%s\r\n" % (fm_entry["actiontype_code"],
                                                      fm_entry["actiontype_desc"],
                                                      fm_entry["timestamp"],
                                                      fm_entry["path"],
                                                      fm_entry["md5"],
                                                      fm_entry["filetype"])

        # package the csv-encoded filemods in the output zip
        #
        zf.writestr("csv/filemods.csv", filemod_csv.encode("utf-8"))

        # build CSV of regmod events
        #
        # SOLR schema included here for documentation
        #
        # <!-- REGMODS - expected to be "(TYPE) | (TIME) | (path)" -->
        #
        regmod_types = {"1": "CreateKey", "2": "WriteValue", "4": "DeleteKey", "8": "DeleteValue"}

        regmod_csv = u'\uFEFF' + "ActionTypeCode,ActionTypeDesc,Timestamp,Path\r\n"

        for regmod in events_dict["process"].get("regmod_complete", []):
            fields = regmod.split('|')
            if len(fields) < 3:
                continue
            rm_entry = {}
            rm_entry["actiontype_code"] = fields[0]
            rm_entry["actiontype_desc"] = regmod_types.get(fields[0], "<UNKNOWN>")
            rm_entry["timestamp"] = fields[1]
            rm_entry["path"] = fields[2]
        
            regmod_csv += "%s,%s,%s,%s\r\n" % (rm_entry["actiontype_code"],
                                               rm_entry["actiontype_desc"],
                                               rm_entry["timestamp"],
                                               rm_entry["path"])

        # package the csv-encoded regmods in the output zip
        #
        zf.writestr("csv/regmods.csv", regmod_csv.encode("utf-8"))

        # build CSV of modload events
        #
        # SOLR schema included here for documentation
        #
        # <!-- MODLOADS - expected to be "(TIME) | (md5) | (path)" -->
        #

        modload_csv = u'\uFEFF' + "ActionTypeCode,ActionTypeDesc,Timestamp,Path,Md5\r\n"

        for modload in events_dict["process"].get("modload_complete", []):
            fields = modload.split('|')
            if len(fields) < 3:
                continue
            ml_entry = {}
            ml_entry["timestamp"] = fields[0]
            ml_entry["md5"] = fields[1]
            ml_entry["path"] = fields[2]
        
            modload_csv += "1,Load,%s,%s,%s\r\n" % (ml_entry["timestamp"],
                                                    ml_entry["path"],
                                                    ml_entry["md5"])

        # package the csv-encoded modloads in the output zip
        #
        zf.writestr("csv/modloads.csv", modload_csv.encode("utf-8"))
        
        # package the netconns based on packager determined by endpoint
        #
        netconns = events_dict["process"].get("netconn_complete", [])
        report_netconn_packager(zf, netconns)

        if netconns:
            # write netconns back in str format
            events_dict["process"]["netconn_complete"] = [normalize_process_netconn(netconn) for netconn in netconns]

        # package the json document and summary in the output zip
        #
        zf.writestr("json/process.json", simplejson.dumps(events_dict))
        zf.writestr("json/summary.json", simplejson.dumps(summary))
        
        # avoid zero'd linux permissions
        # 
        for zfile in zf.filelist:
            zfile.create_system = 0

        zf.close()

        io.seek(0)

        response = make_response_json(events_dict)
        response.headers['Content-Type'] = "application/zip"
        
        return send_file(io, mimetype="application/zip", attachment_filename='events.zip')

    @blueprint.route('/api/v1/process/<guid>/<segment>/threat_intel_hits', methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    @use_cache(per_user=True, ttl=120)
    def process_tic_hits(guid, segment):
        args = None
        if request.query_string is not None:
            args = urlparse.parse_qs(request.query_string)

        reader = ProcessDocReader(cfg, blueprint.api.solr, None, None, blueprint.api.cbcache)
        process_doc = reader.read(guid, segment, args)

        data = None
        if process_doc:
            if not cfg.TicEnableMd5Lookups:
                _logger.info("TIC md5 lookups are disabled")
            iocs = reader.gather_iocs(process_doc, cfg.TicEnableMd5Lookups)

            # confirm the sensor group has permission to send this to TIC
            require_alliance_perm([iocs.pop("group")], AllianceDataSharingWhat.TIC_EVENT)

            data = blueprint.api.tic.get_feed_threat_data(iocs)

        if data is None:
            abort(404)

        return make_response_json(data)

    @blueprint.route('/api/group', defaults={'id': None}, methods=['GET', 'POST'])
    @blueprint.route('/api/group/<id>', methods=['POST', 'DELETE', 'PUT', 'GET'])
    @auth_db.requires_auth()
    def groups(id):
        """
            /api/group/
            GET - gets a list of all configured groups and their settings
            DELETE - deletes specified group
            POST - updates settings for specified group
            PUT - creates new group with specified settings
        """
        try:
            response = None

            if request.method == "GET":
                # get group(s) metadata
                if id:
                    # Do an int check on id before query to stop 500 unhandled exception error?
                    # also acts as xss input filter
                    try:
                        int(id)
                    except ValueError:
                        abort(403)
                    require_perm_on_group(request, 'GET', id)

                group_rows = blueprint.api.db.groups(id)

                teams = team_db.all_teams(g.db_session)

                for team in teams:
                    for row in group_rows:
                        team_access_category = team_db.get_access_category(g.db_session, team["id"], row["id"])
                        if "team_access" not in row:
                            row["team_access"] = []
                        row["team_access"].append({'team_id': team['id'],
                                               'team_name': team['name'],
                                               'access_category': team_access_category})

                response = make_response_json(group_rows)

            elif request.method == "DELETE":
                # TODO - this can be complicated; see ENT-496
                # delete spec'ed group
                if id == 1:
                    abort(403)  # can't delete the default group...

                # Do an int check on id before query to stop 500 unhandled exception error?
                # also acts as xss input filter
                try:
                    int(id)
                except ValueError:
                    abort(403)

                blueprint.api.db.group_delete(id)
                response = make_response()

            elif request.method == "POST":
                require_perm_on_group(request, 'POST', id)

                # add new group
                group_id = blueprint.api.db.group_add(simplejson.loads(request.data))
                response = make_response_json({'id': group_id}, indent=2)

            elif request.method == "PUT":
                require_perm_on_group(request, 'PUT', id)

                # update existing group
                blueprint.api.db.group_update(id, simplejson.loads(request.data))

                response = make_response()
            else:
                abort(405)

            if response is not None:
                response.headers['Content-Type'] = "application/json"

            return response
        except Exception, e:
            if "duplicate_groupname" in str(e) or "IntegrityError" in str(e):
                abort(409)
            else:
                if "405: Method Not Allowed" in str(e):
                    abort(405)
                else:
                    _logger.exception("Unexpected exception in /api/group processing.")
                    abort(500)

    @blueprint.route('/api/v1/sensor', defaults={'id': None}, methods=['GET',])
    @blueprint.route('/api/v1/sensor/<id>', methods=['GET', 'PUT',])
    @auth_db.requires_auth(allow_auth_token=True)
    def hosts(id):
        """
            GET - return one or more sensor registration records; see notes 
            PUT - updates summary metadata for specified hosts
            DELETE - not supported
            PUT - not supported

            Notes: if a sensor ID is specified via a GET request, the return type
                   is a JSON dictionary; if no sensor ID is specified the return
                   type is a JSON list of dictionaries.
        """
        if request.method == "GET":

            # special case for when a specific sensor id is provided by the remote caller
            # the contract with the caller is to return a dictionary representing the sensor
            # registration record
            #
            if id is not None:
            
                # validate that the caller-provided sensor id is a valid integer and abort
                # request with an HTTP 400 error if not
                #
                require_int(id)
   
                # blueprint.api.db.host() will return one of two things:
                #   a dictionary representing the host
                #   an empty list indicating that no such sensor registration was found
                #
                # furthermore, blueprint.api.db.host() does no access control, so we
                # enforce access control here
                # 
                raw_host = blueprint.api.db.host(id)
                if isinstance(raw_host, dict):
                    if check_perm_on_group(request, 'GET', raw_host['group_id']):
                        response = make_response_json(raw_host, indent=2)
                    else:
                        # the sensor id exists, but the remote caller does not have view rights
                        #
                        abort(405)
                else:
                    # the sensor id does not exist
                    #
                    abort(404)

            # handle the cases where no specific sensor id is requested
            # 
            else: 
            
                raw_hosts = []             # all sensors that meet the search criteria
                authorized_hosts = []      # sensors that meet the search criteria that are in groups authorized for current user
                
                # special cases where a particular query is provided
                # this allows listing sensors by particular attributes
                #
                # see ENT-1910, ENT-2032, ENT-4120
                # 
                if request.args is not None and len(request.args) > 0:
                    for arg in request.args:
                        if "ip" == arg:
                            raw_hosts += blueprint.api.db.host_by_ip(request.args.get('ip'))
                        elif "hostname" == arg:
                            raw_hosts += blueprint.api.db.host_by_hostname(request.args.get('hostname'))
                        elif "groupid" == arg:
                            group_id = request.args.get('groupid')
                            require_int(group_id)
                            raw_hosts += blueprint.api.db.host_by_groupid(group_id)
                
                else:
                    # blueprint.api.db.host() returns a list of zero or more sensors when no id is provided, or
                    # a dictionary representing a single sensor registration otherwise
                    #
                    raw_hosts = blueprint.api.db.host(None)

                # filter out any sensors that matched search criteria but are not
                # in groups accessible to current user (ENT-3666)
                #
                # todo: in cases where multiple filter parameters are provided, sensor registrations
                #       may be repeated (no de-duplication implemented)
                # todo: determine if multiple filter parameters should be implicit AND or implicit OR
                #
                # both of these todos are tracked by ENT-4152
                #
                permission_cache = {}
                for host in raw_hosts:
                    if not host['group_id'] in permission_cache:
                        permission_cache[host['group_id']] = check_perm_on_group(request, 'GET', host['group_id'])

                    if permission_cache[host['group_id']]:
                        authorized_hosts.append(host)

                response = make_response_json(authorized_hosts, indent=2)

        elif request.method == "PUT":
            # HTTP PUT requests require global admin rights
            auth_db.require_global_admin(g.db_session, request)
            
            data = cjson.decode(request.data)
            # only update this if you have PUT perms on the group
            if check_perm_on_group(request, 'PUT', data['group_id']):
                blueprint.api.db.hosts_update(id, data)
            response = make_response()
            response.headers['Content-Type'] = "application/json"

        else:
            abort(405)

        return response

    @blueprint.route('/api/server', defaults={'id': None}, methods=['GET'])
    @blueprint.route('/api/server/<id>', methods=['PUT'])
    @auth_db.requires_auth()
    def servers(id):
        """
            /api/servers/(id)
            GET    - return a list of servers
            POST   - Add a new server
            PUT    - Update an existing server
            DELETE - Remove an existing server
        """

        if request.method == 'GET':
            servers = blueprint.api.db.get_servers()
            response = make_response_json(servers)

        elif request.method == 'PUT':
            # we only limit HTTP PUT to global admin because
            # we call this endpoint from the host list page which
            # non global admins have access to
            auth_db.require_global_admin(g.db_session, request)
            
            data = simplejson.loads(request.data)
            blueprint.api.db.server_update(id, data['hostname'], data['address'])
            sensor_backend._cbcache.delete("sensor_upload_url_node_%d" % int(id))
            response = make_response()
            response.headers['Content-Type'] = 'application/json'

        return response

    @blueprint.route("/api/site", defaults={'id': None}, methods=['GET','POST'])
    @blueprint.route('/api/site/<id>', methods=['GET', 'POST','PUT','DELETE'])
    @auth_db.requires_auth()
    def sites(id):
        """
            /api/sites/(id)
            GET - return a list of sites 
            PUT - updates metadata for a site
            POST - creates a new site, returns site id
            DELETE - delete specified site
        """

        if request.method == "GET":
            sites_dict = blueprint.api.db.sites(id)
            response = make_response_json(sites_dict, indent=2)

        elif request.method == "PUT":
            auth_db.require_global_admin(g.db_session, request)
            blueprint.api.db.site_update(id, simplejson.loads(request.data))
            response = make_response()

        elif request.method == "POST":
            auth_db.require_global_admin(g.db_session, request)
            # add new site
            id = blueprint.api.db.site_add(simplejson.loads(request.data))
            response = make_response_json({'id': id}, indent=2)

        elif request.method == "DELETE":
            auth_db.require_global_admin(g.db_session, request)
            blueprint.api.db.site_delete(id)
            response = make_response()

        else:
            abort(405)

        response.headers['Content-Type'] = "application/json"
        return response

    def validate_throttle_request(request_data):
        is_valid = True
        bytes_per_second = request_data.get('bytes_per_second')

        try:
            int(bytes_per_second)
        except (ValueError, TypeError) as e:
            _logger.error("Unable to add throttle. Bytes/second provided '%s' is not a valid integer." %
                          bytes_per_second)
            _logger.debug(repr(e))
            is_valid = False

        return is_valid

    @blueprint.route('/api/throttle/<throttle_id>', methods=['GET', 'PUT','DELETE'])
    @blueprint.route('/api/throttle', defaults={'throttle_id': None}, methods=['GET', 'POST'])
    @auth_db.requires_auth()
    @use_cache(per_user=True, url_token='throttle')
    def throttles(throttle_id):
        """
            /api/throttle/(id)
            GET - return a list of throttles for the specified site
            PUT - updates metadata for a throttle
            POST - creates a new throttle, returns 
            DELETE - delete specified throttle

            This is an odd endpoint, in that it translates the DB entity into
            one more suitable for the UI.  see the coalesce()/explode() functions
            for details.
        
            The id is a .-delimited list of original IDs: i.e., a throttle that 
            was coalesced from three distinct DB throttles w/ ids 3, 4, 7 will end 
            up with the id "3.4.7"
        """
        auth_db.require_global_admin(g.db_session, request)

        if request.method == "GET":
            if throttle_id is not None:
                ids = throttle_id.split(".")
                throttles = blueprint.api.db.throttle(ids)
                throttle = blueprint.api.db.throttle_coalesce(throttles)
                response = make_response_json(throttle[0])

            else: # ALL
                throttles_list = blueprint.api.db.throttle_coalesce(blueprint.api.db.throttles())
                response = make_response_json(throttles_list, indent=2)

        elif request.method == "POST":
            # add new
            request_data = cjson.decode(request.data)
            if validate_throttle_request(request_data) is False:
                abort(405)

            throttles = blueprint.api.db.throttle_explode(request_data)
            ids = blueprint.api.db.throttle_add(throttles)
            throttle_id = ".".join([str(id) for id in ids])
            response = make_response_json({'id': throttle_id}, indent=2)

        elif request.method == "PUT":
            ids = throttle_id.split(".")
            request_data = cjson.decode(request.data)
            if validate_throttle_request(request_data) is False:
                abort(405)

            throttles = blueprint.api.db.throttle_explode(request_data)
            ids = blueprint.api.db.throttle_update(ids, throttles)
            throttle_id = ".".join([str(id) for id in ids])
            response = make_response_json({'id': throttle_id}, indent=2)

        elif request.method == "DELETE":
            ids = throttle_id.split(".")
            blueprint.api.db.throttle_delete(ids)
            response = make_response()

        else:
            abort(405)

        response.headers['Content-Type'] = "application/json"
        return response

    # TODO: Do we use this? - kyle
    @blueprint.route('/api/about')
    @auth_db.requires_auth()
    def about():
        ### not sure that calling rpm in a subprocess is the best way to get the version for responding to a web request...
        # stored in the database or in a flat-file maybe?
        version = subprocess.Popen(['rpm', '-q', 'cb-enterprise'], stdout=subprocess.PIPE).communicate()[0]
        about = {'version': version.rstrip('\n')}
        response = make_response_json(about, indent=2)
        return response

    @blueprint.route('/api/auth')
    def auth():
        """ This is the _one_ api that uses the Authorization header & challenge response.
            The remaining endpoints check for the session cookie that is set at the end of this 
            function. 

               -> user hits /api/auth with a GET, /api/auth returns 403 with a www-authenticate header (challenge)
               -> next response to /api/auth includes an Authorization header with the Digest (response)
               -> that's processed by flask, if it's valid it sets request.authorization
               -> this function executes, refreshes the session cookie and adds the uid into the session cookie
               -> remaining functions all simply check for the valid session cookie; on fail they return 403

               The alternative is when users use a CLI API interface. We give the user a auth token they can use
               for CLI API purposes.
        """
        # validate the authentication header
        if not auth_db.isAuthenticated(g.db_session, request):
            if request.authorization: auth_db.failed_auth(g.db_session, request.authorization.username)
            return auth_db.challenge()

        # isAuth() can return true for either authorization or session cookies
        # other endpoints only validate session cookies.
        if "uid" in session:
            auth_user = auth_db.get_user_by_id(g.db_session, session["uid"])
        else:
            auth_user = auth_db.get_user(g.db_session, request.authorization.username)
        
        if auth_user.last_login_attempt is not None:
            # Figure out the elapsed time between the current date time
            # and the last time the user attempted to login (either successful or failed)
            current = cb.utils.get_utcnow_with_tzinfo()
            elapsedTime = current - auth_user.last_login_attempt
            
            # if the account meets the locking criteria then
            # we should raise the custom exception so we return a 423 status code
            if auth_user.num_successive_failed_logons >= cfg.FailedLogonLockoutCount and \
                            elapsedTime < datetime.timedelta(minutes=cfg.AccountUnlockInterval):
                auth_user.last_login_attempt = cb.utils.get_utcnow_with_tzinfo()
                g.db_session.add_and_commit(auth_user)
                raise AccountLockedException  
        # we have successfully logged in
        if request.authorization:
            auth_db.successful_auth(g.db_session, request.authorization.username)

        current_user = {'user_id': auth_user.id,
                'username': auth_user.username,
                'first_name': auth_user.firstname,
                'last_name': auth_user.lastname,
                'global_admin': auth_user.global_admin,
                'auth_token': auth_user.auth_token
                }

        # the session cookie is crypto secure, as long as the SecretKey stays secret, so we set
        # user id in the session cookie and trust the cookies that come in are true.
        session.permanent = True        # perm cookie lifetime set to cfg.SessionTimeout seconds in cbflask.py
        session["uid"] = auth_user.id
        
        auth_db.set_user_last_login(g.db_session, auth_user)
        response = make_response_json(current_user, indent=2)
        return response

    @blueprint.route('/api/logout')
    @auth_db.requires_auth()
    def logout():
        session.pop('uid', None)
        abort(401) # There isn't a defined way of logging out for digest-auth but this will serve the purpose

    # TODO: Collapse this into the api/user function - kyle
    @blueprint.route('/api/users')
    @auth_db.requires_auth()
    def users():
        auth_db.require_global_admin(g.db_session, request)

        _users = auth_db.all_users(g.db_session)
        exportable_users = []
        for _user in _users:
            export_user = {}
            export_user["username"] = _user.username
            export_user["first_name"] = _user.firstname
            export_user["last_name"] = _user.lastname
            export_user["email"] = _user.email
            export_user["global_admin"] = _user.global_admin
            export_user["teams"] = auth_db.get_user_teams(g.db_session, _user.id)
            exportable_users.append(export_user)
        response = make_response_json(exportable_users, indent=2)
        return response

    @blueprint.route('/api/user', defaults={'username': None}, methods=['POST'])
    @blueprint.route('/api/user/<username>', methods=['GET', 'PUT', 'DELETE'])
    @auth_db.requires_auth()
    def user(username):
        if request.method == 'GET':
            auth_db.ensure_global_admin_or_current_user(username)
            requested_user = auth_db.get_user(g.db_session, username)

            _user = {'username': requested_user.username,
                    'first_name': requested_user.firstname,
                    'last_name': requested_user.lastname,
                    'email': requested_user.email,
                    'global_admin': requested_user.global_admin,
                    'auth_token': requested_user.auth_token,
                    'teams': auth_db.get_user_teams(g.db_session, requested_user.id)
                    }
            response = make_response_json(_user, indent=2)
            return response
        elif request.method == 'PUT':
            auth_db.ensure_global_admin_or_current_user(username)
            try:
                auth_db.update_user(g.db_session, simplejson.loads(request.data))
            except Exception, e:
                if "IntegrityError" in str(e):
                    abort(409)
                else:
                    _logger.exception("Unhandled exception while updating user")
                    abort(500)
        elif request.method == 'POST':
            auth_db.require_global_admin(g.db_session, request)
            try:
                auth_db.add_user(g.db_session, simplejson.loads(request.data))
            except Exception, e:
                # TODO create custom exception and put in cb/utils/exceptions.py
                if str(e) == 'duplicate_username':
                    abort(409) # HTTP error code for resource-conflict
                else:
                    _logger.exception("Unhandled exception while adding user")
                    abort(500)
        elif request.method == 'DELETE':
            auth_db.require_global_admin(g.db_session, request)
            auth_db.del_user(g.db_session, username)

        response = make_response_success_json()
        return response

    @blueprint.route('/api/v1/user/<username>/token', methods=['POST'])
    @auth_db.requires_auth()
    def update_token(username):
        auth_db.ensure_global_admin_or_current_user(username)
        token = auth_db.reset_auth_token(g.db_session, username)
        response = make_response_json({"auth_token": token})
        return response

    @blueprint.route('/api/user/<username>/permissions', methods=['GET'])
    @auth_db.requires_auth()
    def group_permission(username):
         permissions = auth_db.user_group_permissions(g.db_session, username)
         response = make_response_json(permissions, indent=2)
         response.headers['Acess-Control-Allow-Origin'] = "*"   #RICH: Is this intended ?
         return response

    @blueprint.route('/api/useractivity', methods=['GET'])
    @auth_db.requires_auth()
    def user_activity():
        auth_db.require_global_admin(g.db_session, request)
        # Ensure the current user is global admin
        data = auth_db.get_user_activity(g.db_session)

        response = make_response_json(data, indent=2)
        return response

    @blueprint.route('/api/team', defaults={'team_id': None}, methods=['POST'])
    @blueprint.route('/api/team/<team_id>', methods=['GET', 'PUT', 'DELETE'])
    @auth_db.requires_auth()
    def team(team_id):
        auth_db.require_global_admin(g.db_session, request)
        try:
            if request.method == 'GET':
                team = team_db.get_team(g.db_session, team_id)
                response = make_response_json(team, indent=2)
                return response
            elif request.method == 'PUT':
                team_db.update_team(g.db_session, simplejson.loads(request.data))
            elif request.method == 'POST':
                t = team_db.add_team(g.db_session, simplejson.loads(request.data))
                team = team_db.get_team(g.db_session, str(t).split(' ')[1])
                response = make_response_json(team, indent=2)
                return response
            elif request.method == 'DELETE':
                team_db.del_team(g.db_session, team_id)

            response = make_response_success_json()
            return response
        except Exception, e:
            if "duplicate_teamname" in str(e) or "IntegrityError" in str(e):
                abort(409)
            else:
                abort(500)

    @blueprint.route('/api/teams')
    @auth_db.requires_auth()
    def teams():
        auth_db.require_global_admin(g.db_session, request)

        response = make_response_json(team_db.all_teams(g.db_session), indent=2)
        return response

    @blueprint.route("/api/v1/binary/<md5>/icon")
    @auth_db.requires_auth(allow_auth_token=True)
    def icon(md5):
        bytes = blueprint.api.icon(md5)
        if not bytes: abort(404)
        response = make_response(bytes)
        response.headers['Content-Type'] = "image/png"
        return response

    @blueprint.route("/api/v1/license", methods=['GET', 'POST'])
    @auth_db.requires_auth(allow_auth_token=True)
    def license_summary():
        """
           HTTP GET - Provides a simple, parameter-free mechanism to determine
           current license status.
 
           HTTP POST - Apply a new license
        """

        # all queries as to license status require global admin
        #
        auth_db.require_global_admin(g.db_session, request) 
      
        if request.method == 'GET':
            now = cb.utils.get_utcnow_with_tzinfo()

            # query the license usage table for license status as of 
            # the previous midnight.  
            cli = \
            blueprint.api.db.concurrent_license_info(blueprint.cb_engine.license_manager,\
                                                     (now - datetime.timedelta(days=31)).date(),
                                                     now.date())

            # results are provided in a new dictionary
            # this provides a mechanism to abstract what is returned from concurrent_license_info
            # and add several synthesized fields
            #
            results = {}

            # 
            results['license_end_date'] = cli['license_end_date']
            results['licensed_sensor_count'] = cli['licensed_sensors']
            results['server_token'] = cli['server_token']
            results['license_valid'] = cli['is_license_valid']
            results['actual_sensor_count'] = cli['current_sensor_count']

            # determine if the licensed sensor count has been exceeded
            #
            results['licensed_sensor_count_exceeded'] = cli['current_sensor_count'] > cli['licensed_sensors']

            # determine if the license end-date has been exceeded
            #
            end = cb.utils.with_utc_tzinfo(datetime.datetime.strptime(cli['license_end_date'], "%Y-%m-%d"))
            results['license_expired'] = end < now

            # license request block
            results['license_request_block'] = blueprint.api.db.get_license_request(\
                                        blueprint.cb_engine.license_manager)['license_request_block']

            response = make_response_json(results)
        elif request.method == 'POST':
            data = simplejson.loads(request.data)
            if blueprint.api.db.update_server_license(blueprint.cb_engine.license_manager, _get_user(),
                                                      data.get("license")):
                response = make_response_success_json()
            else:
                response = make_response_json({'result': 'failure', 'error': 'Invalid license'})
                response.status_code = 400

        return response

    @blueprint.route("/api/concurrent_license_info/<start_yyyymmdd>/<end_yyyymmdd>", methods=['GET'])
    @auth_db.requires_auth()
    @use_cache(per_user=True)
    def concurrent_license_info(start_yyyymmdd, end_yyyymmdd):
        """
        internal API for server dashboard
        """
        auth_db.require_global_admin(g.db_session, request)

        start_date = cb.utils.with_utc_tzinfo(datetime.datetime.strptime(start_yyyymmdd, "%Y%m%d"))
        end_date = cb.utils.with_utc_tzinfo(datetime.datetime.strptime(end_yyyymmdd, "%Y%m%d"))

        response = make_response_json(blueprint.api.db.concurrent_license_info(\
                blueprint.cb_engine.license_manager, start_date.date(), end_date.date()), indent=2)
        return response

    @blueprint.route("/api/license", methods=['GET', 'POST'])
    @auth_db.requires_auth()
    @use_cache(per_user=True)
    def license_request():
        auth_db.require_global_admin(g.db_session, request)

        if request.method == 'GET':
            response = make_response_json(
                blueprint.api.db.get_license_request(blueprint.cb_engine.license_manager), indent=2)
        elif request.method == 'POST':
            data = cjson.decode(request.data)
            if blueprint.api.db.update_server_license(blueprint.cb_engine.license_manager, _get_user(),
                                                      data.get("license")):
                response = make_response_success_json()
            else:
                response = make_response_json({'result': 'failure', 'error': 'Invalid license'})
                response.status_code = 400
        else:
            abort(405)

        return response

    @blueprint.route('/api/v1/settings/global/platformserver', methods=['GET', 'POST'])
    @auth_db.requires_auth(allow_auth_token=True)
    def platform_server():
        auth_db.require_global_admin(g.db_session, request)

        if request.method == 'GET':
            response = make_response_json(platform_settings.get_platformserver_settings(g.db_session))
        elif request.method == 'POST':
            platform_settings.set_platformserver_settings(g.db_session, cjson.decode(request.data))
            response = make_response_success_json()

        return response

    @blueprint.route('/api/v1/settings/global/platformserver/test', methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def platform_server_test():
        auth_db.require_global_admin(g.db_session, request)

        try:
            platform_response = platform_check.send_post(g.db_session, None)
            _logger.debug('platform server response: %s', platform_response)
        except:
            _logger.exception('Failed attempt to connect to the Bit9 platform server')
            abort(503) # service unavailable
        
        response = make_response_success_json()
        return response

    @blueprint.route("/api/communication_settings", methods=['GET', 'POST'])
    @auth_db.requires_auth()
    @use_cache(per_user=True)
    def communication_settings():
        auth_db.require_global_admin(g.db_session, request)
        
        if request.method == 'GET':
            data = blueprint.api.db.alliance_settings.communication_settings()
            response = make_response_json(data)
        if request.method == 'POST':
            res, message = blueprint.api.db.alliance_settings.communication_settings_save(cjson.decode(request.data))
            if res:
                response = make_response_success_json()
            else:
                response = make_response_json({'result': 'failure', 'error': message})
                response.status_code = 400
        return response

    @blueprint.route("/api/v1/feed/<id>/report", defaults={'report_id': None}, methods=['GET'])
    @blueprint.route("/api/v1/feed/<id>/report/<report_id>", methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def get_feed_reports(id, report_id):
        """
        returns report data for a particular report id, or an entire list of
        reports 

        note:
            <id> MUST be a feed ID in order to avoid what Scott describes
            "difficult-to-explain-from-the-outside behavior"

            If internal feed id is not known, the client will need to retrieve a list of
            feeds first via "GET /api/v1/feed"
        """

        feed_id = int(id)

        with open_feed_store() as fss:
            feed = fss.get_feed(feed_id)
            if report_id is None:
                response_data = [r.to_json_dict() for r in feed.iter_reports()]
            else:
                response_data = feed.get_report(report_id).to_json_dict()

        response = make_response_json(response_data)
        return response

    @blueprint.route("/api/v1/feed/<feed_id>/report/<report_id>/stats", methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def get_report_stats(feed_id, report_id):
        with open_feed_store() as fss:
            stats_results = blueprint.api.solr2.reports.get_stats(fss, int(feed_id), report_id)
        response = make_response_json(stats_results)
        return response

    @blueprint.route("/api/v1/feed", methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def get_feed_list():
        include_auth_data = auth_db.is_user_global_admin(request)
        with open_feed_store() as fss:
            resp_data = [feed.as_dict(include_auth_data) for feed in fss.iter_feeds()]
        response = make_response_json(resp_data, indent=2)
        return response

    @blueprint.route("/api/v1/feed", methods=['POST'])
    @auth_db.requires_auth(allow_auth_token=True)
    def create_feed():
        try:
            auth_db.require_global_admin(g.db_session, request)
            data = cjson.decode(request.data)

            with open_feed_store() as fss:
                feed = fss.add_manual_feed(data)

                response = make_response_json(feed.as_dict(auth_db.is_user_global_admin(request)), indent=2)
                return response
        except FeedSyncJsonError:
            abort(409)
        except FeedSyncTimeoutError:
            abort(408)

    @blueprint.route("/api/internal/alliance", methods=['POST'])
    @auth_db.requires_auth(allow_auth_token=True)
    def check_for_new_feeds():
        auth_db.require_global_admin(g.db_session, request)
        job = FeedSyncJob(cfg, g.db_session)
        job.execute()

        response = make_response_success_json()
        return response

    @blueprint.route("/api/v1/feed/<id>", methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def get_feed_info(id):
        with open_feed_store() as fss:
            feed = fss.get_feed(int(id))

        response = make_response_json(feed.as_dict(), indent=2)
        return response

    @blueprint.route("/api/v1/feed/<id>", methods=['PUT'])
    @auth_db.requires_auth(allow_auth_token=True)
    def modify_feed(id):
        auth_db.require_global_admin(g.db_session, request)
        data = cjson.decode(request.data)
        feed_id = int(id)

        with open_feed_store() as fss:
            # TODO: Verify behavior if invalid feed_id is specified
            fss.get_feed(feed_id).modify(data)

        response = make_response_success_json()
        return response

    @blueprint.route("/api/v1/feed/<id>", methods=['DELETE'])
    @auth_db.requires_auth(allow_auth_token=True)
    def delete_feed(id):
        auth_db.require_global_admin(g.db_session, request)
        feed_id = int(id)
        with open_feed_store() as fss:
            fss.get_feed(feed_id).delete()
        response = make_response_success_json()
        return response

    @blueprint.route("/api/v1/feed/<id>/synchronize", methods=['POST'])
    @auth_db.requires_auth(allow_auth_token=True)
    def synchronize_feed(id):
        feed_id = int(id)
        with open_feed_store() as fss:
            feed = fss.get_feed(feed_id)
            if not feed.enabled:
                abort(409, "Cannot synchronize a disabled feed")
            Cmd_Feed_Synchronize(feed_id=feed_id,
                                 full_sync=cjson.decode(request.data).get("full_sync", False)).fire()
        return make_response_success_json()

    @blueprint.route("/api/v1/feed/<id>/icon", methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    @use_cache()
    def get_feed_icon(id):
        with open_feed_store() as fss:
            feed = fss.get_feed(int(id))

        bytes = feed and feed.icon or feeds.DEFAULT_FEED_ICON
        response = make_response(base64.b64decode(bytes))
        return response

    @blueprint.route("/api/v1/feed/<id>/requirements", methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def get_feed_requirements(id):
        with open_feed_store() as fss:
            feed = fss.get_feed(int(id))

        passed, failed = feed.process_requirements()
        response = make_response_json({"passed": passed, "failed": failed})
        return response

    @blueprint.route('/api/v1/threat_report', methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def search_feed_reports():
        args = urlparse.parse_qs(request.query_string)
        try:
            fmt = "json"
            if "format" in args:
                fmt = args.pop("format")
                if not isinstance(fmt, basestring):
                    fmt = fmt[0]

            results = blueprint.api.solr2.feeds.search(args)

            if fmt == "csv":
                docs = results.docs

                output = StringIO.StringIO()
                writer = csv.writer(output)

                # header row
                header = docs[0]
                header.pop("_version_")
                writer.writerow(header.keys())

                # data rows
                for doc in docs:
                    if "_version_" in doc:
                        doc.pop("_version_")
                    writer.writerow(doc.values())

                csv_str = output.getvalue()
                response = make_response(csv_str)
                response.headers['Content-Type'] = "text/csv; charset=utf-8; name='threat_reports.csv'"
                response.headers['Content-Disposition'] = "attachment; filename='threat_reports.csv'; size=%s" % (len(csv_str))
            else:
                response = make_response_json(results.as_cbapi_dict(), indent=2)

            return response
        except QuerySyntaxError:
            abort(400)

    @blueprint.route("/api/v1/threat_report", methods=["POST"])
    @auth_db.requires_auth(allow_auth_token=True)
    def update_feed_reports():
        """
        Expected structure of request payload:
        {
            "ids": {
                "<feed_id>": ["<report_id>", [...]]
            },
            "query: "<url-encoded query string>",
            "updates": {
                "<property>": "<value>",
            }
        }
        where either "ids" or "query" must be present, and "updates" is always required.

        The only allowed property in "updates" at this time is "is_ignored" (boolean).
        """
        try:
            auth_db.require_global_admin(g.db_session, request)

            data = cjson.decode(request.data)
            ids = data.get("ids", {})
            query_args = data.get("query", "")
            if query_args:
                query_args = urlparse.parse_qs(query_args)
            updates = data.get("updates", [])

            try:
                blueprint.api.solr2.feeds.update_reports(updates, ids=ids, query_args=query_args)
            except SolrApiInvalidParams:
                abort(406)

            return make_response_success_json()
        except FeedConfigError:
            _logger.exception("Error in API parameters")
            abort(405)

    @blueprint.route("/api/v1/watchlist", defaults={'id': None}, methods=['POST', 'GET'])
    @blueprint.route("/api/v1/watchlist/<id>", methods=['GET', 'PUT', 'DELETE'])
    @auth_db.requires_auth(allow_auth_token=True)
    def watchlist(id):
  
        # provide basic sanity on the id, if provided
        # in particular, must be numeric
        #
        if id is not None:
            try:
                id = int(id)
            except:
                abort(400)
 
        if request.method == 'GET':
            
            # get the watchlist(s)
            # returns a list of dictionaries, with each list entry describing
            # a single watchlist
            #
            watchlists = blueprint.api.db.watchlists(id)
            
            # if a specific watchlist was requested by the caller, but no
            # such watchlist could be found, bail with a 404.  this is 
            # distinct from the case of enumerating all watchlists and finding
            # none
            #
            if id is not None and len(watchlists) == 0:
                abort(404)

            # if a specific watchlist was requested, return the dictionary
            # describing that specific watchlist
            #
            if id is not None:
                response = make_response_json(watchlists[0])

            # if no specific watchlist was requested, return the list of
            # all watchlists (empty list if no watchlists exist)
            # 
            else:
                response = make_response_json(watchlists)

        elif request.method == 'POST':
            # TODO -- SAVE ITEM
            data = simplejson.JSONDecoder().decode(request.data)
            id = blueprint.api.db.watchlist_add(data)
            if id is not None:
                response = make_response_json({"id": id})
            else:
                abort(400)

        elif request.method == 'PUT':
            data = simplejson.JSONDecoder().decode(request.data)
            blueprint.api.db.watchlist_update(id, data)
            response = make_response_success_json()

        elif request.method == "DELETE":
            blueprint.api.db.watchlist_delete(id)
            response = make_response_success_json()

        else:
            abort(405)
          
        return response

    @blueprint.route("/api/v1/watchlist/<id>/action", defaults={'action_id': None}, methods=['POST', 'GET'])
    @blueprint.route("/api/v1/watchlist/<id>/action/<action_id>", methods=['DELETE','PUT'])
    @auth_db.requires_auth(allow_auth_token=True)
    def watchlist_actions(id,action_id):

        # make sure id is an integer
        try:
            id = int(id)
        except:
            abort(400)

        if request.method == 'GET':

            # get the watchlist action(s)
            # returns a list of all actions for a given watchlist
            #
            watchlist_actions = blueprint.api.db.watchlist_action_settings(id)
            response = make_response_json(watchlist_actions)

        elif request.method == 'POST':
            data = simplejson.JSONDecoder().decode(request.data)

            #ignore watchlist id from posted data and overwrite with argument id
            data['watchlist_id']=id
            data.pop("id", None)
            #overwrite group_id from posted data and set it to -1
            data['group_id'] = -1
            
            action_id = blueprint.api.db.watchlist_action_setting_add(data)
            if action_id is not None:
                response = make_response_json({"action_id": action_id})
            else:
                abort(400)

        elif request.method == "DELETE":
            blueprint.api.db.watchlist_action_setting_delete(action_id)
            response = make_response_success_json()

        elif request.method == "PUT":
            data = simplejson.JSONDecoder().decode(request.data)

            #ignore watchlist id from posted data and overwrite with argument id
            data['watchlist_id']=id
            data.pop("id")

            blueprint.api.db.watchlist_action_setting_put(action_id,data)
            response = make_response_success_json()
        else:
            abort(405)

        return response

    # TODO: consider consolidating this feed API code with the above watchlist code
    @blueprint.route("/api/v1/feed/<id>/action", defaults={'action_id': None}, methods=['POST', 'GET'])
    @blueprint.route("/api/v1/feed/<id>/action/<action_id>", methods=['DELETE','PUT'])
    @auth_db.requires_auth(allow_auth_token=True)
    def feed_actions(id,action_id):

        # make sure id is an integer
        try:
            id = int(id)
        except:
            abort(400)

        if request.method == 'GET':
            # returns a list of all actions for a given watchlist group
            watchlistgroup_actions = blueprint.api.db.watchlistgroup_actions(id)
            response = make_response_json(watchlistgroup_actions)

        elif request.method == 'POST':
            data = simplejson.JSONDecoder().decode(request.data)

            #ignore watchlist group id from posted data and overwrite with argument id
            data['group_id']=id

            # compensate for client sending empty string instead of NULL
            if data["watchlist_id"] == "":
                data["watchlist_id"] = None

            action_id = blueprint.api.db.watchlist_action_setting_add(data)
            if action_id is not None:
                response = make_response_json({"id": action_id})
            else:
                abort(400)

        elif request.method == "DELETE":
            blueprint.api.db.watchlist_action_setting_delete(action_id)
            response = make_response_success_json()

        elif request.method == "PUT":
            data = simplejson.JSONDecoder().decode(request.data)

            #ignore watchlist id from posted data and overwrite with argument id
            data['group_id']=id
            data.pop("id")

            blueprint.api.db.watchlist_action_setting_put(action_id, data)
            response = make_response_success_json()

        else:
            abort(405)

        return response

    @blueprint.route("/api/v1/dashboard/statistics", methods=['GET'])
    @auth_db.requires_auth()
    @use_cache(per_user=True, ttl=300)
    def dashboard_statistics():
        auth_db.require_global_admin(g.db_session, request)
        model = {}

        model['storage'] = blueprint.api.db.retrieve_statistics_from_cache()

        response = make_response_json(model)
        return response

    @blueprint.route("/api/v1/dashboard/hosts", methods=['GET'])
    @auth_db.requires_auth()
    @use_cache(per_user=True, ttl=300)
    def dashboard_hosts():
        auth_db.require_global_admin(g.db_session, request)
        model = {}

        model['hosts'] = blueprint.api.db.get_sensors_checkin_statuses()

        response = make_response_json(model)
        return response

    @blueprint.route("/api/v1/dashboard/alliance", methods=['GET'])
    @auth_db.requires_auth()
    @use_cache(per_user=True, ttl=300)
    def dashboard_alliance():
        auth_db.require_global_admin(g.db_session, request)
        model = {}

        model['alliance_client'] = blueprint.api.db.get_alliance_client_status()

        response = make_response_json(model)
        return response

    @blueprint.route("/api/notification/<id>", methods=['PUT', 'DELETE'])
    @blueprint.route("/api/notification", defaults={'id': None}, methods=['POST', 'GET'])
    @auth_db.requires_auth()
    def notification(id):
        current_user = _get_user()

        if request.method == 'GET':
            data = blueprint.api.db.notifications(current_user.id)
            response = make_response_json(data)

        elif request.method == 'POST':
            _, watchlist_id = id.split(".")
            data = cjson.decode(request.data)
            _, data["last_viewed"] = datetime_from_str(data["last_viewed"])
            data["user_id"] = current_user.id           # just to be sure...
            data.pop("id")                      

            id = blueprint.api.db.notification_add(current_user.id, watchlist_id, data)
            response = make_response_json({"id": id})

        elif request.method == 'PUT':
            _, watchlist_id = id.split(".")
            data = cjson.decode(request.data)
            _, data["last_viewed"] = datetime_from_str(data["last_viewed"])
            data.pop("id")

            blueprint.api.db.notification_update(current_user.id, watchlist_id, data)
            response = make_response()

        elif request.method == "DELETE":
            _, watchlist_id = id.split(".")
            blueprint.api.db.notification_delete(current_user.id, watchlist_id)
            response = make_response()

        else:
            abort(405)
          
        response.headers['Content-Type'] = "application/json"
        return response

    @blueprint.route("/api/investigation/<id>", methods=['GET', 'PUT', 'DELETE'])
    @blueprint.route("/api/investigation", defaults={'id': None}, methods=['POST'])
    @auth_db.requires_auth()
    def investigation(id):
        if request.method == 'GET':
            data = blueprint.api.db.investigation(id)
            response = make_response_json(data)
        elif request.method == 'POST':
            # TODO -- SAVE ITEM
            data = cjson.decode(request.data)
            uid = blueprint.api.db.investigation_add(_get_user(), data)
            response = make_response_json({"id": uid})

        elif request.method == 'PUT':
            if id == 1: abort(500)
            data = cjson.decode(request.data)
            blueprint.api.db.investigation_update(id, data)
            response = make_response_success_json()

        elif request.method == "DELETE":
            if id == 1: abort(500)
            blueprint.api.db.investigation_delete(id)
            response = make_response_success_json()

        else:
            abort(405)

        return response

    @blueprint.route("/api/investigations", methods=['GET'])
    @auth_db.requires_auth()
    def investigations():

        if request.method == 'GET':
            items = blueprint.api.db.investigations()
            response = make_response_json(items)
        else:
            abort(405)

        return response

    @blueprint.route("/api/tagged_event/<id>", methods=['DELETE', 'PUT', 'GET'])
    @blueprint.route("/api/tagged_event", defaults={'id': None}, methods=['POST'])
    @auth_db.requires_auth()
    def tagged_event(id):
        if request.method == 'GET':
            # Id here is the investigation Id not the event id
            data = blueprint.api.db.tagged_events_for_investigation(id)
            response = make_response_json(data)
        elif request.method == 'POST':
            data = simplejson.JSONDecoder().decode(request.data)
            if data.get("event_type", "") == "childproc":
                # ENT-3244: Unfortunate side effect of process key change when we
                # parse childproc_complete events from 4.1.x sensors for tagging,
                # guid in hex format not the signed long legacy format.
                event = data["event_data"]
                process_id = event.get("guid", None)
                if process_id and len(process_id) == 36:
                    guid = long(process_id[:18].replace('-', ''), 16)
                    if guid > pow(2, 63):
                        guid -= pow(2, 64)
                    segment_id = int(process_id[19:].replace('-', ''))
                    event["analyze_link"] = '/#/analyze/%d/%d' % (guid, segment_id)
                    event["guid"] = str(guid)
                if process_id and len(process_id) > 36:
                    event["guid"] = process_id[:36]
            id = blueprint.api.db.tagged_event_add(data)
            data = {'id' : id}
            response = make_response_json(data)
        elif request.method == 'PUT':
            data = simplejson.JSONDecoder().decode(request.data)
            blueprint.api.db.tagged_event_update(id, data)
            response = make_response() 
        elif request.method == 'DELETE':
            eventId = blueprint.api.db.tagged_event_delete(id)
            data = {'id' : eventId}
            response = make_response_json(data)
        else:
            abort(405)

        return response

    @blueprint.route("/api/tagged_events/<process_id>", methods=['GET'])
    @auth_db.requires_auth()
    @use_cache()
    def tagged_events(process_id):
        data = blueprint.api.db.tagged_events(process_id)
        return make_response_json(data)

    @blueprint.route("/api/terms", methods=['GET'])
    @auth_db.requires_auth()
    @use_cache()
    def terms():
        query = urlparse.parse_qs(request.query_string)
        return make_response_json(blueprint.api.terms(query))

    @blueprint.route("/api/autocomplete", methods=['GET'])
    @auth_db.requires_auth()
    @use_cache()
    def autocomplete():
        query = urlparse.parse_qs(request.query_string)
        data = blueprint.api.autocomplete(query)
        return make_response_json(data)

    @blueprint.route("/api/v1/sensor/statistics", methods=['GET'])
    @auth_db.requires_auth()
    def sensor_statistic():
        auth_db.require_global_admin(g.db_session, request)
        results = blueprint.api.db.sensor_statistics()
        response = make_response_json(results, indent=2)
        return response
 
    @blueprint.route("/api/v1/sensor/<sensor_id>/queued", methods=['GET'])
    @auth_db.requires_auth()
    def sensor_queued_data(sensor_id):
       data = blueprint.api.db.sensor_queued_data(sensor_id)
       response = make_response_json(data, indent=2)
       return response

    @blueprint.route("/api/v1/sensor/version/latest", methods=['GET'])
    @auth_db.requires_auth()
    def latest_sensor_version():
        sensor_version = {'version': blueprint.api.db.latest_sensor_version()}
        response = make_response_json(sensor_version)
        return response

    @blueprint.route("/api/v1/sensor/<sensor_id>/driverdiag", methods=['GET'])
    @auth_db.requires_auth()
    def sensor_driver_diag(sensor_id):
        results = blueprint.api.db.sensor_driver_diag(sensor_id)
        response = make_response_json(results)
        return response

    @blueprint.route("/api/v1/sensor/<sensor_id>/eventdiag", methods=['GET'])
    @auth_db.requires_auth()
    def sensor_event_diag(sensor_id):
        results = blueprint.api.db.sensor_event_diag(sensor_id)
        response = make_response_json(results)
        return response

    @blueprint.route("/api/v1/sensor/<sensor_id>/componentstatus", methods=['GET'])
    @auth_db.requires_auth()
    def sensor_component_status(sensor_id):
        results = blueprint.api.db.sensor_component_status(sensor_id)
        response = make_response_json(results)
        return response
   
    @blueprint.route("/api/v1/sensor/<sensor_id>/resourcestatus", methods=['GET'])
    @auth_db.requires_auth()
    def sensor_resource_status(sensor_id):
        results = blueprint.api.db.sensor_resource_status(sensor_id)
        response = make_response_json(results)
        return response

    @blueprint.route("/api/v1/sensor/<sensor_id>/upgradestatus", methods=['GET'])
    @auth_db.requires_auth()
    def sensor_upgrade_status(sensor_id):
        results = blueprint.api.db.sensor_upgrade_status(sensor_id)
        response = make_response_json(results)
        return response

    @blueprint.route("/api/v1/sensor/<sensor_id>/uninstallstatus", methods=['GET'])
    @auth_db.requires_auth()
    def sensor_uninstall_status(sensor_id):
        results = blueprint.api.db.sensor_uninstall_status(sensor_id)
        response = make_response_json(results)
        return response

    @blueprint.route("/api/v1/sensor/<sensor_id>/activity", methods=['GET'])
    @auth_db.requires_auth()
    def sensor_activity(sensor_id):
        sensor_activity = blueprint.api.db.sensor_activity(sensor_id)
        response = make_response_json(sensor_activity)
        return response

    @blueprint.route("/api/v1/sensor/<sensor_id>/commfailures", methods=['GET'])
    @auth_db.requires_auth()
    def sensor_comm_failures(sensor_id):
        sensor_comm_failures = blueprint.api.db.sensor_comm_failures(sensor_id)
        response = make_response_json(sensor_comm_failures)
        return response

    @blueprint.route("/api/builds", methods=['GET'])
    @auth_db.requires_auth()
    @use_cache()
    def builds():
        builds = blueprint.api.db.builds()
        response = make_response_json(builds)
        return response

    @blueprint.route("/api/v1/binary/<md5hash>", methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def download_module(md5hash):
        # Securely escape any unwanted chars from the input var
        escaped_path = secure_filename(md5hash)

        module_io_stream = blueprint.api.db.get_module_io_stream(escaped_path, _get_user())
        if module_io_stream:
            return send_file(filename_or_fp=module_io_stream,
                             attachment_filename="%s.zip" % (md5hash.upper()),
                             mimetype="application/zip")

        abort(404)

    # begin ENT-1086
    # sensor downloads are now via /api rather than /sensor
    # 

    @blueprint.route('/api/v1/group/<group_id>/installer/windows/exe', methods=['GET'])
    @auth_db.requires_auth()
    def download_installer(group_id):
        # README-- this isn't ideal that we delete the file after
        # sending it, but i don't know another easy way to do it
        # By default, this grabs the config for group 1
        filename, fullpath = blueprint.cb_engine.get_current_installer(group_id, os_type='windows')
        return send_file(filename_or_fp=fullpath, as_attachment=True, attachment_filename=filename)

    @blueprint.route('/api/v1/group/<group_id>/installer/windows/msi', methods=['GET'])
    @auth_db.requires_auth()
    def download_msi_installer(group_id):
        filename, fullpath = blueprint.cb_engine.get_current_installer(group_id, os_type='windows', get_msi_package=True)
        return send_file(filename_or_fp=fullpath, as_attachment=True, attachment_filename=filename)

    @blueprint.route('/api/v1/group/<group_id>/installer/osx', methods=['GET'])
    @auth_db.requires_auth()
    def download_osx_installer(group_id):
        filename, fullpath = blueprint.cb_engine.get_current_installer(group_id, os_type='osx')
        return send_file(filename_or_fp=fullpath, as_attachment=True, attachment_filename=filename)

    @blueprint.route('/api/v1/group/<group_id>/installer/linux', methods=['GET'])
    @auth_db.requires_auth()
    def download_linux_installer(group_id):
        filename, fullpath = blueprint.cb_engine.get_current_installer(group_id, os_type='linux')
        return send_file(filename_or_fp=fullpath, as_attachment=True, attachment_filename=filename)

    @blueprint.route('/api/v1/group/<int:group_id>/datasharing', methods=['GET', 'POST', 'DELETE'])
    @auth_db.requires_auth(allow_auth_token=True)
    def group_alliance_data_sharing(group_id):
        if request.method == 'GET':
            share_configs = blueprint.api.db.alliance_settings.get_group_datasharing_configs(group_id)

            response = make_response_json(share_configs)
            return response
        elif request.method == 'POST':
            data = simplejson.loads(request.data)

            share_configs = blueprint.api.db.alliance_settings.add_group_datasharing_config(group_id, data)
            response = make_response_json(share_configs)
            return response
        elif request.method == 'DELETE':
            blueprint.api.db.alliance_settings.delete_group_datasharing_configs(group_id)
            response = make_response_success_json()
            return response

    @blueprint.route('/api/v1/group/<int:group_id>/datasharing/<int:config_id>', methods=['GET', 'DELETE'])
    @auth_db.requires_auth(allow_auth_token=True)
    def group_alliance_data_sharing_config(group_id, config_id):
        if request.method == 'GET':
            share_configs = blueprint.api.db.alliance_settings.get_group_datasharing_configs(group_id, config_id)

            if not share_configs:
                abort(404)

            response = make_response_json(share_configs[0])
            return response
        if request.method == 'DELETE':
            blueprint.api.db.alliance_settings.delete_group_datasharing_configs(group_id, config_id)
            response = make_response_success_json()
            return response
    
    @blueprint.route('/api/v1/alliance_status', methods=['GET', 'PUT'])
    @auth_db.requires_auth(allow_auth_token=True)
    def alliance_status():
        if request.method == 'GET':
            return 

        children = int(request.args.get("children", 15))

    #
    # end ENT-1086

    #
    # start detect dashboard

    @blueprint.route("/api/v1/detect/report/currentalertstatus", methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_current_alert_status():
        response = make_response_json(blueprint.api.dashboard.get_current_alert_status())
        return response

    @blueprint.route("/api/v1/detect/report/currentmonitoringstatus", methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_current_monitoring_status():
        response = make_response_json(blueprint.api.dashboard.get_current_monitoring_status())
        return response

    @blueprint.route("/api/v1/detect/report/unresolvedalerttrend/<days>", defaults={'feed_name':None}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/unresolvedalerttrend/", defaults={'feed_name':None, 'days': 30}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/<feed_name>/unresolvedalerttrend/<days>", methods=['GET'])
    @blueprint.route("/api/v1/detect/report/<feed_name>/unresolvedalerttrend/", defaults={'days': 30}, methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_unresolved_alert_trend(days, feed_name):
        response = make_response_json(blueprint.api.dashboard.get_unresolved_alert_counts_by_day(int(days), feed_name))
        return response

    @blueprint.route("/api/v1/detect/report/unresolvedalertsbytime/<count>/<sort>", defaults={'feed_name': None}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/unresolvedalertsbytime/<count>", defaults={'feed_name': None, 'sort': 'desc'}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/unresolvedalertsbytime/", defaults={'feed_name': None, 'count': 10, 'sort': 'desc'}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/<feed_name>/unresolvedalertsbytime/<count>/<sort>", methods=['GET'])
    @blueprint.route("/api/v1/detect/report/<feed_name>/unresolvedalertsbytime/<count>", defaults={'sort': 'desc'}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/<feed_name>/unresolvedalertsbytime/", defaults={'count': 10, 'sort': 'desc'}, methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_unresolved_alerts_by_time(count, sort, feed_name):
        response = make_response_json(blueprint.api.dashboard.get_unresolved_alerts(int(count), "created_time", sort, feed_name))
        return response

    @blueprint.route("/api/v1/detect/report/unresolvedalertsbyseverity/<count>/<sort>", defaults={'feed_name': None}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/unresolvedalertsbyseverity/<count>", defaults={'feed_name': None, 'sort': 'desc'}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/unresolvedalertsbyseverity/", defaults={'feed_name': None, 'count': 10, 'sort': 'desc'}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/<feed_name>/unresolvedalertsbyseverity/<count>/<sort>", methods=['GET'])
    @blueprint.route("/api/v1/detect/report/<feed_name>/unresolvedalertsbyseverity/<count>", defaults={'sort': 'desc'}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/<feed_name>/unresolvedalertsbyseverity/", defaults={'count': 10, 'sort': 'desc'}, methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_unresolved_alerts_by_severity(count, sort, feed_name):
        response = make_response_json(blueprint.api.dashboard.get_unresolved_alerts(int(count), "alert_severity", sort, feed_name))
        return response

    @blueprint.route("/api/v1/detect/report/adminsbyalertsresolved/<count>/<sort>", methods=['GET'])
    @blueprint.route("/api/v1/detect/report/adminsbyalertsresolved/<count>", defaults={'sort': 'desc'}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/adminsbyalertsresolved/", defaults={'count': 10, 'sort': 'desc'}, methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_admins_by_alerts_resolved(count, sort):
        response = make_response_json(blueprint.api.dashboard.get_admins_by_total_alerts_resolved(int(count), sort))
        return response

    @blueprint.route("/api/v1/detect/report/adminsbyresolvedtime/<count>/<sort>", methods=['GET'])
    @blueprint.route("/api/v1/detect/report/adminsbyresolvedtime/<count>", defaults={'sort': 'asc'}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/adminsbyresolvedtime/", defaults={'count': 10, 'sort': 'asc'}, methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_admins_by_resolved_time(count, sort):
        response = make_response_json(blueprint.api.dashboard.get_admins_by_average_alert_resolve_time(int(count), sort))
        return response

    @blueprint.route("/api/v1/detect/report/unresolvedhostsbytime/<count>/<sort>", methods=['GET'])
    @blueprint.route("/api/v1/detect/report/unresolvedhostsbytime/<count>", defaults={'sort': 'desc'}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/unresolvedhostsbytime/", defaults={'count': 10, 'sort': 'desc'}, methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_unresolved_hosts_by_time(count, sort):
        response = make_response_json(blueprint.api.dashboard.get_unresolved_hosts_by_time(int(count), sort))
        return response

    @blueprint.route("/api/v1/detect/report/unresolvedhostsbyseverity/<count>/<sort>", methods=['GET'])
    @blueprint.route("/api/v1/detect/report/unresolvedhostsbyseverity/<count>", defaults={'sort': 'desc'}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/unresolvedhostsbyseverity/", defaults={'count': 10, 'sort': 'desc'}, methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_unresolved_hosts_by_severity(count, sort):
        response = make_response_json(blueprint.api.dashboard.get_unresolved_hosts_by_severity(int(count), sort))
        return response

    @blueprint.route("/api/v1/detect/report/unresolvedusersbytime/<count>/<sort>", methods=['GET'])
    @blueprint.route("/api/v1/detect/report/unresolvedusersbytime/<count>", defaults={'sort': 'desc'}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/unresolvedusersbytime/", defaults={'count': 10, 'sort': 'desc'}, methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_unresolved_users_by_time(count, sort):
        response = make_response_json(blueprint.api.dashboard.get_unresolved_users_by_time(int(count), sort))
        return response

    @blueprint.route("/api/v1/detect/report/unresolvedusersbyseverity/<count>/<sort>", methods=['GET'])
    @blueprint.route("/api/v1/detect/report/unresolvedusersbyseverity/<count>", defaults={'sort': 'desc'}, methods=['GET'])
    @blueprint.route("/api/v1/detect/report/unresolvedusersbyseverity/", defaults={'count': 10, 'sort': 'desc'}, methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_unresolved_users_by_severity(count, sort):
        response = make_response_json(blueprint.api.dashboard.get_unresolved_users_by_severity(int(count), sort))
        return response

    @blueprint.route("/api/v1/detect/report/alertresolutionaverage/", methods=['GET'])
    @blueprint.route("/api/v1/detect/report/alertresolutionaverage/<int:days>", methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_resolution_time(days=30):
        response = make_response_json(blueprint.api.dashboard.get_alert_resolution_average(days))
        return response

    @blueprint.route("/api/v1/detect/report/binarydwell/", methods=['GET'])
    @blueprint.route("/api/v1/detect/report/binarydwell/<int:days>", methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_binary_dwell(days=30):
        response = make_response_json(blueprint.api.dashboard.get_binary_dwell_info(days))
        return response

    @blueprint.route("/api/v1/detect/report/hosthygiene/", methods=['GET'])
    @blueprint.route("/api/v1/detect/report/hosthygiene/<int:days>", methods=['GET'])
    @auth_db.requires_auth()
    def detect_dashboard_host_hygiene(days=30):
        response = make_response_json(blueprint.api.dashboard.get_host_hygiene_info(days))
        return response

    #
    # end detect dashboard

    @blueprint.route("/api/docs/<docid>", methods=['GET'])
    @blueprint.route("/api/docs/", defaults={'docid': None}, methods=['GET'])
    @auth_db.requires_auth()
    def docs(docid):
        # securely escape any unwanted chars from the input var
        escapedPath = secure_filename(docid)
        if request.method != "GET":
            abort(405)

        docs = blueprint.api.get_help_doc(escapedPath)
        response = make_response_json(docs)
        return response

    #
    # Cb Banning
    #

    @blueprint.route("/api/v1/banning/blacklist", methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def banning_blacklist():
        # by default we'll return the list in order they were added/deleted
        sort_col = request.args.get("sort_col", "timestamp")
        order_asc = request.args.get("order_asc", "true").lower() == "false"
        start = int(request.args.get("start", 0))
        count = int(request.args.get("count", 500))
        filt = request.args.get("filter")

        try:
            return make_response_json(
                blueprint.api.db.banning_blacklist.get_blacklist(sort_col, order_asc, start, count, filt))
        except ValueError:
            abort(400)

    @blueprint.route("/api/v1/banning/blacklist", methods=['POST'])
    @auth_db.requires_auth(allow_auth_token=True, require_global_admin=True)
    def add_banned_md5():
        args = simplejson.loads(request.data)
        md5hash = args['md5hash']
        reason = args.get('text')

        blueprint.api.db.banning_blacklist.ban_md5(md5hash, _get_user(), reason)

        return make_response_json({"result": "success"})

    @blueprint.route("/api/v1/banning/blacklist/<md5>", methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True, require_global_admin=True)
    def get_banned_md5(md5):
        return make_response_json(blueprint.api.db.banning_blacklist.get_md5(md5))

    @blueprint.route("/api/v1/banning/blacklist/<md5>", methods=['DELETE'])
    @auth_db.requires_auth(allow_auth_token=True, require_global_admin=True)
    def remove_banned_md5(md5):
        args = simplejson.loads(request.data) if request.data else {}
        reason = args.get('text')

        blueprint.api.db.banning_blacklist.unban_md5(md5, _get_user(), reason)

        return make_response_json({"result": "success"})

    @blueprint.route("/api/v1/banning/blacklist/<md5>", methods=['PUT'])
    @auth_db.requires_auth(allow_auth_token=True, require_global_admin=True)
    def update_banned_md5(md5):
        args = simplejson.loads(request.data) if request.data else {}
        reason = args.get('text')
        if reason is None:
            raise Exception("Blacklist hash updates must include reason text")

        blueprint.api.db.banning_blacklist.update_text(md5, reason)

        return make_response_json({"result": "success"})

    @blueprint.route("/api/v1/banning/whitelist", methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def banning_whitelist():
        return make_response_json({'whitelist': list(blueprint.api.db.banning_whitelist.patterns)})

    @blueprint.route("/api/v1/banning/restrictions", methods=['GET'])
    @auth_db.requires_auth(allow_auth_token=True)
    def banning_banrestrictions():
        return make_response_json({'patterns': list(blueprint.api.db.banning_whitelist.patterns)})

    def _apply_user_group_search_filter(search_args):
        if not auth_db.is_user_global_admin():
            user = auth_db.get_current_request_user()
            user_groups = auth_db.get_user_groups(g.db_session, user.id, roles=["No Access"])
            if len(user_groups) > 1:
                search_args["cb.filtered"] = {
                    "group": user_groups
                }
        return search_args

    # Group-auth helpers """
    # I'm putting these in here rather than auth.py
    # since they need access to api.db and I don't
    # want to create a connection from the auth module.
    # MD (3/25/2013)

    def require_int(candidate_int):
        """
        validates that the candidate_int is a valid integer; aborts request with a HTTP 400 if not
        """
        try:
            actual_int = int(candidate_int)
            return
        except:
            abort(400)

    def user_perms(user, type, method, group_id):
        """
        A function that returns a bool value for if the user has permissions to this group.
        It will first look to see if we cache.  If we do pull it from there.
        This is to speed up perf. IF it is not there then go to the db and ask.
        """
        # Get username
        has_perm = blueprint.cb_engine._cbcache.get("%s-perm-user-%s-group-%s-method-%s" % (type, user.id, group_id, method))
        if has_perm is None:
            has_perm = auth_db.user_has_permission_for_group(g.db_session, user.username, type, method, group_id)
            blueprint.cb_engine._cbcache.set("%s-perm-user-%s-group-%s-method-%s" % (type, user.id, group_id, method), has_perm, 600)
            return has_perm
        return has_perm == 'True'

    def require_perm_on_group(request, method, group_id):
        """
        See if the user has permission to perform method
        on group and abort with 405 if they don't
        """
        has_perm = user_perms(_get_user(), 'group', method, group_id)

        if not has_perm:
            # No they don't
            abort(405)

    def check_perm_on_group(request, method, group_id):
        """
        See if the user has permission to perform method
        on group and return True if they have perms else Flase
        """
        # Get username
        return user_perms(_get_user(), 'group', method, group_id)

    def require_perm_on_host(request, method, host_id):
        """
        See if the user has permission to perform method
        on host and abort with 405 if they don't
        """
        # Get group-id of host
        host_result = blueprint.api.db.host(host_id)
        if isinstance(host_result, dict):
            group_id = host_result["group_id"]
        elif isinstance(host_result, list):
            if len(host_result) > 0:
                group_id = host_result[0]["group_id"]
            # Otherwise it doesn't matter since there is no host to return
        else:
            abort(500)

        has_perm = user_perms(_get_user(), 'host', method, group_id)
        if not has_perm:
            # No they don't
            abort(405)

    def require_alliance_perm(group_names, alliance_perm):
        permitted = False

        sensor_groups = g.db_session.query(SensorGroup.id).filter(SensorGroup.name.in_(group_names)).all()
        for sensor_group in sensor_groups:
            share_configs = blueprint.api.db.alliance_settings.get_group_datasharing_configs(sensor_group.id)
            for share_config in share_configs:
                if share_config["who"] == AllianceDataSharingWho.BIT9 and share_config["what"] == alliance_perm:
                    permitted = True
                    break

        if not permitted:
            abort(409)

    def _get_user():
        if g.token_user:
            current_user = g.token_user
        else:
            current_user = auth_db.get_user_by_id(g.db_session, session["uid"])
        return current_user

    # return the app to the caller
    return blueprint
