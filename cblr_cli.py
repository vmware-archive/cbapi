
import os
import sys
import cmd
import requests
import threading
import simplejson
import ntpath
import time
import subprocess
from optparse import OptionParser

class HttpException(Exception):
    pass

class QuitException(Exception):
    pass

class CmdSensorError(Exception):
    pass

class CmdSensorWindowsError(Exception):
    def __init__(self, hr):
        self.hr = hr

    def __str__(self):
        return "HRESULT: 0x%x\n" % self.hr

class CliArgsException(Exception):
    pass

def split_cli(line):
    '''
    we'd like to use shlex.split() but that doesn't work well for
    windows types of things.  for now we'll take the easy approach
    and just split on space. We'll then cycle through and look for leading
    quotes and join those lines
    '''

    parts = line.split(' ')
    final = []

    inQuotes = False
    while len(parts) > 0:

        tok = parts.pop(0)

        if (tok[:1] == '"'):
            tok = tok[1:]
            next = parts.pop(0)
            while(next[-1:] != '"' and len(parts) > 0):
                tok += ' ' + next
                next = parts.pop(0)

            if (next[-1:] == '"'):
                tok += ' ' + next[:-1]

        final.append(tok)

    return final

def parse_argv(target):

    def wrapper(self, line):
        return target(self, split_cli(line))

    return wrapper

def needs_attached(target):

    def wrapper(self, *args, **kwargs):
        if (self.session is None):
            return self.attach_warning(*args, **kwargs)
        else:
            return target(self, *args, **kwargs)

    return wrapper

class CblrCli(cmd.Cmd):

    def __init__(self, url, token, httpLog=None, verbose=False):
        cmd.Cmd.__init__(self)

        # global variables
        # apply regardless of session state
        self.token = token
        self.url = url
        self.verbose = verbose
        if httpLog:
            self.logfile = open(httpLog, "a+")
        else:
            self.logfile = None

        # apply only if a session is attached
        self.session = None
        self.cwd = None
        self.keepaliveThread = None
        self.keepaliveEvent = None
        self.keepaliveSec = 0

        # we filter out stale sessions so that
        # we don't constantly display them to the user
        # when we start we'll grab the sessions and
        # store any "closed" sessions.
        self.stale_sessions = []
        sess = self._session_list(hideStale=False)
        for s in sess:
            if s['status'] == 'close':
                self.stale_sessions.append(s['id'])

    def emptyline(self):
        pass

    def precmd(self, line):
        print ""
        return line

    def cmdloop(self, intro=None):

        while(True):
            try:
                cmd.Cmd.cmdloop(self, intro)
            except QuitException:
                sys.exit(0)
            except CliArgsException as e:
                print "Error parsing arguments!\n %s" % e
                continue
            except HttpException as e:
                print "Got an HTTP exception: %s" % e
                continue
            except CmdSensorWindowsError as e:
                print "Command Failed: %s" % e
                continue
            except Exception as e:
                print "Error: %s" % e
                import traceback
                traceback.print_exc()
                return
    ##########
    # keepalive function
    #########

    def _keepaliveThread(self):
        '''
        when attached to a session this will
        be called by a keep-alive thread to ensure
        the sensor doesn't timeout while waiting
        for a command
        '''

        self.keepaliveSec = 0
        while(not self.keepaliveEvent.is_set()):
            self.keepaliveEvent.wait(1)
            self.keepaliveSec += 1
            if (self.keepaliveSec >= 60):
                self.keepaliveSec = 0
                # every minute we do a keepalive
                # we do it with 1 second waits b/c python blocks
                # it waits and it makes quitting nasty
                try:
                    url = '%s/api/v1/cblr/session/%d/keepalive' % (self.url, self.session)
                    self._doGet(url)
                except HttpException as e:
                    pass
                    # ignore this -the main command window will probably fail

    ######################
    # Helper functions
    ######################

    def _loghttp(self, msg):
        if self.logfile:
            self.logfile.write(msg + '\n')
            self.logfile.flush()
        if self.verbose:
            print msg

    def _quit(self):
        raise QuitException("quit")

    def _doGet(self, url, params=None, retJSON=True):

        self._loghttp("-------------------------")
        self._loghttp("GET (url: %s)\n" % url)

        headers = {'X-Auth-Token': self.token}
        result = requests.get(url, headers=headers, params=params, verify=False, timeout=120)
        if result.status_code != 200:
            raise HttpException("Error processing HTTP get (%s) - %s" % (url, (result.content)))

        if (retJSON):
            ret = simplejson.loads(result.content)
        else:
            ret = result.content

        self._loghttp("%r" % ret)
        self._loghttp("^^^^^^^^^^^^^^^^^^^^^^^^^")
        return ret

    def _doPut(self, url, data_dict):
        self._loghttp("-------------------------")
        self._loghttp("PUT (url: %s) " % url)
        self._loghttp("Data: %r\n" % data_dict)


        headers = {'X-Auth-Token': self.token}

        result = requests.put(url, data=simplejson.dumps(data_dict), headers=headers, verify=False, timeout=120)
        if result.status_code != 200:
            raise HttpException("Error processing HTTP post (%s) - %s" % (url, (result.content)))

        ret = simplejson.loads(result.content)

        self._loghttp("%r" % ret)
        self._loghttp("^^^^^^^^^^^^^^^^^^^^^^^^^")
        return ret

    def _doPost(self, url, json_data=None, files=None):
        data = None

        headers = {'X-Auth-Token': self.token}
        self._loghttp("-------------------------")
        self._loghttp("POST (url: %s) " % url)
        if (json_data):
            self._loghttp("Data: %r\n" % json_data)
            data = simplejson.dumps(json_data)

        if (files):
            self._loghttp("Files: %r" % files)

        result = requests.post(url,
                               data=data,
                               headers=headers,
                               files=files,
                               verify=False,
                               timeout=120)
        if result.status_code != 200:
            raise HttpException("Error processing HTTP post (%s) - %s" % (url, (result.content)))

        ret = simplejson.loads(result.content)

        self._loghttp("%r" % ret)
        self._loghttp("^^^^^^^^^^^^^^^^^^^^^^^^^")
        return ret

    def _is_path_absolute(self, path):

        if path.startswith('\\\\'):
            return True

        if (path[0].isalpha() and path[1:3] == ':\\'):
            return True

        return False

    def _is_path_drive_relative(self, path):

        if path == '\\':
            return True

        if path[0] == '\\' and path[1] != '\\':
            return True

        return False

    def _file_path_fixup(self, path):
        '''
        We have a pseudo-cwd that we use to
        base off all commands.  This means we
        need to figure out if a given path is relative,
        absolute, or file relative and calculate against
        the pseudo cwd.

        This function takes in a given file path arguemnt
        and performs the fixups.
        '''


        if (self._is_path_absolute(path)):
            return path
        elif (self._is_path_drive_relative(path)):
            return self.cwd[:2] + path
        else:
            return ntpath.join(self.cwd, path)

    def _postCommandAndWait(self, name, cmdObject, args=None):
        '''
        Post a command to the server and then post a get to
        get the results.  This will set the wait parameter
        in the get to ensure we wait untill the get returns
        '''
        if (args is None):
            args = {}

        cmd = {}
        cmd['name'] = name
        cmd['object'] = cmdObject
        cmd.update(args)

        url = '%s/api/v1/cblr/session/%d/command' % (self.url, self.session)

        # post the command
        cmdobj = self._doPost(url, cmd)

        try:
            # reset our keepalive - we just did a command
            self.keepaliveSec = 0

            # now wait for the reply
            url += '/%d' % cmdobj['id']

            ret = self._doGet(url, params={'wait':'true'})

        except KeyboardInterrupt:
            # we got a keyboard interupt.  Try to cancel
            # the pending command
            cancel = {'id' : cmdobj['id'], 'status' : 'cancel'}
            self._doPut(url, data_dict=cancel)

            print "Command Canceled"
            return

        err = ret.get('result_code', 0)
        if (err != 0):
            raise CmdSensorWindowsError(err)

        return ret

    def _stat(self, path):
        '''
        Look to see if a given path exists
        on the sensor and whether that is a
        file or directory.

        :param path: a sensor path
        :return: None, "dir", or "file"
        '''
        if path.endswith('\\'):
            path = path[:-1]

        try:
            ret = self._postCommandAndWait("directory list", path)
        except CmdSensorWindowsError:
            return None
        if ('files' not in ret):
            return None

        file = ret['files'][0]
        if 'DIRECTORY' in file['attributes']:
            return "dir"
        else:
            return "file"

    def _session_list(self, hideStale=True):
        url = "%s/api/v1/cblr/session" % (self.url)
        ret = self._doGet(url)

        if not hideStale:
            return ret

        out = []
        for r in ret:
            if (r['id'] not in self.stale_sessions):
                out.append(r)
        return out

    ######################
    # command processing functions
    ######################

    def attach_warning(self, *args, **kwargs):
        print "Must be attached to a session"

    ################################
    # pseduo commands and session commands
    #
    # they don't change state on the sensor
    # (except start a session)
    #####################

    @parse_argv
    def do_session(self, args):

        p = OptionParser()
        p.add_option('-q', '--quit', default=None, help='Quit a given session')
        p.add_option('-c', '--create', default=None, help='Create a new session given the sensor id')
        p.add_option('-a', '--all', default=False, action='store_true', help='Show all sessions')
        (opts, args) = p.parse_args(args=args)

        if (opts.quit is not None):
            sessid = int(opts.quit)
            postdata = {"id": sessid, "status" : "close"}
            url = "%s/api/v1/cblr/session/%d" % (self.url, sessid)

            self._doPut(url, postdata)

            ret = self._session_list()
            for s in ret:
                if (s['id'] == sessid):
                    print "Session: %d\n  status: %s\n" % (s['id'], s['status'])

        elif (opts.create is not None):
            sessid = int(opts.create)
            postdata = {"sensor_id" : sessid}
            url = "%s/api/v1/cblr/session" % self.url

            ret = self._doPost(url, postdata)
            print "New Session: %d" % ret['id']
            print ""

        else:
            # no args - full listing
            ret = self._session_list(hideStale=not opts.all)
            for s in ret:
                print "Session: %d\n  status: %s\n  sensorId: %d\n" % (s['id'], s['status'], s['sensor_id'])

    @needs_attached
    def do_cd(self, arg):

        path = self._file_path_fixup(arg)
        path = ntpath.abspath(path)
        type = self._stat(path)
        if (type != "dir"):
            print "Error: Path %s does not exist" % path
            return
        else:
            self.cwd = path

        # cwd never has a trailing \
        if self.cwd[-1:] == '\\':
            self.cwd = self.cwd[:-1]

    def do_pwd(self, line):
        print self.cwd
        print ""

    @parse_argv
    def do_attach(self, args):
        '''
        attach [opts] SESSION_ID
        '''
        p = OptionParser()
        p.add_option('-w', '--wait', action="store_true", default=False,  help='Quit a given session')
        (opts, args) = p.parse_args(args=args)

        if (len(args) != 1):
            CliArgsException("Invalid number of arguments to attached (got %d expected %d)" % (len(args), 1))
        sessid = int(args[0])

        if (opts.wait):
            timeout = 60*5
        else:
            timeout = 0
        sessioninfo = None

        while (1):

            pending = False
            sess = self._session_list()
            for s in sess:
                # look for an active or pending session
                # matching what we are looking for
                if s['id'] == sessid:
                    if s['status'] == 'active':
                        sessioninfo = s
                        break;
                    elif s['status'] == 'pending':
                        pending = True

            if (sessioninfo is not None):
                break

            if (not pending):
                print "No pending session found for session id %s" % sessid
                return

            if (timeout == 0):
                print 'Session is not active - wait and try attaching again'
                return
            else:
                time.sleep(1)
                timeout -= 1

        # ok -we have a session
        self.session = sessid
        self.prompt = 'Session[%d] >' % sessid
        self.cwd = sessioninfo['current_working_directory']

        # spawn a thread to keep the sensor active
        # when we are attached
        self.keepaliveEvent = threading.Event()
        self.keepaliveThread = threading.Thread(target=self._keepaliveThread, args=())
        self.keepaliveThread.daemon = True
        self.keepaliveThread.start()

    @needs_attached
    def do_detach(self, line):
        self.keepaliveEvent.set()
        self.session = None
        self.prompt = '>'
        self.cwd = None
        self.keepaliveThread.join()

    @needs_attached
    def do_files(self, line):
        url = '%s/api/v1/cblr/session/%d/file' % (self.url, self.session)
        ret = self._doGet(url)

        # note - size might be none if there is an error
        for r in ret:
            print "File Id: %d" % r['id']
            print " name:   %s" % r['file_name']
            if (r['status'] != 0):
                print " error:   0x%x" % r['status']
            else:
                print " size:   %d (%d uploaded)" % (r['size'], r['size_uploaded'])
            print ""

    #############################
    # real commands
    #
    # these change state on the senesor
    ##############################

    @needs_attached
    @parse_argv
    def do_ps(self, args):
        '''
        ps [OPTS]

        where OPTS are:
        -v - Display verbose info about each process
        -p [PID] - Display only the given pid
        '''

        p = OptionParser()
        p.add_option('-v', '--verbose', default=False, action='store_true', help='Display verbose info about each process')
        p.add_option('-p', '--pid', default=None, help='Display only the given pid')
        (opts, args) = p.parse_args(args=args)

        if (opts.pid): opts.pid = int(opts.pid)

        ret = self._postCommandAndWait("process list", '')

        for p in ret.get('processes', []):
            if ((opts.pid and p['pid'] == opts.pid) or opts.pid is None):
                if (opts.verbose):
                    print "Process: %5d : %s" % (p['pid'], ntpath.basename(p['path']))
                    print "  UserName:    %s" % p['username']
                    print "  ExePath:     %s" % p['path']
                    print "  ParentPid:   %d" % p['parent']
                    print "  SID:         %s" % p['sid']
                    print "  CommandLine: %s" % p['command_line']
                    print ""
                else:
                    print "%5d  %-30s %-20s" % (p['pid'], ntpath.basename(p['path']), p['username'])

        if not opts.verbose:
            print ""

    @needs_attached
    def do_exec(self, line):
        '''
        exec [OPTS] [process command line and arguments]

        where OPTS are:
         -o [OutputFile] - Redirect standard out and standard error to
              the given file path.
         -d [WorkingDir] - Use the following directory as the process working
              directory
         -w - Wait for the process to complete execution before returning.
        '''

        #
        # note: option parsing is VERY specific to ensure command args are left
        # as untouched as possible
        #
        OPTS = ['-o', '-d', '-w']
        optOut = None
        optWorkDir = None
        optWait = False

        parts = line.split(' ')
        doParse = True
        while (doParse):
            tok = parts.pop(0)
            if (tok in OPTS):
                if tok == '-w':
                    optWait = True
                if tok == '-o':
                    optOut = parts.pop(0)
                if tok == '-d':
                    optWorkDir = parts.pop(0)
            else:
                doParse = False

        exe = tok

        #ok - now the command (exe) is in tok
        # we need to do some crappy path manipulation
        # to see what we are supposed to execute
        if (self._is_path_absolute(exe)):
            pass
            # do nothin
        elif (self._is_path_drive_relative(exe)):
            # append the current dirve
            exe = self.cwd[:2] + exe
        else:
            # is relative (2 sub-cases)
            ret = self._stat(ntpath.join(self.cwd, exe))
            if (ret == "file"):
                # then a file exist in the current working
                # directory that matches the exe name - execute it
                exe = ntpath.join(self.cwd, exe)
            else :
                # the cwd + exe does not exist - let windows
                # resolve the path
                pass

        # re-format the list and put tok at the front
        cmdline = exe + ' ' + ' '.join(parts)
        #print "CMD: %s" % cmdline

        args = {}
        if (optOut):
            args['output_file'] = optOut
        if (optWorkDir):
            args['working_directory'] = optWorkDir
        if (optWait):
            args['wait'] = True

        ret = self._postCommandAndWait("create process", cmdline, args=args)

        if (optWait):
            retstr = "(ReturnCode: %d)" % ret['return_code']
        else:
            retstr = ''

        print "Process Pid: %d %s\n" % (ret['pid'], retstr)

    @needs_attached
    @parse_argv
    def do_get(self, argv):
        '''
        get [REMOTE PATH] [LOCAL_PATH]
        '''
        if (len(argv) != 2):
            raise CliArgsException("Wrong number of args to get command")

        # open the local path first to error cleanly
        bDidWrite = False
        fout = open(argv[1], 'wb')

        gfile = self._file_path_fixup(argv[0])

        try:
            ret = self._postCommandAndWait("get file", gfile)
            fid = ret["file_id"]
            url = '%s/api/v1/cblr/session/%d/file/%d/content' % (self.url, self.session, fid)
            fdata = self._doGet(url, retJSON=False)

            fout.write(fdata)
            fout.close()
        except:
            #delete the output file on error
            fout.close()
            os.remove(argv[1])
            raise

    @needs_attached
    def do_del(self, line):

        if line is None or line == '':
            raise CliArgsException("Must provide argument to del command")

        path = self._file_path_fixup(line)

        self._postCommandAndWait("delete file", path)

    @needs_attached
    @parse_argv
    def do_put(self, argv):

        if (len(argv) != 2):
            raise CliArgsException("Wrong number of args to put command (need 2)")

        fin = open(argv[0], "rb")
        fpost = {'file': fin}

        url = '%s/api/v1/cblr/session/%d/file' % (self.url, self.session)
        ret = self._doPost(url, files=fpost)

        fid = ret['id']
        data = {'file_id': fid}

        ret = self._postCommandAndWait("put file", argv[1], args=data);

    def _time_dir_gmt(self, unixtime):

        return time.strftime("%m/%d/%Y %I:%M:%S %p", time.gmtime(unixtime))

    @needs_attached
    def do_dir(self, line):
        if line is None or line == '':
            line = self.cwd + "\\"

        path = self._file_path_fixup(line)

        if path.endswith('\\'):
            path += '*'

        ret = self._postCommandAndWait("directory list", path)

        print "Directory: %s\n" % path
        for f in ret.get('files', []):
            timestr = self._time_dir_gmt(f['create_time'])
            if ('DIRECTORY' in f['attributes']):
                x = '<DIR>               '
            else:
                x = '     %15d' % f['size']
            print "%s\t%s %s" % (timestr, x, f['filename'])

        print ""

    @needs_attached
    @parse_argv
    def do_reg(self, args):
        '''
        reg [SUB_COMMAND] [SUB_SPECIFIC_OPTS]

        subs:
        reg add [key] [opts]
            -v : add the value instead of the key
            -t : value type (REG_DWORD, ....) requires -v
            -d : data for the value - converted to appropriate type for
                 binary data hex encode
            -f : force (overwrite value if it already exists)

        reg delete [key] [opts]
            -v : delete the value instead of the key

        reg query [key] [opts]
            -v : query a value instead of just a key
        '''

        REG_OPTS = ['add', 'delete', 'query']
        # pop the first arg off for the sub-command

        subcmd = args.pop(0).lower()
        if (subcmd not in REG_OPTS):
            raise CliArgsException("Invalid reg subcommand! (%s)" % subcmd)

        print ""

        # parse out the args
        p = OptionParser()
        if (subcmd == 'add'):
            p.add_option('-v', '--value', default=None, help='The value to add (instead of a key)')
            p.add_option('-t', '--type', default=None, help='The value type to add')
            p.add_option('-d', '--data', default=None, help='The data value to add')
            p.add_option('-f', '--force', default=False, action='store_true', help='Overwrite existing value')

            (opts, args) = p.parse_args(args=args)

            if (opts.value):
                if (not opts.type):
                    raise CliArgsException("Must provide a value data type (-t) with -v option")
                if (not opts.data):
                    raise CliArgsException("Must provide a data value (-d) with -v option")

                rval = {}
                #rval['value_data'] = opts.data
                rval['value_data'] = opts.data
                rval['value_type'] = opts.type
                rval['overwrite'] = opts.force

                path = args[0] + '\\'+ opts.value

                self._postCommandAndWait('reg set value', path, args=rval)

            else:
                # add a key
                self._postCommandAndWait('reg create key', args[0])

        elif (subcmd == 'delete'):
            p.add_option('-v', '--value', default=None, help='The value to delete (instead of a key)')

            (opts, args) = p.parse_args(args=args)

            if (opts.value):
                path = args[0] + "\\" + opts.value

                print "DeleteValue: %s" % path
                self._postCommandAndWait('reg delete value', path)

            else:
                self._postCommandAndWait('reg delete key', args[0])

        else: # query
            p.add_option('-v', '--value', default=None, help='The value to query (instead of a key)')

            (opts, args) = p.parse_args(args=args)

            if (opts.value):
                path = args[0] + "\\" + opts.value
                ret = self._postCommandAndWait('reg query value', path)

                value = ret.get('value', None)
                if (value):
                    self._print_reg_value(value)

            else:
                ret = self._postCommandAndWait('reg enum key', args[0])

                subs = ret.get('sub_keys', [])
                if (len(subs) > 0):
                    print "Keys:"
                for k in subs:
                    print "%s" % k

                print ""
                values = ret.get('values', [])
                if (len(values) > 0):
                    print "Values:"
                for v in values:
                    self._print_reg_value(v)

    def _print_reg_value(self, value):
        type = value['value_type']
        name = value['value_name']
        rawdata = value['value_data']

        # handle default value
        if (name == ''):
            name = '(Default)'

        print "\t%-30s %10s %s" %(name, type, rawdata)

    # call the system shell
    def do_shell(self, line):
        print subprocess.Popen(line, shell=True, stdout=subprocess.PIPE).stdout.read()


    # quit handlers
    def do_exit(self, line):
        return self._quit()

    def do_quit(self, line):
        return self._quit()

    def do_EOF(self, line):
        return self._quit()


if __name__ == "__main__":

    p = OptionParser()
    p.add_option('-v', '--verbose', default=False, action='store_true', help='Display HTTP transactions to screen')
    p.add_option('-l', '--log', default=None, help='Log HTTP transactions to log file')
    p.add_option('-t', '--token', default=False, action='store_true', help='Prompt for token')
    (opts, args) = p.parse_args()

    if ((opts.token and len(args) != 1) or len(args) != 2):
        print "Usage: cblr_cli [OPTS] [URL] [API_TOKEN]"
        print ""
        print "Options:"
        print "  -v, --verbose   : Display HTTP transactions"
        print "  -l, --log [FILE]: Log HTTP transactions to a file "
        print "  -t, --token     : Prompt for the API token"
        sys.exit(-1)

    url = args[0]

    if (opts.token):
        print "Enter API Token:"
        token = sys.readline().strip()
    else:
        token = args[1]

    print "Connecting to %s" % url

    while (1):
        try:
            cli = CblrCli(url, token, verbose=opts.verbose, httpLog=opts.log);

            cli.prompt = ">"
            cli.cmdloop()
        except Exception as e:
            import traceback
            print "Error: An unknown exception occured:"
            print ""
            print e
            print ""
            traceback.print_exc()
            #traceback.print_tb()
            print "Hit Ctl-c to quit or [enter] to try again."
            sys.stdin.readline()
