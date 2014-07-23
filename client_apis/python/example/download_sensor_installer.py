import sys
import struct
import socket
import pprint
import optparse 

# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi 

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Dump Binary Info")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-t", "--installer-type", action="store", default=None, dest="type",
                      help="Installer type; must be one of [WindowsEXE|WindowsMSI]")
    parser.add_option("-f", "--filename", action="store", default=None, dest="filename",
                      help="Filename to save the installer package to")
    parser.add_option("-g", "--sensor-group", action="store", default="1", dest="group",
                      help="Sensor group ID of the group to download an installer for")
    return parser

def truncate(string, length):
    if len(string) + 2 > length:
        return string[:length] + "..."
    return string

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token or not opts.type or not opts.group or not opts.filename:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token)

    # download the installer package 
    #
    print "-> Downloading..."
    bytes = cb.sensor_installer(opts.type, opts.group)
    print "-> Sensor Installer Package is %s bytes" % (len(bytes))
    print "-> Download complete"

    # save the instaler package to disk
    #
    print "-> Saving to %s..." % (opts.filename)
    open(opts.filename, 'wb').write(bytes)
    print "-> Complete"

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
