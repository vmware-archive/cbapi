
import uuid
import socket
import struct
import time
import json
import eventsv2_pb2 as cbevents

# number of milliseconds between Jan 1st 1601 and Jan 1st 1970
time_shift = 11644473600000

def windows_time_to_unix_time(windows_time):
    if windows_time == 0 :
        return windows_time
    windows_time /= 10000 # ns to ms
    windows_time -= time_shift # since 1601 to since 1970
    windows_time /= 1000
    return windows_time

def filemod_action_to_str(action):
    if action == cbevents.CbFileModMsg.actionFileModCreate:
        return "create" # action must always be lower case
    if action == cbevents.CbFileModMsg.actionFileModWrite:
        return "write" # action must always be lower case
    if action == cbevents.CbFileModMsg.actionFileModDelete:
        return "delete" # action must always be lower case
    if action == cbevents.CbFileModMsg.actionFileModLastWrite:
        return "lastwrite" # action must always be lower case
    return "unknown" # action must always be lower case

def regmod_action_to_str(action):
    if action == cbevents.CbRegModMsg.actionRegModCreateKey:
        return "createkey" # action must always be lower case
    if action == cbevents.CbRegModMsg.actionRegModWriteValue:
        return "writeval" # action must always be lower case
    if action == cbevents.CbRegModMsg.actionRegModDeleteKey:
        return "delkey" # action must always be lower case
    if action == cbevents.CbRegModMsg.actionRegModDeleteValue:
        return "delval" # action must always be lower case
    return "unknown"   # action must always be lower case

def convert_protobuf_to_cb_type(msg, sensorid):
    if msg.HasField('process'):
        return CbProcessEvent(msg.process, msg.header, msg.strings, sensorid)

    if msg.HasField('modload'):
        return CbModuleLoadEvent(msg.modload, msg.header, msg.strings, sensorid)

    if msg.HasField('filemod'):
        return CbFileModEvent(msg.filemod, msg.header, msg.strings, sensorid)

    if msg.HasField('regmod'):
        return CbRegModEvent(msg.regmod, msg.header, msg.strings, sensorid)

    if msg.HasField('network'):
        return CbNetConnEvent(msg.network, msg.header, msg.strings, sensorid)

    if msg.HasField('vtwrite'):
        return CbVtWriteEvent(msg.vtwrite, msg.header, msg.strings, sensorid)

    if msg.HasField('module'):
        return CbModInfoEvent(msg.module, msg.header, msg.strings, sensorid)

    if msg.HasField('childproc'):
        return CbChildProcEvent(msg.childproc, msg.header, msg.strings, sensorid)

    raise Exception("unknown type of message: '%s'" % str(msg))

def protobuf_to_obj_and_host(serialized_pb_event):
    '''
    converts a serialized protobuff from the event bus.

    These are different because the have host info embedded
    as part of the CbEnvironmentMsg (which doesn't exist in the files)

    returns the cb_type object and the host info (as a tuple)

    (sensor_id, cb_object)
    '''
    msg = cbevents.CbEventMsg()
    msg.ParseFromString(serialized_pb_event)

    sensor_id = None

    if (msg.HasField('env')):
        sensor_id = msg.env.endpoint.SensorId

    cb_type = convert_protobuf_to_cb_type(msg, sensor_id)

    return (sensor_id, cb_type.to_obj())

def protobuf_to_obj(serialized_protobuf_event, sensor_id):
    """
    converts a serialized protobuf CB event to a
    native python dictionary
    """
    msg = cbevents.CbEventMsg()
    msg.ParseFromString(serialized_protobuf_event)
    cb_type = convert_protobuf_to_cb_type(msg, sensor_id)
    return cb_type.to_obj()

class CbBaseEvent(object):
    def __init__(self, msg, msg_type, msg_header, filepaths, sensorid, sensorevent=True):
        self.msg = msg
        self.msg_type = msg_type
        self.filepaths = filepaths

        self.version = msg_header.version
        self.event_timestamp = msg_header.timestamp
        self.process_guid = msg_header.process_guid
        self.filepath_string_guid = msg_header.filepath_string_guid

        self.sensorid = sensorid
        if sensorevent:
            self._fixup_guid(msg_header)

    def _make_guid(self, sensorid, pid, createtime):
        pid = int(pid)
        # new style guid
        high = (sensorid & 0xffffffff) << 32
        high = high | (pid & 0xffffffff)
        low = int(createtime)
        b = struct.pack(">QQ", high, low)
        return str(uuid.UUID(bytes=b))

    def _fixup_guid(self, header):

        if header.HasField('process_pid') and header.HasField('process_create_time'):
            pid = int(header.process_pid)
            self.process_guid = self._make_guid(self.sensorid, pid, header.process_create_time)

    def _lookup_filepath(self, target):
        for filepath in self.filepaths:
            if filepath.guid == target :
                return filepath.utf8string
        return str(target)

    def to_obj(self):
        raise NotImplementedError("'to_obj' must be implemented by subclass!")

class CbProcessEvent(CbBaseEvent):
    def __init__(self, msg, msg_header, filepaths, sensorid):
        CbBaseEvent.__init__(self, msg, "PROCESS", msg_header, filepaths, sensorid)
        self.timestamp = self.event_timestamp
        self.guid = self.process_guid
        self.filepath = self._lookup_filepath(self.filepath_string_guid)
        self.pid = self.msg.pid
        self.created = self.msg.created
        # TODO: ADD process_create_time
        self.parent_pid = self.msg.parent_pid
        self.parent_create_time = self.msg.parent_create_time
        self.parent_guid = self._make_guid(self.sensorid, self.parent_pid, self.parent_create_time)
        self.md5hash = self.msg.md5hash
        self.have_seen_before = self.msg.have_seen_before
        self.commandline = self.msg.commandline
        self.parent_md5hash = self.msg.parent_md5
        self.parent_path = self.msg.parent_path
        self.creationobserved = self.msg.creationobserved
        self.username = None
        if msg.HasField('username'):
            self.username = self.msg.username

    def to_obj(self):

        dict = {}

        dict['type'] = 'proc'
        dict['timestamp'] = windows_time_to_unix_time(self.timestamp)
        dict['process_guid'] = self.process_guid
        dict['parent_process_guid'] = self.parent_guid
        
        dict['path'] = self.filepath
        dict['pid'] = self.pid
        dict['md5'] = self.md5hash.encode("hex").upper() 
        dict['command_line'] = self.commandline
        dict['sensor_id'] = self.sensorid
        if (self.username is not None):
            dict['username'] = self.username

        return dict

class CbChildProcEvent(CbBaseEvent):
    def __init__(self, msg, msg_header, filepaths, sensorid):
        CbBaseEvent.__init__(self, msg, "CHILDPROC", msg_header, filepaths, sensorid)
        self.timestamp = self.event_timestamp
        self.created = self.msg.created
        self.parent_guid = self.msg.parent_guid
        self.process_guid = self.msg.parent_guid # system is fragile. NEEDS process_guid
        self.md5hash = self.msg.md5hash
        self.child_guid = self.msg.child_guid
        self.path = self.msg.path
        self.pid = self.msg.pid

        if msg.HasField('create_time'):
            self.child_guid = self._make_guid(self.sensorid, self.pid, msg.create_time)

    def to_obj(self):
        dict = {}

        dict['type'] = 'childproc'
        dict['timestamp'] = windows_time_to_unix_time(self.timestamp)
        dict['process_guid'] = self.parent_guid
        
        dict['created'] = self.created
        dict['md5'] = self.md5hash.encode("hex").upper()
        dict['child_process_guid'] = self.child_guid
        dict['sensor_id'] = self.sensorid

        return dict

class CbModuleLoadEvent(CbBaseEvent):
    def __init__(self, msg, msg_header, filepaths, sensorid):
        CbBaseEvent.__init__(self, msg, "MODULELOAD", msg_header, filepaths, sensorid)

        self.timestamp = self.event_timestamp
        self.guid = self.msg.guid
        self.filepath = self._lookup_filepath(self.filepath_string_guid)
        self.md5hash = self.msg.md5hash
        self.is_process_base_module = self.msg.is_process_base_module
        self.process_guid = self.process_guid

    def to_obj(self):

        dict = {}

        dict['type'] = 'modload'
        dict['timestamp'] = windows_time_to_unix_time(self.timestamp)
        dict['process_guid'] = self.process_guid 

        dict['path'] = self.filepath
        dict['md5'] = self.md5hash.encode('hex').upper()
        dict['sensor_id'] = self.sensorid

        return dict

class CbFileModEvent(CbBaseEvent):
    def __init__(self, msg, msg_header, filepaths, sensorid):
        CbBaseEvent.__init__(self, msg, "FILEMOD", msg_header, filepaths, sensorid)
        self.timestamp = self.event_timestamp
        self.guid = self.msg.guid
        self.filepath = self._lookup_filepath(self.filepath_string_guid)
        self.process_guid = self.process_guid
        self.action = filemod_action_to_str(self.msg.action)
        self.actiontype = self.msg.action

    def to_obj(self):

        dict = {}

        dict['type'] = 'filemod'
        dict['timestamp'] = windows_time_to_unix_time(self.timestamp)
        dict['process_guid'] = self.process_guid
        
        dict['path'] = self.filepath
        dict['action'] = self.action
        dict['actiontype'] = self.actiontype
        dict['sensor_id'] = self.sensorid

        # todo add md5 for filewrite_complete

        return dict

class CbRegModEvent(CbBaseEvent):
    def __init__(self, msg, msg_header, filepaths, sensorid):
        CbBaseEvent.__init__(self, msg, "REGMOD", msg_header, filepaths, sensorid)
        self.timestamp = self.event_timestamp
        self.guid = self.msg.guid
        self.registry_path = msg.utf8_regpath
        self.process_guid = self.process_guid
        self.action = regmod_action_to_str(self.msg.action)
        self.actiontype = self.msg.action

    def to_obj(self):

        dict = {}

        dict['type'] = 'regmod'
        dict['timestamp'] = windows_time_to_unix_time(self.timestamp)
        dict['process_guid'] = self.process_guid
        
        dict['path'] = self.registry_path
        dict['action'] = self.action
        dict['actiontype'] = self.actiontype
        dict['sensor_id'] = self.sensorid

        return dict

class CbNetConnEvent(CbBaseEvent):
    def __init__(self, msg, msg_header, filepaths, sensorid):
        CbBaseEvent.__init__(self, msg, "NETCONN", msg_header, filepaths, sensorid)
        self.timestamp = self.event_timestamp
        self.process_guid = self.process_guid
        self.ipv4address = self.msg.ipv4Address
        self.ipv4address_str = socket.inet_ntoa(struct.pack('<L', self.ipv4address))
        self.port = self.msg.port
        self.protocol = self.msg.protocol
        self.network_path = self.msg.utf8_netpath
        
        if self.msg.outbound:
            self.direction = "outbound"
        else:
            self.direction = "inbound" 

    def to_obj(self):

        dict = {}

        dict['type'] = 'netconn'
        dict['timestamp'] = windows_time_to_unix_time(self.timestamp)
        dict['process_guid'] = self.process_guid
        
        dict['domain'] = self.network_path
        dict['ipv4'] = self.ipv4address_str
        dict['port'] = socket.ntohs(self.port)
        dict['protocol'] = self.protocol
        dict['direction'] = self.direction
        dict['sensor_id'] = self.sensorid

        return dict

class CbVtWriteEvent(CbBaseEvent):
    def __init__(self, msg, msg_header, filepaths, sensorid):
        CbBaseEvent.__init__(self, msg, "VT_WRITE", msg_header, filepaths, sensorid)
        self.timestamp = self.event_timestamp
        self.WritingProcessExeMd5 = msg.WritingProcessExeMd5
        self.FileWrittenMd5 = msg.FileWrittenMd5
        self.FileWrittenIsPeModuleHint = msg.FileWrittenIsPeModuleHint
        self.WritingProcessFilename = msg.WritingProcessFilename
        self.FileWrittenFilename = msg.FileWrittenFilename

        self.FileWrittenMd5Hex = self.FileWrittenMd5.encode('hex').upper()
        self.WritingProcessExeMd5Hex = self.WritingProcessExeMd5.encode('hex').upper()

    def to_obj(self):
        return {}

class CbModInfoEvent(CbBaseEvent):
    def __init__(self, msg, msg_header, filepaths, sensorid):
        CbBaseEvent.__init__(self, msg, "MODINFO", msg_header, filepaths, sensorid, sensorevent=False)
        self.timestamp = self.event_timestamp
        self.md5                     = msg.md5
        self.CopiedModuleLength      = msg.CopiedModuleLength
        self.OriginalModuleLength    = msg.OriginalModuleLength
        self.utf8_FileDescription    = msg.utf8_FileDescription
        self.utf8_CompanyName        = msg.utf8_CompanyName
        self.utf8_ProductName        = msg.utf8_ProductName
        self.utf8_FileVersion        = msg.utf8_FileVersion
        self.utf8_Comments           = msg.utf8_Comments
        self.utf8_LegalCopyright     = msg.utf8_LegalCopyright
        self.utf8_LegalTrademark     = msg.utf8_LegalTrademark
        self.utf8_InternalName       = msg.utf8_InternalName
        self.utf8_OriginalFileName   = msg.utf8_OriginalFileName
        self.utf8_ProductDescription = msg.utf8_ProductDescription
        self.utf8_ProductVersion     = msg.utf8_ProductVersion
        self.utf8_PrivateBuild       = msg.utf8_PrivateBuild
        self.utf8_SpecialBuild       = msg.utf8_SpecialBuild
        self.utf8_DigSig_Publisher   = msg.utf8_DigSig_Publisher
        self.utf8_DigSig_ProgramName = msg.utf8_DigSig_ProgramName
        self.utf8_DigSig_IssuerName  = msg.utf8_DigSig_IssuerName
        self.utf8_DigSig_SubjectName = msg.utf8_DigSig_SubjectName
        self.utf8_DigSig_Result      = msg.utf8_DigSig_Result
        self.utf8_DigSig_ResultCode  = msg.utf8_DigSig_ResultCode
        self.utf8_DigSig_SignTime    = msg.utf8_DigSig_SignTime

    def to_obj(self):

        dict = {}

        dict['type'] = 'binary_info'
        dict['md5'] = self.md5
        dict['size'] = self.OriginalModuleLength
       
        dict['digsig'] = {}
        dict['digsig']['result'] = self.utf8_DigSig_Result
        dict['timestamp'] = windows_time_to_unix_time(self.timestamp)

        return dict
