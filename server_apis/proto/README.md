# CarbonBlack Response Raw Events Protobuffer

## Changes in 5.2

In CarbonBlack Response version 5.2 two significant changes were made to the protobuffer format and state tracking used by
the underlying sensors.   The two changes are:

* Introduction of data-suppression for eventless processes
* The re-mapping of POSIX processes into the SOLR document store. 
These changes result in new and additional protobuffer messages being sent under specific conditions.  

### Data supperession for eventless processes

In CarbonBlack Response a new optional feature was introduced that reduces the storage requirements on the back-end 
data server by eliminating process documents for processes which are "uninteresting".   "Uninteresting" processes are 
processes that do not make a network connection, do not write to the registry, do not have child processes, and do 
 not write files.    (Cross process events can be considered intersting or unintersting depending on the level of
 data suppresion configured.)   When a process is deemed uninteresting the sensor will not report a process event
 for the process, but instead will report a special child process event, CbChildProcessMsg, within the context of 
 the parent.   Extra meta-data for the process will be reported.    This extra meta-data includes:

 * The command line of the process
 * The user context of the process

These can be seen in new fields within the CbChildProcessMsg:

    message CbChildProcessMsg
    {
      enum CbChildProcType
      {
        childProcExec = 0; // default (only type supported on WIN)
        childProcFork = 1;
        childProcOtherExec = 2; // when a posix process calls exec() then exec()
      }

    optional    bool    created                 =  1;   // creation:true::term:false
    optional    int64   parent_guid             =  2;   // deprecated; only provided for backwards compatibility
    optional    bytes   md5hash                 =  3;   // md5 hash of child process
    optional    int64   child_guid              =  4;   // guid of child process (for link)
    optional    string  path                    =  5;   // path of child process (c:\a.exe)
    optional    int64   pid                     =  6;   // Process Identifier (PID) for human consumption
    optional    int64   create_time             =  7;   // higher resolution timestamp of process creation (FILETIME format)
    optional    bool    tamper                  =  8 [default=false];
    optional    CbSuppressedInfo suppressed     =  9;   // if not present - not suppressed
    optional    bytes   commandline             = 10;   // used for suppressed children
    optional    string  username                = 11;   // used for suppressed children
    optional    CbChildProcType childProcType   = 12 [default=childProcExec];
    }

The sensor will also report the process as suppressed child with a new field in the child process, CbSuppresedInfo:

    message CbSuppressedInfo
    {
      enum CbSuppressedProcessState
      {
        suppressedEventlessModloads  = 1; // proc with no events except modloads
        suppressedEventlessWithXproc = 2; // proc with only modloads and xproc
      }

    optional  bool    bIsSuppressed           = 1 [default=false];
    optional  CbSuppressedProcessState state  = 2;
    }
    
When a suppressed process executes, the sensor will report a child process for the suppressed process (as would happen
with previous versions.   The suppressed process will run but will but the sensor will not report a CbProcessMsg for
 that process.   When the process completes, the sensor will report a child process messsage with created=False (as
 it would have with previous versions).  These two child process messages will look like they did in previous versions 
 and they will not have any extra meta-data or suppression info set. 
  
When a child process is suppressed, a third child process message (CbChildProcessMsg) will be sent.  This one will contain 
the fields suppressed, commandline, and username.   

### Data Suppression Example:

An example of data suppression is given for the case of cmd.exe spawning netstat.  In this example, netstat is a 
suppressed process.   

To start, the sensor will report the execution of cmd.exe:

    header {
      version: 4
      timestamp: 131085051335658682
      process_guid: 7783280122080401344
      filepath_string_guid: 1009947387290811465
      process_filepath_string_guid: 1009947387290811465
      process_create_time: 131085051335502681
      process_pid: 1492
      process_md5: "WF\275~%]\326\250\257\240o|B\301\272A"
      process_path: "c:\\windows\\system32\\cmd.exe"
    }
    strings {
       guid: 1009947387290811465
       utf8string: "c:\\windows\\system32\\cmd.exe"
       string_type: typeFilepath
    }
    process {
      pid: 1492
      created: true
      parent_pid: 708
      parent_create_time: 131085050459009488
      parent_guid: 3531365848596093817
      md5hash: "WF\275~%]\326\250\257\240o|B\301\272A"
      commandline: "\"C:\\Windows\\system32\\cmd.exe\" "
      parent_md5: "\254LQ\353$\252\225\267\177pZ\261Y\030\236$"
      parent_path: "c:\\windows\\explorer.exe"
      creationobserved: true
      uid: "S-1-5-21-3382350439-2970772701-2583938045-1000"
      username: "DANWIN764\\dan"
      bFilteringKnownDlls: false
    }


Then cmd.exe will spawn netstat.exe.  In this case we see a childproc for the process start, and the process end. Again
no process message will be created for netstat.exe

First, the childproc for the process start:

    header {
      version: 4
      timestamp: 131085051365590776
      process_guid: 7783280122080401344
      process_create_time: 131085051335502681
      process_pid: 1492
    }
    childproc {
      created: true
      parent_guid: 7783280122080401344
      md5hash: "o9\366\364\214\324\202\213,\207\353-,\253E\245"
      child_guid: -103521102309969993
      path: "c:\\windows\\system32\\netstat.exe"
      pid: 1864
      create_time: 131085051365590776
    }

Then the childproc for the process end:

    header {
      version: 4
      timestamp: 131085051415354864
      process_guid: 0
      process_create_time: 131085051335502681
      process_pid: 1492
    }
    childproc {
      created: false
      parent_guid: 7783280122080401344
      md5hash: "o9\366\364\214\324\202\213,\207\353-,\253E\245"
      child_guid: -103521102309969993
      path: "c:\\windows\\system32\\netstat.exe"
      pid: 1864
      create_time: 131085051365590776
    }

Lastly, the new childproc message is sent when the sensor determines that the process should be suppressed.  This
message contains the extra meta-data about the suppressed process:

    header {
      version: 4
      timestamp: 131085051415354864
      process_guid: 0
      process_create_time: 131085051335502681
      process_pid: 1492
    }
    childproc {
      created: false
      parent_guid: 7783280122080401344
      md5hash: "o9\366\364\214\324\202\213,\207\353-,\253E\245"
      child_guid: -103521102309969993
      path: "c:\\windows\\system32\\netstat.exe"
      pid: 1864
      create_time: 131085051365590776
      suppressed {
        bIsSuppressed: true
      }
      commandline: "netstat"
      username: "DANWIN764\\dan"
    }

