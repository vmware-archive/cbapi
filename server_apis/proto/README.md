# CarbonBlack Response Raw Events Protobuffer

## Changes in 5.2

In CarbonBlack Response version 5.2 two significant changes were made to the protobuffer format and state tracking used by
the underlying sensors.   The two changes are:

* Introduction of data-suppression for eventless processes
* The re-mapping of POSIX processes into the SOLR document store. 
These changes result in new and additional protobuffer messages being sent under specific conditions.  

### Data Suppression for eventless processes

In CarbonBlack Response a new optional feature was introduced that reduces the storage requirements on the back-end 
data server by eliminating process documents for processes which are "uninteresting".   "Uninteresting" processes are 
processes that do not make a network connection, do not write to the registry, do not have child processes, and do 
 not write files.    (Cross process events can be considered interesting or uninteresting depending on the level of
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
with previous versions).   The suppressed process will run, but the sensor will not report a CbProcessMsg for
 that process.   When the process completes, the sensor will report a child process message with created=False (as
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

### Handling of Posix processes

Begining with 5.2, changes were made to how Posix (linux/OS X) processes are mapped into process documents within CarbonBlack
Enterprise Response.    When Cb Response was first developed, the focus was on the Windows OS where processes are relatively
expensive and process creation occurs infrequently.   Thus it made sense to map a single process to a single back-end SOLR 
document.   In a Posix world, the model does not work as well.   In Posix there are two system calls which are used to control how 
processes are created they are:

* fork() - which causes the process to copy itself into a new process id, but maintian the same image and open handles as the parent. 
* exec() - which causes the process to adopt a new image and command line, but the process id remains the same.  

Note: There is also the posix_spawn() system call which can function like fork(), exec(), or both depending on how it's called.  For 
the purpose of keeping discussion here simple, we will treat it logically like a fork() and then an exec().  

Typically a Posix process will create a child process by first performing a fork(), which creates a new process id, then 
the process will perform an exec() from within the new child process.  This causes the process to adopt a new image and
execute as a new process.   

It's also perfectly acceptable for a Posix process to call fork() and never call exec().  This occurs with some processes that
leverage multi-processing to perform a specific functionality.   In this case, the process image never changes, it's just
creating a new process to handle execution of a task.   This is the case that is problematic for handling into SOLR.  A process
could perform thousands of forks (say one per network connection) but not ever perform any other actions.  We wanted to avoid
filling up SOLR with many process documents for fork-ed processes that never call exec().   

Two major changes were made to the process handling in Posix Operating Systems.  

First, any time a process performs a fork(), all events that occur within that process, or any fork() descendants, will continue
to be reported in the context of the parent (or ancestor) UNTIL an exec() occurs.   This means if a process (or a set of processes)
performs a fork() and never performs an exec() all the activity for all the processes will be reported in the originating 
process.   The header field of each CbEventMsg will always contain the meta-data of the original process, even if the process no
longer exists and only the descendant processes exist.    We've made a few changes how the protobuffer events are handled to help
track this activity.  

Any time a process performs a fork() we'll report that event with a modified version of the CbChildProcessMsg.  The sensor
 will report the fork() child with a CbChildProcessMsg setting the new field childProcType to childProcFork.  This field is
is described as:

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
    
While generally speaking the other meta-data in the CbChildProcessMsg will be the same as the parent, the process id will
contain the process id of the fork-ed child.    

Secondly, whenever a Posix process performs a fork(), all the events that occur for that process will be recorded by the
sensor within the context of the originating ancestor.   We have, however, added a new field to the CbEventMsg to track events
and associate them with their given process id.   The CbEventMsg header now contains a fork_pid field that will contain the 
actual process id that performed the event, while the process_id will represent the originating ancestor.   An example
of the new header is displayed below.

    message CbHeaderMsg
    {
      required int32  version                         = 1;    // 4
      optional int32  bootid                          = 2;    // deprecated
      optional int32  eventid                         = 3;    // deprecated
      optional int64  timestamp                       = 4;    // FILETIME
      optional int64  process_guid                    = 5;    // deprecated; only provided for backwards compatibility
      optional int64  filepath_string_guid            = 6;    // lookup key for CbStringMsg
      optional uint32 magic                           = 7;    // deprecated
      optional int64  process_filepath_string_guid    = 8;    // lookup key for CbStringMsg
      optional int64  process_create_time             = 9;    // FILETIME format
      optional int32  process_pid                     = 10;   // Windows Process Identifier (PID)
      optional bytes  process_md5                     = 11;
      optional string process_path                    = 12;
      optional int32  fork_pid                        = 13;
    }

Process boundaries on Posix systems are now defined as an exec().   Whenever a process id (most likely a fork-ed child) performs
an exec() (for the first time), the sensor starts tracking the process as a new logical process.  It creates the CbChildProcessMsg 
and CbProcessMsg associated with the new process and starts reporting the events for that process within the new process.   One 
important thing to note is that the process create time reported by the new process is the create time as reported by the underlying
OS.  This means that a process may fork(), wait a while, then exec().  The new process reported by the sensor at exec() time
will be reported with the create time of when the process id was created, which is actually the time of the fork().   

If a process (a pid) performs any exec()s after the first one, those do not result in a new Cb process being created, but instead
those execs are tracked within the same process context.   The sensor will report to messages when this occurs.  The first is a
new process message containing the meta-data of the image contained within the exec() call.  The second is a new child process message,
CbChildProcessMsg, with childProcType set to ChildProcOtherExec, sent from within the context of the process (not the parent) that 
also contains the meta-data of the image.  This should be thought of as a new event type representing the fact that
the process image has changed.  The header of both of these messages will contain the process id and create time of the pid 
that is performing the exec().   

### Posix Process Example:

This section will provide a few examples on how Posix process mapping will work.   Because the posix process handling can be complex
when dealing with uncommon corner cases, we'll start by focusing on the default case, then present some theoretical cases. 

#### Case 1:  A fork() then an exec()

The first and default case is when a process, in this case bash, spawns a new child process, in this case touch.  The first
event that will be reported is the fork of bash.   In this case bash running as pid 3102 performs a fork() to pid 3103. 

    header {
      version: 4 
      timestamp: 131085690861341010
      process_guid: 334610701438800444
      process_create_time: 131085690836136640
      process_pid: 3102
    }
    childproc {
       created: true
       parent_guid: 334610701438800444
       md5hash: "]u\203\330\016S\024\254\204N\355\306\326\214l\327"
       child_guid: 334610701438800444
       path: "/bin/bash"
       pid: 3103
       create_time: 131085690836136640
       commandline: ""
       childProcType: childProcFork
    }

You'll note, then when the fork occurs, the meta-data whithin the childproc matches the meta-data for the child process.
 Both the create time and guilds match.  The childProcType is reported as childProcFork.  This child is the same logical 
 CarbonBlack process as the parent.   The only difference is that the pid is 3103.   

The next thing that happens is that the forked bash child process performs an exec() system call, executing the image
of touch.  This event is reported by the sensor as:

    header {
      version: 4
      timestamp: 131085690861341010
      process_guid: 334610701438800444
      process_create_time: 131085690836136640
      process_pid: 3102
    }
    childproc {
      created: true
      parent_guid: 334610701438800444
      md5hash: "\276\215\342\3523\033\221\2606\371[\210\341\222H\000"
      child_guid: 7296602249202609862
      path: "/usr/bin/touch"
      pid: 3103
      create_time: 131085690861341010
    }
    
This event signifies that the CarbonBlack is now treating the child process as a new logical CB process.   The sensor
also reports the process event for pid 3103 as well:

    header {
      version: 4
      timestamp: 131085690861341010
      process_guid: 7296602249202609862
      filepath_string_guid: -1868613629866534290
      process_create_time: 131085690861341010
      process_pid: 3103
      process_md5: "\276\215\342\3523\033\221\2606\371[\210\341\222H\000"
    }
    strings {
      guid: -1868613629866534290
      utf8string: "/usr/bin/touch"
    }
    process {
      created: true
      parent_pid: 3102
      parent_create_time: 131085690836136640
      parent_guid: 334610701438800444
      md5hash: "\276\215\342\3523\033\221\2606\371[\210\341\222H\000"
      parent_md5: "]u\203\330\016S\024\254\204N\355\306\326\214l\327"
      parent_path: "/bin/bash"
      creationobserved: true
      username: "dan"
    }

From that point forward, any activity performed by pid 3103 is now reported under that process.   

#### Case 2:  A fork(), exec(), then exec() again.

While this case might seem somewhat contrived it is actually quite common the OS will frequently fork() then exec()
a loader process who's responsible for launching the actual process to run.  Here is an example of launchd loading
the cupds daemon, in OS X:

First, launchd, running as pid 1, forks() with a pid of 3072:

    header {
      version: 4 
      timestamp: 131085688650634330
      process_guid: 4660335880870799799
      process_create_time: 131082261861882820
      process_pid: 1
    }
    childproc {
      created: true
      parent_guid: 4660335880870799799
      md5hash: "\037i\222\323\032\342G\302\204<\021\234>\364\374\264"
      child_guid: 4660335880870799799
      path: "/sbin/launchd"
      pid: 3072
      create_time: 131082261861882820
      commandline: ""
      childProcType: childProcFork
    }

Then, the process 3072, performs an exec() to xpcproxy.   This causes Cb to create a new logical process.  Starting with
the child process message:

    header {
       version: 4 
       timestamp: 131085688650637880
       process_guid: 4660335880870799799
       process_create_time: 131082261861882820
       process_pid: 1
    }
    childproc {
       created: true
       parent_guid: 4660335880870799799
       md5hash: "\224\201\377T\003l}\264\t|\034\234\273\261\216\346"
       child_guid: -2717651500605455476
       path: "/usr/libexec/xpcproxy"
       pid: 3072
       create_time: 131085688650637880
     }

The sensor will also report an new process message for the new xpcproxy process:

    header {
      version: 4 
      timestamp: 131085688650637880
      process_guid: -2717651500605455476
      filepath_string_guid: -5043368041491974539
      process_create_time: 131085688650634330
      process_pid: 3072
      process_md5: "\224\201\377T\003l}\264\t|\034\234\273\261\216\346"
    }
    strings {
      guid: -5043368041491974539
      utf8string: "/usr/libexec/xpcproxy"
    }
    process {
      created: true
      parent_pid: 1
      parent_create_time: 131082261861882820
      parent_guid: 4660335880870799799
      md5hash: "\224\201\377T\003l}\264\t|\034\234\273\261\216\346"
      commandline: "/usr/sbin/cupsd -l"
      parent_md5: "\037i\222\323\032\342G\302\204<\021\234>\364\374\264"
      parent_path: "/sbin/launchd"
      creationobserved: true
      username: "root"
    }

Up to this point, the example is just like the previous example.  But, the next thing this process does is a second exec()
to become the image cupsd.  This is reported first, by a childproc with childProcType of childProcExecOther:

    header {
      version: 4 
      timestamp: 131085688650637880
      process_guid: -2717651500605455476
      process_create_time: 131085688650634330
      process_pid: 3072
    }
    childproc {
      created: true
      parent_guid: -2717651500605455476
      md5hash: ",@\322\235I\324.\035\307\275[\000\331\204\346\324"
      child_guid: -2717651500605455476
      path: "/usr/sbin/cupsd"
      pid: 3072
      create_time: 131085688650634330
      commandline: "/usr/sbin/cupsd -l"
      childProcType: childProcOtherExec
    }

A second message for the process is also generated.  This is the process message indicating the meta-data for the new
process:

    header {
      version: 4
      timestamp: 131085688650637880
      process_guid: -2717651500605455476
      filepath_string_guid: -3173372631934899329
      process_create_time: 131085688650634330
      process_pid: 3072
      process_md5: ",@\322\235I\324.\035\307\275[\000\331\204\346\324"
    }
    strings {
      guid: -3173372631934899329
      utf8string: "/usr/sbin/cupsd"
    }
    process {
      created: true
      parent_pid: 1
      parent_create_time: 131082261861882820
      parent_guid: 4660335880870799799
      md5hash: ",@\322\235I\324.\035\307\275[\000\331\204\346\324"
      commandline: "/usr/sbin/cupsd -l"
      parent_md5: "\037i\222\323\032\342G\302\204<\021\234>\364\374\264"
      parent_path: "/sbin/launchd"
      creationobserved: true
      username: "root"
    }

#### Case 3:  A fork() then event activity:

This example illustrates what happens when a process performs a fork() without ever performing an exec().  In this case
the sensor reports that the fork occurs:

    header {
      version: 4
      timestamp: 131085743111897250
      process_guid: -5418691695691536345
      process_create_time: 131085743111499910
      process_pid: 3298
    }
    childproc {
      created: true
      parent_guid: -5418691695691536345
      md5hash: "yD\245\221$\355\325=w\376l!\373\262\247\004"
      child_guid: -5418691695691536345
      path: "/Users/test"
      pid: 3299
      create_time: 131085743111499910
      commandline: ""
      childProcType: childProcFork
    }

The process test, was running as process id 3298 and has forked and is also running as process id 3299.  The application
then performs a file modification action from the fork child (pid 3299).  In this case the filemod event is reported
in the context of the parent, pid 3298, but the fork_pid attribute is set to the process that actually performed the
file modification, pid 3299.  

    header {
      version: 4
      timestamp: 131085743111901620
      process_guid: -5418691695691536345
      filepath_string_guid: 6626332996787925984
      process_create_time: 131085743111499910
      process_pid: 3298
      process_md5: "yD\245\221$\355\325=w\376l!\373\262\247\004"
      fork_pid: 3299
    }
    strings {
      guid: 6626332996787925984
      utf8string: "/Users/dan/cbprove/automation/acceptance/cb_sensor/child.test"
    }
    filemod {
      guid: -2244810752895939917
      action: actionFileModCreate
    }

