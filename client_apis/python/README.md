Python bindings for Carbon Black Enterprise Server API
http://carbonblack.com

Requires requests >= 1.0

    import cbapi
    cb = cbapi.CbApi("http://cb.example.com", "admin", "pa$$w0rd")
    # get metadata for all svchost.exe's not from c:\\windows
    procs = cb.processes(r"process_name:svchost.exe -path:c:\\windows\\")
    for proc in procs['results']:
        proc_detail = cb.process(proc['id'])
        print proc_detail['process']['start'], proc_detail['process']['hostname'], proc_detail['process']['path']
