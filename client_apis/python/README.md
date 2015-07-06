# Python bindings for Carbon Black REST API

https://www.bit9.com/solutions/carbon-black/

## Requirements

* Python 2.6+
* [requests](http://docs.python-requests.org/en/latest/) >= 1.0
* simplejson
* pika, for communicating with the Cb RabbitMQ message bus
* Google protobuf


## Example scripts

See the `examples/` directory for many examples on how to use the Python Cb API bindings.

### Set up the API and perform a query

```python
    import cbapi
    cb = cbapi.CbApi("http://cb.example.com", token="xxxxxxxxxxxxxx", ssl_verify=False)
    # get metadata for all svchost.exe's not from c:\\windows
    procs = cb.process_search(r"process_name:svchost.exe -path:c:\\windows\\")
    for proc in procs['results']:
        proc_detail = cb.process(proc['id'])
        print proc_detail['process']['start'], proc_detail['process']['hostname'], proc_detail['process']['path']
```

Once you receive a CbApi object, here are the major methods you can call in order to perform
queries on the Cb server:

* `process_search` : prepares a process search query. See the [Query syntax](https://github.com/carbonblack/cbapi/raw/master/client_apis/docs/query_overview.pdf) for how to format queries.
* `binary_search` : prepares a binary search query. Also uses the [Query syntax](https://github.com/carbonblack/cbapi/raw/master/client_apis/docs/query_overview.pdf).
* `binary_summary` : get metadata about a binary by MD5sum
* `process_events` : get process events by Cb process ID
