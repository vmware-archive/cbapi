# Python bindings for Carbon Black REST API

https://www.bit9.com/solutions/carbon-black/

## Requirements

* Python 2.6+
* [requests](http://docs.python-requests.org/en/latest/) >= 1.0
* simplejson
* pika, for communicating with the Cb RabbitMQ message bus
* Google protobuf

## Getting Started

To try out the API without installing it into your Python site-packages directory (for example, to just run the
example scripts in the `examples` directory), then install it in "develop" mode by running `setup.py` with the
`develop` argument:

    python setup.py develop

You can also install it into a virtualenv or the site-wide packages directory by running `setup.py` with the `install`
argument:

    python setup.py install

In order to perform any queries via the API, you will need to get the API token for your Cb user. This can be acquired by
logging into your Cb server, clicking the "Profile info" link under the pulldown on the top right corner of the Cb interface, and selecting "API token".

The direct URL to view that page is https://{cb-server}/#/account/token.

### Set up the API and perform a query

Once you have your API token (see above), you're ready to perform your first query. Paste your token into the CbApi constructor in the code block below:

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

## Example scripts

See the `examples/` directory for many examples on how to use the Python Cb API bindings.

