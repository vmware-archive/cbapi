using Bit9CarbonBlack.CarbonBlack.Client;
using Bit9CarbonBlack.Example.FileSystemViewer.Model;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Bit9CarbonBlack.Example.FileSystemViewer.Client
{
    public class CarbonBlack
    {
        public string ServerUri { get; set; }

        public string ApiToken { get; set; }

        public async Task<List<Hostname>> GetHostnames()
        {
            using (CbClient cbClient = new CbClient(this.ServerUri, this.ApiToken, false))
            {
                var hostnameResponse = await cbClient.HttpGetAsDynamicAsync("/api/v1/sensor");
                if (hostnameResponse.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    var hostnames = ((IEnumerable)hostnameResponse.Response).Cast<dynamic>()
                        .Select(x => new Hostname() { Name = x.computer_name, SensorId = x.id }).OrderBy(x => x.Name).ToList();
                    return hostnames;
                }
                else
                {
                    throw new ApplicationException(String.Format("Could not get list of hostnames - Http Code {0}", hostnameResponse.StatusCode));
                }
            }
        }

        public async Task<int> GetProcessCountForHost(int sensorId)
        {
            using (CbClient cbClient = new CbClient(this.ServerUri, this.ApiToken, false))
            {
                var queryForCountResponse = await cbClient.HttpGetAsDynamicAsync(String.Format("/api/v1/process?rows=0&q=sensor_id:{0} and filemod_count:[1 TO *]", sensorId.ToString()));
                if (queryForCountResponse.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    return queryForCountResponse.Response.total_results;
                }
                else
                {
                    throw new ApplicationException(String.Format("Could not get count of processes for sensor id:{0} - HTTP Code {1}", sensorId, queryForCountResponse.StatusCode));
                }
            }
        }

        public async Task<int> GetSensorIdForHost(string hostname)
        {
            using (CbClient cbClient = new CbClient(this.ServerUri, this.ApiToken, false))
            {
                var queryForSensorIdResponse = await cbClient.HttpGetAsDynamicAsync(String.Format("/api/v1/sensor?hostname={0}", hostname));
                if (queryForSensorIdResponse.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    var sensor = ((IEnumerable)queryForSensorIdResponse.Response).Cast<dynamic>()
                        .FirstOrDefault();
                    if (sensor != null)
                    {
                        return sensor.id;
                    }
                    else
                    {
                        return -1;
                    }
                }
                else
                {
                    throw new ApplicationException(String.Format("Could not find sensor with hostname: '{0}' - Http Code {1}", hostname, queryForSensorIdResponse.StatusCode));
                }
            }
        }

        public async Task<int> UpdateFilesBatch(ObservableFileSystem fileSystem, int sensorId, int start, int rows, CancellationToken cancelToken = default(CancellationToken))
        {
            using (CbClient cbClient = new CbClient(this.ServerUri, this.ApiToken, false))
            {
                var queryForPidsResponse = await cbClient.HttpGetAsDynamicAsync(String.Format("/api/v1/process?start={0}&rows={1}&q=sensor_id:{2} and filemod_count:[1 TO *]&sort=start asc",
                    start, rows, sensorId));
                if (cancelToken.IsCancellationRequested)
                {
                    return -1;
                }

                if (queryForPidsResponse.StatusCode != System.Net.HttpStatusCode.OK)
                {
                    throw new ApplicationException(String.Format("Could not get process batch for sensor id:{0}, start:{1}, rows:{2} - HTTP Code {3}", 
                        sensorId, start, rows, queryForPidsResponse.StatusCode));
                }
                else
                {
                    int resultCount = 0;
                    foreach (var result in queryForPidsResponse.Response.results)
                    {
                        var processId = result.id;
                        var segmentId = result.segment_id;

                        var queryForEventsResponse = await cbClient.HttpGetAsDynamicAsync(String.Format("/api/v1/process/{0}/{1}/event", processId, segmentId));
                        if (queryForEventsResponse.StatusCode != System.Net.HttpStatusCode.OK)
                        {
                            // do something
                        }
                        else
                        {
                            foreach (string evt in queryForEventsResponse.Response.process.filemod_complete)
                            {
                                var evtParts = evt.Split('|');
                                int type = Convert.ToInt32(evtParts[0]);
                                fileSystem.AddFileSystemItem(evtParts[2], evtParts[1], type);
                            }
                        }
                        resultCount++;

                        if (cancelToken.IsCancellationRequested)
                        {
                            return resultCount;
                        }
                    }

                    return resultCount;
                }
            }
        }

    }
}
