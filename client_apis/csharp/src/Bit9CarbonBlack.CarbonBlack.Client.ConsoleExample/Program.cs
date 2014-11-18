using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Bit9CarbonBlack.CarbonBlack.Client.ConsoleExample
{
    public class Program
    {
        static void Main(string[] args)
        {
            CbClientConsoleAsync().Wait();
            CbClientConsole();
        }

        static void CbClientConsole()
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Synchronous API Examples");
            Console.ForegroundColor = ConsoleColor.White;

            // Creates an instance of CbClient in a using (to ensure that it is disposed of properly)
            using (CbClient client = new CbClient("https://192.168.43.164/", "999b934fb2236d1465ecc1577d4c44e9a87128d1", false))
            {
                // Get the server information as a string
                Console.WriteLine("/api/info");
                var infoStringResponse = client.HttpGetAsString("/api/info");
                WriteStringResponse(infoStringResponse);

                // Get the sensor statistics as a dictionary
                Console.WriteLine("/api/v1/sensor/statistics");
                var sensorStatsResponse = client.HttpGetAsDictionary("/api/v1/sensor/statistics");
                WriteDictionaryResponse(sensorStatsResponse);

                // Get up to 5 processes as dynamic
                Console.WriteLine("/api/v1/process?rows=5");
                var processSearchResponse = client.HttpGetAsDynamic("/api/v1/process?rows=5");
                Console.WriteLine("  Status: {0}", processSearchResponse.StatusCode);
                Console.WriteLine("  Content:");
                foreach (dynamic result in processSearchResponse.Response.results)
                {
                    Console.WriteLine("    {0} - {1}", result.process_name, result.process_md5);
                }
                Console.WriteLine();

            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine();
            Console.WriteLine();
        }

        static async Task CbClientConsoleAsync()
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Asynchronous API Examples");
            Console.ForegroundColor = ConsoleColor.White;

            // Creates an instance of CbClient in a using (to ensure that it is disposed of properly)
            using (CbClient client = new CbClient("https://192.168.43.164/", "999b934fb2236d1465ecc1577d4c44e9a87128d1", false))
            {
                // Get the server information as a string
                Console.WriteLine("/api/info");
                var infoStringResponse = await client.HttpGetAsStringAsync("/api/info");
                WriteStringResponse(infoStringResponse);

                // Get the sensor statistics as a dictionary
                Console.WriteLine("/api/v1/sensor/statistics");
                var sensorStatsResponse = await client.HttpGetAsDictionaryAsync("/api/v1/sensor/statistics");
                WriteDictionaryResponse(sensorStatsResponse);

                // Get up to 5 processes as dynamic
                Console.WriteLine("/api/v1/process?rows=5");
                var processSearchResponse = await client.HttpGetAsDynamicAsync("/api/v1/process?rows=5");
                Console.WriteLine("  Status: {0}", processSearchResponse.StatusCode);
                Console.WriteLine("  Content:");
                foreach (dynamic result in processSearchResponse.Response.results)
                {
                    Console.WriteLine("    {0} - {1}", result.process_name, result.process_md5);
                }
                Console.WriteLine();
            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine();
            Console.WriteLine();
        }

        private static void WriteStringResponse(CbClientResult<string> response)
        {
            Console.WriteLine("  Status: {0}{2}  Content: {1}{2}", (int)response.StatusCode, response.Response, Environment.NewLine);
        }

        private static void WriteDictionaryResponse(CbClientResult<IDictionary<string,object>> response)
        {
            Console.WriteLine("  Status: {0}", (int)response.StatusCode);
            Console.WriteLine("  Content:");
            foreach (var key in response.Response.Keys)
            {
                Console.WriteLine("    {0}: {1}", key, response.Response[key].ToString());
            }
            Console.WriteLine();
        }
    }
}