### C# Client for Carbon Black Enterprise Server API ###
http://carbonblack.com

Requires .NET 4.5

Example code in Bit9CarbonBlack.CarbonBlack.Client.ConsoleExample application

```C#
    using Bit9CarbonBlack.CarbonBlack.Client;
    ...
    ...
    using (var client = new CbClient("https://my.carbonblack.server", "my_api_token"))
    {
        // get metadata for all svchost.exe
        var procsResponse = await client.HttpGetAsDynamicAsync("/api/v1/process?q=process_name:svchost.exe");
        if (procsResponse.StatusCode == HttpStatusCode.OK)
        {
            foreach (var proc in procsResponse.Response.results)
            {
                Console.WriteLine("Hostname: {0}, MD5: {1}", proc.hostname, proc.process_md5);
            }
        }
    }
```
