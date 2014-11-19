using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Bit9CarbonBlack.CarbonBlack.Client
{
    /// <summary>
    /// Represents a client to the CarbonBlack server api.
    /// </summary>
    public class CbClient : ICbClient
    {
        private readonly Uri serverUri = null;
        private readonly string token = null;
        private HttpClient httpClient = null;
        private bool disposed = false;

        /// <summary>
        /// Creates a new instannce of <see cref="CbClient"/>, and optionally specifies the ssl verification options.
        /// </summary>
        /// <param name="serverUri">The URI string for the CarbonBlack server.</param>
        /// <param name="token">The user API token for connecting to the CarbonBlack API.</param>
        /// <param name="sslVerify">True to perform SSL verification; otherwise, false.</param>
        /// <exception cref="ArgumentException">
        /// serverUri or token is not a valid string.
        /// serverUri is not a valid absolute URI.
        /// </exception>
        public CbClient(string serverUri, string token, bool sslVerify)
            : this(serverUri, token, sslVerify ? HttpClientMessageHandler.DefaultHandler() : HttpClientMessageHandler.SslIgnoreHandler())
        {
        }

        /// <summary>
        /// Creates a new instance of <see cref="CbClient"/>, with an optional <see cref="HttpMessageHandler"/>.
        /// </summary>
        /// <param name="serverUri">The URI string for the CarbonBlack server.</param>
        /// <param name="token">The user API token for connecting to the CarbonBlack API.</param>
        /// <param name="httpClientMessageHandler">An optional <see cref="HttpMessageHandler"/> instance to use with the underlying <see cref="HttpClient"/>.</param>
        /// <exception cref="ArgumentException">
        /// serverUri or token is not a valid string.
        /// serverUri is not a valid absolute URI.
        /// </exception>
        /// <remarks>
        /// The <see cref="HttpMessageHandler"/> instance passed as httpClientMessageHandler will be disposed when the the <see cref="CbClient"/> instance is disposed.
        /// </remarks>
        public CbClient(string serverUri, string token, HttpMessageHandler httpClientMessageHandler = null)
            : this(serverUri, token, httpClientMessageHandler == null ? new HttpClient() : new HttpClient(httpClientMessageHandler, true))
        {
        }

        /// <summary>
        /// Creates a new instance of <see cref="CbClient"/> with a specific <see cref="HttpClient"/>.
        /// This constuctor is marked as internal and used for testing.
        /// </summary>
        /// <param name="serverUri">The URI string for the CarbonBlack server.</param>
        /// <param name="token">The user API token for connecting to the CarbonBlack API.</param>
        /// <param name="httpClient">The <see cref="HttpClient"/> instance to use as the underlying rest client.</param>
        /// <exception cref="ArgumentException">
        /// serverUri or token is not a valid string.
        /// serverUri is not a valid absolute URI.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// httpClient is null.
        /// </exception>
        /// <remarks>
        /// The <see cref="HttpClient"/> instance passed as httpClient will be disposed when the the <see cref="CbClient"/> instance is disposed.
        /// </remarks>
        internal CbClient(string serverUri, string token, HttpClient httpClient)
        {
            if (String.IsNullOrWhiteSpace(serverUri))
            {
                throw new ArgumentException("a value must be provided for the 'serverUri' argument", "serverUri");
            }

            if (String.IsNullOrWhiteSpace(token))
            {
                throw new ArgumentException("a value must be provided for the 'token' argument", "token");
            }

            if (httpClient == null)
            {
                throw new ArgumentNullException("httpClient");
            }

            if (!Uri.TryCreate(serverUri, UriKind.Absolute, out this.serverUri))
            {
                throw new ArgumentException("'serverUri' must be a valid uri", "serverUri");
            }

            this.token = token;
            this.httpClient = httpClient;

            this.httpClient.DefaultRequestHeaders.Accept.Clear();
            this.httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            this.httpClient.DefaultRequestHeaders.Add("X-Auth-Token", token);
            this.httpClient.BaseAddress = new Uri(this.serverUri.GetLeftPart(UriPartial.Authority));
        }

        /// <summary>
        /// Gets the CarbonBlack server URI that is being used by this <see cref="CbClient"/> instance.
        /// </summary>
        public Uri ServerUri { get { return this.serverUri; } }

        /// <summary>
        /// Gets the CarbonBlack user API token that is being used by this <see cref="CbClient"/> instance.
        /// </summary>
        public string Token { get { return this.token; } }

        /// <summary>
        /// Gets the <see cref="HttpClient"/> instance that is being used.
        /// </summary>
        internal HttpClient HttpClient { get { return this.httpClient; } }

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a <see cref="String"/> representation of the content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public async Task<CbClientResult<string>> HttpGetAsStringAsync(string relativePath)
        {
            Uri path = this.EnsureRelativeUri(relativePath);
            HttpResponseMessage response = await this.httpClient.GetAsync(path);
            return await this.TransformResponse(response, async (c) =>
                {
                    return await c.ReadAsStringAsync();
                });
        }

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a <see cref="String"/> representation of the content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A <see cref="CbClientResult{String}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public CbClientResult<string> HttpGetAsString(string relativePath)
        {
            return Task.Run(() => HttpGetAsStringAsync(relativePath)).Result;
        }

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a <see cref="Stream"/> representation of the content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public async Task<CbClientResult<Stream>> HttpGetAsStreamAsync(string relativePath)
        {
            Uri path = this.EnsureRelativeUri(relativePath);
            HttpResponseMessage response = await this.httpClient.GetAsync(path);
            return await this.TransformResponse(response, async (c) =>
            {
                return await c.ReadAsStreamAsync();
            });
        }

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a <see cref="Stream"/> representation of the content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A <see cref="CbClientResult{Stream}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public CbClientResult<Stream> HttpGetAsStream(string relativePath)
        {
            return Task.Run(() => HttpGetAsStreamAsync(relativePath)).Result;
        }

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a dynamic representation of the content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public async Task<CbClientResult<dynamic>> HttpGetAsDynamicAsync(string relativePath)
        {
            Uri path = this.EnsureRelativeUri(relativePath);
            HttpResponseMessage response = await this.httpClient.GetAsync(path);
            return await this.TransformResponse(response, async (c) =>
            {
                var content = await c.ReadAsStringAsync();
                dynamic dynamicObject = JObject.Parse(content);
                return dynamicObject;
            });
        }

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a dynamic representation of the content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A <see cref="CbClientResult{dynamic}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public CbClientResult<dynamic> HttpGetAsDynamic(string relativePath)
        {
            return Task.Run(() => HttpGetAsDynamicAsync(relativePath)).Result;
        }

        /// <summary>
        /// Sends a GET request for the specified path to retrieve an <see cref="IDictionary{String,Object}"/> representation of the content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public async Task<CbClientResult<IDictionary<string, object>>> HttpGetAsDictionaryAsync(string relativePath)
        {
            Uri path = this.EnsureRelativeUri(relativePath);
            HttpResponseMessage response = await this.httpClient.GetAsync(path);
            return await this.TransformResponse(response, async (c) =>
            {
                var content = await c.ReadAsStringAsync();
                var dict = JsonConvert.DeserializeObject<Dictionary<string, object>>(content);
                return dict as IDictionary<string, object>;
            });
        }

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a <see cref="IDictionary{String,Object}"/> representation of the content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>An <see cref="IDictionary{String,Object}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public CbClientResult<IDictionary<string, object>> HttpGetAsDictionary(string relativePath)
        {
            return Task.Run(() => HttpGetAsDictionaryAsync(relativePath)).Result;
        }

        /// <summary>
        /// Sends a POST request for the specified path to post dynamic content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public async Task<CbClientResult<string>> HttpPostDynamicAsync(string relativePath, dynamic data)
        {
            Uri path = this.EnsureRelativeUri(relativePath);
            HttpResponseMessage response = await HttpClientExtensions.PostAsJsonAsync(this.httpClient, path.ToString(), data);
            return await this.TransformResponse(response, async (c) =>
            {
                return await c.ReadAsStringAsync();
            });
        }

        /// <summary>
        /// Sends a POST request for the specified path to post dynamic content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A <see cref="CbClientResult{String}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public CbClientResult<string> HttpPostDynamic(string relativePath, dynamic data)
        {
            return Task.Run(() => HttpPostDynamicAsync(relativePath, data)).Result;
        }

        /// <summary>
        /// Sends a POST request for the specified path to post <see cref="IDictionary{String,Object}"/> content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public async Task<CbClientResult<string>> HttpPostDictionaryAsync(string relativePath, IDictionary<string, object> data)
        {
            Uri path = this.EnsureRelativeUri(relativePath);
            HttpResponseMessage response = await HttpClientExtensions.PostAsJsonAsync(this.httpClient, path.ToString(), data);
            return await this.TransformResponse(response, async (c) =>
            {
                return await c.ReadAsStringAsync();
            });
        }

        /// <summary>
        /// Sends a POST request for the specified path to post <see cref="IDictionary{String,Object}"/> content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A <see cref="CbClientResult{String}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public CbClientResult<string> HttpPostDictionary(string relativePath, IDictionary<string, object> data)
        {
            return Task.Run(() => HttpPostDictionaryAsync(relativePath, data)).Result;
        }

        /// <summary>
        /// Sends a PUT request for the specified path to put dynamic content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public async Task<CbClientResult<string>> HttpPutDynamicAsync(string relativePath, dynamic data)
        {
            Uri path = this.EnsureRelativeUri(relativePath);
            HttpResponseMessage response = await HttpClientExtensions.PutAsJsonAsync(this.httpClient, path.ToString(), data);
            return await this.TransformResponse(response, async (c) =>
            {
                return await c.ReadAsStringAsync();
            });
        }

        /// <summary>
        /// Sends a PUT request for the specified path to put dynamic content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A <see cref="CbClientResult{String}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public CbClientResult<string> HttpPutDynamic(string relativePath, dynamic data)
        {
            return Task.Run(() => HttpPutDynamicAsync(relativePath, data)).Result;
        }

        /// <summary>
        /// Sends a PUT request for the specified path to put <see cref="IDictionary{String,Object}"/> content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public async Task<CbClientResult<string>> HttpPutDictionaryAsync(string relativePath, IDictionary<string, object> data)
        {
            Uri path = this.EnsureRelativeUri(relativePath);
            HttpResponseMessage response = await HttpClientExtensions.PutAsJsonAsync(this.httpClient, path.ToString(), data);
            return await this.TransformResponse(response, async (c) =>
            {
                return await c.ReadAsStringAsync();
            });
        }

        /// <summary>
        /// Sends a PUT request for the specified path to put <see cref="IDictionary{String,Object}"/> content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A <see cref="CbClientResult{String}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public CbClientResult<string> HttpPutDictionary(string relativePath, IDictionary<string, object> data)
        {
            return Task.Run(() => HttpPutDictionaryAsync(relativePath, data)).Result;
        }

        /// <summary>
        /// Sends a DELETE request for the specified path, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public async Task<CbClientResult<string>> HttpDeleteAsync(string relativePath)
        {
            Uri path = this.EnsureRelativeUri(relativePath);
            HttpResponseMessage response = await this.httpClient.DeleteAsync(path);
            return await this.TransformResponse(response, async (c) =>
            {
                return await c.ReadAsStringAsync();
            });
        }

        /// <summary>
        /// Sends a DELETE request for the specified path.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A <see cref="CbClientResult{String}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        public CbClientResult<string> HttpDelete(string relativePath)
        {
            return Task.Run(() => HttpDeleteAsync(relativePath)).Result;
        }

        /// <summary>
        /// Releases any unmanaged resources and disposes of the managed resources used by this <see cref="CbClient"/> instance.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases any unmanaged resources and optionally disposes of the managed resources used by this <see cref="CbClient"/> instance.
        /// </summary>
        /// <param name="disposing">True to release both managed and unmanaged resources; False to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    if (this.httpClient != null)
                    {
                        this.httpClient.Dispose();
                        this.httpClient = null;
                    }
                }

                this.disposed = true;
            }
        }

        private Uri EnsureRelativeUri(string relativeUri)
        {
            Uri relativePathUri;
            if (!Uri.TryCreate(relativeUri, UriKind.Relative, out relativePathUri))
            {
                throw new ArgumentException("'relativeUri' must be a valid relative URI", "relativeUri");
            }
            return relativePathUri;
        }

        private async Task<CbClientResult<T>> TransformResponse<T>(HttpResponseMessage responseMessage, Func<HttpContent, Task<T>> contentTransform) where T : class
        {
            if (responseMessage.IsSuccessStatusCode)
            {
                T content = await contentTransform(responseMessage.Content);
                return new CbClientResult<T>(responseMessage.StatusCode, content);
            }
            else
            {
                return new CbClientResult<T>(responseMessage.StatusCode, null);
            }
        }
    }
}
