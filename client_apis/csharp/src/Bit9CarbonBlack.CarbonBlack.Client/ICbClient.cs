using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
namespace Bit9CarbonBlack.CarbonBlack.Client
{
    /// <summary>
    /// An interface definition for a CarbonBlack API Client.
    /// </summary>
    public interface ICbClient : IDisposable
    {
        /// <summary>
        /// Gets the CarbonBlack server URI that is being used by this <see cref="ICbClient"/> instance.
        /// </summary>
        Uri ServerUri { get; }

        /// <summary>
        /// Gets the CarbonBlack user API token that is being used by this <see cref="ICbClient"/> instance.
        /// </summary>
        string Token { get; }

        /// <summary>
        /// Sends a DELETE request for the specified path.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A <see cref="CbClientResult{String}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        CbClientResult<string> HttpDelete(string relativePath);

        /// <summary>
        /// Sends a DELETE request for the specified path, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        Task<CbClientResult<string>> HttpDeleteAsync(string relativePath);

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a <see cref="IDictionary{String,Object}"/> representation of the content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>An <see cref="IDictionary{String,Object}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        CbClientResult<IDictionary<string, object>> HttpGetAsDictionary(string relativePath);

        /// <summary>
        /// Sends a GET request for the specified path to retrieve an <see cref="IDictionary{String,Object}"/> representation of the content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        Task<CbClientResult<IDictionary<string, object>>> HttpGetAsDictionaryAsync(string relativePath);

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a dynamic representation of the content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A <see cref="CbClientResult{dynamic}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        CbClientResult<dynamic> HttpGetAsDynamic(string relativePath);

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a dynamic representation of the content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        Task<CbClientResult<dynamic>> HttpGetAsDynamicAsync(string relativePath);

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a <see cref="Stream"/> representation of the content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A <see cref="CbClientResult{Stream}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        CbClientResult<Stream> HttpGetAsStream(string relativePath);

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a <see cref="Stream"/> representation of the content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        Task<CbClientResult<Stream>> HttpGetAsStreamAsync(string relativePath);

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a <see cref="String"/> representation of the content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A <see cref="CbClientResult{String}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        CbClientResult<string> HttpGetAsString(string relativePath);

        /// <summary>
        /// Sends a GET request for the specified path to retrieve a <see cref="String"/> representation of the content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        Task<CbClientResult<string>> HttpGetAsStringAsync(string relativePath);

        /// <summary>
        /// Sends a POST request for the specified path to post <see cref="IDictionary{String,Object}"/> content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A <see cref="CbClientResult{String}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        CbClientResult<string> HttpPostDictionary(string relativePath, IDictionary<string, object> data);

        /// <summary>
        /// Sends a POST request for the specified path to post <see cref="IDictionary{String,Object}"/> content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        Task<CbClientResult<string>> HttpPostDictionaryAsync(string relativePath, IDictionary<string, object> data);

        /// <summary>
        /// Sends a POST request for the specified path to post dynamic content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A <see cref="CbClientResult{String}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        CbClientResult<string> HttpPostDynamic(string relativePath, dynamic data);

        /// <summary>
        /// Sends a POST request for the specified path to post dynamic content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        Task<CbClientResult<string>> HttpPostDynamicAsync(string relativePath, dynamic data);

        /// <summary>
        /// Sends a PUT request for the specified path to put <see cref="IDictionary{String,Object}"/> content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A <see cref="CbClientResult{String}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        CbClientResult<string> HttpPutDictionary(string relativePath, IDictionary<string, object> data);

        /// <summary>
        /// Sends a PUT request for the specified path to put <see cref="IDictionary{String,Object}"/> content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        Task<CbClientResult<string>> HttpPutDictionaryAsync(string relativePath, IDictionary<string, object> data);

        /// <summary>
        /// Sends a PUT request for the specified path to put dynamic content.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A <see cref="CbClientResult{String}"/> that contains the response information.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        CbClientResult<string> HttpPutDynamic(string relativePath, dynamic data);

        /// <summary>
        /// Sends a PUT request for the specified path to put <see cref="IDictionary{String,Object}"/> content, as an asynchronous operation.
        /// </summary>
        /// <param name="relativePath">The path to the api.</param>
        /// <param name="data">The data to send.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">relativePath is not a valid relative URI.</exception>
        Task<CbClientResult<string>> HttpPutDynamicAsync(string relativePath, dynamic data);
    }
}
