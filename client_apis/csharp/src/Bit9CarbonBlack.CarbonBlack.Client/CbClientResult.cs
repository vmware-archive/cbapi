using System.Net;

namespace Bit9CarbonBlack.CarbonBlack.Client
{
    /// <summary>
    /// Represents a <see cref="CbClient"/> operation response.
    /// </summary>
    /// <typeparam name="T">The type for the <see cref="CbClientResult{T}.Response"/> value.</typeparam>
    public class CbClientResult<T> where T: class
    {
        private readonly HttpStatusCode statusCode;
        private readonly T response;

        /// <summary>
        /// Creates a new instance of <see cref="CbClientResult{T}"/>.
        /// </summary>
        /// <param name="statusCode">The <see cref="HttpStatusCode"/> associated with the response.</param>
        /// <param name="response">The contents of the response.</param>
        public CbClientResult(HttpStatusCode statusCode, T response)
        {
            this.statusCode = statusCode;
            this.response = response;
        }

        /// <summary>
        /// The <see cref="HttpStatusCode"/> associated with the response.
        /// </summary>
        public HttpStatusCode StatusCode { get { return this.statusCode; } }

        /// <summary>
        /// The contents of the response.
        /// </summary>
        public T Response { get { return this.response; } }
    }
}
