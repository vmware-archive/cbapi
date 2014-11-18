using System.Net.Http;

namespace Bit9CarbonBlack.CarbonBlack.Client
{
    /// <summary>
    /// Contains builder methods for generating a type of <see cref="HttpMessageHandler"/> for using with the <see cref="HttpClient"/> class.
    /// </summary>
    public static class HttpClientMessageHandler
    {
        /// <summary>
        /// Generates a default handler.
        /// </summary>
        /// <returns>An <see cref="HttpClientHandler"/>.</returns>
        public static HttpMessageHandler DefaultHandler()
        {
            return new HttpClientHandler();
        }

        /// <summary>
        /// Generates a handler that ignores SSL validation.
        /// This handler will always validate an SSL server certificate.
        /// </summary>
        /// <returns>A <see cref="WebRequestHandler"/> that ignores certificate validation.</returns>
        public static HttpMessageHandler SslIgnoreHandler()
        {
            return new WebRequestHandler()
            {
                ServerCertificateValidationCallback = (sender, cert, chain, errors) => { return true; }
            };
        }
    }
}
