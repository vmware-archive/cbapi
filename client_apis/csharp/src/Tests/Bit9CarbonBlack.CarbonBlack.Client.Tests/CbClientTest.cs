using Microsoft.VisualStudio.TestTools.UnitTesting;
using Rhino.Mocks;
using SoftwareApproach.TestingExtensions;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Reflection;
using System.Threading.Tasks;

namespace Bit9CarbonBlack.CarbonBlack.Client
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void Constructors_should_throw_exception_if_serverUri_is_invalid_string()
        {
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: null, token: "token", sslVerify: false));
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: String.Empty, token: "token", sslVerify: false));
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "  ", token: "token", sslVerify: false));

            var messageHandler = MockRepository.GenerateMock<HttpMessageHandler>();
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: null, token: "token", httpClientMessageHandler: messageHandler));
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: String.Empty, token: "token", httpClientMessageHandler: messageHandler));
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "  ", token: "token", httpClientMessageHandler: messageHandler));

            var httpClient = MockRepository.GenerateMock<HttpClient>();
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: null, token: "token", httpClient: httpClient));
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: String.Empty, token: "token", httpClient: httpClient));
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "  ", token: "token", httpClient: httpClient));
        }

        [TestMethod]
        public void Constructors_should_throw_exception_if_token_is_invalid_string()
        {
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "http://serverUri", token: null, sslVerify: false));
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "http://serverUri", token: String.Empty, sslVerify: false));
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "http://serverUri", token: "  ", sslVerify: false));

            var messageHandler = MockRepository.GenerateMock<HttpMessageHandler>();
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "http://serverUri", token: null, httpClientMessageHandler: messageHandler));
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "http://serverUri", token: String.Empty, httpClientMessageHandler: messageHandler));
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "http://serverUri", token: "  ", httpClientMessageHandler: messageHandler));

            var httpClient = MockRepository.GenerateMock<HttpClient>();
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "http://serverUri", token: null, httpClient: httpClient));
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "http://serverUri", token: String.Empty, httpClient: httpClient));
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "http://serverUri", token: "  ", httpClient: httpClient));
        }

        [TestMethod]
        public void Constructors_should_throw_exception_if_serverUri_is_not_an_absolute_uri()
        {
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "serverUri", token: null, sslVerify: false));

            var messageHandler = MockRepository.GenerateMock<HttpMessageHandler>();
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "serverUri", token: null, httpClientMessageHandler: messageHandler));

            var httpClient = MockRepository.GenerateMock<HttpClient>();
            Testing.ShouldThrowException<ArgumentException>(() => new CbClient(serverUri: "serverUri", token: null, httpClient: httpClient));
        }

        [TestMethod]
        public void Constructor1_should_initialize_http_client_properties()
        {
            string serverUri = "http://serveruri";
            string token = "token";

            var client = new CbClient(serverUri: serverUri, token: token, sslVerify: true);

            client.Token.ShouldEqual(token);
            client.ServerUri.ShouldEqual(new Uri(serverUri, UriKind.Absolute));
            client.HttpClient.ShouldNotBeNull();
            client.HttpClient.BaseAddress.ShouldEqual(new Uri(serverUri, UriKind.Absolute));
            client.HttpClient.DefaultRequestHeaders.Where(x => x.Key == "X-Auth-Token" && x.Value.Contains(token)).ShouldHaveCountOf(1);
            client.HttpClient.DefaultRequestHeaders.Accept.ShouldHaveCountOf(1);
            client.HttpClient.DefaultRequestHeaders.Accept.First().MediaType.ShouldEqualIgnoringCase("application/json");
        }

        [TestMethod]
        public void Constructor2_should_initialize_http_client_properties()
        {
            string serverUri = "http://serveruri";
            string token = "token";
            var messageHandler = MockRepository.GenerateMock<HttpMessageHandler>();

            var client = new CbClient(serverUri: serverUri, token: token, httpClientMessageHandler: messageHandler);

            client.Token.ShouldEqual(token);
            client.ServerUri.ShouldEqual(new Uri(serverUri, UriKind.Absolute));
            client.HttpClient.ShouldNotBeNull();
            client.HttpClient.BaseAddress.ShouldEqual(new Uri(serverUri, UriKind.Absolute));
            client.HttpClient.DefaultRequestHeaders.Where(x => x.Key == "X-Auth-Token" && x.Value.Contains(token)).ShouldHaveCountOf(1);
            client.HttpClient.DefaultRequestHeaders.Accept.ShouldHaveCountOf(1);
            client.HttpClient.DefaultRequestHeaders.Accept.First().MediaType.ShouldEqualIgnoringCase("application/json");
        }

        [TestMethod]
        public void Constructor3_should_initialize_http_client_properties()
        {
            string serverUri = "http://serveruri";
            string token = "token";
            var httpClient = MockRepository.GenerateMock<HttpClient>();

            var client = new CbClient(serverUri: serverUri, token: token, httpClient: httpClient);

            client.Token.ShouldEqual(token);
            client.ServerUri.ShouldEqual(new Uri(serverUri, UriKind.Absolute));
            client.HttpClient.ShouldNotBeNull();
            client.HttpClient.BaseAddress.ShouldEqual(new Uri(serverUri, UriKind.Absolute));
            client.HttpClient.DefaultRequestHeaders.Where(x => x.Key == "X-Auth-Token" && x.Value.Contains(token)).ShouldHaveCountOf(1);
            client.HttpClient.DefaultRequestHeaders.Accept.ShouldHaveCountOf(1);
            client.HttpClient.DefaultRequestHeaders.Accept.First().MediaType.ShouldEqualIgnoringCase("application/json");
        }

        [TestMethod]
        public void Constructor3_should_use_http_client_from_argument()
        {
            string serverUri = "http://serveruri";
            string token = "token";
            var httpClient = MockRepository.GenerateMock<HttpClient>();

            var client = new CbClient(serverUri: serverUri, token: token, httpClient: httpClient);

            client.HttpClient.ShouldNotBeNull();
            client.HttpClient.ShouldBeSameAs(httpClient);
        }

        [TestMethod]
        public void Constructor3_should_throw_exception_if_httpClient_is_null()
        {
            string serverUri = "http://serveruri";
            string token = "token";
            HttpClient httpClient = null;

            Testing.ShouldThrowException<ArgumentNullException>(() => new CbClient(serverUri: serverUri, token: token, httpClient: httpClient));  
        }

        [TestMethod]
        public void Constructor2_should_use_httpClientMessageHandler_if_passed()
        {
            string serverUri = "http://serveruri";
            string token = "token";
            var httpMessageHandler = MockRepository.GenerateMock<HttpMessageHandler>();

            var client = new CbClient(serverUri: serverUri, token: token, httpClientMessageHandler: httpMessageHandler);

            client.HttpClient.ShouldNotBeNull();
            this.GetHandlerFromHttpClient(client.HttpClient).ShouldBeSameAs(httpMessageHandler);
        }

        [TestMethod]
        public void Constructor1_should_use_default_handler_if_sslVerify_is_true()
        {
            string serverUri = "http://serveruri";
            string token = "token";

            var client = new CbClient(serverUri: serverUri, token: token, sslVerify: true);

            client.HttpClient.ShouldNotBeNull();
            this.GetHandlerFromHttpClient(client.HttpClient).ShouldBeOfType(typeof(HttpClientHandler));
        }

        [TestMethod]
        public void Constructor1_should_use_no_ssl_handler_if_sslVerify_is_false_and_should_return_true_for_server_certificate_validation()
        {
            string serverUri = "http://serveruri";
            string token = "token";

            var client = new CbClient(serverUri: serverUri, token: token, sslVerify: false);

            client.HttpClient.ShouldNotBeNull();
            var handler = this.GetHandlerFromHttpClient(client.HttpClient) as WebRequestHandler;
            handler.ShouldNotBeNull();
            handler.ServerCertificateValidationCallback.ShouldNotBeNull();
            handler.ServerCertificateValidationCallback(null, null, null, SslPolicyErrors.RemoteCertificateNameMismatch).ShouldBeTrue();
        }

        private HttpMessageHandler GetHandlerFromHttpClient(HttpClient httpClient)
        {
            return httpClient.GetType().BaseType.GetField("handler", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(httpClient) as HttpMessageHandler;
        }
    }
}
