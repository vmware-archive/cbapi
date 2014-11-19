using Microsoft.VisualStudio.TestTools.UnitTesting;
using SoftwareApproach.TestingExtensions;
using System;

namespace Bit9CarbonBlack.CarbonBlack.Client
{
    [TestClass]
    public class SolrExtensionsTest
    {
        [TestMethod]
        public void ConvertToSolrDateTime_should_convert_datetime_to_a_solr_datetime()
        {
            DateTime date = DateTime.Now;
            var expected = date.ToString("yyyy-MM-ddTHH:mm:ss");

            var actual = date.ConvertToSolrDateTime();

            actual.ShouldEqual(expected);
        }

        [TestMethod]
        public void ConvertToSolrDateTime_should_convert_datetime_to_a_solr_datetime_as_UTC()
        {
            DateTime date = DateTime.Now;
            var expected = date.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss");

            var actual = date.ConvertToSolrDateTime(true);

            actual.ShouldEqual(expected);
        }

        [TestMethod]
        public void TryConvertFromSolrDateTime_should_convert_solr_datetime_to_a_datetime()
        {
            string date = "2011-11-11T11:11:11Z";
            var expected = new DateTime(2011, 11, 11, 11, 11, 11, DateTimeKind.Utc);

            var actual = date.TryConvertFromSolrDateTime();

            actual.ShouldEqual(expected);
        }

        [TestMethod]
        public void TryConvertFromSolrDateTime_should_convert_solr_datetime_to_a_datetime_without_Z()
        {
            string date = "2011-11-11T11:11:11";
            var expected = new DateTime(2011, 11, 11, 11, 11, 11, DateTimeKind.Utc);

            var actual = date.TryConvertFromSolrDateTime();

            actual.ShouldEqual(expected);
        }

        [TestMethod]
        public void TryConvertFromSolrDateTime_should_convert_solr_datetime_to_a_datetime_with_milliseconds()
        {
            string date = "2011-11-11T11:11:11.111Z";
            var expected = new DateTime(2011, 11, 11, 11, 11, 11, 111, DateTimeKind.Utc);

            var actual = date.TryConvertFromSolrDateTime();

            actual.ShouldEqual(expected);
        }

        [TestMethod]
        public void TryConvertFromSolrDateTime_should_return_null_if_string_can_not_be_parsed()
        {
            string date = "datetime";

            var actual = date.TryConvertFromSolrDateTime();

            actual.ShouldBeNull();
        }
    }
}
