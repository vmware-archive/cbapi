using System;
using System.Globalization;

namespace Bit9CarbonBlack.CarbonBlack.Client
{
    /// <summary>
    /// Extension methods for SOLR interactions.
    /// </summary>
    public static class SolrExtensions
    {
        /// <summary>
        /// Converts a <see cref="DateTime"/> to a SOLR compatible datetime string, optionally converting to UTC.
        /// </summary>
        /// <param name="source">The <see cref="DateTime"/> to convert from.</param>
        /// <param name="performUTCConversion">true to perform UTC conversion; otherwise, false (the default).</param>
        /// <returns>A string representation of the SOLR datetime.</returns>
        public static string ConvertToSolrDateTime(this DateTime source, bool performUTCConversion = false)
        {
            return (performUTCConversion ? source.ToUniversalTime() : source).ToString("yyyy-MM-ddTHH:mm:ss");
        }

        /// <summary>
        /// Attempts to convert a SOLR compatible datetime string to a <see cref="Nullable{DateTime}"/> as UTC.
        /// </summary>
        /// <param name="source">The datetime string to convert from.</param>
        /// <returns>A <see cref="Nullable{DateTime}"/> that represents the SOLR datetime, or null if the conversion failed.</returns>
        public static DateTime? TryConvertFromSolrDateTime(this string source)
        {
            DateTime result;
            if (DateTime.TryParseExact(source, new String[] { "yyyy-MM-ddTHH:mm:ss", "yyyy-MM-ddTHH:mm:ssZ", "yyyy-MM-ddTHH:mm:ss.fffZ" }, 
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out result))
            {
                return result;
            }
            else
            {
                return null;
            }
        }
    }
}
