/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of PKI <https://github.com/OpenChargingCloud/PKI>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.PKI.Issuance
{

    /// <summary>
    /// Who a certificate is about, as somebody fills it in: a common name,
    /// and the organization, unit, country, state and town around it where
    /// they are given.
    /// </summary>
    /// <remarks>
    /// The six attributes every certificate of the e-mobility world is made
    /// with, and no more: an OCPP charging station is its serial number as
    /// the common name and its operator as the organization, a CA of ISO
    /// 15118 a name, an organization and a country. Written into the
    /// distinguished name in the order X.500 reads it - from the country
    /// down to the common name - which is the order openssl and every CA
    /// write it in too.
    /// </remarks>
    public sealed record SubjectName(String   CommonName,
                                     String?  Organization        = null,
                                     String?  OrganizationalUnit  = null,
                                     String?  Country             = null,
                                     String?  State               = null,
                                     String?  Locality            = null)
    {

        #region TryParse(JSON, out SubjectName, out Error)

        /// <summary>
        /// The subject of a request: {"commonName", "organization",
        /// "organizationalUnit", "country", "state", "locality"}, of which the
        /// common name has to be there and everything else may be left out,
        /// null or empty.
        /// </summary>
        public static Boolean TryParse(JToken?                                JSON,
                                       [NotNullWhen(true)]  out SubjectName?  SubjectName,
                                       [NotNullWhen(false)] out String?       Error)
        {

            SubjectName  = null;
            Error        = null;

            if (JSON is not JObject subject)
            {
                Error = "'subject' must be an object with at least a 'commonName'.";
                return false;
            }

            String? Text(String Key)
            {
                var value = subject[Key];
                return value is null || value.Type == JTokenType.Null
                           ? null
                           : value.Type == JTokenType.String
                                 ? value.Value<String>()?.Trim() is { Length: > 0 } text ? text : null
                                 : throw new FormatException($"'subject.{Key}' must be text.");
            }

            try
            {

                var commonName = Text("commonName");

                if (commonName is null)
                {
                    Error = "A certificate needs a common name.";
                    return false;
                }

                var country = Text("country")?.ToUpperInvariant();

                // Two letters of ISO 3166, and nothing else: an X.509 country is
                // a PrintableString of exactly two, and a certificate with "GER"
                // in it is refused by the first parser that reads it.
                if (country is not null && !Regex.IsMatch(country, "^[A-Z]{2}$"))
                {
                    Error = $"'{country}' is not a country: it is two letters, as ISO 3166 writes it - 'DE', 'NL'.";
                    return false;
                }

                foreach (var (key, value) in new[] { ("commonName", commonName), ("organization", Text("organization")), ("organizationalUnit", Text("organizationalUnit")),
                                                     ("state", Text("state")), ("locality", Text("locality")) })
                {
                    if (value is not null && value.Length > 64)
                    {
                        Error = $"'{key}' is {value.Length} characters long; X.509 allows 64.";
                        return false;
                    }
                }

                SubjectName = new SubjectName(
                                  CommonName:          commonName,
                                  Organization:        Text("organization"),
                                  OrganizationalUnit:  Text("organizationalUnit"),
                                  Country:             country,
                                  State:               Text("state"),
                                  Locality:            Text("locality")
                              );

                return true;

            }
            catch (FormatException e)
            {
                Error = e.Message;
                return false;
            }

        }

        #endregion

        #region ToX500()

        /// <summary>
        /// The distinguished name, encoded from the country down to the common
        /// name.
        /// </summary>
        /// <remarks>
        /// Added the other way round: the builder encodes what it is given
        /// last first, in the order .NET prints a name - "CN=..., O=..., C=..."
        /// - so the common name goes in first to come out last.
        /// </remarks>
        public X500DistinguishedName ToX500()
        {

            var builder = new X500DistinguishedNameBuilder();

            builder.AddCommonName(CommonName);

            if (OrganizationalUnit is not null) builder.AddOrganizationalUnitName(OrganizationalUnit);
            if (Organization       is not null) builder.AddOrganizationName      (Organization);
            if (Locality           is not null) builder.AddLocalityName          (Locality);
            if (State              is not null) builder.AddStateOrProvinceName   (State);
            if (Country            is not null) builder.AddCountryOrRegion       (Country);

            return builder.Build();

        }

        #endregion

    }


    /// <summary>
    /// The other names a certificate is valid for - host names, addresses,
    /// mail addresses and URIs - each told apart by what it looks like.
    /// </summary>
    public static class AlternativeNames
    {

        private static readonly Regex HostName = new (@"^(\*\.)?([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*\.?$");

        #region TryParse(JSON, out Names, out Error)

        /// <summary>
        /// A list of names, as text: an address where it reads as one, a URI
        /// where it has a scheme, a mail address where it has an '@' and a
        /// host name - "*.example.org" among them - otherwise. Empty entries
        /// are passed over, and the same name twice is one name.
        /// </summary>
        public static Boolean TryParse(JToken?                                   JSON,
                                       [NotNullWhen(true)]  out List<String>?    Names,
                                       [NotNullWhen(false)] out String?          Error)
        {

            Names  = [];
            Error  = null;

            if (JSON is null || JSON.Type == JTokenType.Null)
                return true;

            if (JSON is not JArray array)
            {
                Names = null;
                Error = "'subjectAlternativeNames' must be a list of names.";
                return false;
            }

            foreach (var entry in array)
            {

                if (entry.Type != JTokenType.String)
                {
                    Names = null;
                    Error = "Every alternative name is text.";
                    return false;
                }

                var name = entry.Value<String>()!.Trim();

                if (name.Length == 0 || Names.Contains(name, StringComparer.OrdinalIgnoreCase))
                    continue;

                if (!IsValid(name, out var why))
                {
                    Names = null;
                    Error = why;
                    return false;
                }

                Names.Add(name);

            }

            return true;

        }

        #endregion

        #region IsValid(Name, out Why)

        /// <summary>
        /// Whether a name is one a certificate can carry, and why not.
        /// </summary>
        public static Boolean IsValid(String                            Name,
                                      [NotNullWhen(false)] out String?  Why)
        {

            Why = null;

            if (IPAddress.TryParse(Name, out _))
                return true;

            if (Name.Contains("://"))
            {
                if (Uri.TryCreate(Name, UriKind.Absolute, out _))
                    return true;
                Why = $"'{Name}' looks like a URI and is none.";
                return false;
            }

            if (Name.Contains('@'))
            {
                if (Name.IndexOf('@') > 0 && Name.IndexOf('@') == Name.LastIndexOf('@') && Name.IndexOf('@') < Name.Length - 1)
                    return true;
                Why = $"'{Name}' looks like a mail address and is none.";
                return false;
            }

            if (Name.Length <= 253 && HostName.IsMatch(Name))
                return true;

            Why = $"'{Name}' is neither a host name, an IP address, a mail address nor a URI.";
            return false;

        }

        #endregion

        #region Looks like a host name(Name)

        /// <summary>
        /// Whether a common name could be a server's host name as well - what a
        /// server certificate without alternative names is given as its one.
        /// </summary>
        public static Boolean LooksLikeAHostName(String Name)

            => IPAddress.TryParse(Name, out _) ||
               (Name.Contains('.') && !Name.Contains(' ') && HostName.IsMatch(Name));

        #endregion

        #region ToExtension(Names)

        /// <summary>
        /// The extension that says them, or null for none.
        /// </summary>
        public static X509Extension? ToExtension(IEnumerable<String> Names)
        {

            var builder = new SubjectAlternativeNameBuilder();
            var any     = false;

            foreach (var name in Names)
            {

                any = true;

                if      (IPAddress.TryParse(name, out var address))
                    builder.AddIpAddress(address);

                else if (name.Contains("://"))
                    builder.AddUri(new Uri(name));

                else if (name.Contains('@'))
                    builder.AddEmailAddress(name);

                else
                    builder.AddDnsName(name.TrimEnd('.'));

            }

            return any ? builder.Build(critical: false) : null;

        }

        #endregion

        #region Of(Certificate) / Of(Extensions)

        /// <summary>
        /// The alternative names a certificate - or a request - carries, as text.
        /// </summary>
        public static List<String> Of(IEnumerable<X509Extension> Extensions)
        {

            var names = new List<String>();

            foreach (var extension in Extensions)
            {

                if (extension.Oid?.Value != "2.5.29.17")
                    continue;

                var san = extension as X509SubjectAlternativeNameExtension
                              ?? new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);

                names.AddRange(san.EnumerateDnsNames());
                names.AddRange(san.EnumerateIPAddresses().Select(address => address.ToString()));

                // Mail addresses and URIs are not enumerated by .NET, and are
                // read from the extension's own words, as Format() writes them:
                // "RFC822 Name=" and "URL=" on Windows, "email:" and "URI:" where
                // OpenSSL formats it - one per line on the one, separated by
                // commas on the other.
                foreach (var part in san.Format(true).Split([ '\n', ',' ], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    foreach (var prefix in new[] { "RFC822 Name=", "email:", "URL=", "URI:" })
                    {
                        if (part.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                            names.Add(part[prefix.Length..]);
                    }
                }

            }

            return names;

        }

        public static List<String> Of(X509Certificate2 Certificate)

            => Of(Certificate.Extensions.Cast<X509Extension>());

        #endregion

    }

}
