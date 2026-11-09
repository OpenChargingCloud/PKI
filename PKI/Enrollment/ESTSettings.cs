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
using System.Text.RegularExpressions;

using Newtonsoft.Json.Linq;

using cloud.charging.open.PKI.Issuance;

#endregion

namespace cloud.charging.open.PKI.Enrollment
{

    /// <summary>
    /// What EST signs a CSR as: below which CA, as a server's or a client's
    /// certificate, and for how long.
    /// </summary>
    /// <param name="IssuerId">The CA that signs, by its fingerprint.</param>
    /// <param name="Profile">A server's or a client's certificate.</param>
    /// <param name="ValidDays">For how many days what it signs holds.</param>
    public sealed record ESTProfile(String              IssuerId,
                                    CertificateProfile  Profile,
                                    Int32               ValidDays)
    {

        public JObject ToJSON()

            => new (
                   new JProperty("issuer",     IssuerId),
                   new JProperty("profile",    Profile.AsText()),
                   new JProperty("validDays",  ValidDays)
               );

        /// <summary>
        /// One profile of EST from its JSON, or why it is none.
        /// </summary>
        public static Boolean TryParse(JToken?                                JSON,
                                       String                                 Where,
                                       [NotNullWhen(true)]  out ESTProfile?   Profile,
                                       [NotNullWhen(false)] out String?       Error)
        {

            Profile  = null;
            Error    = null;

            if (JSON is not JObject json)
            {
                Error = $"{Where} is {{ \"issuer\", \"profile\", \"validDays\" }}.";
                return false;
            }

            var issuer = PKIStore.Normalized(json.Value<String>("issuer") ?? "");

            if (issuer.Length != 64)
            {
                Error = $"The \"issuer\" of {Where} is the SHA-256 fingerprint of a CA of this PKI.";
                return false;
            }

            if (!CertificateProfileExtensions.TryParse(json.Value<String>("profile") ?? "client", out var profile) ||
                profile is not (CertificateProfile.Server or CertificateProfile.Client))
            {
                Error = $"The \"profile\" of {Where} is \"server\" or \"client\": EST makes no CA.";
                return false;
            }

            var token = json["validDays"];
            var days  = token is null || token.Type == JTokenType.Null ? ESTSettings.DefaultValidDays : token.Type == JTokenType.Integer ? token.Value<Int32>() : -1;

            if (days < 1 || days > PKIStore.MaxValidityDays)
            {
                Error = $"The \"validDays\" of {Where} is 1 to {PKIStore.MaxValidityDays}.";
                return false;
            }

            Profile = new ESTProfile(issuer, profile.Value, days);
            return true;

        }

    }


    /// <summary>
    /// What the EST server of the PKI - RFC 7030, at "/.well-known/est" -
    /// signs, and how those who ask may show who they are: the "est" of the
    /// "pki" section of the configuration file.
    /// </summary>
    /// <remarks>
    /// <code>
    /// "est": {
    ///   "issuer": "&lt;fingerprint of a CA&gt;", "profile": "client", "validDays": 365,
    ///   "labels": { "csms": { "issuer": "...", "profile": "server", "validDays": 365 } },
    ///   "tlsClientCertificates": true
    /// }
    /// </code>
    /// A request at "/.well-known/est/simpleenroll" is signed as the section
    /// itself says, one at "/.well-known/est/csms/simpleenroll" as its label
    /// "csms" says. Without an issuer, and without labels, EST signs nothing.
    /// </remarks>
    /// <param name="Default">What a request without a label is signed as; null for nothing.</param>
    /// <param name="Labels">What a request with a label is signed as, by the label.</param>
    /// <param name="TLSClientCertificates">Whether the HTTPS server of the PKI asks for a TLS client certificate, which re-enrolls a certificate of this PKI with itself.</param>
    public sealed record ESTSettings(ESTProfile?                              Default,
                                     IReadOnlyDictionary<String, ESTProfile>  Labels,
                                     Boolean                                  TLSClientCertificates)
    {

        /// <summary>
        /// For how many days what EST signs holds, where its profile says nothing.
        /// </summary>
        public const Int32 DefaultValidDays = 365;

        /// <summary>
        /// The operations of RFC 7030, section 3.2.2, which no label may be
        /// called.
        /// </summary>
        public static readonly IReadOnlyList<String> Operations = [ "cacerts", "simpleenroll", "simplereenroll", "csrattrs", "serverkeygen", "fullcmc" ];

        private static readonly Regex LabelPattern = new ("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", RegexOptions.Compiled);

        /// <summary>
        /// EST signing nothing.
        /// </summary>
        public static readonly ESTSettings None = new (null, new Dictionary<String, ESTProfile>(), false);

        /// <summary>
        /// Whether EST signs anything at all.
        /// </summary>
        public Boolean Enabled
            => Default is not null || Labels.Count > 0;

        /// <summary>
        /// What a request with the given label - or none, null - is signed as,
        /// or null where it is nothing.
        /// </summary>
        public ESTProfile? For(String? Label)

            => Label is null
                   ? Default
                   : Labels.TryGetValue(Label, out var profile) ? profile : null;

        public JObject ToJSON()
        {

            var json = Default?.ToJSON() ?? [];

            json.Add(new JProperty("labels",                 new JObject(Labels.OrderBy(label => label.Key, StringComparer.Ordinal).
                                                                                  Select (label => new JProperty(label.Key, label.Value.ToJSON())))));
            json.Add(new JProperty("tlsClientCertificates",  TLSClientCertificates));

            return json;

        }

        /// <summary>
        /// The settings from the "est" of the "pki" section - none, where it says
        /// nothing - or why they are none.
        /// </summary>
        public static Boolean TryParse(JToken?                                 JSON,
                                       [NotNullWhen(true)]  out ESTSettings?   Settings,
                                       [NotNullWhen(false)] out String?        Error)
        {

            Settings  = null;
            Error     = null;

            if (JSON is null || JSON.Type == JTokenType.Null)
            {
                Settings = None;
                return true;
            }

            if (JSON is not JObject json)
            {
                Error = "\"est\" is { \"issuer\", \"profile\", \"validDays\", \"labels\", \"tlsClientCertificates\" }.";
                return false;
            }

            ESTProfile? @default = null;

            if (!String.IsNullOrWhiteSpace(json.Value<String>("issuer")) &&
                !ESTProfile.TryParse(json, "\"est\"", out @default, out Error))
            {
                return false;
            }

            var labels = new Dictionary<String, ESTProfile>(StringComparer.Ordinal);

            if (json["labels"] is JToken labelsToken && labelsToken.Type != JTokenType.Null)
            {

                if (labelsToken is not JObject labelsJSON)
                {
                    Error = "The \"labels\" of \"est\" are { \"<label>\": { \"issuer\", \"profile\", \"validDays\" } }.";
                    return false;
                }

                foreach (var label in labelsJSON.Properties())
                {

                    if (!LabelPattern.IsMatch(label.Name) || Operations.Contains(label.Name, StringComparer.OrdinalIgnoreCase))
                    {
                        Error = $"'{label.Name}' is no label of EST: letters, digits, '-' and '_', and none of {String.Join(", ", Operations)}.";
                        return false;
                    }

                    if (!ESTProfile.TryParse(label.Value, $"the label '{label.Name}'", out var profile, out Error))
                        return false;

                    labels[label.Name] = profile;

                }

            }

            var tls = json["tlsClientCertificates"];

            if (tls is not null && tls.Type is not JTokenType.Boolean and not JTokenType.Null)
            {
                Error = "\"tlsClientCertificates\" of \"est\" is true or false.";
                return false;
            }

            Settings = new ESTSettings(@default, labels, tls?.Type == JTokenType.Boolean && tls.Value<Boolean>());
            return true;

        }

    }

}
