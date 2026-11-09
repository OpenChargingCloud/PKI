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
    /// certificate, for how long - and as one of ISO 15118, below a CA of it.
    /// </summary>
    /// <param name="IssuerId">The CA that signs, by its fingerprint.</param>
    /// <param name="Profile">A server's or a client's certificate.</param>
    /// <param name="ValidDays">For how many days what it signs holds.</param>
    /// <param name="V2G">The domain of a certificate of ISO 15118 - a SECC certificate of CPO, say - or null for one of X.509.</param>
    public sealed record ESTProfile(String              IssuerId,
                                    CertificateProfile  Profile,
                                    Int32               ValidDays,
                                    V2GDomain?          V2G = null)
    {

        /// <summary>
        /// What it signs, in words: "a client's certificate", "SECC certificate".
        /// </summary>
        public String InWords

            => V2G is V2GDomain domain
                   ? ISO15118.InWords(Profile, domain)
                   : Profile.InWords();

        public JObject ToJSON()

            => new (
                   new JProperty("issuer",     IssuerId),
                   new JProperty("profile",    Profile.AsText()),
                   new JProperty("validDays",  ValidDays),
                   new JProperty("v2g",        V2G?.AsText())
               );

        /// <summary>
        /// One profile of EST from its JSON, or why it is none.
        /// </summary>
        /// <remarks>
        /// Below a CA of ISO 15118, where the CA is known, a profile that names
        /// neither "v2g" nor "profile" is what that CA signs: a SECC certificate
        /// below one of V2G, the certificate of its own domain below every other.
        /// </remarks>
        /// <param name="CA">The CA of this PKI with the given fingerprint, where there is one.</param>
        public static Boolean TryParse(JToken?                                  JSON,
                                       String                                   Where,
                                       [NotNullWhen(true)]  out ESTProfile?     Profile,
                                       [NotNullWhen(false)] out String?         Error,
                                       Func<String, IssuedCertificate?>?        CA = null)
        {

            Profile  = null;
            Error    = null;

            if (JSON is not JObject json)
            {
                Error = $"{Where} is {{ \"issuer\", \"profile\", \"validDays\", \"v2g\" }}.";
                return false;
            }

            var issuer = PKIStore.Normalized(json.Value<String>("issuer") ?? "");

            if (issuer.Length != 64)
            {
                Error = $"The \"issuer\" of {Where} is the SHA-256 fingerprint of a CA of this PKI.";
                return false;
            }

            V2GDomain? v2g = null;

            if (json["v2g"] is JToken v2gToken && v2gToken.Type != JTokenType.Null &&
                (v2gToken.Type != JTokenType.String || !ISO15118.TryParse(v2gToken.Value<String>(), out v2g)))
            {
                Error = $"The \"v2g\" of {Where} is the domain of a certificate of ISO 15118 - \"CPO\", \"MO\", \"OEM\" or \"CPS\" - or null.";
                return false;
            }

            if (v2g is null && CA?.Invoke(issuer)?.V2G is V2GDomain issuerDomain)
                v2g = ISO15118.LeafDomainBelow(issuerDomain);

            var profileText = json.Value<String>("profile") ?? (v2g is V2GDomain leaf ? ISO15118.LeafProfileOf(leaf).AsText() : "client");

            if (!CertificateProfileExtensions.TryParse(profileText, out var profile) ||
                profile is not (CertificateProfile.Server or CertificateProfile.Client))
            {
                Error = $"The \"profile\" of {Where} is \"server\" or \"client\": EST makes no CA.";
                return false;
            }

            if (v2g is V2GDomain domain && !ISO15118.IsAllowed(profile.Value, domain, out var why))
            {
                Error = $"{Where}: {why}";
                return false;
            }

            var token = json["validDays"];
            var days  = token is null || token.Type == JTokenType.Null ? ESTSettings.DefaultValidDays : token.Type == JTokenType.Integer ? token.Value<Int32>() : -1;

            if (days < 1 || days > PKIStore.MaxValidityDays)
            {
                Error = $"The \"validDays\" of {Where} is 1 to {PKIStore.MaxValidityDays}.";
                return false;
            }

            Profile = new ESTProfile(issuer, profile.Value, days, v2g);
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
    ///   "labels": { "csms": { "issuer": "...", "profile": "server", "validDays": 365 },
    ///               "secc": { "issuer": "&lt;fingerprint of a CPO sub-CA&gt;", "v2g": "CPO", "validDays": 365 } },
    ///   "tlsClientCertificates": true, "serverKeyGeneration": false
    /// }
    /// </code>
    /// A request at "/.well-known/est/simpleenroll" is signed as the section
    /// itself says, one at "/.well-known/est/csms/simpleenroll" as its label
    /// "csms" says. Without an issuer, and without labels, EST signs nothing.
    /// Below a CA of ISO 15118, EST signs certificates of ISO 15118 - "v2g"
    /// says which, and where it does not, the CA does.
    /// With "serverKeyGeneration", "serverkeygen" makes the key as well, for
    /// whoever cannot make one of its own.
    /// </remarks>
    /// <param name="Default">What a request without a label is signed as; null for nothing.</param>
    /// <param name="Labels">What a request with a label is signed as, by the label.</param>
    /// <param name="TLSClientCertificates">Whether the HTTPS server of the PKI asks for a TLS client certificate, which re-enrolls a certificate of this PKI with itself.</param>
    /// <param name="ServerKeyGeneration">Whether "serverkeygen" makes keys: the key of the certificate made here, and handed out with it - over HTTPS only.</param>
    public sealed record ESTSettings(ESTProfile?                              Default,
                                     IReadOnlyDictionary<String, ESTProfile>  Labels,
                                     Boolean                                  TLSClientCertificates,
                                     Boolean                                  ServerKeyGeneration = false)
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
            json.Add(new JProperty("serverKeyGeneration",    ServerKeyGeneration));

            return json;

        }

        /// <summary>
        /// The settings from the "est" of the "pki" section - none, where it says
        /// nothing - or why they are none.
        /// </summary>
        /// <param name="CA">The CA of this PKI with the given fingerprint, where there is one: what EST signs below a CA of ISO 15118, where the JSON does not say it.</param>
        public static Boolean TryParse(JToken?                                 JSON,
                                       [NotNullWhen(true)]  out ESTSettings?   Settings,
                                       [NotNullWhen(false)] out String?        Error,
                                       Func<String, IssuedCertificate?>?       CA = null)
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
                Error = "\"est\" is { \"issuer\", \"profile\", \"validDays\", \"v2g\", \"labels\", \"tlsClientCertificates\", \"serverKeyGeneration\" }.";
                return false;
            }

            ESTProfile? @default = null;

            if (!String.IsNullOrWhiteSpace(json.Value<String>("issuer")) &&
                !ESTProfile.TryParse(json, "\"est\"", out @default, out Error, CA))
            {
                return false;
            }

            var labels = new Dictionary<String, ESTProfile>(StringComparer.Ordinal);

            if (json["labels"] is JToken labelsToken && labelsToken.Type != JTokenType.Null)
            {

                if (labelsToken is not JObject labelsJSON)
                {
                    Error = "The \"labels\" of \"est\" are { \"<label>\": { \"issuer\", \"profile\", \"validDays\", \"v2g\" } }.";
                    return false;
                }

                foreach (var label in labelsJSON.Properties())
                {

                    if (!LabelPattern.IsMatch(label.Name) || Operations.Contains(label.Name, StringComparer.OrdinalIgnoreCase))
                    {
                        Error = $"'{label.Name}' is no label of EST: letters, digits, '-' and '_', and none of {String.Join(", ", Operations)}.";
                        return false;
                    }

                    if (!ESTProfile.TryParse(label.Value, $"the label '{label.Name}'", out var profile, out Error, CA))
                        return false;

                    labels[label.Name] = profile;

                }

            }

            var tls     = json["tlsClientCertificates"];
            var keygen  = json["serverKeyGeneration"];

            foreach (var (name, token) in new[] { ("tlsClientCertificates", tls), ("serverKeyGeneration", keygen) })
            {
                if (token is not null && token.Type is not JTokenType.Boolean and not JTokenType.Null)
                {
                    Error = $"\"{name}\" of \"est\" is true or false.";
                    return false;
                }
            }

            Settings = new ESTSettings(@default,
                                       labels,
                                       tls?.   Type == JTokenType.Boolean && tls.   Value<Boolean>(),
                                       keygen?.Type == JTokenType.Boolean && keygen.Value<Boolean>());
            return true;

        }

    }

}
