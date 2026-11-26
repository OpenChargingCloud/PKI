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
using System.Net.Sockets;
using System.Text.RegularExpressions;

using Newtonsoft.Json.Linq;

using cloud.charging.open.PKI.Issuance;

#endregion

namespace cloud.charging.open.PKI.Enrollment
{

    /// <summary>
    /// What ACME signs an order as: below which CA, as a server's or a
    /// client's certificate, for how long - and what a client is told of it.
    /// </summary>
    /// <param name="IssuerId">The CA that signs, by its fingerprint.</param>
    /// <param name="Profile">A server's or a client's certificate.</param>
    /// <param name="ValidDays">For how many days what it signs holds.</param>
    /// <param name="Description">What the directory says of it, where it is a named profile.</param>
    public sealed record ACMEProfile(String              IssuerId,
                                     CertificateProfile  Profile,
                                     Int32               ValidDays,
                                     String?             Description = null)
    {

        public JObject ToJSON()

            => new (
                   new JProperty("issuer",       IssuerId),
                   new JProperty("profile",      Profile.AsText()),
                   new JProperty("validDays",    ValidDays),
                   new JProperty("description",  Description)
               );

        /// <summary>
        /// One profile of ACME from its JSON, or why it is none.
        /// </summary>
        public static Boolean TryParse(JToken?                                JSON,
                                       String                                 Where,
                                       [NotNullWhen(true)]  out ACMEProfile?  Profile,
                                       [NotNullWhen(false)] out String?       Error)
        {

            Profile  = null;
            Error    = null;

            if (JSON is not JObject json)
            {
                Error = $"{Where} is {{ \"issuer\", \"profile\", \"validDays\", \"description\" }}.";
                return false;
            }

            var issuer = PKIStore.Normalized(json.Value<String>("issuer") ?? "");

            if (issuer.Length != 64)
            {
                Error = $"The \"issuer\" of {Where} is the SHA-256 fingerprint of a CA of this PKI.";
                return false;
            }

            if (!CertificateProfileExtensions.TryParse(json.Value<String>("profile") ?? "server", out var profile) ||
                profile is not (CertificateProfile.Server or CertificateProfile.Client))
            {
                Error = $"The \"profile\" of {Where} is \"server\" or \"client\": ACME makes no CA.";
                return false;
            }

            var token = json["validDays"];
            var days  = token is null || token.Type == JTokenType.Null ? ACMESettings.DefaultValidDays : token.Type == JTokenType.Integer ? token.Value<Int32>() : -1;

            if (days < 1 || days > PKIStore.MaxValidityDays)
            {
                Error = $"The \"validDays\" of {Where} is 1 to {PKIStore.MaxValidityDays}.";
                return false;
            }

            var description = json["description"];

            if (description is not null && description.Type is not JTokenType.String and not JTokenType.Null)
            {
                Error = $"The \"description\" of {Where} is text.";
                return false;
            }

            Profile = new ACMEProfile(issuer, profile.Value, days, description?.Type == JTokenType.String ? description.Value<String>() : null);
            return true;

        }

    }


    /// <summary>
    /// What the ACME server of the PKI - RFC 8555, at "/acme/directory" -
    /// signs, for whom and for which names: the "acme" of the "pki" section of
    /// the configuration file.
    /// </summary>
    /// <remarks>
    /// <code>
    /// "acme": {
    ///   "issuer": "&lt;fingerprint of a CA&gt;", "profile": "server", "validDays": 90,
    ///   "profiles": { "shortlived": { "issuer": "...", "validDays": 7, "description": "A week." } },
    ///   "externalAccountRequired": true,
    ///   "allowedNames": [ "lab.example.org", "10.0.0.0/8" ],
    ///   "challenges": [ "http-01", "dns-01" ],
    ///   "http01Port": 80,
    ///   "termsOfService": "https://pki.example.org/terms"
    /// }
    /// </code>
    /// An order that names no profile is signed as the section itself says;
    /// one that names a profile - draft-ietf-acme-profiles, which Let's
    /// Encrypt speaks - as that profile says. Without an issuer, and without
    /// profiles, ACME signs nothing.
    /// <para>
    /// "allowedNames" are the names ACME signs for: a domain stands for itself
    /// and every name below it, an address for itself, and an address with a
    /// prefix length for every address of that network. None at all is every
    /// name whoever asks can prove control of - which is what a public CA does,
    /// and rarely what the PKI of a charging network should.
    /// </para>
    /// <para>
    /// With "externalAccountRequired", an account is opened with a key of the
    /// PKI's own only (RFC 8555, section 7.3.4): one that somebody who may sign
    /// certificates made for it, once.
    /// </para>
    /// </remarks>
    /// <param name="Default">What an order without a profile is signed as; null for nothing.</param>
    /// <param name="Profiles">What an order with a profile is signed as, by the profile's name.</param>
    /// <param name="ExternalAccountRequired">Whether an account is opened only with a key the PKI made for it.</param>
    /// <param name="AllowedNames">The domains and networks ACME signs for; empty for every one.</param>
    /// <param name="Challenges">The kinds of challenge offered: "http-01" and "dns-01".</param>
    /// <param name="HTTP01Port">The port http-01 asks at; 80 as RFC 8555 has it, another only on a bench.</param>
    /// <param name="TermsOfService">Where the terms of service are, which a new account then agrees to; none by default.</param>
    public sealed record ACMESettings(ACMEProfile?                              Default,
                                      IReadOnlyDictionary<String, ACMEProfile>  Profiles,
                                      Boolean                                   ExternalAccountRequired,
                                      IReadOnlyList<String>                     AllowedNames,
                                      IReadOnlyList<String>                     Challenges,
                                      UInt16                                    HTTP01Port      = 80,
                                      String?                                   TermsOfService  = null)
    {

        #region Data

        /// <summary>
        /// For how many days what ACME signs holds, where its profile says
        /// nothing: Let's Encrypt's 90.
        /// </summary>
        public const Int32 DefaultValidDays = 90;

        /// <summary>
        /// The kinds of challenge the PKI can check.
        /// </summary>
        public static readonly IReadOnlyList<String> KnownChallenges = [ "http-01", "dns-01" ];

        private static readonly Regex ProfileName = new ("^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", RegexOptions.Compiled);

        /// <summary>
        /// ACME signing nothing.
        /// </summary>
        public static readonly ACMESettings None = new (null, new Dictionary<String, ACMEProfile>(), false, [], KnownChallenges);

        #endregion

        #region Enabled

        /// <summary>
        /// Whether ACME signs anything at all.
        /// </summary>
        public Boolean Enabled
            => Default is not null || Profiles.Count > 0;

        /// <summary>
        /// Whether ACME signs for every name, for everybody who reaches it - as
        /// a public CA does: neither "allowedNames" nor an external account
        /// binding says otherwise.
        /// </summary>
        public Boolean OpenToEverybody
            => Enabled && AllowedNames.Count == 0 && !ExternalAccountRequired;

        /// <summary>
        /// What is said of it where it is open to everybody.
        /// </summary>
        public const String OpenToEverybodyWarning = "ACME signs for every name whoever reaches it proves to be theirs, as a public CA does: " +
                                                     "neither \"allowedNames\" nor \"externalAccountRequired\" says otherwise.";

        #endregion

        #region For(ProfileName)

        /// <summary>
        /// What an order with the given profile - or none, null - is signed as,
        /// or null where it is nothing. An order without one, where there is
        /// no default and one profile only, is signed as that one.
        /// </summary>
        public ACMEProfile? For(String? ProfileName)

            => ProfileName is null
                   ? Default ?? (Profiles.Count == 1 ? Profiles.Values.First() : null)
                   : Profiles.TryGetValue(ProfileName, out var profile) ? profile : null;

        #endregion

        #region Allows(Type, Value)

        /// <summary>
        /// Whether ACME signs for the given identifier - "dns" or "ip" - at all,
        /// before anybody proves anything: "allowedNames" says so, or says none.
        /// </summary>
        /// <param name="Type">"dns" or "ip".</param>
        /// <param name="Value">A host name - without a wildcard's "*." - or an address.</param>
        public Boolean Allows(String  Type,
                              String  Value)
        {

            if (AllowedNames.Count == 0)
                return true;

            foreach (var allowed in AllowedNames)
            {

                if (Type == "ip")
                {

                    if (!IPAddress.TryParse(Value, out var address))
                        return false;

                    if (TryNetwork(allowed, out var network, out var prefixLength) && InNetwork(address, network, prefixLength))
                        return true;

                }

                else if (!allowed.Contains('/') && !IPAddress.TryParse(allowed, out _))
                {

                    var domain = allowed.TrimStart('*', '.').TrimEnd('.');

                    if (Value.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                        Value.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                }

            }

            return false;

        }

        /// <summary>
        /// An address, or a network as an address with its prefix length.
        /// </summary>
        private static Boolean TryNetwork(String                                Text,
                                          [NotNullWhen(true)] out IPAddress?    Network,
                                          out Int32                             PrefixLength)
        {

            var parts     = Text.Split('/', 2);

            PrefixLength  = -1;

            if (!IPAddress.TryParse(parts[0], out Network))
                return false;

            var bits      = Network.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;

            if (parts.Length == 1)
            {
                PrefixLength = bits;
                return true;
            }

            return Int32.TryParse(parts[1], out PrefixLength) && PrefixLength >= 0 && PrefixLength <= bits;

        }

        private static Boolean InNetwork(IPAddress  Address,
                                         IPAddress  Network,
                                         Int32      PrefixLength)
        {

            if (Address.IsIPv4MappedToIPv6)
                Address = Address.MapToIPv4();

            if (Address.AddressFamily != Network.AddressFamily)
                return false;

            var address  = Address.GetAddressBytes();
            var network  = Network.GetAddressBytes();

            for (var bit = 0; bit < PrefixLength; bit++)
            {
                var mask = (Byte) (0x80 >> (bit % 8));
                if ((address[bit / 8] & mask) != (network[bit / 8] & mask))
                    return false;
            }

            return true;

        }

        #endregion

        #region ToJSON()

        public JObject ToJSON()
        {

            var json = Default?.ToJSON() ?? [];

            json.Remove("description");

            json.Add(new JProperty("profiles",                 new JObject(Profiles.OrderBy(profile => profile.Key, StringComparer.Ordinal).
                                                                                    Select (profile => new JProperty(profile.Key, profile.Value.ToJSON())))));
            json.Add(new JProperty("externalAccountRequired",  ExternalAccountRequired));
            json.Add(new JProperty("allowedNames",             new JArray(AllowedNames)));
            json.Add(new JProperty("challenges",               new JArray(Challenges)));
            json.Add(new JProperty("http01Port",               HTTP01Port));
            json.Add(new JProperty("termsOfService",           TermsOfService));

            return json;

        }

        #endregion

        #region (static) TryParse(JSON, out Settings, out Error)

        /// <summary>
        /// The settings from the "acme" of the "pki" section - none, where it
        /// says nothing - or why they are none.
        /// </summary>
        public static Boolean TryParse(JToken?                                  JSON,
                                       [NotNullWhen(true)]  out ACMESettings?   Settings,
                                       [NotNullWhen(false)] out String?         Error)
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
                Error = "\"acme\" is { \"issuer\", \"profile\", \"validDays\", \"profiles\", \"externalAccountRequired\", \"allowedNames\", \"challenges\", \"http01Port\", \"termsOfService\" }.";
                return false;
            }

            #region The default, and the profiles

            ACMEProfile? @default = null;

            if (!String.IsNullOrWhiteSpace(json.Value<String>("issuer")) &&
                !ACMEProfile.TryParse(json, "\"acme\"", out @default, out Error))
            {
                return false;
            }

            if (@default is not null)
                @default = @default with { Description = null };

            var profiles = new Dictionary<String, ACMEProfile>(StringComparer.Ordinal);

            if (json["profiles"] is JToken profilesToken && profilesToken.Type != JTokenType.Null)
            {

                if (profilesToken is not JObject profilesJSON)
                {
                    Error = "The \"profiles\" of \"acme\" are { \"<name>\": { \"issuer\", \"profile\", \"validDays\", \"description\" } }.";
                    return false;
                }

                foreach (var named in profilesJSON.Properties())
                {

                    if (!ProfileName.IsMatch(named.Name))
                    {
                        Error = $"'{named.Name}' is no name of a profile of ACME: letters, digits, '.', '-' and '_'.";
                        return false;
                    }

                    if (!ACMEProfile.TryParse(named.Value, $"the profile '{named.Name}'", out var profile, out Error))
                        return false;

                    profiles[named.Name] = profile;

                }

            }

            #endregion

            #region Who may open an account

            var eab = json["externalAccountRequired"];

            if (eab is not null && eab.Type is not JTokenType.Boolean and not JTokenType.Null)
            {
                Error = "\"externalAccountRequired\" of \"acme\" is true or false.";
                return false;
            }

            #endregion

            #region For which names

            var allowed = new List<String>();

            if (json["allowedNames"] is JToken allowedToken && allowedToken.Type != JTokenType.Null)
            {

                if (allowedToken is not JArray allowedArray || allowedArray.Any(entry => entry.Type != JTokenType.String))
                {
                    Error = "\"allowedNames\" of \"acme\" is a list of domains and networks: [ \"lab.example.org\", \"10.0.0.0/8\" ].";
                    return false;
                }

                foreach (var entry in allowedArray.Select(entry => entry.Value<String>()!.Trim()).Where(entry => entry.Length > 0))
                {

                    var isNetwork = entry.Contains('/') || IPAddress.TryParse(entry, out _);

                    if (isNetwork ? !TryNetwork(entry, out _, out _)
                                  : !AlternativeNames.IsValid(entry.TrimStart('*', '.'), out _) || entry.TrimStart('*', '.').Contains('@') || entry.Contains("://"))
                    {
                        Error = $"'{entry}' of \"allowedNames\" is neither a domain nor an address, with or without its prefix length.";
                        return false;
                    }

                    if (!allowed.Contains(entry, StringComparer.OrdinalIgnoreCase))
                        allowed.Add(entry);

                }

            }

            #endregion

            #region How names are proven

            var challenges = new List<String>(KnownChallenges);

            if (json["challenges"] is JToken challengesToken && challengesToken.Type != JTokenType.Null)
            {

                if (challengesToken is not JArray challengesArray || challengesArray.Any(entry => entry.Type != JTokenType.String))
                {
                    Error = $"\"challenges\" of \"acme\" is a list of {String.Join(" and ", KnownChallenges.Select(known => $"\"{known}\""))}.";
                    return false;
                }

                challenges = [.. challengesArray.Select(entry => entry.Value<String>()!).Distinct()];

                if (challenges.FirstOrDefault(challenge => !KnownChallenges.Contains(challenge)) is String unknown)
                {
                    Error = $"'{unknown}' is no challenge the PKI checks: {String.Join(", ", KnownChallenges)}.";
                    return false;
                }

                if (challenges.Count == 0)
                {
                    Error = "\"challenges\" of \"acme\" names at least one: nobody could prove anything otherwise.";
                    return false;
                }

            }

            var portToken = json["http01Port"];
            var port      = portToken is null || portToken.Type == JTokenType.Null ? 80 : portToken.Type == JTokenType.Integer ? portToken.Value<Int32>() : -1;

            if (port < 1 || port > 65535)
            {
                Error = "\"http01Port\" of \"acme\" is a TCP port, 80 unless on a bench.";
                return false;
            }

            #endregion

            #region The terms of service

            var terms = json["termsOfService"];

            if (terms is not null && terms.Type != JTokenType.Null &&
                (terms.Type != JTokenType.String || !Uri.TryCreate(terms.Value<String>(), UriKind.Absolute, out _)))
            {
                Error = "\"termsOfService\" of \"acme\" is the URL of the terms of service.";
                return false;
            }

            #endregion

            Settings = new ACMESettings(@default,
                                        profiles,
                                        eab?.Type == JTokenType.Boolean && eab.Value<Boolean>(),
                                        allowed,
                                        challenges,
                                        (UInt16) port,
                                        terms?.Type == JTokenType.String ? terms.Value<String>() : null);

            return true;

        }

        #endregion

    }

}
