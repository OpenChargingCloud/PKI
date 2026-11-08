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
using System.Globalization;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.PKI.Revocation
{

    /// <summary>
    /// One certificate this PKI revoked: which, below which CA, when, why and
    /// by whom.
    /// </summary>
    /// <remarks>
    /// Kept apart from the index of the store, in "revocation/revoked.json",
    /// because it outlives the certificate: one deleted from the PKI after it
    /// was revoked is still in the CRL of its CA, and still revoked when its
    /// responder is asked, until it expires.
    /// </remarks>
    public sealed record RevokedCertificate(String                Id,
                                            String                IssuerId,
                                            String                SerialNumber,
                                            String                CommonName,
                                            DateTimeOffset        NotAfter,
                                            DateTimeOffset        RevokedAt,
                                            X509RevocationReason  Reason,
                                            String?               RevokedBy)
    {

        #region ToJSON()

        public JObject ToJSON()

            => new (
                   new JProperty("id",            Id),
                   new JProperty("issuerId",      IssuerId),
                   new JProperty("serialNumber",  SerialNumber),
                   new JProperty("commonName",    CommonName),
                   new JProperty("notAfter",      NotAfter. ToString("o", CultureInfo.InvariantCulture)),
                   new JProperty("revokedAt",     RevokedAt.ToString("o", CultureInfo.InvariantCulture)),
                   new JProperty("reason",        RevocationReasons.AsText(Reason)),
                   new JProperty("revokedBy",     RevokedBy)
               );

        #endregion

        #region (static) TryParse(JSON)

        /// <summary>
        /// One entry of the list, or null where it is not one.
        /// </summary>
        public static RevokedCertificate? TryParse(JToken JSON)
        {

            try
            {

                if (JSON is not JObject json ||
                    !RevocationReasons.TryParse(json.Value<String>("reason"), out var reason))
                {
                    return null;
                }

                return new RevokedCertificate(
                           Id:            json.Value<String>("id")!.ToLowerInvariant(),
                           IssuerId:      json.Value<String>("issuerId")!.ToLowerInvariant(),
                           SerialNumber:  RevocationReasons.NormalizedSerial(json.Value<String>("serialNumber")!),
                           CommonName:    json.Value<String>("commonName") ?? "",
                           NotAfter:      DateTimeOffset.Parse(json.Value<String>("notAfter")!,  CultureInfo.InvariantCulture),
                           RevokedAt:     DateTimeOffset.Parse(json.Value<String>("revokedAt")!, CultureInfo.InvariantCulture),
                           Reason:        reason.Value,
                           RevokedBy:     json.Value<String>("revokedBy")
                       );

            }
            catch (Exception)
            {
                return null;
            }

        }

        #endregion

    }


    /// <summary>
    /// Why a certificate was revoked, in the names of RFC 5280, section
    /// 5.3.1 - those of them a PKI of charging stations has any use for.
    /// </summary>
    /// <remarks>
    /// No "certificateHold": a revocation here is for good, and a
    /// certificate that is to be believed again is made anew.
    /// </remarks>
    public static class RevocationReasons
    {

        /// <summary>
        /// The reasons a certificate may be revoked for, as the JSON API writes
        /// them.
        /// </summary>
        public static readonly IReadOnlyList<X509RevocationReason> All = [
                                                                             X509RevocationReason.Unspecified,
                                                                             X509RevocationReason.KeyCompromise,
                                                                             X509RevocationReason.CACompromise,
                                                                             X509RevocationReason.AffiliationChanged,
                                                                             X509RevocationReason.Superseded,
                                                                             X509RevocationReason.CessationOfOperation,
                                                                             X509RevocationReason.PrivilegeWithdrawn
                                                                         ];

        /// <summary>
        /// "unspecified", "keyCompromise", "caCompromise", ...
        /// </summary>
        public static String AsText(X509RevocationReason Reason)

            => Reason switch {
                   X509RevocationReason.KeyCompromise         => "keyCompromise",
                   X509RevocationReason.CACompromise          => "caCompromise",
                   X509RevocationReason.AffiliationChanged    => "affiliationChanged",
                   X509RevocationReason.Superseded            => "superseded",
                   X509RevocationReason.CessationOfOperation  => "cessationOfOperation",
                   X509RevocationReason.PrivilegeWithdrawn    => "privilegeWithdrawn",
                   _                                          => "unspecified"
               };

        /// <summary>
        /// A reason by the name the JSON API writes it with, whatever its case;
        /// "unspecified" where there is none.
        /// </summary>
        public static Boolean TryParse(String?                                        Text,
                                       [NotNullWhen(true)] out X509RevocationReason?  Reason)
        {

            if (String.IsNullOrWhiteSpace(Text))
            {
                Reason = X509RevocationReason.Unspecified;
                return true;
            }

            Reason = All.Cast<X509RevocationReason?>().
                         FirstOrDefault(reason => AsText(reason!.Value).Equals(Text.Trim(), StringComparison.OrdinalIgnoreCase));

            return Reason is not null;

        }

        /// <summary>
        /// A serial number as hex in capitals, without the zeros in front a
        /// positive INTEGER may be written with: so that the serial of a
        /// certificate and the serial an OCSP request asks for compare equal.
        /// </summary>
        public static String NormalizedSerial(String Hex)
        {

            var hex = new String(Hex.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();

            if (hex.Length % 2 == 1)
                hex = "0" + hex;

            while (hex.Length > 2 && hex.StartsWith("00", StringComparison.Ordinal))
                hex = hex[2..];

            return hex;

        }

    }

}
