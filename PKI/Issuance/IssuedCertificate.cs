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

using System.Globalization;

using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.PKI.Issuance
{

    /// <summary>
    /// One certificate this PKI made: what it is, who it is about, who signed
    /// it, for how long it holds - and who asked for it, and when.
    /// </summary>
    /// <remarks>
    /// What the index of the store keeps of a certificate, so that a list of
    /// a thousand of them is drawn without reading a thousand files. The
    /// certificate itself is the file beside it, and is what anything that
    /// signs or is shown reads.
    /// </remarks>
    public sealed record IssuedCertificate(String                  Id,
                                           CertificateProfile      Profile,
                                           String                  CommonName,
                                           String                  Subject,
                                           String                  Issuer,
                                           String?                 IssuerId,
                                           String                  SerialNumber,
                                           DateTimeOffset          NotBefore,
                                           DateTimeOffset          NotAfter,
                                           String                  KeyAlgorithm,
                                           IReadOnlyList<String>   SubjectAlternativeNames,
                                           Int32?                  PathLength,
                                           Boolean                 HasPrivateKey,
                                           Boolean                 FromCSR,
                                           DateTimeOffset          CreatedAt,
                                           String?                 CreatedBy)
    {

        #region StatusAt(Now)

        /// <summary>
        /// "valid", "expired" or "notYetValid", at the given time.
        /// </summary>
        public String StatusAt(DateTimeOffset Now)

            => Now < NotBefore
                   ? "notYetValid"
                   : Now > NotAfter
                         ? "expired"
                         : "valid";

        #endregion

        #region ToJSON(Now)

        /// <summary>
        /// The certificate as the list of the web interface shows it, and as
        /// the index keeps it - with its status at the given time, which the
        /// index does not keep.
        /// </summary>
        public JObject ToJSON(DateTimeOffset? Now = null)
        {

            var json = new JObject(
                           new JProperty("id",                       Id),
                           new JProperty("profile",                  Profile.AsText()),
                           new JProperty("commonName",               CommonName),
                           new JProperty("subject",                  Subject),
                           new JProperty("issuer",                   Issuer),
                           new JProperty("issuerId",                 IssuerId),
                           new JProperty("serialNumber",             SerialNumber),
                           new JProperty("notBefore",                NotBefore.ToString("o", CultureInfo.InvariantCulture)),
                           new JProperty("notAfter",                 NotAfter. ToString("o", CultureInfo.InvariantCulture)),
                           new JProperty("keyAlgorithm",             KeyAlgorithm),
                           new JProperty("subjectAlternativeNames",  new JArray(SubjectAlternativeNames)),
                           new JProperty("pathLength",               PathLength),
                           new JProperty("hasPrivateKey",            HasPrivateKey),
                           new JProperty("fromCSR",                  FromCSR),
                           new JProperty("createdAt",                CreatedAt.ToString("o", CultureInfo.InvariantCulture)),
                           new JProperty("createdBy",                CreatedBy)
                       );

            if (Now is not null)
                json.Add(new JProperty("status", StatusAt(Now.Value)));

            return json;

        }

        #endregion

        #region TryParse(JSON, out Certificate)

        /// <summary>
        /// One entry of the index, or null where it is not one: an entry
        /// somebody broke by hand is passed over rather than stopping the
        /// start, and the certificate it was about is still a file somebody
        /// can look at.
        /// </summary>
        public static IssuedCertificate? TryParse(JToken JSON)
        {

            try
            {

                if (JSON is not JObject json ||
                    !CertificateProfileExtensions.TryParse(json.Value<String>("profile"), out var profile))
                {
                    return null;
                }

                return new IssuedCertificate(
                           Id:                       json.Value<String>("id")!.ToLowerInvariant(),
                           Profile:                  profile.Value,
                           CommonName:               json.Value<String>("commonName")    ?? "",
                           Subject:                  json.Value<String>("subject")       ?? "",
                           Issuer:                   json.Value<String>("issuer")        ?? "",
                           IssuerId:                 json.Value<String>("issuerId")?.ToLowerInvariant(),
                           SerialNumber:             json.Value<String>("serialNumber")  ?? "",
                           NotBefore:                DateTimeOffset.Parse(json.Value<String>("notBefore")!, CultureInfo.InvariantCulture),
                           NotAfter:                 DateTimeOffset.Parse(json.Value<String>("notAfter")!,  CultureInfo.InvariantCulture),
                           KeyAlgorithm:             json.Value<String>("keyAlgorithm")  ?? "",
                           SubjectAlternativeNames:  json["subjectAlternativeNames"]?.Values<String>().OfType<String>().ToList() ?? [],
                           PathLength:               json.Value<Int32?>("pathLength"),
                           HasPrivateKey:            json.Value<Boolean?>("hasPrivateKey") ?? false,
                           FromCSR:                  json.Value<Boolean?>("fromCSR")       ?? false,
                           CreatedAt:                DateTimeOffset.Parse(json.Value<String>("createdAt")!, CultureInfo.InvariantCulture),
                           CreatedBy:                json.Value<String>("createdBy")
                       );

            }
            catch (Exception)
            {
                return null;
            }

        }

        #endregion

    }

}
