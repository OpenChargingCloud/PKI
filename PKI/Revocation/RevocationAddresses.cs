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

#endregion

namespace cloud.charging.open.PKI.Revocation
{

    /// <summary>
    /// Where whoever checks a certificate of this PKI finds out whether it was
    /// revoked: the CRL of its CA, the OCSP responder, and the CA's own
    /// certificate - written into every certificate made below a CA, as the
    /// CRL distribution points and the authority information access of RFC
    /// 5280.
    /// </summary>
    /// <remarks>
    /// Made from the address the PKI is reached at from outside - not the
    /// one it listens on, which is 127.0.0.1 more often than not - and the path
    /// of its JSON API.
    /// </remarks>
    /// <param name="PublicURL">The address the PKI is reached at, as it was given: "http://pki.example.org".</param>
    /// <param name="APIURL">The JSON API at that address, with a slash at the end: "http://pki.example.org/api/".</param>
    public sealed record RevocationAddresses(String  PublicURL,
                                             String  APIURL)
    {

        /// <summary>
        /// The CRL of the given CA.
        /// </summary>
        public String CRL(String CAId)
            => $"{APIURL}v1/pki/crl/{CAId}.crl";

        /// <summary>
        /// The OCSP responder of every CA of this PKI.
        /// </summary>
        public String OCSP
            => $"{APIURL}v1/pki/ocsp";

        /// <summary>
        /// The certificate of the given CA, as DER.
        /// </summary>
        public String CAIssuer(String CAId)
            => $"{APIURL}v1/pki/ca/{CAId}.crt";

        /// <summary>
        /// The addresses below the given public address and the path of the
        /// JSON API - or why that address is none.
        /// </summary>
        /// <remarks>
        /// http as well as https: a CRL and an OCSP response are signed, and
        /// are fetched over plain HTTP by most of whoever checks them - over
        /// HTTPS, the check of the server's certificate would need the very
        /// answer it is fetching.
        /// </remarks>
        public static Boolean TryParse(String?                                        PublicURL,
                                       String                                         APIPath,
                                       [NotNullWhen(true)]  out RevocationAddresses?  Addresses,
                                       [NotNullWhen(false)] out String?               Error)
        {

            Addresses  = null;
            Error      = null;

            var text   = PublicURL?.Trim() ?? "";

            if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
                uri.Host.Length == 0 ||
                uri.Query.Length > 0 ||
                uri.Fragment.Length > 0)
            {
                Error = $"'{text}' is no address of http or https, such as 'http://pki.example.org'.";
                return false;
            }

            var root   = uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
            var api    = APIPath.Trim('/');

            Addresses  = new RevocationAddresses(root, api.Length > 0 ? $"{root}/{api}/" : $"{root}/");
            return true;

        }

    }

}
