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

namespace cloud.charging.open.PKI.Issuance
{

    /// <summary>
    /// What a certificate of this PKI is: a root, a CA below one, or a
    /// certificate for a server or a client below either.
    /// </summary>
    /// <remarks>
    /// The profile is what the extensions of a certificate are made from -
    /// whether it is a CA, what its key may be used for, which extended key
    /// usage it carries - and it is what the list of certificates is
    /// filtered by. It is said when a certificate is made and never changes.
    /// </remarks>
    public enum CertificateProfile
    {

        /// <summary>
        /// Signed by itself: what everything below it is believed through.
        /// </summary>
        RootCA,

        /// <summary>
        /// Signed by a root or by another sub-CA, and signing in its turn.
        /// </summary>
        SubCA,

        /// <summary>
        /// Who a TLS server is: a CSMS, a local controller, a time server.
        /// </summary>
        Server,

        /// <summary>
        /// Who a TLS client is: a charging station towards its CSMS, a
        /// controller towards its backend.
        /// </summary>
        Client

    }


    /// <summary>
    /// The names a profile is written with, and what it allows.
    /// </summary>
    public static class CertificateProfileExtensions
    {

        /// <summary>
        /// "rootCA", "subCA", "server", "client": as the JSON API writes it.
        /// </summary>
        public static String AsText(this CertificateProfile Profile)

            => Profile switch {
                   CertificateProfile.RootCA  => "rootCA",
                   CertificateProfile.SubCA   => "subCA",
                   CertificateProfile.Server  => "server",
                   _                          => "client"
               };

        /// <summary>
        /// "root CA", "sub-CA", "server certificate", "client certificate": as
        /// a sentence says it.
        /// </summary>
        public static String InWords(this CertificateProfile Profile)

            => Profile switch {
                   CertificateProfile.RootCA  => "root CA",
                   CertificateProfile.SubCA   => "sub-CA",
                   CertificateProfile.Server  => "server certificate",
                   _                          => "client certificate"
               };

        /// <summary>
        /// Whether a certificate of this profile signs others.
        /// </summary>
        public static Boolean IsCA(this CertificateProfile Profile)

            => Profile is CertificateProfile.RootCA or CertificateProfile.SubCA;

        /// <summary>
        /// A profile by the name the JSON API writes it with, whatever its case.
        /// </summary>
        public static Boolean TryParse(String?                                     Text,
                                       [NotNullWhen(true)] out CertificateProfile? Profile)
        {

            Profile = Enum.GetValues<CertificateProfile>().
                           Cast<CertificateProfile?>().
                           FirstOrDefault(profile => profile!.Value.AsText().Equals(Text?.Trim(), StringComparison.OrdinalIgnoreCase));

            return Profile is not null;

        }

    }

}
