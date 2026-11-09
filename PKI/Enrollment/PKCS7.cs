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

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

#endregion

namespace cloud.charging.open.PKI.Enrollment
{

    /// <summary>
    /// The "certs-only" PKCS#7 of RFC 5652 - a SignedData that signs nothing
    /// and carries certificates - which is how EST hands out certificates.
    /// </summary>
    /// <remarks>
    /// Written with System.Formats.Asn1 rather than taken from the operating
    /// system, which writes it on Windows and not everywhere else.
    /// </remarks>
    public static class PKCS7
    {

        private const String SignedDataOID  = "1.2.840.113549.1.7.2";
        private const String DataOID        = "1.2.840.113549.1.7.1";

        private static readonly Asn1Tag Context0 = new (TagClass.ContextSpecific, 0, isConstructed: true);

        #region CertsOnly(Certificates)

        /// <summary>
        /// The given certificates as a certs-only PKCS#7, as DER.
        /// </summary>
        public static Byte[] CertsOnly(IEnumerable<X509Certificate2> Certificates)
        {

            var writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())                       // ContentInfo
            {

                writer.WriteObjectIdentifier(SignedDataOID);

                using (writer.PushSequence(Context0))           // [0] EXPLICIT
                using (writer.PushSequence())                   // SignedData
                {

                    writer.WriteInteger(1);                     // version

                    using (writer.PushSetOf()) { }              // digestAlgorithms

                    using (writer.PushSequence())               // encapContentInfo
                        writer.WriteObjectIdentifier(DataOID);

                    using (writer.PushSetOf(Context0))          // certificates [0] IMPLICIT
                    {
                        foreach (var certificate in Certificates)
                            writer.WriteEncodedValue(certificate.RawData);
                    }

                    using (writer.PushSetOf()) { }              // signerInfos

                }

            }

            return writer.Encode();

        }

        #endregion

        #region ReadCertsOnly(DER)

        /// <summary>
        /// The certificates of a certs-only PKCS#7 - as a client of EST reads
        /// what it was handed.
        /// </summary>
        public static IReadOnlyList<X509Certificate2> ReadCertsOnly(ReadOnlyMemory<Byte> DER)
        {

            var contentInfo  = new AsnReader(DER, AsnEncodingRules.BER).ReadSequence();

            if (contentInfo.ReadObjectIdentifier() != SignedDataOID)
                throw new AsnContentException("This is no SignedData.");

            var signedData   = contentInfo.ReadSequence(Context0).ReadSequence();

            signedData.ReadInteger();                           // version
            signedData.ReadSetOf();                             // digestAlgorithms
            signedData.ReadSequence();                          // encapContentInfo

            var certificates = new List<X509Certificate2>();

            if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(Context0))
            {
                var set = signedData.ReadSetOf(true, Context0);
                while (set.HasData)
                    certificates.Add(X509CertificateLoader.LoadCertificate(set.ReadEncodedValue().ToArray()));
            }

            return certificates;

        }

        #endregion

    }

}
