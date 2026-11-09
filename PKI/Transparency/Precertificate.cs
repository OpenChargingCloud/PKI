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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

#endregion

namespace cloud.charging.open.PKI.Transparency
{

    /// <summary>
    /// A signed certificate timestamp as a certificate carries it: which log,
    /// when, and the log's signature - RFC 6962, section 3.2.
    /// </summary>
    /// <param name="LogId">The id of the log: SHA-256 of its public key.</param>
    /// <param name="Timestamp">When the log took it in, in milliseconds since 1970.</param>
    /// <param name="Extensions">Its extensions, none so far.</param>
    /// <param name="Signature">The log's signature, as the DigitallySigned of RFC 5246.</param>
    public sealed record SignedCertificateTimestamp(Byte[]  LogId,
                                                    Int64   Timestamp,
                                                    Byte[]  Extensions,
                                                    Byte[]  Signature)
    {

        /// <summary>
        /// When the log took it in.
        /// </summary>
        public DateTimeOffset LoggedAt
            => DateTimeOffset.FromUnixTimeMilliseconds(Timestamp);

    }


    /// <summary>
    /// Precertificates after RFC 6962, section 3.1: a certificate signed with
    /// the poison extension, which nothing believes, is what the log signs
    /// the timestamp of - and the certificate itself, signed afterwards, is
    /// the same but for the poison, and carries that timestamp. Whoever
    /// checks it takes the timestamp out again, and checks the log's
    /// signature over what is left.
    /// </summary>
    /// <remarks>
    /// The CA signs the precertificate itself, rather than a precertificate
    /// signing certificate below it: the issuer of the precertificate is the
    /// issuer of the certificate, and the TBSCertificate the log signs is the
    /// precertificate's without its poison.
    /// </remarks>
    public static class Precertificate
    {

        /// <summary>
        /// The poison extension: critical, so that nothing believes a
        /// precertificate.
        /// </summary>
        public const String PoisonOID   = "1.3.6.1.4.1.11129.2.4.3";

        /// <summary>
        /// The extension a certificate carries its signed certificate
        /// timestamps in.
        /// </summary>
        public const String SCTListOID  = "1.3.6.1.4.1.11129.2.4.2";

        private static readonly Asn1Tag Extensions = new (TagClass.ContextSpecific, 3, isConstructed: true);

        #region Poison()

        /// <summary>
        /// The poison extension: critical, its value ASN.1 NULL.
        /// </summary>
        public static X509Extension Poison()

            => new (new Oid(PoisonOID), [ 0x05, 0x00 ], critical: true);

        #endregion

        #region SCTList(SignedCertificateTimestamps)

        /// <summary>
        /// The extension that carries the given signed certificate
        /// timestamps, each as TLS writes it: the list of them, as TLS writes
        /// it, in an OCTET STRING.
        /// </summary>
        public static X509Extension SCTList(IEnumerable<Byte[]> SerializedSCTs)
        {

            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteOctetString(TLS.SCTList(SerializedSCTs));

            return new X509Extension(new Oid(SCTListOID), writer.Encode(), critical: false);

        }

        #endregion

        #region SCTsOf(Certificate)

        /// <summary>
        /// The signed certificate timestamps a certificate carries: none, where
        /// it carries none, or where they cannot be read.
        /// </summary>
        public static IReadOnlyList<SignedCertificateTimestamp> SCTsOf(X509Certificate2 Certificate)
        {

            var extension = Certificate.Extensions[SCTListOID];

            if (extension is null)
                return [];

            try
            {
                return TLS.ReadSCTList(new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadOctetString());
            }
            catch (Exception)
            {
                return [];
            }

        }

        #endregion

        #region TBSWithout(Certificate, OID)

        /// <summary>
        /// The TBSCertificate of a certificate, DER, without the extension of
        /// the given OID - and without its extensions altogether, where that
        /// was its only one. Everything else is as it was written.
        /// </summary>
        public static Byte[] TBSWithout(ReadOnlyMemory<Byte> Certificate, String OID)
        {

            var tbs     = new AsnReader(Certificate, AsnEncodingRules.DER).ReadSequence().ReadSequence();
            var writer  = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {
                while (tbs.HasData)
                {

                    if (!tbs.PeekTag().HasSameClassAndValue(Extensions))
                    {
                        writer.WriteEncodedValue(tbs.ReadEncodedValue().Span);
                        continue;
                    }

                    var extensions  = tbs.ReadSequence(Extensions).ReadSequence();
                    var kept        = new List<ReadOnlyMemory<Byte>>();

                    while (extensions.HasData)
                    {
                        var extension = extensions.ReadEncodedValue();
                        if (new AsnReader(extension, AsnEncodingRules.DER).ReadSequence().ReadObjectIdentifier() != OID)
                            kept.Add(extension);
                    }

                    if (kept.Count == 0)
                        continue;

                    using (writer.PushSequence(Extensions))
                    using (writer.PushSequence())
                    {
                        foreach (var extension in kept)
                            writer.WriteEncodedValue(extension.Span);
                    }

                }
            }

            return writer.Encode();

        }

        #endregion

        #region IssuerKeyHash(Issuer)

        /// <summary>
        /// SHA-256 of the SubjectPublicKeyInfo of the CA that signs: what ties
        /// a precertificate to its CA in the log.
        /// </summary>
        public static Byte[] IssuerKeyHash(X509Certificate2 Issuer)

            => SHA256.HashData(Issuer.PublicKey.ExportSubjectPublicKeyInfo());

        /// <summary>
        /// SHA-256 of the SubjectPublicKeyInfo of the CA of the given DER.
        /// </summary>
        public static Byte[] IssuerKeyHash(Byte[] Issuer)
        {
            using var issuer = X509CertificateLoader.LoadCertificate(Issuer);
            return IssuerKeyHash(issuer);
        }

        #endregion

        #region IsPoisoned(Certificate)

        /// <summary>
        /// Whether a certificate carries the poison extension, critical.
        /// </summary>
        public static Boolean IsPoisoned(X509Certificate2 Certificate)

            => Certificate.Extensions[PoisonOID] is X509Extension poison && poison.Critical;

        #endregion

    }

}
