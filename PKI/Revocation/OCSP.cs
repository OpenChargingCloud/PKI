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
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

#endregion

namespace cloud.charging.open.PKI.Revocation
{

    /// <summary>
    /// What an OCSP request asks of one certificate: which CA it is below -
    /// by the hashes of the CA's name and key - and its serial number.
    /// </summary>
    /// <param name="HashAlgorithm">The OID of the hash the CA's name and key were hashed with.</param>
    /// <param name="IssuerNameHash">The hash of the CA's distinguished name, as DER.</param>
    /// <param name="IssuerKeyHash">The hash of the CA's public key, without the BIT STRING around it.</param>
    /// <param name="SerialNumber">The serial number, as hex in capitals.</param>
    /// <param name="Encoded">The CertID as it was asked, which the answer repeats.</param>
    public sealed record OCSPCertID(String  HashAlgorithm,
                                    Byte[]  IssuerNameHash,
                                    Byte[]  IssuerKeyHash,
                                    String  SerialNumber,
                                    Byte[]  Encoded);

    /// <summary>
    /// An OCSP request: the certificates it asks about, and its nonce, where
    /// it has one.
    /// </summary>
    /// <param name="Nonce">The value of the nonce extension, as it was sent - the answer repeats it.</param>
    public sealed record OCSPRequest(IReadOnlyList<OCSPCertID>  Certificates,
                                     Byte[]?                    Nonce);

    /// <summary>
    /// What an OCSP response says of the whole request: RFC 6960, section 4.2.1.
    /// </summary>
    public enum OCSPResponseStatus
    {
        Successful        = 0,
        MalformedRequest  = 1,
        InternalError     = 2,
        TryLater          = 3,
        SigRequired       = 5,
        Unauthorized      = 6
    }

    /// <summary>
    /// What an OCSP response says of one certificate.
    /// </summary>
    public enum OCSPCertStatus
    {
        Good,
        Revoked,
        Unknown
    }

    /// <summary>
    /// What an OCSP response says of one certificate, and from when to when
    /// that is to be believed.
    /// </summary>
    public sealed record OCSPSingleResponse(OCSPCertID             CertID,
                                            OCSPCertStatus         Status,
                                            DateTimeOffset?        RevokedAt,
                                            X509RevocationReason?  Reason,
                                            DateTimeOffset         ThisUpdate,
                                            DateTimeOffset?        NextUpdate);

    /// <summary>
    /// An OCSP response as it was read: what it says, and what it was signed
    /// with - so that whoever reads it can check the signature.
    /// </summary>
    public sealed record OCSPResponse(OCSPResponseStatus                 Status,
                                      Byte[]?                            ResponderKeyHash,
                                      DateTimeOffset?                    ProducedAt,
                                      IReadOnlyList<OCSPSingleResponse>  Responses,
                                      Byte[]?                            Nonce,
                                      IReadOnlyList<X509Certificate2>    Certificates,
                                      Byte[]?                            SignedData,
                                      String?                            SignatureAlgorithm,
                                      Byte[]?                            Signature)
    {

        /// <summary>
        /// Whether the response was signed with the key of the given
        /// certificate.
        /// </summary>
        public Boolean IsSignedBy(X509Certificate2 Signer)
        {

            if (SignedData is null || Signature is null || SignatureAlgorithm is null)
                return false;

            var hash = OCSP.HashOfSignature(SignatureAlgorithm);

            if (hash is null)
                return false;

            using var ecdsa = Signer.GetECDsaPublicKey();
            if (ecdsa is not null)
                return ecdsa.VerifyData(SignedData, Signature, hash.Value, DSASignatureFormat.Rfc3279DerSequence);

            using var rsa   = Signer.GetRSAPublicKey();
            return rsa is not null && rsa.VerifyData(SignedData, Signature, hash.Value, RSASignaturePadding.Pkcs1);

        }

    }


    /// <summary>
    /// The Online Certificate Status Protocol of RFC 6960, as far as a
    /// responder needs it: a request read, a response written - and, for
    /// whoever checks a responder, a request written and a response read.
    /// </summary>
    /// <remarks>
    /// Written with System.Formats.Asn1, since .NET has no OCSP of its own;
    /// the structures are those of RFC 6960, appendix B.1, whose module tags
    /// explicitly. A response is a BasicOCSPResponse, its responder named by
    /// the SHA-1 of its key, as RFC 5019 has a responder of many clients do.
    /// </remarks>
    public static class OCSP
    {

        #region Data

        /// <summary>
        /// id-pkix-ocsp-basic: the only kind of response there is.
        /// </summary>
        public const String BasicResponseOID   = "1.3.6.1.5.5.7.48.1.1";

        /// <summary>
        /// id-pkix-ocsp-nonce.
        /// </summary>
        public const String NonceOID           = "1.3.6.1.5.5.7.48.1.2";

        /// <summary>
        /// id-pkix-ocsp-nocheck: what says of a responder's certificate that
        /// nobody need ask whether it was revoked.
        /// </summary>
        public const String NoCheckOID         = "1.3.6.1.5.5.7.48.1.5";

        /// <summary>
        /// id-kp-OCSPSigning: the extended key usage of a responder.
        /// </summary>
        public const String OCSPSigningOID     = "1.3.6.1.5.5.7.3.9";

        public const String SHA1OID            = "1.3.14.3.2.26";
        public const String SHA256OID          = "2.16.840.1.101.3.4.2.1";
        public const String SHA384OID          = "2.16.840.1.101.3.4.2.2";
        public const String SHA512OID          = "2.16.840.1.101.3.4.2.3";

        /// <summary>
        /// The hashes a request may name a CA with: SHA-1, what nearly every
        /// client sends, and the three of SHA-2.
        /// </summary>
        public static readonly IReadOnlyList<String> HashAlgorithms = [ SHA1OID, SHA256OID, SHA384OID, SHA512OID ];

        private static readonly Asn1Tag Context0           = new (TagClass.ContextSpecific, 0);
        private static readonly Asn1Tag Context1           = new (TagClass.ContextSpecific, 1);
        private static readonly Asn1Tag Context2           = new (TagClass.ContextSpecific, 2);

        #endregion


        #region Hashes

        /// <summary>
        /// The hash of the given OID, or null where it is none a request may name.
        /// </summary>
        public static HashAlgorithmName? HashOf(String OID)

            => OID switch {
                   SHA1OID    => HashAlgorithmName.SHA1,
                   SHA256OID  => HashAlgorithmName.SHA256,
                   SHA384OID  => HashAlgorithmName.SHA384,
                   SHA512OID  => HashAlgorithmName.SHA512,
                   _          => null
               };

        /// <summary>
        /// The given data hashed with the hash of the given OID.
        /// </summary>
        public static Byte[] Hash(String OID, ReadOnlySpan<Byte> Data)

            => OID switch {
                   SHA1OID    => SHA1.  HashData(Data),
                   SHA256OID  => SHA256.HashData(Data),
                   SHA384OID  => SHA384.HashData(Data),
                   SHA512OID  => SHA512.HashData(Data),
                   _          => throw new ArgumentException($"'{OID}' is no hash of OCSP here.", nameof(OID))
               };

        /// <summary>
        /// The hashes a CertID names a CA by: of its distinguished name, and of
        /// its public key without the BIT STRING around it.
        /// </summary>
        public static (Byte[] NameHash, Byte[] KeyHash) HashesOf(X509Certificate2  CA,
                                                                 String            HashAlgorithm)

            => (Hash(HashAlgorithm, CA.SubjectName.RawData),
                Hash(HashAlgorithm, CA.PublicKey.EncodedKeyValue.RawData));

        /// <summary>
        /// The hash a signature algorithm signs with, by its OID.
        /// </summary>
        public static HashAlgorithmName? HashOfSignature(String OID)

            => OID switch {
                   "1.2.840.10045.4.3.2"    => HashAlgorithmName.SHA256,
                   "1.2.840.10045.4.3.3"    => HashAlgorithmName.SHA384,
                   "1.2.840.10045.4.3.4"    => HashAlgorithmName.SHA512,
                   "1.2.840.113549.1.1.11"  => HashAlgorithmName.SHA256,
                   "1.2.840.113549.1.1.12"  => HashAlgorithmName.SHA384,
                   "1.2.840.113549.1.1.13"  => HashAlgorithmName.SHA512,
                   _                        => null
               };

        #endregion

        #region TryParseRequest(DER, out Request, out Error)

        /// <summary>
        /// An OCSP request, from its DER. A signature on it is not looked at:
        /// this responder answers whoever asks.
        /// </summary>
        public static Boolean TryParseRequest(ReadOnlyMemory<Byte>                   DER,
                                              [NotNullWhen(true)]  out OCSPRequest?  Request,
                                              [NotNullWhen(false)] out String?       Error)
        {

            Request  = null;
            Error    = null;

            try
            {

                var outer         = new AsnReader(DER, AsnEncodingRules.DER);
                var ocspRequest   = outer.ReadSequence();
                outer.ThrowIfNotEmpty();

                var tbsRequest    = ocspRequest.ReadSequence();

                if (tbsRequest.PeekTag().HasSameClassAndValue(Context0))
                    tbsRequest.ReadEncodedValue();                         // version

                if (tbsRequest.PeekTag().HasSameClassAndValue(Context1))
                    tbsRequest.ReadEncodedValue();                         // requestorName

                var requestList   = tbsRequest.ReadSequence();
                var certificates  = new List<OCSPCertID>();

                while (requestList.HasData)
                {

                    var request    = requestList.ReadSequence();
                    var encoded    = request.PeekEncodedValue().ToArray();
                    var certID     = request.ReadSequence();
                    var algorithm  = certID.ReadSequence();
                    var oid        = algorithm.ReadObjectIdentifier();
                    var nameHash   = certID.ReadOctetString();
                    var keyHash    = certID.ReadOctetString();
                    var serial     = certID.ReadIntegerBytes();

                    certificates.Add(new OCSPCertID(oid, nameHash, keyHash, RevocationReasons.NormalizedSerial(Convert.ToHexString(serial.Span)), encoded));

                }

                Byte[]? nonce = null;

                if (tbsRequest.HasData && tbsRequest.PeekTag().HasSameClassAndValue(Context2))
                    nonce = NonceOf(tbsRequest.ReadSequence(Context2).ReadSequence());

                if (certificates.Count == 0)
                {
                    Error = "The request asks about no certificate.";
                    return false;
                }

                Request = new OCSPRequest(certificates, nonce);
                return true;

            }
            catch (Exception e) when (e is AsnContentException or CryptographicException or ArgumentException)
            {
                Error = $"This is no OCSP request: {e.Message}";
                return false;
            }

        }

        #endregion

        #region Request(CA, SerialNumbers, HashAlgorithm, Nonce)

        /// <summary>
        /// An OCSP request for the given serial numbers below the given CA - as
        /// a client sends one.
        /// </summary>
        public static Byte[] Request(X509Certificate2     CA,
                                     IEnumerable<String>  SerialNumbers,
                                     String               HashAlgorithm  = SHA1OID,
                                     Byte[]?              Nonce          = null)
        {

            var (nameHash, keyHash) = HashesOf(CA, HashAlgorithm);

            var writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())                   // OCSPRequest
            using (writer.PushSequence())                   // TBSRequest
            {

                using (writer.PushSequence())               // requestList
                {
                    foreach (var serial in SerialNumbers)
                    {
                        using (writer.PushSequence())       // Request
                            WriteCertID(writer, HashAlgorithm, nameHash, keyHash, serial);
                    }
                }

                if (Nonce is not null)
                {
                    using (writer.PushSequence(Context2))
                    using (writer.PushSequence())
                        WriteNonce(writer, Nonce);
                }

            }

            return writer.Encode();

        }

        #endregion

        #region ErrorResponse(Status)

        /// <summary>
        /// A response that answers nothing: why not, unsigned - RFC 6960,
        /// section 2.3.
        /// </summary>
        public static Byte[] ErrorResponse(OCSPResponseStatus Status)
        {

            var writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
                writer.WriteEnumeratedValue(Status);

            return writer.Encode();

        }

        #endregion

        #region Response(Responses, Nonce, Responder, Key, ProducedAt)

        /// <summary>
        /// A successful response: what the responder says of each certificate,
        /// signed with its key, and its certificate beside it so that a client
        /// finds the CA vouches for it.
        /// </summary>
        public static Byte[] Response(IReadOnlyList<OCSPSingleResponse>  Responses,
                                      Byte[]?                            Nonce,
                                      X509Certificate2                   Responder,
                                      AsymmetricAlgorithm                Key,
                                      HashAlgorithmName                  Hash,
                                      DateTimeOffset                     ProducedAt)
        {

            #region ResponseData

            var data = new AsnWriter(AsnEncodingRules.DER);

            using (data.PushSequence())
            {

                // responderID: byKey [2] KeyHash
                using (data.PushSequence(Context2))
                    data.WriteOctetString(SHA1.HashData(Responder.PublicKey.EncodedKeyValue.RawData));

                data.WriteGeneralizedTime(ProducedAt.ToUniversalTime(), omitFractionalSeconds: true);

                using (data.PushSequence())
                {
                    foreach (var response in Responses)
                    {
                        using (data.PushSequence())
                        {

                            data.WriteEncodedValue(response.CertID.Encoded);

                            switch (response.Status)
                            {

                                case OCSPCertStatus.Good:
                                    data.WriteNull(Context0);
                                    break;

                                case OCSPCertStatus.Revoked:
                                    using (data.PushSequence(Context1))
                                    {
                                        data.WriteGeneralizedTime(response.RevokedAt!.Value.ToUniversalTime(), omitFractionalSeconds: true);
                                        if (response.Reason is X509RevocationReason reason && reason != X509RevocationReason.Unspecified)
                                        {
                                            using (data.PushSequence(Context0))
                                                data.WriteEnumeratedValue(reason);
                                        }
                                    }
                                    break;

                                default:
                                    data.WriteNull(Context2);
                                    break;

                            }

                            data.WriteGeneralizedTime(response.ThisUpdate.ToUniversalTime(), omitFractionalSeconds: true);

                            if (response.NextUpdate is DateTimeOffset nextUpdate)
                            {
                                using (data.PushSequence(Context0))
                                    data.WriteGeneralizedTime(nextUpdate.ToUniversalTime(), omitFractionalSeconds: true);
                            }

                        }
                    }
                }

                if (Nonce is not null)
                {
                    using (data.PushSequence(Context1))
                    using (data.PushSequence())
                        WriteNonce(data, Nonce);
                }

            }

            var tbs = data.Encode();

            #endregion

            #region BasicOCSPResponse, inside OCSPResponse

            var generator  = Key switch {
                                 ECDsa  ecdsa  => X509SignatureGenerator.CreateForECDsa(ecdsa),
                                 RSA    rsa    => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
                                 _             => throw new NotSupportedException($"A key of {Key.GetType().Name} signs nothing here.")
                             };

            var basic      = new AsnWriter(AsnEncodingRules.DER);

            using (basic.PushSequence())
            {

                basic.WriteEncodedValue(tbs);
                basic.WriteEncodedValue(generator.GetSignatureAlgorithmIdentifier(Hash));
                basic.WriteBitString(generator.SignData(tbs, Hash));

                using (basic.PushSequence(Context0))
                using (basic.PushSequence())
                    basic.WriteEncodedValue(Responder.RawData);

            }

            var writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {

                writer.WriteEnumeratedValue(OCSPResponseStatus.Successful);

                using (writer.PushSequence(Context0))
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(BasicResponseOID);
                    writer.WriteOctetString(basic.Encode());
                }

            }

            return writer.Encode();

            #endregion

        }

        #endregion

        #region TryParseResponse(DER, out Response, out Error)

        /// <summary>
        /// An OCSP response, from its DER - as a client reads one. Its
        /// signature is for whoever reads it to check, see
        /// <see cref="OCSPResponse.IsSignedBy"/>.
        /// </summary>
        public static Boolean TryParseResponse(ReadOnlyMemory<Byte>                    DER,
                                               [NotNullWhen(true)]  out OCSPResponse?  Response,
                                               [NotNullWhen(false)] out String?        Error)
        {

            Response  = null;
            Error     = null;

            try
            {

                var ocspResponse  = new AsnReader(DER, AsnEncodingRules.DER).ReadSequence();
                var status        = ocspResponse.ReadEnumeratedValue<OCSPResponseStatus>();

                if (!ocspResponse.HasData)
                {
                    Response = new OCSPResponse(status, null, null, [], null, [], null, null, null);
                    return true;
                }

                var bytes         = ocspResponse.ReadSequence(Context0).ReadSequence();

                if (bytes.ReadObjectIdentifier() != BasicResponseOID)
                {
                    Error = "The response is no basic OCSP response.";
                    return false;
                }

                var basic         = new AsnReader(bytes.ReadOctetString(), AsnEncodingRules.DER).ReadSequence();
                var tbs           = basic.PeekEncodedValue().ToArray();
                var responseData  = basic.ReadSequence();
                var algorithm     = basic.ReadSequence().ReadObjectIdentifier();
                var signature     = basic.ReadBitString(out _);
                var certificates  = new List<X509Certificate2>();

                if (basic.HasData && basic.PeekTag().HasSameClassAndValue(Context0))
                {
                    var certs = basic.ReadSequence(Context0).ReadSequence();
                    while (certs.HasData)
                        certificates.Add(X509CertificateLoader.LoadCertificate(certs.ReadEncodedValue().ToArray()));
                }

                if (responseData.PeekTag().HasSameClassAndValue(Context0))
                    responseData.ReadEncodedValue();                       // version

                Byte[]? keyHash = null;

                if (responseData.PeekTag().HasSameClassAndValue(Context2))
                    keyHash = responseData.ReadSequence(Context2).ReadOctetString();
                else
                    responseData.ReadEncodedValue();                       // byName

                var producedAt    = responseData.ReadGeneralizedTime();
                var singles       = new List<OCSPSingleResponse>();
                var responses     = responseData.ReadSequence();

                while (responses.HasData)
                {

                    var single     = responses.ReadSequence();
                    var encoded    = single.PeekEncodedValue().ToArray();
                    var certID     = single.ReadSequence();
                    var hash       = certID.ReadSequence().ReadObjectIdentifier();
                    var nameHash   = certID.ReadOctetString();
                    var issuerKey  = certID.ReadOctetString();
                    var serial     = RevocationReasons.NormalizedSerial(Convert.ToHexString(certID.ReadIntegerBytes().Span));
                    var tag        = single.PeekTag();

                    OCSPCertStatus          certStatus;
                    DateTimeOffset?         revokedAt  = null;
                    X509RevocationReason?   reason     = null;

                    if (tag.HasSameClassAndValue(Context0))
                    {
                        single.ReadNull(Context0);
                        certStatus = OCSPCertStatus.Good;
                    }
                    else if (tag.HasSameClassAndValue(Context1))
                    {
                        var revoked  = single.ReadSequence(Context1);
                        revokedAt    = revoked.ReadGeneralizedTime();
                        if (revoked.HasData)
                            reason   = revoked.ReadSequence(Context0).ReadEnumeratedValue<X509RevocationReason>();
                        certStatus   = OCSPCertStatus.Revoked;
                    }
                    else
                    {
                        single.ReadNull(Context2);
                        certStatus = OCSPCertStatus.Unknown;
                    }

                    var thisUpdate  = single.ReadGeneralizedTime();
                    var nextUpdate  = single.HasData && single.PeekTag().HasSameClassAndValue(Context0)
                                          ? single.ReadSequence(Context0).ReadGeneralizedTime()
                                          : (DateTimeOffset?) null;

                    singles.Add(new OCSPSingleResponse(new OCSPCertID(hash, nameHash, issuerKey, serial, encoded),
                                                       certStatus, revokedAt, reason, thisUpdate, nextUpdate));

                }

                Byte[]? nonce = null;

                if (responseData.HasData && responseData.PeekTag().HasSameClassAndValue(Context1))
                    nonce = NonceOf(responseData.ReadSequence(Context1).ReadSequence());

                Response = new OCSPResponse(status, keyHash, producedAt, singles, nonce, certificates, tbs, algorithm, signature);
                return true;

            }
            catch (Exception e) when (e is AsnContentException or CryptographicException or ArgumentException or InvalidCastException)
            {
                Error = $"This is no OCSP response: {e.Message}";
                return false;
            }

        }

        #endregion


        #region (private static) Helpers

        private static void WriteCertID(AsnWriter  Writer,
                                        String     HashAlgorithm,
                                        Byte[]     NameHash,
                                        Byte[]     KeyHash,
                                        String     SerialNumber)
        {

            using (Writer.PushSequence())
            {

                using (Writer.PushSequence())
                {
                    Writer.WriteObjectIdentifier(HashAlgorithm);
                    Writer.WriteNull();
                }

                Writer.WriteOctetString(NameHash);
                Writer.WriteOctetString(KeyHash);

                // Unsigned, as a serial number of RFC 5280 is: a zero in front
                // where its first bit would make it negative.
                var serial = Convert.FromHexString(RevocationReasons.NormalizedSerial(SerialNumber));
                Writer.WriteIntegerUnsigned(serial);

            }

        }

        private static void WriteNonce(AsnWriter Writer, Byte[] Nonce)
        {
            using (Writer.PushSequence())
            {
                Writer.WriteObjectIdentifier(NonceOID);
                Writer.WriteOctetString(Nonce);
            }
        }

        /// <summary>
        /// The value of the nonce among the given extensions, or null.
        /// </summary>
        private static Byte[]? NonceOf(AsnReader Extensions)
        {

            Byte[]? nonce = null;

            while (Extensions.HasData)
            {

                var extension  = Extensions.ReadSequence();
                var oid        = extension.ReadObjectIdentifier();

                if (extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                    extension.ReadBoolean();

                var value      = extension.ReadOctetString();

                if (oid == NonceOID)
                    nonce = value;

            }

            return nonce;

        }

        #endregion

    }

}
