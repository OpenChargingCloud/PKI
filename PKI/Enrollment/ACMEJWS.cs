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

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.PKI.Enrollment
{

    /// <summary>
    /// What an ACME server answers instead of what was asked: a problem
    /// document of RFC 7807 with a type of RFC 8555, section 6.7.
    /// </summary>
    /// <param name="Status">The HTTP status.</param>
    /// <param name="Type">The last part of "urn:ietf:params:acme:error:...", "badNonce" say.</param>
    /// <param name="Detail">What went wrong, in a sentence.</param>
    public sealed class ACMEProblem(Int32   Status,
                                    String  Type,
                                    String  Detail) : Exception(Detail)
    {

        public Int32    Status       { get; } = Status;
        public String   Type         { get; } = Type;

        /// <summary>
        /// More of the answer: "algorithms" for badSignatureAlgorithm, say.
        /// </summary>
        public JObject? More         { get; init; }

        /// <summary>
        /// Where what conflicts is - the account that has the key already.
        /// </summary>
        public String?  Location     { get; init; }

        public JObject ToJSON()
        {

            var json = new JObject(
                           new JProperty("type",    $"urn:ietf:params:acme:error:{Type}"),
                           new JProperty("detail",  Message),
                           new JProperty("status",  Status)
                       );

            if (More is not null)
                json.Merge(More);

            return json;

        }

    }


    /// <summary>
    /// A request of ACME as RFC 8555, section 6.2 has it: a JWS in its
    /// flattened JSON serialization - its protected header, read, its
    /// payload, and whether a signature holds by a key.
    /// </summary>
    /// <remarks>
    /// Read here, and checked here as far as the JWS alone says: one
    /// signature, no unprotected header, an algorithm of public keys, and
    /// either a "jwk" or a "kid". Whether the nonce is fresh, the URL the one
    /// it was sent to and the key the account's is for the server to say.
    /// </remarks>
    public sealed class ACMEJWS
    {

        #region Data

        /// <summary>
        /// The algorithms of a signature a request may have: of ECDSA on the
        /// three curves of NIST, RSA with PKCS#1 v1.5 or PSS. Never "none",
        /// never a MAC (RFC 8555, section 6.2).
        /// </summary>
        public static readonly IReadOnlyList<String> Algorithms = [ "ES256", "ES384", "ES512", "RS256", "PS256" ];

        /// <summary>
        /// The algorithms of the MAC of an external account binding.
        /// </summary>
        public static readonly IReadOnlyList<String> MACAlgorithms = [ "HS256", "HS384", "HS512" ];

        /// <summary>
        /// The fewest bits of an RSA key that signs a request.
        /// </summary>
        public const Int32 MinimumRSABits = 2048;

        #endregion

        #region Properties

        /// <summary>The protected header, base64url as sent: what is signed.</summary>
        public String    ProtectedText  { get; }

        /// <summary>The payload, base64url as sent: empty for a POST-as-GET.</summary>
        public String    PayloadText    { get; }

        public Byte[]    Signature      { get; }

        public JObject   Header         { get; }

        public String    Algorithm      { get; }

        /// <summary>The key of a new account, or of a certificate revoked with it.</summary>
        public JObject?  JWK            { get; }

        /// <summary>The URL of the account that signed, for everything else.</summary>
        public String?   KeyId          { get; }

        public String?   Nonce          { get; }

        public String?   URL            { get; }

        /// <summary>The payload, read; null for a POST-as-GET.</summary>
        public JObject?  Payload        { get; }

        /// <summary>Whether this is a POST-as-GET: an empty payload (RFC 8555, section 6.3).</summary>
        public Boolean   IsPostAsGet
            => PayloadText.Length == 0;

        #endregion

        #region Constructor(s)

        private ACMEJWS(String    ProtectedText,
                        String    PayloadText,
                        Byte[]    Signature,
                        JObject   Header,
                        JObject?  Payload)
        {

            this.ProtectedText  = ProtectedText;
            this.PayloadText    = PayloadText;
            this.Signature      = Signature;
            this.Header         = Header;
            this.Payload        = Payload;
            this.Algorithm      = Header.Value<String>("alg") ?? "";
            this.JWK            = Header["jwk"] as JObject;
            this.KeyId          = Header["kid"]?.Type == JTokenType.String ? Header.Value<String>("kid") : null;
            this.Nonce          = Header["nonce"]?.Type == JTokenType.String ? Header.Value<String>("nonce") : null;
            this.URL            = Header["url"]?.Type == JTokenType.String ? Header.Value<String>("url") : null;

        }

        #endregion


        #region (static) Parse(Body, MACAllowed = false)

        /// <summary>
        /// The JWS of a request's body, or the problem with it.
        /// </summary>
        /// <param name="Body">The body, as sent.</param>
        /// <param name="MACAllowed">Whether a MAC is the algorithm looked for - as in an external account binding - rather than a signature.</param>
        public static ACMEJWS Parse(String   Body,
                                    Boolean  MACAllowed = false)
        {

            JObject json;

            try
            {
                json = JsonConvert.DeserializeObject<JObject>(Body, new JsonSerializerSettings { DateParseHandling = DateParseHandling.None, MaxDepth = 16 })
                           ?? throw new ACMEProblem(400, "malformed", "The body is no JWS.");
            }
            catch (JsonException)
            {
                throw new ACMEProblem(400, "malformed", "The body is no JSON, and so no JWS.");
            }

            return Parse(json, MACAllowed);

        }

        /// <summary>
        /// The JWS of a JSON object - the body of a request, or a JWS inside
        /// one - or the problem with it.
        /// </summary>
        public static ACMEJWS Parse(JObject  JSON,
                                    Boolean  MACAllowed = false)
        {

            if (JSON["signatures"] is not null)
                throw new ACMEProblem(400, "malformed", "A request of ACME is a flattened JWS of one signature, not a general one of several.");

            if (JSON["header"] is not null)
                throw new ACMEProblem(400, "malformed", "A request of ACME has no unprotected header (RFC 8555, section 6.2).");

            if (JSON["protected"]?.Type != JTokenType.String ||
                JSON["payload"]  ?.Type != JTokenType.String ||
                JSON["signature"]?.Type != JTokenType.String)
            {
                throw new ACMEProblem(400, "malformed", "A JWS has \"protected\", \"payload\" and \"signature\", each base64url.");
            }

            var protectedText  = JSON.Value<String>("protected")!;
            var payloadText    = JSON.Value<String>("payload")!;

            JObject header;
            JObject? payload   = null;
            Byte[]   signature;

            try
            {

                header    = JObject.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(protectedText)));
                signature = Base64Url.DecodeFromChars(JSON.Value<String>("signature")!);

                if (payloadText.Length > 0)
                {

                    var text = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(payloadText));

                    // A payload that is no object is one no resource of ACME
                    // reads - but for "{}", which is an object.
                    payload  = JsonConvert.DeserializeObject<JToken>(text, new JsonSerializerSettings { DateParseHandling = DateParseHandling.None, MaxDepth = 16 }) as JObject
                                   ?? throw new ACMEProblem(400, "malformed", "The payload is no JSON object.");

                }

            }
            catch (ACMEProblem)
            {
                throw;
            }
            catch (Exception e) when (e is FormatException or JsonException or ArgumentException)
            {
                throw new ACMEProblem(400, "malformed", "The protected header, the payload or the signature is not base64url of what it should be.");
            }

            var jws = new ACMEJWS(protectedText, payloadText, signature, header, payload);

            if (MACAllowed)
            {
                if (!MACAlgorithms.Contains(jws.Algorithm))
                    throw new ACMEProblem(400, "malformed", $"An external account binding is signed with a MAC: {String.Join(", ", MACAlgorithms)}.");
            }

            else if (!Algorithms.Contains(jws.Algorithm))
                throw new ACMEProblem(400, "badSignatureAlgorithm", $"'{jws.Algorithm}' is no algorithm this server takes: {String.Join(", ", Algorithms)}.") {
                          More = new JObject(new JProperty("algorithms", new JArray(Algorithms)))
                      };

            if (!MACAllowed && (jws.JWK is null) == (jws.KeyId is null))
                throw new ACMEProblem(400, "malformed", "A request has either a \"jwk\" or a \"kid\" in its protected header, and never both.");

            return jws;

        }

        #endregion

        #region SignedBy(JWK)

        /// <summary>
        /// Whether the signature holds by the given public key - of the kind,
        /// and the size, the algorithm asks for.
        /// </summary>
        public Boolean SignedBy(JObject JWK)
        {

            var data = Encoding.ASCII.GetBytes($"{ProtectedText}.{PayloadText}");

            switch (Algorithm)
            {

                case "ES256":
                case "ES384":
                case "ES512":
                {

                    using var key = ECKeyOf(JWK, Algorithm);
                    var hash      = Algorithm switch { "ES384" => HashAlgorithmName.SHA384, "ES512" => HashAlgorithmName.SHA512, _ => HashAlgorithmName.SHA256 };

                    return key.VerifyData(data, Signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

                }

                case "RS256":
                case "PS256":
                {

                    using var key = RSAKeyOf(JWK);

                    return key.VerifyData(data, Signature, HashAlgorithmName.SHA256,
                                          Algorithm == "PS256" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);

                }

                default:
                    return false;

            }

        }

        #endregion

        #region MACHolds(Key)

        /// <summary>
        /// Whether the MAC of an external account binding holds by its key.
        /// </summary>
        public Boolean MACHolds(Byte[] Key)
        {

            var data = Encoding.ASCII.GetBytes($"{ProtectedText}.{PayloadText}");

            var mac  = Algorithm switch {
                           "HS384" => HMACSHA384.HashData(Key, data),
                           "HS512" => HMACSHA512.HashData(Key, data),
                           _       => HMACSHA256.HashData(Key, data)
                       };

            return CryptographicOperations.FixedTimeEquals(mac, Signature);

        }

        #endregion


        #region (static) Thumbprint(JWK)

        /// <summary>
        /// The thumbprint of a public key, RFC 7638: SHA-256 of its members
        /// that matter, in the order of their names, base64url - what a key
        /// authorization ends with, and what tells accounts apart.
        /// </summary>
        public static String Thumbprint(JObject JWK)
        {

            var kty = JWK.Value<String>("kty");

            var canonical = kty switch {
                                "EC"  => $"{{\"crv\":{Quoted(JWK, "crv")},\"kty\":\"EC\",\"x\":{Quoted(JWK, "x")},\"y\":{Quoted(JWK, "y")}}}",
                                "RSA" => $"{{\"e\":{Quoted(JWK, "e")},\"kty\":\"RSA\",\"n\":{Quoted(JWK, "n")}}}",
                                _     => throw new ACMEProblem(400, "badPublicKey", $"A key of the type '{kty}' is none this server takes: EC and RSA.")
                            };

            return Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));

        }

        private static String Quoted(JObject JWK, String Member)

            => JWK[Member]?.Type == JTokenType.String
                   ? JsonConvert.ToString(JWK.Value<String>(Member)!)
                   : throw new ACMEProblem(400, "badPublicKey", $"The key has no \"{Member}\".");

        #endregion

        #region (static) Check(JWK)

        /// <summary>
        /// The key of a JWK, checked to be one this server takes - or the
        /// problem with it.
        /// </summary>
        public static void Check(JObject JWK)
        {
            switch (JWK.Value<String>("kty"))
            {

                case "EC":
                    using (ECKeyOf(JWK, null)) { }
                    break;

                case "RSA":
                    using (RSAKeyOf(JWK)) { }
                    break;

                default:
                    throw new ACMEProblem(400, "badPublicKey", "A key of ACME is of EC or of RSA.");

            }
        }

        #endregion

        #region (static) SameKey(JWK, Certificate)

        /// <summary>
        /// Whether a JWK is the public key of a certificate - what may revoke
        /// it without an account (RFC 8555, section 7.6).
        /// </summary>
        public static Boolean SameKey(JObject           JWK,
                                      X509Certificate2  Certificate)
        {

            try
            {

                Byte[] spki;

                switch (JWK.Value<String>("kty"))
                {

                    case "EC":
                        using (var key = ECKeyOf(JWK, null))
                            spki = key.ExportSubjectPublicKeyInfo();
                        break;

                    case "RSA":
                        using (var key = RSAKeyOf(JWK))
                            spki = key.ExportSubjectPublicKeyInfo();
                        break;

                    default:
                        return false;

                }

                return spki.AsSpan().SequenceEqual(Certificate.PublicKey.ExportSubjectPublicKeyInfo());

            }
            catch (ACMEProblem)
            {
                return false;
            }

        }

        #endregion

        #region (static) JWKOf(PublicKey)

        /// <summary>
        /// The JWK of a public key of EC or RSA - to tell whether the key of a
        /// CSR is the key of the account, which RFC 8555, section 11.1, forbids.
        /// </summary>
        public static JObject? JWKOf(PublicKey PublicKey)
        {

            if (PublicKey.GetECDsaPublicKey() is ECDsa ec)
            {
                using (ec)
                {

                    var parameters = ec.ExportParameters(false);

                    var curve      = parameters.Curve.Oid?.Value switch {
                                         "1.2.840.10045.3.1.7" => "P-256",
                                         "1.3.132.0.34"        => "P-384",
                                         "1.3.132.0.35"        => "P-521",
                                         _                     => null
                                     };

                    return curve is null
                               ? null
                               : new JObject(
                                     new JProperty("crv", curve),
                                     new JProperty("kty", "EC"),
                                     new JProperty("x",   Base64Url.EncodeToString(parameters.Q.X)),
                                     new JProperty("y",   Base64Url.EncodeToString(parameters.Q.Y))
                                 );

                }
            }

            if (PublicKey.GetRSAPublicKey() is RSA rsa)
            {
                using (rsa)
                {
                    var parameters = rsa.ExportParameters(false);
                    return new JObject(
                               new JProperty("e",   Base64Url.EncodeToString(parameters.Exponent)),
                               new JProperty("kty", "RSA"),
                               new JProperty("n",   Base64Url.EncodeToString(parameters.Modulus))
                           );
                }
            }

            return null;

        }

        #endregion


        #region (private static) ECKeyOf(JWK, Algorithm) / RSAKeyOf(JWK)

        private static ECDsa ECKeyOf(JObject  JWK,
                                     String?  Algorithm)
        {

            if (JWK.Value<String>("kty") != "EC")
                throw new ACMEProblem(400, "badPublicKey", $"{Algorithm} is signed with a key of EC.");

            var crv = JWK.Value<String>("crv");

            var (curve, length, algorithm) = crv switch {
                                                 "P-256" => (ECCurve.NamedCurves.nistP256, 32, "ES256"),
                                                 "P-384" => (ECCurve.NamedCurves.nistP384, 48, "ES384"),
                                                 "P-521" => (ECCurve.NamedCurves.nistP521, 66, "ES512"),
                                                 _       => throw new ACMEProblem(400, "badPublicKey", $"'{crv}' is no curve this server takes: P-256, P-384 and P-521.")
                                             };

            // RFC 7518, section 3.4: ES256 on P-256, ES384 on P-384, ES512 on P-521.
            if (Algorithm is not null && Algorithm != algorithm)
                throw new ACMEProblem(400, "badSignatureAlgorithm", $"A key of {crv} signs with {algorithm}, not with {Algorithm}.") {
                          More = new JObject(new JProperty("algorithms", new JArray(Algorithms)))
                      };

            try
            {

                var x = Base64Url.DecodeFromChars(JWK.Value<String>("x") ?? "");
                var y = Base64Url.DecodeFromChars(JWK.Value<String>("y") ?? "");

                if (x.Length != length || y.Length != length)
                    throw new ACMEProblem(400, "badPublicKey", $"A point of {crv} has coordinates of {length} bytes.");

                // ECDsa.Create checks that the point is on the curve.
                return ECDsa.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = x, Y = y } });

            }
            catch (Exception e) when (e is FormatException or CryptographicException)
            {
                throw new ACMEProblem(400, "badPublicKey", $"The key is no point of {crv}.");
            }

        }

        private static RSA RSAKeyOf(JObject JWK)
        {

            if (JWK.Value<String>("kty") != "RSA")
                throw new ACMEProblem(400, "badPublicKey", "RS256 and PS256 are signed with a key of RSA.");

            try
            {

                var n = Base64Url.DecodeFromChars(JWK.Value<String>("n") ?? "");
                var e = Base64Url.DecodeFromChars(JWK.Value<String>("e") ?? "");

                var bits = (n.Length - (n.Length > 0 && n[0] == 0 ? 1 : 0)) * 8;

                if (bits < MinimumRSABits || bits > 8192)
                    throw new ACMEProblem(400, "badPublicKey", $"A key of RSA has {MinimumRSABits} to 8192 bits, not {bits}.");

                var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });
                return rsa;

            }
            catch (Exception e) when (e is FormatException or CryptographicException)
            {
                throw new ACMEProblem(400, "badPublicKey", "The key is no key of RSA.");
            }

        }

        #endregion

    }

}
