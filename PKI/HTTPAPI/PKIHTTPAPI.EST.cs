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
using System.Text;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;

using cloud.charging.open.PKI.Enrollment;
using cloud.charging.open.PKI.Issuance;

#endregion

namespace cloud.charging.open.PKI
{

    /// <summary>
    /// Enrollment over Secure Transport, RFC 7030: the CSR of a charging
    /// station - or of whatever asks - signed without anybody at the web
    /// interface, at "/.well-known/est" of the PKI's HTTP server; and below
    /// "v1/pki/est" of the JSON API, what it signs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// | | |
    /// |---|---|
    /// | <c>GET /.well-known/est[/&lt;label&gt;]/cacerts</c> | the CA that signs and those above it, as a certs-only PKCS#7 - to everybody |
    /// | <c>POST /.well-known/est[/&lt;label&gt;]/simpleenroll</c> | a CSR signed: a PKCS#10 in Base64 in, the certificate as a certs-only PKCS#7 in Base64 out |
    /// | <c>POST /.well-known/est[/&lt;label&gt;]/simplereenroll</c> | the same, for whoever renews a certificate of this PKI |
    /// | <c>POST /.well-known/est[/&lt;label&gt;]/serverkeygen</c> | where it is allowed, and over HTTPS only: a CSR's subject and names signed for a key made here, and the key with the certificate, as multipart/mixed |
    /// | <c>GET /.well-known/est[/&lt;label&gt;]/csrattrs</c> | below a CA of ISO 15118, a key of secp256r1 and ECDSA with SHA-256; 204 otherwise: nothing in particular is asked of a CSR |
    /// | <c>GET v1/pki/est</c>, <c>PUT v1/pki/est</c> | what EST signs, and whether a TLS client certificate is asked for |
    /// </para>
    /// <para>
    /// Who enrolls shows who they are as everybody at the JSON API does - an
    /// API key, or HTTP Basic - as an account that may sign certificates of
    /// servers and clients: a backend of charging stations in the "registrar"
    /// role, say. Who re-enrolls may also show the certificate it renews, as
    /// its TLS client certificate, where the PKI speaks HTTPS of its own and
    /// asks for one: the certificate must be one of this PKI, valid and not
    /// revoked, and the CSR must be for the same subject and the same names.
    /// </para>
    /// <para>
    /// What a CSR is signed as is what the label says, whatever the CSR asks
    /// for - its subject and its names are taken, nothing else, as at "Sign a
    /// CSR". The CA signs without anybody there, so a CA whose key has a
    /// password signs nothing over EST.
    /// </para>
    /// <para>
    /// Below a CA of ISO 15118, EST signs what that CA signs - a SECC
    /// certificate below one of V2G, the certificate of its own domain below
    /// every other - with the DomainComponent first in its subject, without
    /// the names the CSR asks for, and for a key of secp256r1 only, which
    /// "csrattrs" asks for: where a CSMS sends the CSR of a charging
    /// station's V2GCertificate, OCPP 2.0.1.
    /// </para>
    /// <para>
    /// "serverkeygen" is for a station that cannot make a key of its own: the
    /// key of its CSR, and the signature, only carry the subject, RFC 7030,
    /// section 4.4.1, and the PKI makes the key - of the kind the CSR was
    /// signed with, where it makes those - and hands it back unencrypted
    /// beside the certificate. Over HTTPS only, the PKI's own or that of a
    /// trusted proxy in front: a private key does not go over plain HTTP. The
    /// key is kept in the PKI as every key it makes, for whoever may download
    /// keys. Who may ask is who may enroll or re-enroll.
    /// </para>
    /// </remarks>
    public partial class PKIHTTPAPI
    {

        #region Data

        /// <summary>
        /// Where RFC 7030, section 3.2.2, puts EST.
        /// </summary>
        public const            String           ESTPath                = "/.well-known/est";

        private static readonly HTTPContentType  PKCS7ContentType       = ContentType("application/pkcs7-mime");

        private static readonly String           PKCS7ContentTypeText   = "application/pkcs7-mime; smime-type=certs-only";

        private static readonly HTTPContentType  MultipartContentType   = ContentType("multipart/mixed");

        private static readonly HTTPContentType  CSRAttributesContentType = ContentType("application/csrattrs");

        #endregion

        #region (private) RegisterESTURLTemplates()

        private void RegisterESTURLTemplates()
        {

            AddHandler(HTTPPath.Root + "v1/pki/est",  GetEST,  HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/pki/est",  PutEST,  HTTPMethod.PUT);

            HTTPAPI est;

            try
            {
                est = PKI.HTTPServer.AddHTTPAPI(HTTPPath.Parse(ESTPath));
            }
            catch (ArgumentException e)
            {
                Log.Warning($"PKI: EST could not be served at '{ESTPath}': {e.Message}", "pki", "est");
                return;
            }

            foreach (var label in new[] { "", "{label}/" })
            {
                est.AddHandler(HTTPPath.Root + label + "cacerts",         ESTCACerts,          HTTPMethod.GET);
                est.AddHandler(HTTPPath.Root + label + "simpleenroll",    ESTSimpleEnroll,     HTTPMethod.POST);
                est.AddHandler(HTTPPath.Root + label + "simplereenroll",  ESTSimpleReenroll,   HTTPMethod.POST);
                est.AddHandler(HTTPPath.Root + label + "serverkeygen",    ESTServerKeyGen,     HTTPMethod.POST);
                est.AddHandler(HTTPPath.Root + label + "csrattrs",        ESTCSRAttributes,    HTTPMethod.GET);
            }

        }

        #endregion


        #region (private) GetEST(Request) / PutEST(Request)

        /// <summary>
        /// GET /api/v1/pki/est: what EST signs, where it is, and whether a TLS
        /// client certificate is asked for.
        /// </summary>
        private Task<HTTPResponse> GetEST(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, ESTJSON()));

        }

        /// <summary>
        /// PUT /api/v1/pki/est: what EST signs - {"issuer", "profile",
        /// "validDays", "labels", "tlsClientCertificates",
        /// "serverKeyGeneration"} - kept in the "pki" section of the
        /// configuration file; answered as GET is.
        /// </summary>
        /// <remarks>
        /// At the permission to make CAs: it has a CA sign without anybody
        /// there, for whoever an account of the PKI vouches for.
        /// </remarks>
        private Task<HTTPResponse> PutEST(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(PKIAccess.Authorities), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!ESTSettings.TryParse(json, out var settings, out var error, PKI.Store.Get) ||
                !PKI.TrySetEST(settings, out error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));
            }

            Log.Notice(settings.Enabled
                           ? $"'{user.Id}' set what EST signs: {DescribeEST(settings)}."
                           : $"'{user.Id}' set EST to sign nothing.",
                       "pki", "est", "configuration", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, ESTJSON()));

        }

        private JObject ESTJSON()
        {

            var settings  = PKI.EST;
            var json      = settings.ToJSON();
            var cas       = new JArray();

            foreach (var issuerId in new[] { settings.Default?.IssuerId }.Concat(settings.Labels.Values.Select(profile => profile.IssuerId)).OfType<String>().Distinct())
            {
                var ca = PKI.Store.Get(issuerId);
                cas.Add(new JObject(
                            new JProperty("id",            issuerId),
                            new JProperty("commonName",    ca?.CommonName),
                            new JProperty("problem",       ProblemOf(issuerId))
                        ));
            }

            json.Add(new JProperty("enabled",   settings.Enabled));
            json.Add(new JProperty("path",      ESTPath));
            json.Add(new JProperty("https",     PKI.HTTPS));
            json.Add(new JProperty("issuers",   cas));

            return json;

        }

        private String DescribeEST(ESTSettings Settings)

            => String.Join("; ", new[] { (Label: (String?) null, Profile: Settings.Default) }.
                                     Concat(Settings.Labels.Select(label => (Label: (String?) label.Key, Profile: (ESTProfile?) label.Value))).
                                     Where (one => one.Profile is not null).
                                     Select(one => $"{(one.Label is null ? "without a label" : $"'{one.Label}'")} as a {one.Profile!.InWords} of {one.Profile.ValidDays} days below '{PKI.Store.Get(one.Profile.IssuerId)?.CommonName ?? one.Profile.IssuerId}'"));

        /// <summary>
        /// Why the given CA signs nothing over EST, or null where it does.
        /// </summary>
        private String? ProblemOf(String IssuerId)
        {

            var ca = PKI.Store.Get(IssuerId);

            if (ca is null || !ca.Profile.IsCA())
                return "It is no CA of this PKI.";

            if (!ca.HasPrivateKey)
                return "Its private key is not in this PKI.";

            if (ca.KeyEncrypted)
                return "Its private key has a password, and EST signs without anybody there to give it.";

            var status = ca.StatusAt(PKI.TimeProvider.GetUtcNow());

            return status == "valid"
                       ? null
                       : $"It is {status}.";

        }

        #endregion


        #region (private) ESTCACerts(Request)

        /// <summary>
        /// GET /.well-known/est[/label]/cacerts: the CA that signs for the
        /// label and every CA above it, up to its root - RFC 7030, section 4.1.
        /// </summary>
        private Task<HTTPResponse> ESTCACerts(HTTPRequest Request)
        {

            var profile = PKI.EST.For(LabelOf(Request));

            if (profile is null)
                return Task.FromResult(ESTError(Request, HTTPStatusCode.NotFound, NoEST(Request)));

            var chain = PKI.Store.Chain(profile.IssuerId).Select(one => PKI.Store.Load(one.Id)).OfType<X509Certificate2>().ToList();

            try
            {

                if (chain.Count == 0)
                    return Task.FromResult(ESTError(Request, HTTPStatusCode.ServiceUnavailable, $"The CA of EST, '{profile.IssuerId}', is not in this PKI."));

                return Task.FromResult(PKCS7Response(Request, PKCS7.CertsOnly(chain)));

            }
            finally
            {
                foreach (var certificate in chain)
                    certificate.Dispose();
            }

        }

        #endregion

        #region (private) ESTCSRAttributes(Request)

        /// <summary>
        /// GET /.well-known/est[/label]/csrattrs: what is asked of a CSR, RFC
        /// 7030, section 4.5.2 - for a certificate of ISO 15118, a key of
        /// secp256r1 and a signature of ECDSA with SHA-256; for every other,
        /// nothing in particular, 204.
        /// </summary>
        private Task<HTTPResponse> ESTCSRAttributes(HTTPRequest Request)
        {

            var profile = PKI.EST.For(LabelOf(Request));

            if (profile is null)
                return Task.FromResult(ESTError(Request, HTTPStatusCode.NotFound, NoEST(Request)));

            if (profile.V2G is null)
                return Task.FromResult(new HTTPResponse.Builder(Request) {
                                           HTTPStatusCode  = HTTPStatusCode.NoContent,
                                           CacheControl    = "no-store"
                                       }.WithCommonSecurityHeaders().AsImmutable);

            return Task.FromResult(new HTTPResponse.Builder(Request) {
                                       HTTPStatusCode  = HTTPStatusCode.OK,
                                       ContentType     = CSRAttributesContentType,
                                       Content         = Encoding.ASCII.GetBytes(Convert.ToBase64String(ISO15118CSRAttributes(), Base64FormattingOptions.InsertLineBreaks) + "\r\n"),
                                       CacheControl    = "no-store"
                                   }.Set("Content-Transfer-Encoding", "base64").
                                     WithCommonSecurityHeaders().AsImmutable);

        }

        /// <summary>
        /// The CsrAttrs of RFC 7030, section 4.5.2, that ask for what ISO
        /// 15118-2 signs: ecdsa-with-SHA256, and an id-ecPublicKey of secp256r1
        /// - as the example of RFC 7030, section 4.5.2, asks for P-384.
        /// </summary>
        private static Byte[] ISO15118CSRAttributes()
        {

            var writer = new AsnWriter(AsnEncodingRules.DER);

            using (writer.PushSequence())
            {

                writer.WriteObjectIdentifier("1.2.840.10045.4.3.2");          // ecdsa-with-SHA256

                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("1.2.840.10045.2.1");        // id-ecPublicKey
                    using (writer.PushSetOf())
                        writer.WriteObjectIdentifier("1.2.840.10045.3.1.7");  // secp256r1
                }

            }

            return writer.Encode();

        }

        #endregion

        #region (private) ESTSimpleEnroll(Request) / ESTSimpleReenroll(Request)

        /// <summary>
        /// POST /.well-known/est[/label]/simpleenroll: a CSR signed, RFC 7030,
        /// section 4.2.1.
        /// </summary>
        private Task<HTTPResponse> ESTSimpleEnroll(HTTPRequest Request)
            => Task.FromResult(Enroll(Request, Renewal: false));

        /// <summary>
        /// POST /.well-known/est[/label]/simplereenroll: a certificate of this
        /// PKI renewed, RFC 7030, section 4.2.2.
        /// </summary>
        private Task<HTTPResponse> ESTSimpleReenroll(HTTPRequest Request)
            => Task.FromResult(Enroll(Request, Renewal: true));

        /// <summary>
        /// POST /.well-known/est[/label]/serverkeygen: a CSR's subject and names
        /// signed for a key made here, RFC 7030, section 4.4 - a renewal, where
        /// the certificate renewed is the TLS client certificate.
        /// </summary>
        private Task<HTTPResponse> ESTServerKeyGen(HTTPRequest Request)
            => Task.FromResult(Enroll(Request, Renewal: false, ServerKeyGen: true));

        private HTTPResponse Enroll(HTTPRequest  Request,
                                    Boolean      Renewal,
                                    Boolean      ServerKeyGen = false)
        {

            var label    = LabelOf(Request);
            var profile  = PKI.EST.For(label);

            if (profile is null)
                return ESTError(Request, HTTPStatusCode.NotFound, NoEST(Request));

            if (ServerKeyGen && !PKI.EST.ServerKeyGeneration)
                return ESTError(Request, HTTPStatusCode.NotImplemented, "EST makes no keys here: a station makes its own, and sends its CSR to simpleenroll.");

            if (ServerKeyGen && !PKI.ReachedOverHTTPS(Request))
                return ESTError(Request, HTTPStatusCode.Forbidden, "A private key goes out over HTTPS only, and this request came over plain HTTP.");

            if (Request.ContentType?.MediaType is not "application/pkcs10")
                return ESTError(Request, HTTPStatusCode.UnsupportedMediaType, "A CSR is sent as application/pkcs10: a PKCS#10 in Base64.");

            #region Who asks: a certificate of this PKI it renews, or an account

            String               who;
            IssuedCertificate?   renewed = null;

            if ((Renewal || ServerKeyGen) && Request.ClientCertificate is X509Certificate2 clientCertificate)
            {

                renewed = PKI.Store.Get(clientCertificate.GetCertHashString(HashAlgorithmName.SHA256));

                if (renewed is null || renewed.Profile.IsCA() || renewed.StatusAt(PKI.TimeProvider.GetUtcNow()) != "valid")
                    return ESTError(Request, HTTPStatusCode.Forbidden,
                                    renewed is null
                                        ? "The TLS client certificate is no certificate of this PKI."
                                        : $"The TLS client certificate is {renewed.StatusAt(PKI.TimeProvider.GetUtcNow())}, and renews nothing.");

                who = $"the {renewed.Profile.InWords()} '{renewed.CommonName}' ({renewed.Id})";

            }

            else
            {

                if (RefuseCrossSite(Request, PKI.ProxyHostOf(Request)) is HTTPResponse crossSite)
                    return crossSite;

                if (!ExtAPI.TryGetHTTPUser(Request, out var user) || user is null)
                    return new HTTPResponse.Builder(Request) {
                               HTTPStatusCode   = HTTPStatusCode.Unauthorized,
                               ContentType      = HTTPContentType.Text.PLAIN,
                               Content          = Encoding.UTF8.GetBytes(Renewal
                                                                            ? "Sign in with an API key or HTTP Basic, or show the certificate to renew as the TLS client certificate."
                                                                            : "Sign in with an API key or HTTP Basic."),
                               WWWAuthenticate  = WWWAuthenticate.Basic("EST"),
                               CacheControl     = "no-store"
                           }.WithCommonSecurityHeaders().AsImmutable;

                var required = Permission.Edit(PKIAccess.Issuance);

                if (!PKI.IsAllowed(user, [ required ]))
                    return ESTError(Request, HTTPStatusCode.Forbidden, $"'{user.Id}' may sign no certificate of a server or a client.");

                who = $"'{user.Id}'";

            }

            #endregion

            #region The CSR, and what a renewal must keep

            if (!TryReadCSR(Request.HTTPBody ?? [], out var csr))
                return ESTError(Request, HTTPStatusCode.BadRequest, "The body is no PKCS#10 in Base64.");

            if (!PKIStore.TryInspectCSR(csr, out var inspection, out var error))
                return ESTError(Request, HTTPStatusCode.BadRequest, error);

            // Where the PKI makes the key, the CSR's key and signature only
            // carry the subject, and are not looked at: RFC 7030, 4.4.1.
            if (!inspection.SignatureValid && !ServerKeyGen)
                return ESTError(Request, HTTPStatusCode.BadRequest, "The signature of the CSR does not hold.");

            if (renewed is not null)
            {

                using var current  = PKI.Store.Load(renewed.Id)!;

                // A certificate of ISO 15118 has no other names, and the
                // DomainComponent first in its subject, where the CSR may
                // name none: it is renewed for the subject it would be given.
                var sameNames      = profile.V2G is not null ||
                                     new HashSet<String>(inspection.SubjectAlternativeNames, StringComparer.OrdinalIgnoreCase).
                                         SetEquals(AlternativeNames.Of(current));

                if (SubjectAsSigned(inspection.Subject, profile.V2G) != current.SubjectName.Name || !sameNames)
                    return ESTError(Request, HTTPStatusCode.BadRequest,
                                    "A certificate is renewed for the subject and the names it has: the CSR asks for others.");

                if (renewed.Profile != profile.Profile || renewed.V2G != profile.V2G)
                    return ESTError(Request, HTTPStatusCode.BadRequest,
                                    $"The {renewed.InWords} '{renewed.CommonName}' is not renewed as a {profile.InWords}{(label is null ? "" : $" at the label '{label}'")}.");

            }

            #endregion

            if (ProblemOf(profile.IssuerId) is String problem)
                return ESTError(Request, HTTPStatusCode.ServiceUnavailable, $"The CA of EST signs nothing: {problem}");

            var createdBy   = renewed is null ? $"{who.Trim('\'')} (EST)" : $"EST, renewing {renewed.Id}";

            IssuedCertificate?  certificate;
            Byte[]?             privateKey  = null;
            Boolean             notSaved;

            var signed      = ServerKeyGen
                                  ? PKI.Store.TryIssueWithKeyFor(profile.IssuerId, null, profile.Profile, csr, profile.ValidDays, createdBy,
                                                                 out certificate, out privateKey, out error, out notSaved, profile.V2G)
                                  : PKI.Store.TryIssueFromCSR   (profile.IssuerId, null, profile.Profile, csr, profile.ValidDays, [], true, null, createdBy,
                                                                 out certificate, out error, out notSaved, profile.V2G);

            if (!signed || certificate is null)
                return ESTError(Request, notSaved ? HTTPStatusCode.InternalServerError : HTTPStatusCode.BadRequest, error ?? "Nothing was signed.");

            Log.Notice($"EST: {who} {(Renewal || renewed is not null ? "re-enrolled" : "enrolled")} the {certificate.InWords} '{certificate.CommonName}' ({certificate.Id}) " +
                       $"below '{PKI.Store.Get(profile.IssuerId)?.CommonName}'{(label is null ? "" : $" at the label '{label}'")}" +
                       $"{(ServerKeyGen ? ", with a key the PKI made" : "")}, valid until {certificate.NotAfter:u}.",
                       "pki", "est", "security");

            using var issued = PKI.Store.Load(certificate.Id)!;

            return privateKey is null
                       ? PKCS7Response(Request, PKCS7.CertsOnly([ issued ]))
                       : KeyAndCertificateResponse(Request, privateKey, PKCS7.CertsOnly([ issued ]));

        }

        #endregion


        #region (private) What EST shares

        /// <summary>
        /// The subject of a CSR as the certificate is signed with it: for one
        /// of ISO 15118, with the DomainComponent of its domain first.
        /// </summary>
        private static String SubjectAsSigned(String      Subject,
                                              V2GDomain?  V2G)
        {

            if (V2G is not V2GDomain domain)
                return Subject;

            try
            {
                return ISO15118.TryWithDomainComponent(new X500DistinguishedName(Subject), domain, out var withIt, out _)
                           ? withIt.Name
                           : Subject;
            }
            catch (CryptographicException)
            {
                return Subject;
            }

        }

        private static String? LabelOf(HTTPRequest Request)

            => Request.ParsedURLParameters.Length > 0
                   ? Request.ParsedURLParameters[0]
                   : null;

        private String NoEST(HTTPRequest Request)

            => LabelOf(Request) is String label
                   ? $"EST has no label '{label}'."
                   : PKI.EST.Enabled
                         ? "EST signs at its labels only."
                         : "EST signs nothing here: the PKI was told no CA to sign with.";

        /// <summary>
        /// A CSR as Base64 - what RFC 7030 sends - or as PEM or DER, which some
        /// clients send instead.
        /// </summary>
        private static Boolean TryReadCSR(Byte[] Body, out String CSR)
        {

            CSR = "";

            if (Body.Length == 0)
                return false;

            if (Body[0] == 0x30)
            {
                CSR = Convert.ToBase64String(Body);
                return true;
            }

            var text = Encoding.ASCII.GetString(Body).Trim();

            if (text.Contains("-----BEGIN", StringComparison.Ordinal))
            {
                CSR = text;
                return true;
            }

            CSR = new String(text.Where(character => !Char.IsWhiteSpace(character)).ToArray());
            return CSR.Length > 0;

        }

        private static HTTPResponse PKCS7Response(HTTPRequest  Request,
                                                  Byte[]       PKCS7)

            => new HTTPResponse.Builder(Request) {
                   HTTPStatusCode  = HTTPStatusCode.OK,
                   ContentType     = PKCS7ContentType,
                   Content         = Encoding.ASCII.GetBytes(Convert.ToBase64String(PKCS7, Base64FormattingOptions.InsertLineBreaks) + "\r\n"),
                   CacheControl    = "no-store"
               }.Set("Content-Type",               PKCS7ContentTypeText).
                 Set("Content-Transfer-Encoding",  "base64").
                 WithCommonSecurityHeaders().AsImmutable;

        /// <summary>
        /// The answer of serverkeygen, RFC 7030, section 4.4.2: multipart/mixed
        /// of the key - PKCS#8 in Base64, unencrypted, where TLS is what
        /// protects it - and the certificate, as a certs-only PKCS#7 in Base64.
        /// </summary>
        private static HTTPResponse KeyAndCertificateResponse(HTTPRequest  Request,
                                                              Byte[]       PrivateKey,
                                                              Byte[]       PKCS7)
        {

            var boundary = "est-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();

            var body = new StringBuilder().
                           Append("--").Append(boundary).Append("\r\n").
                           Append("Content-Type: application/pkcs8\r\n").
                           Append("Content-Transfer-Encoding: base64\r\n\r\n").
                           Append(Convert.ToBase64String(PrivateKey, Base64FormattingOptions.InsertLineBreaks)).Append("\r\n").
                           Append("--").Append(boundary).Append("\r\n").
                           Append("Content-Type: ").Append(PKCS7ContentTypeText).Append("\r\n").
                           Append("Content-Transfer-Encoding: base64\r\n\r\n").
                           Append(Convert.ToBase64String(PKCS7, Base64FormattingOptions.InsertLineBreaks)).Append("\r\n").
                           Append("--").Append(boundary).Append("--\r\n").
                           ToString();

            // Not even the bytes of the key stay where they need not.
            CryptographicOperations.ZeroMemory(PrivateKey);

            return new HTTPResponse.Builder(Request) {
                       HTTPStatusCode  = HTTPStatusCode.OK,
                       ContentType     = MultipartContentType,
                       Content         = Encoding.ASCII.GetBytes(body),
                       CacheControl    = "no-store"
                   }.Set("Content-Type", $"multipart/mixed; boundary={boundary}").
                     WithCommonSecurityHeaders().AsImmutable;

        }

        private static HTTPResponse ESTError(HTTPRequest     Request,
                                             HTTPStatusCode  StatusCode,
                                             String          Message)

            => new HTTPResponse.Builder(Request) {
                   HTTPStatusCode  = StatusCode,
                   ContentType     = HTTPContentType.Text.PLAIN,
                   Content         = Encoding.UTF8.GetBytes(Message),
                   CacheControl    = "no-store"
               }.WithCommonSecurityHeaders().AsImmutable;

        #endregion

    }

}
