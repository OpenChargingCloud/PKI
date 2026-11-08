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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;

using cloud.charging.open.PKI.Issuance;
using cloud.charging.open.PKI.Revocation;

#endregion

namespace cloud.charging.open.PKI
{

    /// <summary>
    /// What the PKI says of the certificates it revoked: revoking one, the CRL
    /// of each CA and the OCSP responder - and a certificate with its key as
    /// one PKCS#12 file.
    /// </summary>
    /// <remarks>
    /// <para>
    /// | | |
    /// |---|---|
    /// | <c>POST v1/pki/certificates/{id}/revoke</c> | revoke it, for good: {"reason", "issuerKeyPassword"} |
    /// | <c>POST v1/pki/certificates/{id}/crl</c> | sign the CRL of a CA anew: {"keyPassword", "validDays"} |
    /// | <c>POST v1/pki/certificates/{id}/pkcs12</c> | the certificate, its key and the sub-CAs above it as PKCS#12: {"keyPassword", "pkcs12Password", "legacy"} |
    /// | <c>GET v1/pki/revocation</c>, <c>PUT v1/pki/revocation</c> | the address the PKI is reached at, every certificate revoked, and the CRL and the responder of each CA |
    /// | <c>GET v1/pki/crl/{id}.crl</c> | the newest CRL of a CA, as DER - open to everybody |
    /// | <c>GET v1/pki/ca/{id}.crt</c> | the certificate of a CA, as DER - open to everybody |
    /// | <c>POST v1/pki/ocsp</c>, <c>GET v1/pki/ocsp/{request}</c> | the OCSP responder of RFC 6960 - open to everybody |
    /// </para>
    /// <para>
    /// The CRLs, the CAs and the responder are open to everybody, as RFC 5280
    /// and RFC 6960 have them: whoever checks a certificate does so before
    /// anything is signed in, and what they say - a CA's certificate, the
    /// serial numbers it revoked, whether one serial number is - names nobody.
    /// Everything else is behind the sign-in, as the rest of the PKI is.
    /// </para>
    /// </remarks>
    public partial class PKIHTTPAPI
    {

        #region Data

        private static readonly HTTPContentType  CRLContentType           = ContentType("application/pkix-crl");
        private static readonly HTTPContentType  CertificateContentType   = ContentType("application/pkix-cert");
        private static readonly HTTPContentType  OCSPResponseContentType  = ContentType("application/ocsp-response");

        /// <summary>
        /// How many segments the Base64 of an OCSP request asked with GET may
        /// come in - one more than the slashes in it.
        /// </summary>
        private const           Int32            MaxOCSPSegments          = 16;

        #endregion

        #region (private) RegisterRevocationURLTemplates()

        private void RegisterRevocationURLTemplates()
        {

            var root = HTTPPath.Root + "v1/pki";

            AddHandler(root + "/certificates/{id}/revoke",  PostRevoke,           HTTPMethod.POST);
            AddHandler(root + "/certificates/{id}/crl",     PostSignCRL,          HTTPMethod.POST);
            AddHandler(root + "/certificates/{id}/pkcs12",  PostPKCS12,           HTTPMethod.POST);

            AddHandler(root + "/revocation",                GetRevocation,        HTTPMethod.GET);
            AddHandler(root + "/revocation",                PutRevocation,        HTTPMethod.PUT);

            AddHandler(root + "/crl/{id}",                  GetCRL,               HTTPMethod.GET);
            AddHandler(root + "/ca/{id}",                   GetCACertificate,     HTTPMethod.GET);
            AddHandler(root + "/ocsp",                      PostOCSP,             HTTPMethod.POST);

            // Base64 has slashes of its own, and the HTTP server takes no
            // slash written as %2F: a request with them comes as several
            // segments, put together again.
            for (var segments = 1; segments <= MaxOCSPSegments; segments++)
                AddHandler(root + "/ocsp/" + String.Join("/", Enumerable.Range(1, segments).Select(segment => $"{{r{segment}}}")),
                                                            GetOCSP,              HTTPMethod.GET);

        }

        #endregion


        #region (private) PostRevoke(Request)

        /// <summary>
        /// POST /api/v1/pki/certificates/{id}/revoke: revoke a certificate for
        /// good - {"reason", "issuerKeyPassword"} - answered 200 with it.
        /// </summary>
        /// <remarks>
        /// A CA at the permission to make one, a server's or a client's
        /// certificate at the permission to sign one, as deleting them is. Each
        /// revocation is said in the log, at Notice, with who and why.
        /// </remarks>
        private Task<HTTPResponse> PostRevoke(HTTPRequest Request)
        {

            if (!TryMayRead(Request, true, out var user, out var refused))
                return Task.FromResult(refused);

            var certificate = PKI.Store.Get(IdOf(Request));

            if (certificate is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, $"There is no certificate '{IdOf(Request)}' in this PKI."));

            var required = Permission.Edit(certificate.Profile.IsCA() ? PKIAccess.Authorities : PKIAccess.Issuance);

            if (!PKI.IsAllowed(user, [ required ]))
                return Task.FromResult(RefusePermission(Request, user, [ required ], null));

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!RevocationReasons.TryParse(json.Value<String>("reason"), out var reason))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 $"'reason' is one of: {String.Join(", ", RevocationReasons.All.Select(RevocationReasons.AsText))}."));

            if (!TryReadPassword(json, "issuerKeyPassword", out var issuerKey, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            if (!PKI.Store.TryRevoke(certificate.Id, reason.Value, issuerKey, user.Id.ToString(),
                                     out var revoked, out error, out var warning, out var notFound, out var notSaved))
            {
                return Task.FromResult(NotChanged(Request, notFound ? HTTPStatusCode.NotFound : HTTPStatusCode.BadRequest, error, notSaved));
            }

            Log.Notice($"'{user.Id}' revoked the {revoked.Profile.InWords()} '{revoked.CommonName}' ({revoked.Id}) for {RevocationReasons.AsText(reason.Value)}.",
                       "pki", "security", "web");

            if (warning is not null)
                Log.Warning($"PKI: {warning}", "pki", "security");

            var details = DetailsJSON(revoked, user);
            details.Add(new JProperty("warning", warning));

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, details));

        }

        #endregion

        #region (private) PostSignCRL(Request)

        /// <summary>
        /// POST /api/v1/pki/certificates/{id}/crl: sign the CRL of a CA anew -
        /// {"keyPassword", "validDays"} - answered 200 with what it says of
        /// itself.
        /// </summary>
        private Task<HTTPResponse> PostSignCRL(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(PKIAccess.Authorities), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!TryReadPassword(json, "keyPassword", out var keyPassword, out var error) ||
                !TryReadOptional(json, "validDays",   out var validDays,   out error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error!));
            }

            if (!PKI.Store.TrySignCRL(IdOf(Request), keyPassword, validDays, out var crl, out error, out var notFound, out var notSaved))
                return Task.FromResult(NotChanged(Request, notFound ? HTTPStatusCode.NotFound : HTTPStatusCode.BadRequest, error, notSaved));

            var ca = PKI.Store.Get(IdOf(Request))!;

            Log.Notice($"'{user.Id}' signed the CRL of the {ca.Profile.InWords()} '{ca.CommonName}' ({ca.Id}) anew: number {crl.Number}, until {crl.NextUpdate:u}.",
                       "pki", "security", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, CARevocationJSON(ca)));

        }

        #endregion

        #region (private) PostPKCS12(Request)

        /// <summary>
        /// POST /api/v1/pki/certificates/{id}/pkcs12: a server's or a client's
        /// certificate with its key and the sub-CAs above it, as one PKCS#12
        /// file - {"keyPassword", "pkcs12Password", "legacy"} - answered with
        /// {"fileName", "pkcs12"}, the file as Base64.
        /// </summary>
        /// <remarks>
        /// A POST, since it carries passwords, which belong in no address. At
        /// the permission the key itself is downloaded at, and said in the log
        /// as that is.
        /// </remarks>
        private Task<HTTPResponse> PostPKCS12(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(PKIAccess.Issuance), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!TryReadPassword(json, "keyPassword",     out var keyPassword,   out var error) ||
                !TryReadPassword(json, "pkcs12Password",  out var filePassword,  out error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));
            }

            var legacy = json.Value<Boolean?>("legacy") ?? false;

            if (!PKI.Store.TryExportPKCS12(IdOf(Request), keyPassword, filePassword, legacy, out var pkcs12, out error, out var notFound))
                return Task.FromResult(ErrorJSON(Request, notFound ? HTTPStatusCode.NotFound : HTTPStatusCode.BadRequest, error));

            var certificate = PKI.Store.Get(IdOf(Request))!;

            Log.Notice($"'{user.Id}' downloaded the {certificate.Profile.InWords()} '{certificate.CommonName}' ({certificate.Id}) with its private key as PKCS#12{(legacy ? ", encrypted as older devices read it" : "")}.",
                       "pki", "security", "web");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("id",        certificate.Id),
                           new JProperty("fileName",  $"{FileNameOf(certificate.CommonName)}.p12"),
                           new JProperty("pkcs12",    Convert.ToBase64String(pkcs12)),
                           new JProperty("legacy",    legacy)
                       ))
                   );

        }

        #endregion

        #region (private) GetRevocation(Request)

        /// <summary>
        /// GET /api/v1/pki/revocation: the address the PKI is reached at and
        /// what certificates name as their CRL and OCSP responder, every
        /// certificate revoked, and the CRL and the responder of each CA.
        /// </summary>
        private Task<HTTPResponse> GetRevocation(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, RevocationJSON()));

        }

        #endregion

        #region (private) PutRevocation(Request)

        /// <summary>
        /// PUT /api/v1/pki/revocation: the address the PKI is reached at -
        /// {"publicURL"}, null or empty for none - kept in the "pki" section of
        /// the configuration file; answered 200 as GET is.
        /// </summary>
        private Task<HTTPResponse> PutRevocation(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(PKIAccess.Authorities), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var token = json["publicURL"];

            if (token is not null && token.Type is not JTokenType.Null and not JTokenType.String)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "'publicURL' is an address, such as 'http://pki.example.org', or null."));

            if (!PKI.TrySetPublicURL(token?.Value<String>(), out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            Log.Notice(PKI.Store.Addresses is RevocationAddresses addresses
                           ? $"'{user.Id}' set the address the PKI is reached at to '{addresses.PublicURL}': certificates made below a CA from now on name {addresses.OCSP} as their OCSP responder."
                           : $"'{user.Id}' took the address the PKI is reached at away: certificates made below a CA from now on name no CRL and no OCSP responder.",
                       "pki", "configuration", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, RevocationJSON()));

        }

        #endregion

        #region (private) GetCRL(Request)

        /// <summary>
        /// GET /api/v1/pki/crl/{id}.crl: the newest CRL of a CA, as DER - to
        /// everybody, as RFC 5280 has a CRL distribution point.
        /// </summary>
        private Task<HTTPResponse> GetCRL(HTTPRequest Request)
        {

            var id   = IdOf(Request, ".crl");
            var ca   = PKI.Store.Get(id);
            var crl  = ca is not null && ca.Profile.IsCA() ? PKI.Store.CRL(id) : null;

            if (crl is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, $"There is no CRL of a CA '{id}' in this PKI."));

            return Task.FromResult(Binary(Request, CRLContentType, crl, $"{FileNameOf(ca!.CommonName)}.crl", "public, max-age=3600"));

        }

        #endregion

        #region (private) GetCACertificate(Request)

        /// <summary>
        /// GET /api/v1/pki/ca/{id}.crt: the certificate of a CA, as DER - to
        /// everybody, as RFC 5280 has the "caIssuers" of a certificate's
        /// authority information access.
        /// </summary>
        private Task<HTTPResponse> GetCACertificate(HTTPRequest Request)
        {

            var id  = IdOf(Request, ".crt", ".cer", ".der");
            var ca  = PKI.Store.Get(id);

            if (ca is null || !ca.Profile.IsCA())
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, $"There is no CA '{id}' in this PKI."));

            using var certificate = PKI.Store.Load(id)!;

            return Task.FromResult(Binary(Request, CertificateContentType, certificate.RawData, $"{FileNameOf(ca.CommonName)}.crt", "public, max-age=86400"));

        }

        #endregion

        #region (private) PostOCSP(Request) / GetOCSP(Request)

        /// <summary>
        /// POST /api/v1/pki/ocsp: the answer to an OCSP request, its DER the
        /// body - RFC 6960, appendix A.1.
        /// </summary>
        private Task<HTTPResponse> PostOCSP(HTTPRequest Request)

            => Task.FromResult(OCSPAnswer(Request, Request.HTTPBody ?? []));

        /// <summary>
        /// GET /api/v1/pki/ocsp/{request}: the answer to an OCSP request, its
        /// DER as Base64 and URL-encoded in the path - what a client sends to
        /// have the answer cached on the way.
        /// </summary>
        /// <remarks>
        /// With the slashes of the Base64 as they are: the HTTP server refuses
        /// a path with "%2F" in it before it comes here, so that a client that
        /// writes them so is to POST.
        /// </remarks>
        private Task<HTTPResponse> GetOCSP(HTTPRequest Request)
        {

            Byte[] der;

            try
            {
                var text = Uri.UnescapeDataString(String.Join("/", Request.ParsedURLParameters));
                der = Convert.FromBase64String(text.Replace(' ', '+').Replace('-', '+').Replace('_', '/'));
            }
            catch (FormatException)
            {
                der = [];
            }

            return Task.FromResult(OCSPAnswer(Request, der));

        }

        private HTTPResponse OCSPAnswer(HTTPRequest Request, Byte[] DER)
        {

            Byte[] answer;

            try
            {
                answer = PKI.Store.AnswerOCSP(DER);
            }
            catch (Exception e)
            {
                Log.Error($"PKI: an OCSP request could not be answered: {e.Message}", "pki", "security");
                answer = OCSP.ErrorResponse(OCSPResponseStatus.InternalError);
            }

            return new HTTPResponse.Builder(Request) {
                       HTTPStatusCode  = HTTPStatusCode.OK,
                       ContentType     = OCSPResponseContentType,
                       Content         = answer,
                       CacheControl    = Request.HTTPMethod == HTTPMethod.GET ? "public, max-age=600" : "no-store"
                   }.WithCommonSecurityHeaders().AsImmutable;

        }

        #endregion


        #region (private) What these routes share

        /// <summary>
        /// The revocation of a certificate, for its details - or null where it
        /// was not revoked.
        /// </summary>
        private JObject? RevocationJSONOf(IssuedCertificate Certificate)

            => PKI.Store.RevocationOf(Certificate.Id)?.ToJSON();

        /// <summary>
        /// The CRL and the OCSP responder of a CA, and whether the PKI keeps
        /// them by itself - which it does where the CA's key has no password.
        /// </summary>
        private JObject CARevocationJSON(IssuedCertificate CA)
        {

            using var responder = PKI.Store.ResponderOf(CA.Id);

            return new JObject(
                       new JProperty("id",          CA.Id),
                       new JProperty("commonName",  CA.CommonName),
                       new JProperty("profile",     CA.Profile.AsText()),
                       new JProperty("automatic",   CA.HasPrivateKey && !CA.KeyEncrypted),
                       new JProperty("hasKey",      CA.HasPrivateKey),
                       new JProperty("crl",         PKI.Store.CRLInfoOf(CA.Id)?.ToJSON()),
                       new JProperty("crlURL",      PKI.Store.Addresses?.CRL(CA.Id)),
                       new JProperty("responder",   responder is null
                                                        ? null
                                                        : new JObject(
                                                              new JProperty("serialNumber",  RevocationReasons.NormalizedSerial(responder.SerialNumber)),
                                                              new JProperty("notBefore",     new DateTimeOffset(responder.NotBefore.ToUniversalTime(), TimeSpan.Zero).ToString("o", CultureInfo.InvariantCulture)),
                                                              new JProperty("notAfter",      new DateTimeOffset(responder.NotAfter. ToUniversalTime(), TimeSpan.Zero).ToString("o", CultureInfo.InvariantCulture)),
                                                              new JProperty("pem",           responder.ExportCertificatePem())
                                                          ))
                   );

        }

        private JObject RevocationJSON()

            => new (
                   new JProperty("publicURL",        PKI.Store.Addresses?.PublicURL),
                   new JProperty("ocspURL",          PKI.Store.Addresses?.OCSP),
                   new JProperty("crlURL",           PKI.Store.Addresses?.CRL("{id}")),
                   new JProperty("reasons",          new JArray(RevocationReasons.All.Select(RevocationReasons.AsText))),
                   new JProperty("crlValidDays",     (Int32) PKIStore.CRLValidity.TotalDays),
                   new JProperty("crlValidDaysWithPassword",
                                                     (Int32) PKIStore.CRLValidityWithPassword.TotalDays),
                   new JProperty("maxCRLValidDays",  PKIStore.MaxCRLValidityDays),
                   new JProperty("cas",              new JArray(PKI.Store.Find().
                                                                    Where  (certificate => certificate.Profile.IsCA()).
                                                                    OrderBy(certificate => certificate.CreatedAt).
                                                                    Select (CARevocationJSON))),
                   new JProperty("revoked",          new JArray(PKI.Store.Revoked().Select(revocation => {
                                                                    var json = revocation.ToJSON();
                                                                    json.Add(new JProperty("inPKI", PKI.Store.Get(revocation.Id) is not null));
                                                                    json.Add(new JProperty("issuer", PKI.Store.Get(revocation.IssuerId)?.CommonName));
                                                                    return json;
                                                                })))
               );

        /// <summary>
        /// The certificate the route names, as the store spells it, without the
        /// file extension it may be asked with.
        /// </summary>
        private static String IdOf(HTTPRequest Request, params String[] Extensions)
        {

            var text = Request.ParsedURLParameters.FirstOrDefault() ?? "";

            foreach (var extension in Extensions)
                if (text.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
                    text = text[..^extension.Length];

            return PKIStore.Normalized(text);

        }

        /// <summary>
        /// A common name as the name of a file: what no file system minds.
        /// </summary>
        private static String FileNameOf(String CommonName)
        {

            var name = new String(CommonName.Select(character => Char.IsLetterOrDigit(character) || character is '-' or '_' or '.' ? character : '_').ToArray()).Trim('.', '_');

            return name.Length > 0 ? name : "certificate";

        }

        private static HTTPResponse Binary(HTTPRequest      Request,
                                           HTTPContentType  ContentType,
                                           Byte[]           Content,
                                           String           FileName,
                                           String           CacheControl)

            => new HTTPResponse.Builder(Request) {
                   HTTPStatusCode      = HTTPStatusCode.OK,
                   ContentType         = ContentType,
                   Content             = Content,
                   CacheControl        = CacheControl,
                   ContentDisposition  = HTTPContentDisposition.Attachment(FileName)
               }.WithCommonSecurityHeaders().AsImmutable;

        private static HTTPContentType ContentType(String MediaType)

            => HTTPContentType.TryParse(MediaType, out var contentType)
                   ? contentType
                   : HTTPContentType.Application.OCTETSTREAM;

        #endregion

    }

}
