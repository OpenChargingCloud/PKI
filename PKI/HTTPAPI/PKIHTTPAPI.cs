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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Web;

using cloud.charging.open.PKI.Issuance;

#endregion

namespace cloud.charging.open.PKI
{

    /// <summary>
    /// The JSON API the browser talks to, registered at "/api": what every
    /// node has - see <see cref="NodeHTTPAPI"/> - and below "v1/pki" what
    /// only a PKI has, its certificates and what makes more of them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The sign-in, the status and the clock, the configuration, name
    /// resolution and the time servers, the node's own certificate store, the
    /// log and the event stream are the node's, as they are every other
    /// kind's. The node's store is at "v1/certificates" and is what this PKI
    /// itself believes; what it makes is at "v1/pki/certificates", and the two
    /// are never the same list.
    /// </para>
    /// <para>
    /// | | |
    /// |---|---|
    /// | <c>GET v1/pki/certificates</c> | every certificate, <c>?commonName=</c> for those whose common name holds a text, <c>?profile=</c> for one profile |
    /// | <c>GET v1/pki/certificates/{id}</c> | one, with its PEM, its chain and how many it signed |
    /// | <c>GET v1/pki/certificates/{id}/key</c> | the private key of a server or client certificate made here |
    /// | <c>DELETE v1/pki/certificates/{id}</c> | delete it for good; <c>?withIssued=true</c> with everything it signed |
    /// | <c>POST v1/pki/rootCAs</c>, <c>POST v1/pki/subCAs</c> | a new root CA, a new sub-CA below a CA |
    /// | <c>POST v1/pki/certificates</c> | a new server or client certificate below a CA, with a key made here |
    /// | <c>POST v1/pki/csr</c>, <c>POST v1/pki/csr/inspect</c> | a certificate for the key of a CSR, and what a CSR says before that |
    /// </para>
    /// <para>
    /// Who asks with an API key of an account - a charging station's backend
    /// sending the CSR of a station, say - is let in as that account, as the
    /// node lets in every request.
    /// </para>
    /// </remarks>
    public class PKIHTTPAPI : NodeHTTPAPI
    {

        #region Properties

        /// <summary>
        /// The PKI this API speaks for.
        /// </summary>
        public PKI  PKI  { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create and register the JSON API within the given HTTP server.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server.</param>
        /// <param name="PKI">The PKI this API speaks for.</param>
        /// <param name="ExtAPI">The accounts and the groups they are in.</param>
        /// <param name="Log">Everything that happens inside this PKI.</param>
        /// <param name="APIPath">The root path of the API, the PKI's own by default.</param>
        /// <param name="Version">The version reported by the status resource.</param>
        public PKIHTTPAPI(HTTPServer  HTTPServer,
                          PKI         PKI,
                          HTTPExtAPI  ExtAPI,
                          EventLog    Log,
                          HTTPPath?   APIPath   = null,
                          String?     Version   = null)

            : base(HTTPServer,
                   PKI,
                   ExtAPI,
                   Log,
                   APIPath,
                   Version ?? typeof(PKIHTTPAPI).Assembly.GetName().Version?.ToString(3) ?? "0.0.0")

        {

            this.PKI = PKI;

            RegisterURLTemplates();

        }

        #endregion


        #region (private) RegisterURLTemplates()

        /// <summary>
        /// What only a PKI has.
        /// </summary>
        private void RegisterURLTemplates()
        {

            var root = HTTPPath.Root + "v1/pki";

            AddHandler(root + "/certificates",           GetCertificates,     HTTPMethod.GET);
            AddHandler(root + "/certificates",           PostCertificate,     HTTPMethod.POST);
            AddHandler(root + "/certificates/{id}",      GetCertificate,      HTTPMethod.GET);
            AddHandler(root + "/certificates/{id}",      DeleteCertificate,   HTTPMethod.DELETE);
            AddHandler(root + "/certificates/{id}/key",  GetPrivateKey,       HTTPMethod.GET);

            AddHandler(root + "/rootCAs",                PostRootCA,          HTTPMethod.POST);
            AddHandler(root + "/subCAs",                 PostSubCA,           HTTPMethod.POST);

            AddHandler(root + "/csr",                    PostCSR,             HTTPMethod.POST);
            AddHandler(root + "/csr/inspect",            PostCSRInspect,      HTTPMethod.POST);

        }

        #endregion


        #region (private) GetCertificates(Request)

        /// <summary>
        /// GET /api/v1/pki/certificates: every certificate of this PKI, the
        /// newest first - or those whose common name holds the text of
        /// "?commonName=", whatever its case, and those of "?profile=".
        /// </summary>
        private Task<HTTPResponse> GetCertificates(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            CertificateProfile? profile = null;

            if (Request.QueryString.GetString("profile") is String profileText && profileText.Length > 0)
            {
                if (!CertificateProfileExtensions.TryParse(profileText, out profile))
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                     $"'{profileText}' is no profile: rootCA, subCA, server or client."));
            }

            var now  = PKI.TimeProvider.GetUtcNow();
            var all  = PKI.Store.Find(Request.QueryString.GetString("commonName"), profile);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("certificates",     new JArray(all.Select(certificate => certificate.ToJSON(now)))),
                           new JProperty("total",            PKI.Store.Count),
                           new JProperty("directory",        PKI.Store.Directory),
                           new JProperty("keyAlgorithms",    new JArray(KeyAlgorithm.All.Select(algorithm => algorithm.Name))),
                           new JProperty("maxValidityDays",  PKIStore.MaxValidityDays)
                       ))
                   );

        }

        #endregion

        #region (private) GetCertificate(Request)

        /// <summary>
        /// GET /api/v1/pki/certificates/{id}: one certificate, with its PEM,
        /// the chain above it and how many it signed.
        /// </summary>
        private Task<HTTPResponse> GetCertificate(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out var user, out var refused))
                return Task.FromResult(refused);

            var certificate = PKI.Store.Get(IdOf(Request));

            if (certificate is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, $"There is no certificate '{IdOf(Request)}' in this PKI."));

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, DetailsJSON(certificate, user))
                   );

        }

        #endregion

        #region (private) GetPrivateKey(Request)

        /// <summary>
        /// GET /api/v1/pki/certificates/{id}/key: the private key of a server
        /// or client certificate this PKI made the key of, as PKCS#8 PEM.
        /// </summary>
        /// <remarks>
        /// Never the key of a CA: whoever has that signs as the CA, from
        /// anywhere and without anybody here knowing. A CA's key stays in the
        /// directory of the PKI, which whoever has to back it up has a shell
        /// on anyway. Each download is said in the log, at Notice, with who.
        /// </remarks>
        private Task<HTTPResponse> GetPrivateKey(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(PKIAccess.Issuance), false, out var user, out var refused))
                return Task.FromResult(refused);

            var certificate = PKI.Store.Get(IdOf(Request));

            if (certificate is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, $"There is no certificate '{IdOf(Request)}' in this PKI."));

            if (certificate.Profile.IsCA())
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Forbidden,
                                                 $"The private key of the {certificate.Profile.InWords()} '{certificate.CommonName}' does not leave this PKI."));

            var key = PKI.Store.PrivateKeyPEM(certificate.Id);

            if (key is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound,
                                                 certificate.FromCSR
                                                     ? $"'{certificate.CommonName}' was signed for a CSR: its private key never was here."
                                                     : $"The private key of '{certificate.CommonName}' is not in this PKI any more."));

            Log.Notice($"'{user.Id}' downloaded the private key of the {certificate.Profile.InWords()} '{certificate.CommonName}' ({certificate.Id}).",
                       "pki", "security", "web");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("id",          certificate.Id),
                           new JProperty("privateKey",  key)
                       ))
                   );

        }

        #endregion

        #region (private) DeleteCertificate(Request)

        /// <summary>
        /// DELETE /api/v1/pki/certificates/{id}: delete a certificate for good
        /// - and, with "?withIssued=true", everything it signed.
        /// </summary>
        /// <remarks>
        /// A CA is deleted at the permission to make one, a server's or a
        /// client's certificate at the permission to sign one; a CA with
        /// everything below it needs both where there is a server's or a
        /// client's among it. A CA that signed certificates still here is
        /// refused with 409 unless the request says to take them along.
        /// </remarks>
        private Task<HTTPResponse> DeleteCertificate(HTTPRequest Request)
        {

            if (!TryMayRead(Request, true, out var user, out var refused))
                return Task.FromResult(refused);

            var certificate = PKI.Store.Get(IdOf(Request));

            if (certificate is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, $"There is no certificate '{IdOf(Request)}' in this PKI."));

            var withIssued  = "true".Equals(Request.QueryString.GetString("withIssued"), StringComparison.OrdinalIgnoreCase);

            var below       = withIssued ? Below(certificate.Id) : [];
            var required    = new List<Permission>();

            if (certificate.Profile.IsCA() || below.Any(one => one.Profile.IsCA()))
                required.Add(Permission.Edit(PKIAccess.Authorities));

            if (!certificate.Profile.IsCA() || below.Any(one => !one.Profile.IsCA()))
                required.Add(Permission.Edit(PKIAccess.Issuance));

            if (!PKI.IsAllowed(user, required))
                return Task.FromResult(RefusePermission(Request, user, required, null));

            if (!PKI.Store.TryRemove(certificate.Id, withIssued, out var removed, out var error, out var notFound, out var notSaved))
                return Task.FromResult(NotChanged(Request, notFound ? HTTPStatusCode.NotFound : HTTPStatusCode.Conflict, error, notSaved));

            foreach (var one in removed)
                Log.Notice($"'{user.Id}' deleted the {one.Profile.InWords()} '{one.CommonName}' ({one.Id}) from the PKI.",
                           "pki", "security", "web");

            if (error is not null)
                Log.Warning($"PKI: {error}", "pki", "security");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("deleted",  new JArray(removed.Select(one => one.Id))),
                           new JProperty("warning",  error)
                       ))
                   );

        }

        #endregion

        #region (private) PostRootCA(Request)

        /// <summary>
        /// POST /api/v1/pki/rootCAs: a new root CA - {"subject", "keyAlgorithm",
        /// "validDays", "pathLength"} - answered 201 with the CA.
        /// </summary>
        private Task<HTTPResponse> PostRootCA(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(PKIAccess.Authorities), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!SubjectName.TryParse(json["subject"], out var subject, out var error) ||
                !TryReadKeyAlgorithm(json, KeyAlgorithm.ECC_P384, out var keyAlgorithm, out error) ||
                !TryReadInt32       (json, "validDays",  3650,    out var validDays,    out error)     ||
                !TryReadOptional    (json, "pathLength",          out var pathLength,   out error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error!));
            }

            if (!PKI.Store.TryCreateRootCA(subject, keyAlgorithm, validDays.Value, pathLength, user.Id.ToString(),
                                           out var certificate, out error, out var notSaved))
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));
            }

            return Task.FromResult(Made(Request, user, certificate, $"made the root CA '{certificate.CommonName}'"));

        }

        #endregion

        #region (private) PostSubCA(Request)

        /// <summary>
        /// POST /api/v1/pki/subCAs: a new sub-CA below a CA of this PKI -
        /// {"issuer", "subject", "keyAlgorithm", "validDays", "pathLength"} -
        /// answered 201 with the sub-CA.
        /// </summary>
        private Task<HTTPResponse> PostSubCA(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(PKIAccess.Authorities), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!TryReadIssuer      (json,                        out var issuer,       out var error) ||
                !SubjectName.TryParse(json["subject"],            out var subject,      out error)     ||
                !TryReadKeyAlgorithm(json, KeyAlgorithm.ECC_P384, out var keyAlgorithm, out error)     ||
                !TryReadInt32       (json, "validDays",  1825,    out var validDays,    out error)     ||
                !TryReadOptional    (json, "pathLength",          out var pathLength,   out error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error!));
            }

            if (!PKI.Store.TryIssue(issuer, CertificateProfile.SubCA, subject, keyAlgorithm, validDays.Value, [], pathLength, user.Id.ToString(),
                                    out var certificate, out error, out var notSaved))
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));
            }

            return Task.FromResult(Made(Request, user, certificate, $"made the sub-CA '{certificate.CommonName}' below '{IssuerName(certificate)}'"));

        }

        #endregion

        #region (private) PostCertificate(Request)

        /// <summary>
        /// POST /api/v1/pki/certificates: a new certificate for a server or a
        /// client below a CA of this PKI, with a key made here - {"issuer",
        /// "profile", "subject", "keyAlgorithm", "validDays",
        /// "subjectAlternativeNames"} - answered 201 with the certificate.
        /// </summary>
        private Task<HTTPResponse> PostCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(PKIAccess.Issuance), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!TryReadIssuer      (json,                        out var issuer,       out var error) ||
                !TryReadLeafProfile (json,                        out var profile,      out error)     ||
                !SubjectName.TryParse(json["subject"],            out var subject,      out error)     ||
                !TryReadKeyAlgorithm(json, KeyAlgorithm.ECC_P256, out var keyAlgorithm, out error)     ||
                !TryReadInt32       (json, "validDays",  365,     out var validDays,    out error)     ||
                !AlternativeNames.TryParse(json["subjectAlternativeNames"], out var names, out error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error!));
            }

            if (!PKI.Store.TryIssue(issuer, profile, subject, keyAlgorithm, validDays.Value, names, null, user.Id.ToString(),
                                    out var certificate, out error, out var notSaved))
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));
            }

            return Task.FromResult(Made(Request, user, certificate, $"made the {profile.InWords()} '{certificate.CommonName}' below '{IssuerName(certificate)}'"));

        }

        #endregion

        #region (private) PostCSR(Request)

        /// <summary>
        /// POST /api/v1/pki/csr: a certificate below a CA of this PKI for the
        /// key of a certificate signing request - {"issuer", "profile", "csr",
        /// "validDays", "subjectAlternativeNames",
        /// "takeSubjectAlternativeNames", "pathLength"} - answered 201 with the
        /// certificate.
        /// </summary>
        /// <remarks>
        /// As a server's or a client's certificate at the permission to sign
        /// one; as a sub-CA - a CA elsewhere, whose key is its own - at the
        /// permission to make a CA.
        /// </remarks>
        private Task<HTTPResponse> PostCSR(HTTPRequest Request)
        {

            if (!TryMayRead(Request, true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!CertificateProfileExtensions.TryParse(json.Value<String>("profile") ?? "client", out var profile) ||
                profile == CertificateProfile.RootCA)
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "A CSR is signed as a 'subCA', a 'server' or a 'client'."));
            }

            var required = Permission.Edit(profile.Value.IsCA() ? PKIAccess.Authorities : PKIAccess.Issuance);

            if (!PKI.IsAllowed(user, [ required ]))
                return Task.FromResult(RefusePermission(Request, user, [ required ], null));

            if (!TryReadIssuer      (json,                     out var issuer,      out var error) ||
                !TryReadInt32       (json, "validDays",  365,  out var validDays,   out error)     ||
                !TryReadOptional    (json, "pathLength",       out var pathLength,  out error)     ||
                !AlternativeNames.TryParse(json["subjectAlternativeNames"], out var names, out error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error!));
            }

            if (json["csr"]?.Type != JTokenType.String)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "'csr' is the certificate signing request, as PEM."));

            if (!PKI.Store.TryIssueFromCSR(issuer, profile.Value, json.Value<String>("csr")!, validDays.Value, names,
                                           json.Value<Boolean?>("takeSubjectAlternativeNames") ?? true,
                                           pathLength, user.Id.ToString(),
                                           out var certificate, out error, out var notSaved))
            {
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.BadRequest, error, notSaved));
            }

            return Task.FromResult(Made(Request, user, certificate, $"signed a CSR of '{certificate.CommonName}' as a {profile.Value.InWords()} below '{IssuerName(certificate)}'"));

        }

        #endregion

        #region (private) PostCSRInspect(Request)

        /// <summary>
        /// POST /api/v1/pki/csr/inspect: what a CSR says - {"csr"} - without
        /// signing anything.
        /// </summary>
        private Task<HTTPResponse> PostCSRInspect(HTTPRequest Request)
        {

            if (!TryMayRead(Request, true, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!PKIStore.TryInspectCSR(json.Value<String>("csr") ?? "", out var inspection, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, inspection.ToJSON())
                   );

        }

        #endregion


        #region (private) What every route shares

        /// <summary>
        /// Who is behind the request, when they may read the PKI - either of
        /// its two resources lets them, since the list is one list.
        /// </summary>
        private Boolean TryMayRead(HTTPRequest                                         Request,
                                   Boolean                                             StateChanging,
                                   [NotNullWhen(true)]  out IUser?         User,
                                   [NotNullWhen(false)] out HTTPResponse?              Refused)
        {

            if (!TryAuthorize(Request, [], StateChanging, out User, out Refused))
                return false;

            if (PKI.IsAllowed(User, [ Permission.Read(PKIAccess.Issuance) ]) ||
                PKI.IsAllowed(User, [ Permission.Read(PKIAccess.Authorities) ]))
            {
                return true;
            }

            Refused = RefusePermission(Request, User, [ Permission.Read(PKIAccess.Issuance) ], null);
            User    = null;
            return false;

        }

        /// <summary>
        /// The certificate the route names, as the store spells it.
        /// </summary>
        private static String IdOf(HTTPRequest Request)

            => Request.ParsedURLParameters.Length > 0
                   ? PKIStore.Normalized(Request.ParsedURLParameters[0])
                   : "";

        /// <summary>
        /// Everything below a certificate, all the way down.
        /// </summary>
        private List<IssuedCertificate> Below(String Id)
        {

            var below = new List<IssuedCertificate>();
            var queue = new Queue<String>([ Id ]);

            while (queue.TryDequeue(out var next))
            {
                foreach (var issued in PKI.Store.IssuedBy(next))
                {
                    if (below.All(one => one.Id != issued.Id))
                    {
                        below.Add(issued);
                        queue.Enqueue(issued.Id);
                    }
                }
            }

            return below;

        }

        /// <summary>
        /// The common name of a certificate's CA, or its distinguished name
        /// where the store does not have it any more.
        /// </summary>
        private String IssuerName(IssuedCertificate Certificate)

            => Certificate.IssuerId is not null && PKI.Store.Get(Certificate.IssuerId) is IssuedCertificate issuer
                   ? issuer.CommonName
                   : Certificate.Issuer;

        /// <summary>
        /// One certificate, as the details of the web interface show it: what
        /// the list says, its PEM and the chain above it, what it signed, and
        /// whether whoever asks may have its key.
        /// </summary>
        private JObject DetailsJSON(IssuedCertificate                                  Certificate,
                                    IUser                                              User)
        {

            var json   = Certificate.ToJSON(PKI.TimeProvider.GetUtcNow());
            var chain  = PKI.Store.Chain(Certificate.Id);

            json.Add(new JProperty("pem",          PKI.Store.CertificatePEM(Certificate.Id)));
            json.Add(new JProperty("chainPem",     PKI.Store.ChainPEM(Certificate.Id)));
            json.Add(new JProperty("chain",        new JArray(chain.Select(one => new JObject(
                                                                   new JProperty("id",          one.Id),
                                                                   new JProperty("commonName",  one.CommonName),
                                                                   new JProperty("profile",     one.Profile.AsText())
                                                               )))));
            json.Add(new JProperty("issuedCount",  PKI.Store.IssuedBy(Certificate.Id).Count));
            json.Add(new JProperty("belowCount",   Below(Certificate.Id).Count));

            // Said rather than left to the page to work out: the key of a CA
            // is never handed out, whoever asks.
            json.Add(new JProperty("mayDownloadPrivateKey",
                                   Certificate.HasPrivateKey &&
                                   !Certificate.Profile.IsCA() &&
                                   PKI.IsAllowed(User, [ Permission.Edit(PKIAccess.Issuance) ])));

            return json;

        }

        /// <summary>
        /// The answer to a certificate made: 201 with its details, and a line
        /// in the log at Notice saying who made what.
        /// </summary>
        private HTTPResponse Made(HTTPRequest                                   Request,
                                  IUser                                         User,
                                  IssuedCertificate                             Certificate,
                                  String                                        What)
        {

            Log.Notice($"'{User.Id}' {What} ({Certificate.Id}), valid until {Certificate.NotAfter:u}.",
                       "pki", "security", "web");

            return JSONResponse(Request, HTTPStatusCode.Created, DetailsJSON(Certificate, User));

        }

        #endregion

        #region (private static) Reading a request

        private static Boolean TryReadIssuer(JObject                           JSON,
                                             [NotNullWhen(true)]  out String?  Issuer,
                                             [NotNullWhen(false)] out String?  Error)
        {

            Issuer = JSON.Value<String>("issuer")?.Trim();
            Error  = String.IsNullOrEmpty(Issuer) ? "'issuer' is the fingerprint of the CA that signs it." : null;

            return Error is null;

        }

        private static Boolean TryReadLeafProfile(JObject                           JSON,
                                                  out CertificateProfile            Profile,
                                                  [NotNullWhen(false)] out String?  Error)
        {

            Profile = CertificateProfile.Client;
            Error   = null;

            if (CertificateProfileExtensions.TryParse(JSON.Value<String>("profile"), out var profile) &&
                profile is CertificateProfile.Server or CertificateProfile.Client)
            {
                Profile = profile.Value;
                return true;
            }

            Error = "'profile' is 'server' or 'client'.";
            return false;

        }

        private static Boolean TryReadKeyAlgorithm(JObject                                 JSON,
                                                   KeyAlgorithm                            Default,
                                                   [NotNullWhen(true)]  out KeyAlgorithm?  KeyAlgorithm,
                                                   [NotNullWhen(false)] out String?        Error)
        {

            Error = null;

            var text = JSON.Value<String>("keyAlgorithm");

            if (String.IsNullOrWhiteSpace(text))
            {
                KeyAlgorithm = Default;
                return true;
            }

            if (Issuance.KeyAlgorithm.TryParse(text, out KeyAlgorithm))
                return true;

            Error = $"'{text}' is no key algorithm of this PKI: {String.Join(", ", Issuance.KeyAlgorithm.All.Select(algorithm => algorithm.Name))}.";
            return false;

        }

        private static Boolean TryReadInt32(JObject                           JSON,
                                            String                            Key,
                                            Int32                             Default,
                                            [NotNullWhen(true)]  out Int32?   Value,
                                            [NotNullWhen(false)] out String?  Error)
        {

            if (!TryReadOptional(JSON, Key, out Value, out Error))
                return false;

            Value ??= Default;
            return true;

        }

        private static Boolean TryReadOptional(JObject                           JSON,
                                               String                            Key,
                                               out Int32?                        Value,
                                               [NotNullWhen(false)] out String?  Error)
        {

            Value = null;
            Error = null;

            var token = JSON[Key];

            if (token is null || token.Type == JTokenType.Null)
                return true;

            if (token.Type == JTokenType.Integer)
            {
                Value = token.Value<Int32>();
                return true;
            }

            Error = $"'{Key}' is a whole number.";
            return false;

        }

        #endregion

    }

}
