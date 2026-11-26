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
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;

using cloud.charging.open.PKI.Enrollment;
using cloud.charging.open.PKI.Issuance;
using cloud.charging.open.PKI.Revocation;

#endregion

namespace cloud.charging.open.PKI
{

    /// <summary>
    /// The Automatic Certificate Management Environment, RFC 8555: the
    /// certificate of a server - of a CSMS, a gateway, a time server, a web
    /// interface - signed for whoever proves that the names are theirs, and
    /// renewed by its ACME client without anybody there, at "/acme" of the
    /// PKI's HTTP server; and below "v1/pki/acme" of the JSON API, what it
    /// signs and for whom.
    /// </summary>
    /// <remarks>
    /// <para>
    /// | | |
    /// |---|---|
    /// | <c>GET /acme/directory</c> | where everything else is, RFC 8555, section 7.1.1 - what a client is pointed at |
    /// | <c>HEAD, GET /acme/new-nonce</c> | a nonce for the next request |
    /// | <c>POST /acme/new-account</c>, <c>/acme/acct/{id}</c>, <c>/acme/acct/{id}/orders</c>, <c>/acme/key-change</c> | an account: opened - with an external account binding where the PKI asks for one - found, changed, deactivated, its orders, a new key for it |
    /// | <c>POST /acme/new-order</c>, <c>/acme/order/{id}</c>, <c>/acme/finalize/{id}</c> | an order for names - "dns", wildcards among them, and "ip" of RFC 8738 - and its CSR signed once every name is proven |
    /// | <c>POST /acme/authz/{id}</c>, <c>/acme/chall/{id}</c> | what proves a name: http-01 and dns-01 |
    /// | <c>POST /acme/cert/{id}</c> | the certificate, with the sub-CAs above it, as application/pem-certificate-chain |
    /// | <c>POST /acme/revoke-cert</c> | a certificate revoked - by its account, by an account that proved its names, or with its own key |
    /// | <c>GET /acme/renewal-info/{id}</c> | when a certificate should be renewed, RFC 9773 |
    /// | <c>GET, PUT v1/pki/acme</c> | what ACME signs, for which names and for whom |
    /// | <c>GET v1/pki/acme/accounts</c>, <c>DELETE v1/pki/acme/accounts/{id}</c> | the accounts, and one deactivated |
    /// | <c>GET, POST v1/pki/acme/eab</c>, <c>DELETE v1/pki/acme/eab/{kid}</c> | the keys of external account bindings: listed, made, taken away |
    /// </para>
    /// <para>
    /// Every request but the directory, the nonces and the renewal
    /// information is a JWS (RFC 8555, section 6.2), and is checked as Let's
    /// Encrypt checks it: a nonce handed out and not used before, the URL it
    /// was sent to, a "jwk" for a new account and a "kid" for everything else,
    /// and a signature of ES256, ES384, ES512, RS256 or PS256 by the key of
    /// the account. What answers is a problem document of RFC 7807, with a
    /// fresh nonce, as every answer has one.
    /// </para>
    /// <para>
    /// A name is proven as RFC 8555, section 8, has it: http-01 asks for the
    /// key authorization at "/.well-known/acme-challenge/{token}" on port 80
    /// of the name - following redirects, as Let's Encrypt does - and dns-01
    /// looks for its digest in the TXT records of "_acme-challenge" below the
    /// name, through the name servers of the node. A wildcard is proven by
    /// dns-01 only, an address by http-01 only. A name once proven stays
    /// proven for its account for 30 days.
    /// </para>
    /// <para>
    /// What is signed is a certificate of the profile the order asked for -
    /// draft-ietf-acme-profiles - or of the default: for the names of the
    /// order exactly, with the first of them as its common name, and with
    /// nothing else of the CSR but its key. The CA signs without anybody
    /// there, so a CA whose key has a password signs nothing over ACME.
    /// </para>
    /// <para>
    /// The accounts, the keys of external account bindings, and which
    /// certificate was signed for which account are kept in "acme/accounts.json"
    /// of the PKI's directory. Orders, authorizations and nonces are kept in
    /// memory: a restart forgets an order not finished, which its client then
    /// places anew.
    /// </para>
    /// </remarks>
    public partial class PKIHTTPAPI
    {

        #region Data

        /// <summary>
        /// Where the ACME server is, below the root of the HTTP server.
        /// </summary>
        public const            String           ACMEPath                 = "/acme";

        private static readonly HTTPContentType  ProblemContentType       = ContentType("application/problem+json");

        private static readonly HTTPContentType  PEMChainContentType      = ContentType("application/pem-certificate-chain");

        /// <summary>
        /// How many names an order has at most - as at Let's Encrypt.
        /// </summary>
        public const            Int32            MaxACMEIdentifiers       = 100;

        /// <summary>
        /// The reasons a certificate is revoked for over ACME - those of
        /// RFC 5280 a subscriber may give, as at Let's Encrypt.
        /// </summary>
        private static readonly IReadOnlyList<Int32> ACMERevocationReasons = [ 0, 1, 3, 4, 5 ];

        /// <summary>
        /// How often a client is asked to look at its renewal information again.
        /// </summary>
        private static readonly TimeSpan         RenewalInfoRetryAfter    = TimeSpan.FromHours(6);

        #endregion

        #region (private) RegisterACMEURLTemplates()

        private void RegisterACMEURLTemplates()
        {

            AddHandler(HTTPPath.Root + "v1/pki/acme",                 GetACME,               HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/pki/acme",                 PutACME,               HTTPMethod.PUT);
            AddHandler(HTTPPath.Root + "v1/pki/acme/accounts",        GetACMEAccounts,       HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/pki/acme/accounts/{id}",   DeleteACMEAccount,     HTTPMethod.DELETE);
            AddHandler(HTTPPath.Root + "v1/pki/acme/eab",             GetACMEKeys,           HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/pki/acme/eab",             PostACMEKey,           HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/pki/acme/eab/{kid}",       DeleteACMEKey,         HTTPMethod.DELETE);

            HTTPAPI acme;

            try
            {
                acme = PKI.HTTPServer.AddHTTPAPI(HTTPPath.Parse(ACMEPath));
            }
            catch (ArgumentException e)
            {
                Log.Warning($"PKI: ACME could not be served at '{ACMEPath}': {e.Message}", "pki", "acme");
                return;
            }

            acme.AddHandler(HTTPPath.Root + "directory",          ACMEDirectory,                 HTTPMethod.GET);
            acme.AddHandler(HTTPPath.Root + "new-nonce",          request => ACMENewNonce(request, HTTPStatusCode.OK),         HTTPMethod.HEAD);
            acme.AddHandler(HTTPPath.Root + "new-nonce",          request => ACMENewNonce(request, HTTPStatusCode.NoContent),  HTTPMethod.GET);
            acme.AddHandler(HTTPPath.Root + "renewal-info/{id}",  ACMERenewalInfo,               HTTPMethod.GET);

            ACMEPost(acme, "new-account",       ACMEKey.JWK,       (request, jws) => ACMENewAccount   (request, jws));
            ACMEPost(acme, "acct/{id}",         ACMEKey.Account,   (request, jws) => ACMEUpdateAccount(request, jws, IdOfACME(request)));
            ACMEPost(acme, "acct/{id}/orders",  ACMEKey.Account,   (request, jws) => ACMEOrders       (request, jws, IdOfACME(request)));
            ACMEPost(acme, "key-change",        ACMEKey.Account,   (request, jws) => ACMEKeyChange    (request, jws));
            ACMEPost(acme, "new-order",         ACMEKey.Account,   (request, jws) => ACMENewOrder     (request, jws));
            ACMEPost(acme, "order/{id}",        ACMEKey.Account,   (request, jws) => ACMEGetOrder     (request, jws, IdOfACME(request)));
            ACMEPost(acme, "authz/{id}",        ACMEKey.Account,   (request, jws) => ACMEAuthz        (request, jws, IdOfACME(request)));
            ACMEPost(acme, "chall/{id}",        ACMEKey.Account,   (request, jws) => ACMEChallenge    (request, jws, IdOfACME(request)));
            ACMEPost(acme, "finalize/{id}",     ACMEKey.Account,   (request, jws) => ACMEFinalize     (request, jws, IdOfACME(request)));
            ACMEPost(acme, "cert/{id}",         ACMEKey.Account,   (request, jws) => ACMECertificate  (request, jws, IdOfACME(request)));
            ACMEPost(acme, "revoke-cert",       ACMEKey.Either,    (request, jws) => ACMERevoke       (request, jws));

        }

        private void ACMEPost(HTTPAPI                                           API,
                              String                                            Path,
                              ACMEKey                                           Key,
                              Func<HTTPRequest, ACMERequest, HTTPResponse>      Handler)

            => API.AddHandler(HTTPPath.Root + Path,
                              request => Task.FromResult(ACMEHandle(request, Key, Handler)),
                              HTTPMethod.POST);

        private static String IdOfACME(HTTPRequest Request)

            => Request.ParsedURLParameters.Length > 0
                   ? Request.ParsedURLParameters[0]
                   : "";

        #endregion


        #region (private) The JSON API: GetACME(Request) / PutACME(Request)

        /// <summary>
        /// GET /api/v1/pki/acme: what ACME signs, where it is, and how many
        /// accounts it has.
        /// </summary>
        private Task<HTTPResponse> GetACME(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, ACMEJSON()));

        }

        /// <summary>
        /// PUT /api/v1/pki/acme: what ACME signs - {"issuer", "profile",
        /// "validDays", "profiles", "externalAccountRequired", "allowedNames",
        /// "challenges", "http01Port", "termsOfService"} - kept in the "pki"
        /// section of the configuration file; answered as GET is.
        /// </summary>
        /// <remarks>
        /// At the permission to make CAs: it has a CA sign without anybody
        /// there, for whoever proves a name.
        /// </remarks>
        private Task<HTTPResponse> PutACME(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(PKIAccess.Authorities), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!ACMESettings.TryParse(json, out var settings, out var error) ||
                !PKI.TrySetACME(settings, out error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));
            }

            Log.Notice(settings.Enabled
                           ? $"'{user.Id}' set what ACME signs: {DescribeACME(settings)}."
                           : $"'{user.Id}' set ACME to sign nothing.",
                       "pki", "acme", "configuration", "web");

            if (settings.OpenToEverybody)
                Log.Warning($"PKI: {ACMESettings.OpenToEverybodyWarning}", "pki", "acme", "security");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, ACMEJSON()));

        }

        private JObject ACMEJSON()
        {

            var settings  = PKI.ACME;
            var json      = settings.ToJSON();
            var cas       = new JArray();

            foreach (var issuerId in new[] { settings.Default?.IssuerId }.Concat(settings.Profiles.Values.Select(profile => profile.IssuerId)).OfType<String>().Distinct())
            {
                var ca = PKI.Store.Get(issuerId);
                cas.Add(new JObject(
                            new JProperty("id",            issuerId),
                            new JProperty("commonName",    ca?.CommonName),
                            new JProperty("problem",       ProblemOf(issuerId, "ACME"))
                        ));
            }

            var accounts = PKI.ACMEState.Accounts();

            json.Add(new JProperty("enabled",              settings.Enabled));
            json.Add(new JProperty("path",                 ACMEPath + "/directory"));
            json.Add(new JProperty("https",                PKI.HTTPS));
            json.Add(new JProperty("issuers",              cas));
            json.Add(new JProperty("accounts",             accounts.Count(account => account.Status == "valid")));
            json.Add(new JProperty("externalAccountKeys",  PKI.ACMEState.ExternalAccountKeys().Count(key => key.BoundTo is null)));
            json.Add(new JProperty("problem",              PKI.ACMEState.LoadError));
            json.Add(new JProperty("warning",              settings.OpenToEverybody ? ACMESettings.OpenToEverybodyWarning : null));

            return json;

        }

        private String DescribeACME(ACMESettings Settings)

            => String.Join("; ", new[] { (Name: (String?) null, Profile: Settings.Default) }.
                                     Concat(Settings.Profiles.Select(profile => (Name: (String?) profile.Key, Profile: (ACMEProfile?) profile.Value))).
                                     Where (one => one.Profile is not null).
                                     Select(one => $"{(one.Name is null ? "by default" : $"as '{one.Name}'")} a {one.Profile!.Profile.InWords()} of {one.Profile.ValidDays} days below '{PKI.Store.Get(one.Profile.IssuerId)?.CommonName ?? one.Profile.IssuerId}'")) +
               (Settings.AllowedNames.Count == 0 ? ", for every name proven" : $", for {String.Join(", ", Settings.AllowedNames)}") +
               (Settings.ExternalAccountRequired ? ", to accounts opened with a key of the PKI" : "");

        #endregion

        #region (private) The JSON API: GetACMEAccounts(Request) / DeleteACMEAccount(Request)

        /// <summary>
        /// GET /api/v1/pki/acme/accounts: every account, with how many
        /// certificates it was signed.
        /// </summary>
        private Task<HTTPResponse> GetACMEAccounts(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            var array = new JArray(PKI.ACMEState.Accounts().Select(account => new JObject(
                                       new JProperty("id",               account.Id),
                                       new JProperty("status",           account.Status),
                                       new JProperty("contact",          new JArray(account.Contacts)),
                                       new JProperty("thumbprint",       account.Thumbprint),
                                       new JProperty("keyType",          account.JWK.Value<String>("kty") == "EC" ? $"EC {account.JWK.Value<String>("crv")}" : "RSA"),
                                       new JProperty("createdAt",        account.CreatedAt.ToString("o")),
                                       new JProperty("externalAccount",  account.ExternalAccount),
                                       new JProperty("vouchedForBy",     account.VouchedForBy),
                                       new JProperty("certificates",     PKI.ACMEState.IssuedFor(account.Id).Count)
                                   )));

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, array));

        }

        /// <summary>
        /// DELETE /api/v1/pki/acme/accounts/{id}: an account deactivated for
        /// good (RFC 8555, section 7.3.6) - its key signs nothing any more.
        /// What it was signed stays as it is: revoking is another thing.
        /// </summary>
        private Task<HTTPResponse> DeleteACMEAccount(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(PKIAccess.Authorities), true, out var user, out var refused))
                return Task.FromResult(refused);

            var account = PKI.ACMEState.Account(IdOfACME(Request));

            if (account is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, $"There is no account '{IdOfACME(Request)}' of ACME."));

            if (account.Status != "valid")
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict, $"The account '{account.Id}' of ACME is {account.Status} already."));

            if (!PKI.ACMEState.TryChange(account, one => one.Status = "deactivated", out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.InternalServerError, error));

            Log.Notice($"'{user.Id}' deactivated the account '{account.Id}' of ACME{ContactsOf(account)}.", "pki", "acme", "security");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, new JObject(new JProperty("id", account.Id), new JProperty("status", account.Status))));

        }

        #endregion

        #region (private) The JSON API: GetACMEKeys(Request) / PostACMEKey(Request) / DeleteACMEKey(Request)

        /// <summary>
        /// GET /api/v1/pki/acme/eab: the keys of external account bindings,
        /// without their MAC keys - which only the one who made a key ever sees.
        /// </summary>
        private Task<HTTPResponse> GetACMEKeys(HTTPRequest Request)
        {

            if (!TryMayRead(Request, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK,
                                                new JArray(PKI.ACMEState.ExternalAccountKeys().Select(key => key.ToJSON()))));

        }

        /// <summary>
        /// POST /api/v1/pki/acme/eab: a new key of an external account binding
        /// - {"description"} - for one ACME client to open its account with,
        /// answered 201 with its "kid" and its "hmacKey", base64url, as certbot's
        /// --eab-kid and --eab-hmac-key take them. The MAC key is said this once.
        /// </summary>
        /// <remarks>
        /// At the permission to sign certificates of servers and clients: an
        /// account opened with the key is one this account vouches for.
        /// </remarks>
        private Task<HTTPResponse> PostACMEKey(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(PKIAccess.Issuance), true, out var user, out var refused))
                return Task.FromResult(refused);

            JObject json = [];

            if ((Request.HTTPBody?.Length ?? 0) > 0)
            {
                if (!TryParseJSONObject(Request, out var parsed, out var errorResponse))
                    return Task.FromResult(errorResponse);
                json = parsed;
            }

            var description = json["description"];

            if (description is not null && description.Type is not JTokenType.String and not JTokenType.Null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "'description' is text."));

            if (!PKI.ACMEState.TryNewExternalAccountKey(description?.Type == JTokenType.String ? description.Value<String>() : null,
                                                        user.Id.ToString(), out var key, out var error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.InternalServerError, error));
            }

            Log.Notice($"'{user.Id}' made the key '{key.KeyId}' of an external account binding of ACME{(key.Description is null ? "" : $" ({key.Description})")}.",
                       "pki", "acme", "security");

            var answer = key.ToJSON();
            answer.Add(new JProperty("hmacKey",    Base64Url.EncodeToString(key.MACKey)));
            answer.Add(new JProperty("directory",  PKI.ACMEDirectoryAt()));

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.Created, answer));

        }

        /// <summary>
        /// DELETE /api/v1/pki/acme/eab/{kid}: a key of an external account
        /// binding taken away. An account it opened stays.
        /// </summary>
        private Task<HTTPResponse> DeleteACMEKey(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(PKIAccess.Issuance), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!PKI.ACMEState.TryRemoveExternalAccountKey(IdOfACME(Request), out var notFound, out var error))
                return Task.FromResult(ErrorJSON(Request, notFound ? HTTPStatusCode.NotFound : HTTPStatusCode.InternalServerError, error));

            Log.Notice($"'{user.Id}' took away the key '{IdOfACME(Request)}' of an external account binding of ACME.", "pki", "acme", "security");

            return Task.FromResult(new HTTPResponse.Builder(Request) {
                                       HTTPStatusCode  = HTTPStatusCode.NoContent,
                                       CacheControl    = "no-store"
                                   }.WithCommonSecurityHeaders().AsImmutable);

        }

        #endregion


        #region (private) ACMEDirectory(Request) / ACMENewNonce(Request, StatusCode)

        /// <summary>
        /// GET /acme/directory: where everything else is (RFC 8555, section
        /// 7.1.1), what is asked of a new account, and the profiles.
        /// </summary>
        private Task<HTTPResponse> ACMEDirectory(HTTPRequest Request)
        {

            var settings = PKI.ACME;

            if (!settings.Enabled)
                return Task.FromResult(ACMEProblemResponse(Request, NoACME()));

            var base_    = ACMEBase(Request);

            var meta     = new JObject(
                               new JProperty("website",                  PKI.WebInterfaceURL.ToString()),
                               new JProperty("externalAccountRequired",  settings.ExternalAccountRequired)
                           );

            if (settings.TermsOfService is String terms)
                meta.AddFirst(new JProperty("termsOfService", terms));

            if (settings.Profiles.Count > 0)
                meta.Add(new JProperty("profiles", new JObject(settings.Profiles.OrderBy(profile => profile.Key, StringComparer.Ordinal).
                                                                                  Select (profile => new JProperty(profile.Key, profile.Value.Description ?? $"A {profile.Value.Profile.InWords()} of {profile.Value.ValidDays} days.")))));

            var directory = new JObject(
                                new JProperty("newNonce",     $"{base_}/new-nonce"),
                                new JProperty("newAccount",   $"{base_}/new-account"),
                                new JProperty("newOrder",     $"{base_}/new-order"),
                                new JProperty("revokeCert",   $"{base_}/revoke-cert"),
                                new JProperty("keyChange",    $"{base_}/key-change"),
                                new JProperty("renewalInfo",  $"{base_}/renewal-info"),
                                new JProperty("meta",         meta)
                            );

            return Task.FromResult(new HTTPResponse.Builder(Request) {
                                       HTTPStatusCode  = HTTPStatusCode.OK,
                                       ContentType     = HTTPContentType.Application.JSON_UTF8,
                                       Content         = Encoding.UTF8.GetBytes(directory.ToString(Formatting.Indented)),
                                       CacheControl    = "public, max-age=0, no-cache"
                                   }.WithCommonSecurityHeaders().AsImmutable);

        }

        /// <summary>
        /// HEAD and GET /acme/new-nonce: a nonce, in Replay-Nonce (RFC 8555,
        /// section 7.2).
        /// </summary>
        private Task<HTTPResponse> ACMENewNonce(HTTPRequest     Request,
                                                HTTPStatusCode  StatusCode)
        {

            if (!PKI.ACME.Enabled)
                return Task.FromResult(ACMEProblemResponse(Request, NoACME()));

            return Task.FromResult(WithACMEHeaders(new HTTPResponse.Builder(Request) {
                                                       HTTPStatusCode  = StatusCode
                                                   }, Request).AsImmutable);

        }

        #endregion

        #region (private) ACMENewAccount(Request, JWS)

        /// <summary>
        /// POST /acme/new-account: an account for the key that signed - or the
        /// one it has already (RFC 8555, section 7.3).
        /// </summary>
        private HTTPResponse ACMENewAccount(HTTPRequest  Request,
                                            ACMERequest  JWS)
        {

            var settings    = PKI.ACME;
            var jwk         = JWS.JWS.JWK!;
            var thumbprint  = ACMEJWS.Thumbprint(jwk);
            var payload     = JWS.JWS.Payload ?? throw new ACMEProblem(400, "malformed", "A new account is asked for with a payload: {\"termsOfServiceAgreed\", \"contact\"}.");

            #region The account the key has already

            if (PKI.ACMEState.AccountByThumbprint(thumbprint) is ACMEAccount existing)
            {

                if (existing.Status != "valid")
                    throw new ACMEProblem(401, "unauthorized", $"The account of this key is {existing.Status}.");

                return ACMEJSONResponse(Request, HTTPStatusCode.OK, AccountJSON(existing, JWS.Base), AccountURL(existing, JWS.Base));

            }

            if (payload["onlyReturnExisting"]?.Type == JTokenType.Boolean && payload.Value<Boolean>("onlyReturnExisting"))
                throw new ACMEProblem(400, "accountDoesNotExist", "This key has no account here.");

            #endregion

            #region The terms of service, and who to write to

            var agreed = payload["termsOfServiceAgreed"]?.Type == JTokenType.Boolean && payload.Value<Boolean>("termsOfServiceAgreed");

            if (settings.TermsOfService is String terms && !agreed)
                throw new ACMEProblem(400, "malformed", $"An account is opened by agreeing to the terms of service at {terms}: \"termsOfServiceAgreed\": true.");

            var contacts = ContactsOf(payload);

            #endregion

            #region The external account binding

            ACMEExternalAccountKey? externalKey = null;

            if (payload["externalAccountBinding"] is JToken bindingToken && bindingToken.Type != JTokenType.Null)
            {

                if (bindingToken is not JObject bindingJSON)
                    throw new ACMEProblem(400, "malformed", "\"externalAccountBinding\" is a JWS.");

                var binding = ACMEJWS.Parse(bindingJSON, MACAllowed: true);

                externalKey = binding.KeyId is String keyId ? PKI.ACMEState.ExternalAccountKey(keyId) : null;

                if (externalKey is null)
                    throw new ACMEProblem(401, "unauthorized", $"'{binding.KeyId}' is no key of an external account binding of this PKI.");

                if (externalKey.BoundTo is not null)
                    throw new ACMEProblem(401, "unauthorized", $"The key '{externalKey.KeyId}' of an external account binding opened an account already, and opens no other.");

                if (binding.URL != $"{JWS.Base}/new-account")
                    throw new ACMEProblem(400, "malformed", "The external account binding is for another URL than new-account's.");

                if (binding.Nonce is not null)
                    throw new ACMEProblem(400, "malformed", "An external account binding has no nonce (RFC 8555, section 7.3.4).");

                if (!binding.MACHolds(externalKey.MACKey))
                    throw new ACMEProblem(401, "unauthorized", $"The MAC of the external account binding '{externalKey.KeyId}' does not hold.");

                if (binding.Payload is null || ACMEJWS.Thumbprint(binding.Payload) != thumbprint)
                    throw new ACMEProblem(400, "malformed", "The external account binding binds another key than the one that signed.");

            }

            else if (settings.ExternalAccountRequired)
                throw new ACMEProblem(400, "externalAccountRequired", "An account is opened here with a key of an external account binding, which somebody of the PKI makes.");

            #endregion

            var account = new ACMEAccount(
                              Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant(),
                              jwk,
                              contacts,
                              "valid",
                              PKI.ACMEState.Now,
                              agreed,
                              externalKey?.KeyId,
                              externalKey?.CreatedBy
                          );

            if (!PKI.ACMEState.TryAdd(account, out var taken, out var error))
                throw taken
                          ? new ACMEProblem(401, "unauthorized", error)
                          : new ACMEProblem(500, "serverInternal", error);

            Log.Notice($"ACME: the account '{account.Id}' was opened{ContactsOf(account)}" +
                       (externalKey is null ? "" : $", with the key '{externalKey.KeyId}' of '{externalKey.CreatedBy}'") + ".",
                       "pki", "acme", "security");

            return ACMEJSONResponse(Request, HTTPStatusCode.Created, AccountJSON(account, JWS.Base), AccountURL(account, JWS.Base));

        }

        /// <summary>
        /// The contacts of a new or a changed account: "mailto:" URLs of one
        /// address each (RFC 8555, section 7.3).
        /// </summary>
        private static List<String> ContactsOf(JObject Payload)
        {

            var contacts = new List<String>();

            if (Payload["contact"] is not JToken token || token.Type == JTokenType.Null)
                return contacts;

            if (token is not JArray array || array.Any(entry => entry.Type != JTokenType.String))
                throw new ACMEProblem(400, "invalidContact", "\"contact\" is a list of \"mailto:\" URLs.");

            if (array.Count > 10)
                throw new ACMEProblem(400, "invalidContact", "An account has ten contacts at most.");

            foreach (var contact in array.Select(entry => entry.Value<String>()!.Trim()))
            {

                if (!contact.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
                    throw new ACMEProblem(400, "unsupportedContact", $"'{contact}' is no \"mailto:\" URL, which is the one kind of contact here.");

                var address = contact["mailto:".Length..];

                if (address.Length == 0 || address.Contains(',') || address.Contains('?') ||
                    address.IndexOf('@') <= 0 || address.IndexOf('@') != address.LastIndexOf('@') || address.IndexOf('@') == address.Length - 1)
                {
                    throw new ACMEProblem(400, "invalidContact", $"'{contact}' is no \"mailto:\" URL of one mail address.");
                }

                if (!contacts.Contains(contact, StringComparer.OrdinalIgnoreCase))
                    contacts.Add(contact);

            }

            return contacts;

        }

        private static String ContactsOf(ACMEAccount Account)

            => Account.Contacts.Count == 0
                   ? ""
                   : $" ({String.Join(", ", Account.Contacts.Select(contact => contact.Replace("mailto:", "", StringComparison.OrdinalIgnoreCase)))})";

        #endregion

        #region (private) ACMEUpdateAccount(Request, JWS, Id) / ACMEOrders(Request, JWS, Id)

        /// <summary>
        /// POST /acme/acct/{id}: the account - and with a payload, its contacts
        /// changed, or itself deactivated for good (RFC 8555, sections 7.3.2
        /// and 7.3.6).
        /// </summary>
        private HTTPResponse ACMEUpdateAccount(HTTPRequest  Request,
                                               ACMERequest  JWS,
                                               String       Id)
        {

            var account = OwnAccount(JWS, Id);

            if (JWS.JWS.Payload is JObject payload)
            {

                if (payload["status"] is JToken status && status.Type != JTokenType.Null)
                {

                    if (status.Type != JTokenType.String || status.Value<String>() != "deactivated")
                        throw new ACMEProblem(400, "malformed", "The one status an account is given is \"deactivated\".");

                    if (!PKI.ACMEState.TryChange(account, one => one.Status = "deactivated", out var error))
                        throw new ACMEProblem(500, "serverInternal", error);

                    Log.Notice($"ACME: the account '{account.Id}'{ContactsOf(account)} deactivated itself.", "pki", "acme", "security");

                }

                else if (payload["contact"] is not null)
                {

                    var contacts = ContactsOf(payload);

                    if (!PKI.ACMEState.TryChange(account, one => one.Contacts = contacts, out var error))
                        throw new ACMEProblem(500, "serverInternal", error);

                }

            }

            return ACMEJSONResponse(Request, HTTPStatusCode.OK, AccountJSON(account, JWS.Base), AccountURL(account, JWS.Base));

        }

        /// <summary>
        /// POST /acme/acct/{id}/orders: the orders of the account this PKI
        /// remembers (RFC 8555, section 7.1.2.1).
        /// </summary>
        private HTTPResponse ACMEOrders(HTTPRequest  Request,
                                        ACMERequest  JWS,
                                        String       Id)
        {

            var account = OwnAccount(JWS, Id);
            var now     = PKI.ACMEState.Now;

            return ACMEJSONResponse(Request, HTTPStatusCode.OK,
                                    new JObject(new JProperty("orders", new JArray(PKI.ACMEState.OrdersOf(account).
                                                                                       Where (order => order.StatusAt(now) is "pending" or "ready" or "valid").
                                                                                       Select(order => $"{JWS.Base}/order/{order.Id}")))));

        }

        /// <summary>
        /// The account a request is about, which must be the one that signed it.
        /// </summary>
        private static ACMEAccount OwnAccount(ACMERequest  JWS,
                                              String       Id)

            => JWS.Account!.Id == Id
                   ? JWS.Account
                   : throw new ACMEProblem(403, "unauthorized", "An account is asked about by its own key only.");

        #endregion

        #region (private) ACMEKeyChange(Request, JWS)

        /// <summary>
        /// POST /acme/key-change: a new key for the account (RFC 8555, section
        /// 7.3.5) - a JWS signed by it inside one signed by the old key.
        /// </summary>
        private HTTPResponse ACMEKeyChange(HTTPRequest  Request,
                                           ACMERequest  JWS)
        {

            var account  = JWS.Account!;

            var inner    = ACMEJWS.Parse(JWS.JWS.Payload ?? throw new ACMEProblem(400, "malformed", "A new key is sent as a JWS signed by it."));

            if (inner.JWK is null)
                throw new ACMEProblem(400, "malformed", "The inner JWS of a key change has the new key as its \"jwk\".");

            if (inner.URL != JWS.JWS.URL)
                throw new ACMEProblem(400, "malformed", "The inner JWS of a key change is for the URL the outer one is for.");

            if (inner.Nonce is not null)
                throw new ACMEProblem(400, "malformed", "The inner JWS of a key change has no nonce.");

            ACMEJWS.Check(inner.JWK);

            if (!inner.SignedBy(inner.JWK))
                throw new ACMEProblem(400, "malformed", "The inner JWS of a key change is not signed by the new key.");

            if (inner.Payload?["account"]?.Type != JTokenType.String || inner.Payload.Value<String>("account") != AccountURL(account, JWS.Base))
                throw new ACMEProblem(400, "malformed", "The inner JWS of a key change names the account it is for.");

            if (inner.Payload["oldKey"] is not JObject oldKey || ACMEJWS.Thumbprint(oldKey) != account.Thumbprint)
                throw new ACMEProblem(400, "malformed", "The inner JWS of a key change names the old key of the account as \"oldKey\".");

            var thumbprint = ACMEJWS.Thumbprint(inner.JWK);

            if (PKI.ACMEState.AccountByThumbprint(thumbprint) is ACMEAccount other)
                throw new ACMEProblem(409, "conflict", "The new key is the key of an account already.") { Location = AccountURL(other, JWS.Base) };

            if (!PKI.ACMEState.TryChange(account, one => { one.JWK = inner.JWK; one.Thumbprint = thumbprint; }, out var error))
                throw new ACMEProblem(500, "serverInternal", error);

            Log.Notice($"ACME: the account '{account.Id}'{ContactsOf(account)} has a new key.", "pki", "acme", "security");

            return ACMEJSONResponse(Request, HTTPStatusCode.OK, AccountJSON(account, JWS.Base), AccountURL(account, JWS.Base));

        }

        #endregion

        #region (private) ACMENewOrder(Request, JWS)

        /// <summary>
        /// POST /acme/new-order: an order for names (RFC 8555, section 7.4),
        /// with an authorization for each that is not proven for the account
        /// already.
        /// </summary>
        private HTTPResponse ACMENewOrder(HTTPRequest  Request,
                                          ACMERequest  JWS)
        {

            var settings  = PKI.ACME;
            var account   = JWS.Account!;
            var payload   = JWS.JWS.Payload ?? throw new ACMEProblem(400, "malformed", "An order is placed with a payload: {\"identifiers\"}.");
            var now       = PKI.ACMEState.Now;

            if (payload["notBefore"] is not null || payload["notAfter"] is not null)
                throw new ACMEProblem(400, "malformed", "How long a certificate holds is what its profile says: an order names no \"notBefore\" and no \"notAfter\".");

            #region The profile

            String? profileName = null;

            if (payload["profile"] is JToken profileToken && profileToken.Type != JTokenType.Null)
            {

                if (profileToken.Type != JTokenType.String)
                    throw new ACMEProblem(400, "malformed", "\"profile\" is the name of a profile.");

                profileName = profileToken.Value<String>();

            }

            var profile = settings.For(profileName)
                              ?? throw new ACMEProblem(400, "invalidProfile",
                                                       profileName is null
                                                           ? $"An order here names its profile: {String.Join(", ", settings.Profiles.Keys)}."
                                                           : $"'{profileName}' is no profile here: {String.Join(", ", settings.Profiles.Keys)}.");

            #endregion

            #region The names

            if (payload["identifiers"] is not JArray identifiersJSON || identifiersJSON.Count == 0)
                throw new ACMEProblem(400, "malformed", "An order names at least one identifier: [{\"type\": \"dns\", \"value\": \"...\"}].");

            if (identifiersJSON.Count > MaxACMEIdentifiers)
                throw new ACMEProblem(400, "rejectedIdentifier", $"An order names {MaxACMEIdentifiers} identifiers at most.");

            var identifiers = new List<ACMEIdentifier>();
            var problems    = new List<ACMEProblem>();

            foreach (var entry in identifiersJSON)
            {

                if (entry is not JObject identifierJSON || identifierJSON["type"]?.Type != JTokenType.String || identifierJSON["value"]?.Type != JTokenType.String)
                    throw new ACMEProblem(400, "malformed", "An identifier is {\"type\", \"value\"}.");

                try
                {

                    var identifier = Identifier(identifierJSON.Value<String>("type")!, identifierJSON.Value<String>("value")!, settings);

                    if (!identifiers.Contains(identifier))
                        identifiers.Add(identifier);

                }
                catch (ACMEProblem problem)
                {
                    problems.Add(problem);
                }

            }

            if (problems.Count == 1)
                throw problems[0];

            if (problems.Count > 1)
                throw new ACMEProblem(400, problems.All(problem => problem.Type == problems[0].Type) ? problems[0].Type : "rejectedIdentifier",
                                      String.Join(" ", problems.Select(problem => problem.Message)));

            #endregion

            #region The certificate it replaces (RFC 9773)

            String? replaces = null;

            if (payload["replaces"] is JToken replacesToken && replacesToken.Type != JTokenType.Null)
            {

                var replaced = replacesToken.Type == JTokenType.String
                                   ? CertificateOfARIIdentifier(replacesToken.Value<String>()!)
                                   : null;

                if (replaced is null)
                    throw new ACMEProblem(400, "malformed", $"\"replaces\" names no certificate of this PKI.");

                if (PKI.ACMEState.Issued(replaced.Id)?.AccountId != account.Id)
                    throw new ACMEProblem(403, "unauthorized", "\"replaces\" names a certificate this account was not signed.");

                if (PKI.ACMEState.IsReplaced(replaced.Id))
                    throw new ACMEProblem(409, "alreadyReplaced", $"The certificate '{replaced.CommonName}' ({replaced.Id}) was replaced already.");

                replaces = replaced.Id;

            }

            #endregion

            if (PKI.ACMEState.PendingOrdersOf(account) >= ACMEState.MaxPendingOrders)
                throw new ACMEProblem(429, "rateLimited", $"An account has {ACMEState.MaxPendingOrders} orders pending at most: finish or forget some first.");

            var order = new ACMEOrder(ACMEState.NewId(), account, identifiers, profileName, profile, replaces, now + ACMEState.OrderLifetime);

            foreach (var identifier in identifiers)
            {

                if (PKI.ACMEState.ValidAuthorization(account, identifier) is ACMEAuthorization proven)
                {
                    order.Authorizations.Add(proven);
                    continue;
                }

                var authorization = new ACMEAuthorization(ACMEState.NewId(), account, identifier, now + ACMEState.OrderLifetime);

                // As Let's Encrypt: no http-01 for a wildcard, no dns-01 for an
                // address - RFC 8738, section 7.
                if (settings.Challenges.Contains("http-01") && !identifier.IsWildcard)
                    authorization.Challenges.Add(new ACMEChallenge(ACMEState.NewId(), authorization, "http-01", NewToken()));

                if (settings.Challenges.Contains("dns-01") && identifier.Type == "dns")
                    authorization.Challenges.Add(new ACMEChallenge(ACMEState.NewId(), authorization, "dns-01", NewToken()));

                order.Authorizations.Add(authorization);

            }

            PKI.ACMEState.Add(order);

            Log.Info($"ACME: the account '{account.Id}' ordered a {profile.Profile.InWords()} for {String.Join(", ", identifiers.Select(identifier => identifier.Value))}" +
                     $"{(profileName is null ? "" : $" as '{profileName}'")}{(replaces is null ? "" : $", replacing {replaces}")}.",
                     "pki", "acme");

            return ACMEJSONResponse(Request, HTTPStatusCode.Created, OrderJSON(order, JWS.Base), $"{JWS.Base}/order/{order.Id}");

        }

        /// <summary>
        /// A name of an order, as the PKI writes it - or why it is none it
        /// signs for.
        /// </summary>
        private static ACMEIdentifier Identifier(String        Type,
                                                 String        Value,
                                                 ACMESettings  Settings)
        {

            ACMEIdentifier identifier;

            switch (Type)
            {

                case "dns":
                {

                    var name = Value.Trim().TrimEnd('.').ToLowerInvariant();

                    if (IPAddress.TryParse(name, out _))
                        throw new ACMEProblem(400, "malformed", $"'{Value}' is an address, which is of the type \"ip\" (RFC 8738).");

                    var proven = name.StartsWith("*.", StringComparison.Ordinal) ? name[2..] : name;

                    if (proven.Length == 0 || proven.Contains('*') || proven.Contains('@') || proven.Contains("://") || proven.Contains('_') ||
                        !AlternativeNames.IsValid(proven, out _))
                    {
                        throw new ACMEProblem(400, "rejectedIdentifier", $"'{Value}' is no host name.");
                    }

                    identifier = new ACMEIdentifier("dns", name);

                    if (identifier.IsWildcard && !Settings.Challenges.Contains("dns-01"))
                        throw new ACMEProblem(400, "rejectedIdentifier", $"A wildcard - '{Value}' - is proven by dns-01, which is not offered here.");

                    if (!identifier.IsWildcard && !Settings.Challenges.Contains("http-01") && !Settings.Challenges.Contains("dns-01"))
                        throw new ACMEProblem(400, "rejectedIdentifier", $"'{Value}' cannot be proven here.");

                    break;

                }

                case "ip":
                {

                    if (!IPAddress.TryParse(Value.Trim(), out var address) || Value.Contains('/') || Value.Contains('%'))
                        throw new ACMEProblem(400, "malformed", $"'{Value}' is no address.");

                    if (address.IsIPv4MappedToIPv6)
                        address = address.MapToIPv4();

                    identifier = new ACMEIdentifier("ip", address.ToString());

                    if (!Settings.Challenges.Contains("http-01"))
                        throw new ACMEProblem(400, "rejectedIdentifier", $"An address - '{Value}' - is proven by http-01, which is not offered here.");

                    break;

                }

                default:
                    throw new ACMEProblem(400, "unsupportedIdentifier", $"'{Type}' is no type of identifier this PKI signs: \"dns\" and \"ip\".");

            }

            if (!Settings.Allows(identifier.Type, identifier.Proven))
                throw new ACMEProblem(400, "rejectedIdentifier", $"'{identifier.Value}' is no name this PKI signs for over ACME.");

            return identifier;

        }

        private static String NewToken()
            => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

        #endregion

        #region (private) ACMEGetOrder(Request, JWS, Id)

        /// <summary>
        /// POST /acme/order/{id}: an order as it stands (RFC 8555, section 7.1.3).
        /// </summary>
        private HTTPResponse ACMEGetOrder(HTTPRequest  Request,
                                          ACMERequest  JWS,
                                          String       Id)
        {

            var order = OwnOrder(JWS, Id);

            return ACMEJSONResponse(Request, HTTPStatusCode.OK, OrderJSON(order, JWS.Base), $"{JWS.Base}/order/{order.Id}");

        }

        private ACMEOrder OwnOrder(ACMERequest  JWS,
                                   String       Id)

            => PKI.ACMEState.Order(Id) is ACMEOrder order
                   ? order.Account == JWS.Account
                         ? order
                         : throw new ACMEProblem(403, "unauthorized", "The order is another account's.")
                   : throw new ACMEProblem(404, "malformed", $"There is no order '{Id}'.");

        #endregion

        #region (private) ACMEAuthz(Request, JWS, Id)

        /// <summary>
        /// POST /acme/authz/{id}: an authorization as it stands (RFC 8555,
        /// section 7.5) - and with {"status": "deactivated"}, given up (section
        /// 7.5.2).
        /// </summary>
        private HTTPResponse ACMEAuthz(HTTPRequest  Request,
                                       ACMERequest  JWS,
                                       String       Id)
        {

            var authorization = PKI.ACMEState.Authorization(Id) is ACMEAuthorization found
                                    ? found.Account == JWS.Account
                                          ? found
                                          : throw new ACMEProblem(403, "unauthorized", "The authorization is another account's.")
                                    : throw new ACMEProblem(404, "malformed", $"There is no authorization '{Id}'.");

            if (JWS.JWS.Payload is JObject payload && payload["status"] is JToken status && status.Type != JTokenType.Null)
            {

                if (status.Type != JTokenType.String || status.Value<String>() != "deactivated")
                    throw new ACMEProblem(400, "malformed", "The one status an authorization is given is \"deactivated\".");

                lock (PKI.ACMEState.Gate)
                {

                    if (authorization.StatusAt(PKI.ACMEState.Now) is not ("pending" or "valid"))
                        throw new ACMEProblem(400, "malformed", $"The authorization is {authorization.StatusAt(PKI.ACMEState.Now)}, and is deactivated no more.");

                    authorization.Status = "deactivated";

                }

            }

            return ACMEJSONResponse(Request, HTTPStatusCode.OK, AuthorizationJSON(authorization, JWS.Base));

        }

        #endregion

        #region (private) ACMEChallenge(Request, JWS, Id)

        /// <summary>
        /// POST /acme/chall/{id}: a challenge as it stands - and with a payload,
        /// "{}", looked at now (RFC 8555, section 7.5.1): in the background, as
        /// it takes a moment, while the client asks again.
        /// </summary>
        private HTTPResponse ACMEChallenge(HTTPRequest  Request,
                                           ACMERequest  JWS,
                                           String       Id)
        {

            var challenge = PKI.ACMEState.Challenge(Id) is ACMEChallenge found
                                ? found.Authorization.Account == JWS.Account
                                      ? found
                                      : throw new ACMEProblem(403, "unauthorized", "The challenge is another account's.")
                                : throw new ACMEProblem(404, "malformed", $"There is no challenge '{Id}'.");

            var start = false;

            if (JWS.JWS.Payload is not null)
            {
                lock (PKI.ACMEState.Gate)
                {
                    if (challenge.Status == "pending" && challenge.Authorization.StatusAt(PKI.ACMEState.Now) == "pending")
                    {
                        challenge.Status = "processing";
                        start            = true;
                    }
                }
            }

            if (start)
            {

                var keyAuthorization = $"{challenge.Token}.{JWS.Account!.Thumbprint}";
                var port             = PKI.ACME.HTTP01Port;

                _ = Task.Run(() => ValidateACMEChallenge(challenge, keyAuthorization, port));

            }

            return ACMEJSONResponse(Request, HTTPStatusCode.OK, ChallengeJSON(challenge, JWS.Base), null,
                                    $"<{JWS.Base}/authz/{challenge.Authorization.Id}>;rel=\"up\"");

        }

        /// <summary>
        /// Look at a challenge, and say what was found: the authorization valid
        /// with it, or invalid.
        /// </summary>
        private async Task ValidateACMEChallenge(ACMEChallenge  Challenge,
                                                 String         KeyAuthorization,
                                                 UInt16         HTTP01Port)
        {

            ACMEProblem? problem;

            try
            {
                problem = await PKI.ACMEValidator.ValidateAsync(Challenge.Type,
                                                                Challenge.Authorization.Identifier,
                                                                Challenge.Token,
                                                                KeyAuthorization,
                                                                HTTP01Port);
            }
            catch (Exception e)
            {
                problem = new ACMEProblem(500, "serverInternal", $"{Challenge.Type} could not be looked at: {e.Message}");
            }

            var now            = PKI.ACMEState.Now;
            var authorization  = Challenge.Authorization;

            lock (PKI.ACMEState.Gate)
            {

                Challenge.Status     = problem is null ? "valid" : "invalid";
                Challenge.Validated  = problem is null ? now : null;
                Challenge.Error      = problem;

                if (authorization.Status == "pending")
                {
                    authorization.Status   = Challenge.Status;
                    if (problem is null)
                        authorization.Expires = now + ACMEState.AuthorizationLifetime;
                }

            }

            if (problem is null)
                Log.Info($"ACME: the account '{authorization.Account.Id}' proved '{authorization.Identifier.Value}' by {Challenge.Type}.", "pki", "acme");
            else
                Log.Info($"ACME: the account '{authorization.Account.Id}' did not prove '{authorization.Identifier.Value}' by {Challenge.Type}: {problem.Message}", "pki", "acme");

        }

        #endregion

        #region (private) ACMEFinalize(Request, JWS, Id)

        /// <summary>
        /// POST /acme/finalize/{id}: the CSR of an order whose names are all
        /// proven, signed at once (RFC 8555, section 7.4).
        /// </summary>
        private HTTPResponse ACMEFinalize(HTTPRequest  Request,
                                          ACMERequest  JWS,
                                          String       Id)
        {

            var order    = OwnOrder(JWS, Id);
            var account  = JWS.Account!;
            var payload  = JWS.JWS.Payload ?? throw new ACMEProblem(400, "malformed", "An order is finalized with its CSR: {\"csr\"}.");

            lock (PKI.ACMEState.Gate)
            {

                var status = order.StatusAt(PKI.ACMEState.Now);

                if (status != "ready")
                    throw new ACMEProblem(403, "orderNotReady", status == "pending"
                                                                    ? "The order is pending: not every name of it is proven yet."
                                                                    : $"The order is {status}, and is finalized no more.");

                #region The CSR: its signature, its names, its key

                if (payload["csr"]?.Type != JTokenType.String)
                    throw new ACMEProblem(400, "malformed", "\"csr\" is the DER of a CSR, base64url.");

                Byte[]              der;
                CertificateRequest  csr;

                try
                {
                    der = Base64Url.DecodeFromChars(payload.Value<String>("csr")!);
                    csr = CertificateRequest.LoadSigningRequest(der, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
                }
                catch (Exception e) when (e is FormatException or CryptographicException)
                {
                    throw new ACMEProblem(400, "badCSR", "\"csr\" is no CSR whose signature holds.");
                }

                var sanNames  = new List<String>();
                var others    = false;

                foreach (var extension in csr.CertificateExtensions.Where(extension => extension.Oid?.Value == "2.5.29.17"))
                {

                    var san = extension as X509SubjectAlternativeNameExtension
                                  ?? new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);

                    sanNames.AddRange(san.EnumerateDnsNames().Select(name => name.TrimEnd('.').ToLowerInvariant()));
                    sanNames.AddRange(san.EnumerateIPAddresses().Select(address => (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString()));

                    others |= AlternativeNames.Of([ san ]).Count > san.EnumerateDnsNames().Count() + san.EnumerateIPAddresses().Count();

                }

                if (others)
                    throw new ACMEProblem(400, "badCSR", "The CSR asks for names other than host names and addresses, which nobody proved.");

                var commonName = csr.SubjectName.EnumerateRelativeDistinguishedNames().
                                     Where (rdn => rdn.GetSingleElementType().Value == "2.5.4.3").
                                     Select(rdn => rdn.GetSingleElementValue()).
                                     FirstOrDefault()?.TrimEnd('.');

                var asked      = new HashSet<String>(sanNames, StringComparer.OrdinalIgnoreCase);

                if (commonName is not null)
                    asked.Add(IPAddress.TryParse(commonName, out var address) ? address.ToString() : commonName.ToLowerInvariant());

                var ordered    = new HashSet<String>(order.Identifiers.Select(identifier => identifier.Value), StringComparer.OrdinalIgnoreCase);

                if (!asked.SetEquals(ordered))
                    throw new ACMEProblem(400, "badCSR", $"The CSR asks for {String.Join(", ", asked.Order())}, and the order is for {String.Join(", ", ordered.Order())}.");

                if (ACMEJWS.JWKOf(csr.PublicKey) is JObject csrKey && ACMEJWS.Thumbprint(csrKey) == account.Thumbprint)
                    throw new ACMEProblem(400, "badCSR", "The key of a certificate is not the key of the account (RFC 8555, section 11.1).");

                #endregion

                if (ProblemOf(order.Profile.IssuerId, "ACME") is String problem)
                    throw new ACMEProblem(500, "serverInternal", $"The CA of ACME signs nothing: {problem}");

                var names  = order.Identifiers.Select(identifier => identifier.Value).ToList();

                // A common name has 64 characters at most (RFC 5280,
                // ub-common-name), and is no more than a courtesy.
                var cn     = commonName is not null && commonName.Length <= 64
                                 ? commonName
                                 : names.FirstOrDefault(name => !name.StartsWith("*.", StringComparison.Ordinal) && name.Length <= 64)
                                       ?? names.FirstOrDefault(name => name.Length <= 64)
                                       ?? names[0][..64];

                if (!PKI.Store.TryIssueForNames(order.Profile.IssuerId, order.Profile.Profile, Convert.ToBase64String(der), cn, names,
                                                order.Profile.ValidDays, $"ACME account {account.Id}",
                                                out var certificate, out var error, out var notSaved))
                {
                    throw notSaved
                              ? new ACMEProblem(500, "serverInternal", error)
                              : new ACMEProblem(400, "badCSR", error);
                }

                if (!PKI.ACMEState.TryRecord(new ACMEIssued(certificate.Id, account.Id, PKI.ACMEState.Now, order.Replaces), out error))
                    Log.Warning($"ACME: the {certificate.InWords} '{certificate.CommonName}' ({certificate.Id}) was signed, and is not remembered as the account's: {error}", "pki", "acme");

                order.CertificateId = certificate.Id;

                Log.Notice($"ACME: the account '{account.Id}'{ContactsOf(account)} was signed the {certificate.InWords} '{certificate.CommonName}' ({certificate.Id}) " +
                           $"for {String.Join(", ", names)} below '{PKI.Store.Get(order.Profile.IssuerId)?.CommonName}', valid until {certificate.NotAfter:u}" +
                           $"{(order.Replaces is null ? "" : $", replacing {order.Replaces}")}.",
                           "pki", "acme", "security");

            }

            return ACMEJSONResponse(Request, HTTPStatusCode.OK, OrderJSON(order, JWS.Base), $"{JWS.Base}/order/{order.Id}");

        }

        #endregion

        #region (private) ACMECertificate(Request, JWS, Id)

        /// <summary>
        /// POST /acme/cert/{id}: the certificate, and the sub-CAs above it - not
        /// the root, which a client knows already or is not to learn here (RFC
        /// 8555, section 7.4.2).
        /// </summary>
        private HTTPResponse ACMECertificate(HTTPRequest  Request,
                                             ACMERequest  JWS,
                                             String       Id)
        {

            var id      = PKIStore.Normalized(Id);
            var issued  = PKI.ACMEState.Issued(id)
                              ?? throw new ACMEProblem(404, "malformed", $"There is no certificate '{Id}' of ACME.");

            if (issued.AccountId != JWS.Account!.Id)
                throw new ACMEProblem(403, "unauthorized", "The certificate is another account's.");

            var pem     = PKI.Store.ChainPEM(id)
                              ?? throw new ACMEProblem(404, "malformed", $"The certificate '{Id}' is not in this PKI any more.");

            return WithACMEHeaders(new HTTPResponse.Builder(Request) {
                                       HTTPStatusCode  = HTTPStatusCode.OK,
                                       ContentType     = PEMChainContentType,
                                       Content         = Encoding.ASCII.GetBytes(pem)
                                   }, Request).AsImmutable;

        }

        #endregion

        #region (private) ACMERevoke(Request, JWS)

        /// <summary>
        /// POST /acme/revoke-cert: a certificate revoked (RFC 8555, section 7.6)
        /// - signed by the account it was signed for, by an account that proved
        /// every name of it, or with the key of the certificate itself.
        /// </summary>
        private HTTPResponse ACMERevoke(HTTPRequest  Request,
                                        ACMERequest  JWS)
        {

            var payload = JWS.JWS.Payload ?? throw new ACMEProblem(400, "malformed", "A certificate is revoked with a payload: {\"certificate\", \"reason\"}.");

            if (payload["certificate"]?.Type != JTokenType.String)
                throw new ACMEProblem(400, "malformed", "\"certificate\" is the DER of the certificate, base64url.");

            X509Certificate2 x509;

            try
            {
                x509 = X509CertificateLoader.LoadCertificate(Base64Url.DecodeFromChars(payload.Value<String>("certificate")!));
            }
            catch (Exception e) when (e is FormatException or CryptographicException)
            {
                throw new ACMEProblem(400, "malformed", "\"certificate\" is no certificate.");
            }

            using (x509)
            {

                var id          = PKIStore.Normalized(x509.GetCertHashString(HashAlgorithmName.SHA256));
                var certificate = PKI.Store.Get(id)
                                      ?? throw new ACMEProblem(404, "malformed", "The certificate is none of this PKI.");

                if (certificate.Profile.IsCA())
                    throw new ACMEProblem(403, "unauthorized", "A CA is not revoked over ACME.");

                #region Who may: the account, one that proved every name, or the key of the certificate

                String revokedBy;

                if (JWS.Account is ACMEAccount account)
                {

                    var owner     = PKI.ACMEState.Issued(id)?.AccountId == account.Id;

                    var allProven = !owner &&
                                    AlternativeNames.Of(x509).Count > 0 &&
                                    AlternativeNames.Of(x509).All(name => PKI.ACMEState.ValidAuthorization(account,
                                                                              new ACMEIdentifier(IPAddress.TryParse(name, out _) ? "ip" : "dns", name.ToLowerInvariant())) is not null);

                    if (!owner && !allProven)
                        throw new ACMEProblem(403, "unauthorized", "The certificate was signed for another account, and this one proved not every name of it.");

                    revokedBy = $"ACME account {account.Id}";

                }

                else
                {

                    if (!ACMEJWS.SameKey(JWS.JWS.JWK!, x509))
                        throw new ACMEProblem(403, "unauthorized", "The key that signed is not the key of the certificate.");

                    revokedBy = "ACME, with the key of the certificate";

                }

                #endregion

                var reasonToken = payload["reason"];
                var reason      = reasonToken is null || reasonToken.Type == JTokenType.Null ? 0 : reasonToken.Type == JTokenType.Integer ? reasonToken.Value<Int32>() : -1;

                if (!ACMERevocationReasons.Contains(reason))
                    throw new ACMEProblem(400, "badRevocationReason", $"A certificate is revoked over ACME for one of the reasons {String.Join(", ", ACMERevocationReasons)} of RFC 5280.");

                if (certificate.RevokedAt is not null)
                    throw new ACMEProblem(400, "alreadyRevoked", $"The certificate was revoked already, on {certificate.RevokedAt:u}.");

                if (!PKI.Store.TryRevoke(id, (X509RevocationReason) reason, null, revokedBy,
                                         out var revoked, out var error, out var warning, out _, out var notSaved))
                {
                    throw new ACMEProblem(notSaved ? 500 : 400, notSaved ? "serverInternal" : "malformed", error);
                }

                if (warning is not null)
                    Log.Warning($"PKI: {warning}", "pki", "acme", "security");

                Log.Notice($"{revokedBy} revoked the {revoked.InWords} '{revoked.CommonName}' ({revoked.Id}) for {RevocationReasons.AsText((X509RevocationReason) reason)}.",
                           "pki", "acme", "security");

            }

            return WithACMEHeaders(new HTTPResponse.Builder(Request) {
                                       HTTPStatusCode  = HTTPStatusCode.OK
                                   }, Request).AsImmutable;

        }

        #endregion

        #region (private) ACMERenewalInfo(Request)

        /// <summary>
        /// GET /acme/renewal-info/{id}: when a certificate of this PKI should be
        /// renewed (RFC 9773) - in the last third of its life, and at once where
        /// it was revoked.
        /// </summary>
        private Task<HTTPResponse> ACMERenewalInfo(HTTPRequest Request)
        {

            if (!PKI.ACME.Enabled)
                return Task.FromResult(ACMEProblemResponse(Request, NoACME()));

            var certificate = CertificateOfARIIdentifier(IdOfACME(Request));

            if (certificate is null)
                return Task.FromResult(ACMEProblemResponse(Request, new ACMEProblem(404, "malformed", $"'{IdOfACME(Request)}' names no certificate of this PKI.")));

            var now           = PKI.ACMEState.Now;
            var lifetime      = certificate.NotAfter - certificate.NotBefore;

            var (start, end)  = certificate.RevokedAt is not null
                                    ? (now.AddHours(-2), now.AddHours(-1))
                                    : (certificate.NotAfter - lifetime / 3, certificate.NotAfter - lifetime / 6);

            var json          = new JObject(
                                    new JProperty("suggestedWindow", new JObject(
                                        new JProperty("start", start.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")),
                                        new JProperty("end",   end.  UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"))
                                    ))
                                );

            return Task.FromResult(WithACMEHeaders(new HTTPResponse.Builder(Request) {
                                                       HTTPStatusCode  = HTTPStatusCode.OK,
                                                       ContentType     = HTTPContentType.Application.JSON_UTF8,
                                                       Content         = Encoding.UTF8.GetBytes(json.ToString(Formatting.None))
                                                   }.Set("Retry-After", ((Int32) RenewalInfoRetryAfter.TotalSeconds).ToString()), Request).AsImmutable);

        }

        /// <summary>
        /// The certificate of this PKI an identifier of RFC 9773, section 4.1,
        /// names: the key identifier of its CA and its serial number, both
        /// base64url, with a dot between them - or null.
        /// </summary>
        private IssuedCertificate? CertificateOfARIIdentifier(String Identifier)
        {

            var parts = Identifier.Split('.');

            if (parts.Length != 2)
                return null;

            Byte[] keyIdentifier, serial;

            try
            {
                keyIdentifier = Base64Url.DecodeFromChars(parts[0]);
                serial        = Base64Url.DecodeFromChars(parts[1]);
            }
            catch (FormatException)
            {
                return null;
            }

            var serialHex = Convert.ToHexString(serial);

            foreach (var candidate in PKI.Store.Find().Where(one => !one.Profile.IsCA() &&
                                                                    (one.SerialNumber.Equals(serialHex, StringComparison.OrdinalIgnoreCase) ||
                                                                     one.SerialNumber.TrimStart('0').Equals(serialHex.TrimStart('0'), StringComparison.OrdinalIgnoreCase))))
            {

                using var x509 = PKI.Store.Load(candidate.Id);

                var aki = x509?.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().FirstOrDefault()?.KeyIdentifier;

                if (aki is not null && aki.Value.Span.SequenceEqual(keyIdentifier))
                    return candidate;

            }

            return null;

        }

        #endregion


        #region (private) ACMEHandle(Request, Key, Handler)

        /// <summary>
        /// What a request of ACME is signed with: the key of a new account, the
        /// account's, or either - to revoke a certificate.
        /// </summary>
        private enum ACMEKey
        {
            JWK,
            Account,
            Either
        }

        /// <summary>
        /// A request of ACME, checked: its JWS, the account that signed it,
        /// where one did, and where the ACME server is as the client sees it.
        /// </summary>
        private sealed record ACMERequest(ACMEJWS       JWS,
                                          ACMEAccount?  Account,
                                          String        Base);

        private HTTPResponse ACMEHandle(HTTPRequest                                   Request,
                                        ACMEKey                                       Key,
                                        Func<HTTPRequest, ACMERequest, HTTPResponse>  Handler)
        {
            try
            {
                return Handler(Request, VerifyACME(Request, Key));
            }
            catch (ACMEProblem problem)
            {
                return ACMEProblemResponse(Request, problem);
            }
            catch (Exception e)
            {
                Log.Error($"ACME: {Request.Path} failed: {e.Message}", "pki", "acme");
                return ACMEProblemResponse(Request, new ACMEProblem(500, "serverInternal", "Something went wrong inside the PKI."));
            }
        }

        #endregion

        #region (private) VerifyACME(Request, Key)

        /// <summary>
        /// Check a request as RFC 8555, section 6.2 asks: a flattened JWS, an
        /// algorithm of public keys, a nonce handed out and not used before,
        /// the URL it was sent to, a "jwk" or a "kid" where each belongs, and a
        /// signature by that key - the account's, which must be valid.
        /// </summary>
        private ACMERequest VerifyACME(HTTPRequest  Request,
                                       ACMEKey      Key)
        {

            if (!PKI.ACME.Enabled)
                throw NoACME();

            if (Request.ContentType?.MediaType != "application/jose+json")
                throw new ACMEProblem(415, "malformed", "A request of ACME is sent as application/jose+json.");

            var jws   = ACMEJWS.Parse(Request.HTTPBodyAsUTF8String ?? "");

            if (!PKI.ACMEState.TryUseNonce(jws.Nonce))
                throw new ACMEProblem(400, "badNonce", "The nonce was never handed out here, is used up or is too old: a new one is in Replay-Nonce.");

            var base_ = ACMEBase(Request);
            var url   = ACMERoot(Request) + Request.Path.ToString();

            if (jws.URL != url)
                throw new ACMEProblem(401, "unauthorized", $"The JWS is for '{jws.URL}', and was sent to '{url}'.");

            if (jws.JWK is JObject jwk)
            {

                if (Key == ACMEKey.Account)
                    throw new ACMEProblem(400, "malformed", "This request is signed by the key of an account, named by its \"kid\".");

                ACMEJWS.Check(jwk);

                if (!jws.SignedBy(jwk))
                    throw new ACMEProblem(400, "malformed", "The signature of the JWS does not hold.");

                return new ACMERequest(jws, null, base_);

            }

            if (Key == ACMEKey.JWK)
                throw new ACMEProblem(400, "malformed", "A new account is asked for with its key as the \"jwk\", not with a \"kid\".");

            var prefix  = $"{base_}/acct/";
            var account = jws.KeyId!.StartsWith(prefix, StringComparison.Ordinal)
                              ? PKI.ACMEState.Account(jws.KeyId[prefix.Length..])
                              : null;

            if (account is null)
                throw new ACMEProblem(400, "accountDoesNotExist", $"'{jws.KeyId}' is no account here.");

            if (account.Status != "valid")
                throw new ACMEProblem(401, "unauthorized", $"The account '{account.Id}' is {account.Status}.");

            if (!jws.SignedBy(account.JWK))
                throw new ACMEProblem(400, "malformed", "The signature of the JWS does not hold by the key of the account.");

            return new ACMERequest(jws, account, base_);

        }

        #endregion

        #region (private) JSON of the resources

        private static String AccountURL(ACMEAccount  Account,
                                         String       Base)

            => $"{Base}/acct/{Account.Id}";

        private static JObject AccountJSON(ACMEAccount  Account,
                                           String       Base)
        {

            var json = new JObject(
                           new JProperty("status",     Account.Status),
                           new JProperty("contact",    new JArray(Account.Contacts)),
                           new JProperty("orders",     $"{Base}/acct/{Account.Id}/orders"),
                           new JProperty("createdAt",  Account.CreatedAt.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"))
                       );

            if (Account.AgreedToTerms)
                json.Add(new JProperty("termsOfServiceAgreed", true));

            return json;

        }

        private JObject OrderJSON(ACMEOrder  Order,
                                  String     Base)
        {

            lock (PKI.ACMEState.Gate)
            {

                var status = Order.StatusAt(PKI.ACMEState.Now);

                var json   = new JObject(
                                 new JProperty("status",          status),
                                 new JProperty("expires",         Order.Expires.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")),
                                 new JProperty("identifiers",     new JArray(Order.Identifiers.Select(identifier => identifier.ToJSON()))),
                                 new JProperty("authorizations",  new JArray(Order.Authorizations.Select(authorization => $"{Base}/authz/{authorization.Id}"))),
                                 new JProperty("finalize",        $"{Base}/finalize/{Order.Id}")
                             );

                if (Order.ProfileName is not null)
                    json.Add(new JProperty("profile", Order.ProfileName));

                if (Order.CertificateId is not null)
                    json.Add(new JProperty("certificate", $"{Base}/cert/{Order.CertificateId}"));

                if (status == "invalid")
                    json.Add(new JProperty("error", (Order.Error ?? Order.Authorizations.SelectMany(authorization => authorization.Challenges).
                                                                                          Select   (challenge     => challenge.Error).
                                                                                          OfType<ACMEProblem>().
                                                                                          FirstOrDefault()
                                                           ?? new ACMEProblem(403, "unauthorized", PKI.ACMEState.Now > Order.Expires
                                                                                                       ? "The order expired."
                                                                                                       : "Not every name of the order could be proven.")).ToJSON()));

                return json;

            }

        }

        private JObject AuthorizationJSON(ACMEAuthorization  Authorization,
                                          String             Base)
        {

            lock (PKI.ACMEState.Gate)
            {

                var json = new JObject(
                               new JProperty("status",      Authorization.StatusAt(PKI.ACMEState.Now)),
                               new JProperty("expires",     Authorization.Expires.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")),
                               new JProperty("identifier",  new ACMEIdentifier(Authorization.Identifier.Type, Authorization.Identifier.Proven).ToJSON()),
                               new JProperty("challenges",  new JArray(Authorization.Challenges.Select(challenge => ChallengeJSON(challenge, Base))))
                           );

                if (Authorization.Identifier.IsWildcard)
                    json.Add(new JProperty("wildcard", true));

                return json;

            }

        }

        private static JObject ChallengeJSON(ACMEChallenge  Challenge,
                                             String         Base)
        {

            var json = new JObject(
                           new JProperty("type",    Challenge.Type),
                           new JProperty("url",     $"{Base}/chall/{Challenge.Id}"),
                           new JProperty("status",  Challenge.Status),
                           new JProperty("token",   Challenge.Token)
                       );

            if (Challenge.Validated is DateTimeOffset validated)
                json.Add(new JProperty("validated", validated.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")));

            if (Challenge.Error is ACMEProblem error)
                json.Add(new JProperty("error", error.ToJSON()));

            return json;

        }

        #endregion

        #region (private) Answers

        /// <summary>
        /// Where the ACME server is as the client sees it: the scheme and the
        /// host it asked - or a trusted proxy in front says it asked - and
        /// "/acme".
        /// </summary>
        private String ACMEBase(HTTPRequest Request)
            => ACMERoot(Request) + ACMEPath;

        private String ACMERoot(HTTPRequest Request)
            => $"{(PKI.ReachedOverHTTPS(Request) ? "https" : "http")}://{PKI.ProxyHostOf(Request) ?? Request.Host.ToString()}";

        private static ACMEProblem NoACME()
            => new (404, "malformed", "ACME signs nothing here: the PKI was told no CA to sign with.");

        /// <summary>
        /// What every answer of ACME has: a fresh nonce, where the directory
        /// is, and that it is not to be cached.
        /// </summary>
        private HTTPResponse.Builder WithACMEHeaders(HTTPResponse.Builder  Builder,
                                                     HTTPRequest           Request,
                                                     String?               MoreLinks = null)
        {

            Builder.CacheControl = "no-store";
            Builder.Set("Replay-Nonce", PKI.ACMEState.NewNonce());
            Builder.Set("Link",         $"<{ACMEBase(Request)}/directory>;rel=\"index\"" + (MoreLinks is null ? "" : $", {MoreLinks}"));

            return Builder.WithCommonSecurityHeaders();

        }

        private HTTPResponse ACMEJSONResponse(HTTPRequest     Request,
                                              HTTPStatusCode  StatusCode,
                                              JObject         JSON,
                                              String?         Location   = null,
                                              String?         MoreLinks  = null)
        {

            var builder = new HTTPResponse.Builder(Request) {
                              HTTPStatusCode  = StatusCode,
                              ContentType     = HTTPContentType.Application.JSON_UTF8,
                              Content         = Encoding.UTF8.GetBytes(JSON.ToString(Formatting.None))
                          };

            if (Location is not null)
                builder.Set("Location", Location);

            return WithACMEHeaders(builder, Request, MoreLinks).AsImmutable;

        }

        private HTTPResponse ACMEProblemResponse(HTTPRequest  Request,
                                                 ACMEProblem  Problem)
        {

            var builder = new HTTPResponse.Builder(Request) {
                              HTTPStatusCode  = HTTPStatusCode.TryParseUInt16((UInt16) Problem.Status, out var statusCode) ? statusCode : HTTPStatusCode.BadRequest,
                              ContentType     = ProblemContentType,
                              Content         = Encoding.UTF8.GetBytes(Problem.ToJSON().ToString(Formatting.None))
                          };

            if (Problem.Location is not null)
                builder.Set("Location", Problem.Location);

            return WithACMEHeaders(builder, Request).AsImmutable;

        }

        #endregion

    }

}
