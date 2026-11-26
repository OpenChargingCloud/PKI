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
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.ACME;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.PKI.Issuance;

using ACMESettings = cloud.charging.open.PKI.Enrollment.ACMESettings;
using ACMEProfile  = cloud.charging.open.PKI.Enrollment.ACMEProfile;

#endregion

namespace cloud.charging.open.PKI.Tests
{

    /// <summary>
    /// The ACME server of the PKI, RFC 8555, against a started PKI and as
    /// Hermod's ACME client speaks it: an account, names proven by http-01
    /// from a Hermod HTTP server and by dns-01 from a zone of the test, the
    /// certificate signed below a sub-CA of the PKI, its renewal information,
    /// and its revocation - and the PKI as strict as Let's Encrypt where a
    /// client could get it wrong.
    /// </summary>
    public class ACMETests
    {

        #region Data

        private const String  NoTimeServers  = """{ "nts": { "groups": { "legal": { "enabled": false } } } }""";

        private String                     directory  = "";
        private PKI?                       pki;
        private HTTPServer?                port80;
        private HTTP01ChallengeResponder?  http01;
        private IssuedCertificate?         root;
        private IssuedCertificate?         sub;

        /// <summary>The zone the dns-01 of the tests is written to, and looked into: name to values.</summary>
        private readonly ConcurrentDictionary<String, ConcurrentDictionary<String, Byte>> zone = new (StringComparer.OrdinalIgnoreCase);

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "pki-acme-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);

            zone.Clear();

        }

        [TearDown]
        public async Task TearDown()
        {

            if (port80 is not null)
                await port80.DisposeAsync();

            if (pki is not null)
                await pki.DisposeAsync();

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            {
                // A temporary directory that outlives one test run is not worth
                // failing the run over.
            }

        }

        #endregion


        #region (helpers)

        /// <summary>
        /// A started PKI with a root and a sub-CA below it, ACME signing below
        /// the sub-CA as the given settings say, http-01 asked on a "port 80"
        /// of the test, and dns-01 looked for in the test's zone.
        /// </summary>
        private async Task<PKI> Started(Func<String, JObject>? Settings = null)
        {

            var file = Path.Combine(directory, WWCPConfigFile.DefaultFileName);
            File.WriteAllText(file, NoTimeServers);

            await TestPorts.StartedOnFreshPorts(() => pki = new PKI(HTTPPort:        TestPorts.Free(),
                                                                    AccountsPath:    Path.Combine(directory, "accounts"),
                                                                    ConfigFile:      new WWCPConfigFile(file),
                                                                    LogToConsole:    false,
                                                                    BridgeDebugLog:  false));

            Assert.That(pki!.Store.TryCreateRootCA(new SubjectName("ACME Root"), KeyAlgorithm.ECC_P256, 365, null, null, null, out root, out var error, out _), Is.True, error);
            Assert.That(pki.Store.TryIssue(root!.Id, null, CertificateProfile.SubCA, new SubjectName("ACME Sub"), KeyAlgorithm.ECC_P256, 300, [], null, null, null,
                                           out sub, out error, out _), Is.True, error);

            port80 = new HTTPServer(IPAddress: IPv4Address.Localhost, TCPPort: IPPort.Zero, AutoStart: true);
            http01 = new HTTP01ChallengeResponder();
            http01.RegisterAt(port80);

            var settings = Settings?.Invoke(sub!.Id) ?? new JObject(new JProperty("issuer", sub!.Id));
            settings["http01Port"] = port80.TCPPort.ToUInt16();

            Assert.That(ACMESettings.TryParse(settings, out var acme, out error), Is.True, error);
            Assert.That(pki.TrySetACME(acme!, out error), Is.True, error);

            pki.ACMEValidator.LookupTXT = (name, _) => Task.FromResult<IReadOnlyList<String>>(
                                                           zone.TryGetValue(name, out var values) ? [.. values.Keys] : []);

            return pki;

        }

        private ACMEClient NewClient(ACMEAccountKey? Key = null)

            => new (new Uri(pki!.ACMEDirectoryAt()),
                    Key ?? ACMEAccountKey.Generate(),
                    PollInterval: TimeSpan.FromMilliseconds(100),
                    PollTimeout:  TimeSpan.FromSeconds(20));

        /// <summary>
        /// What dns-01 of the tests answers with: TXT records in the zone.
        /// </summary>
        private DNS01ChallengeResponder DNS01()

            => new (Publish:   (name, value, ct) => {
                                   zone.GetOrAdd(name.TrimEnd('.'), _ => new ConcurrentDictionary<String, Byte>())[value] = 0;
                                   return Task.CompletedTask;
                               },
                    Withdraw:  (name, value, ct) => {
                                   if (zone.TryGetValue(name.TrimEnd('.'), out var values))
                                       values.TryRemove(value, out _);
                                   return Task.CompletedTask;
                               });

        /// <summary>
        /// An account made for the purpose, in the group of the given role, and
        /// the HTTP Basic credentials it signs in with.
        /// </summary>
        private async Task<AuthenticationHeaderValue> Account(User_Id Name, String Role)
        {

            var password = "correct-horse-battery-" + Guid.NewGuid().ToString("N")[..8];

            Assert.That(pki!.ExtAPI.TryGetOrganization(Organization_Id.Parse("PKI"), out var organization), Is.True);

            await pki.ExtAPI.CreateUser(Name,
                                        I18NString.Create(Languages.en, Name.ToString()),
                                        SimpleEMailAddress.Parse($"{Name}@localhost"),
                                        User2OrganizationEdgeLabel.IsMember,
                                        (Organization) organization!,
                                        Password:                  password,
                                        SkipDefaultNotifications:  true,
                                        SkipNewUserEMail:          true,
                                        SkipNewUserNotifications:  true,
                                        AcceptedEULA:              DateTimeOffset.UtcNow.AddSeconds(-1),
                                        IsAuthenticated:           true);

            Assert.That(pki.ExtAPI.TryGetUser(Name, out var stored), Is.True);
            Assert.That(pki.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group), Is.True);
            Assert.That((await pki.ExtAPI.AddUserToUserGroup((User) stored!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!)).IsSuccess, Is.True);

            return new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Name}:{password}")));

        }

        #region (helpers) A JWS by hand

        /// <summary>
        /// A request of ACME signed by hand: to see what the PKI makes of one a
        /// careful client would never send.
        /// </summary>
        private static async Task<(HttpStatusCode Status, JObject? Body, HttpResponseMessage Response)> PostJWS(HttpClient       HTTP,
                                                                                                                  String           URL,
                                                                                                                  JObject?         Payload,
                                                                                                                  ACMEAccountKey   Key,
                                                                                                                  String?          KeyId      = null,
                                                                                                                  String?          Nonce      = null,
                                                                                                                  String?          HeaderURL  = null)
        {

            Nonce ??= await NonceOf(HTTP, URL);

            var header = new JObject(
                             new JProperty("alg",    "ES256"),
                             new JProperty("nonce",  Nonce),
                             new JProperty("url",    HeaderURL ?? URL)
                         );

            if (KeyId is null)
                header["jwk"] = Key.JWK;
            else
                header["kid"] = KeyId;

            var protected_ = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToString(Formatting.None)));
            var payload    = Payload is null ? "" : Base64Url.EncodeToString(Encoding.UTF8.GetBytes(Payload.ToString(Formatting.None)));
            var signature  = Base64Url.EncodeToString(Key.Sign(Encoding.ASCII.GetBytes($"{protected_}.{payload}")));

            var content    = new StringContent(new JObject(new JProperty("protected", protected_), new JProperty("payload", payload), new JProperty("signature", signature)).ToString(), Encoding.UTF8);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");

            var response   = await HTTP.PostAsync(URL, content);
            var text       = await response.Content.ReadAsStringAsync();

            return (response.StatusCode, text.StartsWith('{') ? JObject.Parse(text) : null, response);

        }

        private static async Task<String> NonceOf(HttpClient HTTP, String AnyURL)
        {
            using var head = new HttpRequestMessage(HttpMethod.Head, new Uri(new Uri(AnyURL), "/acme/new-nonce"));
            using var response = await HTTP.SendAsync(head);
            return response.Headers.GetValues("Replay-Nonce").Single();
        }

        private static String? TypeOf(JObject? Problem)
            => Problem?.Value<String>("type")?.Replace("urn:ietf:params:acme:error:", "");

        #endregion

        #endregion


        #region TheSettingsOfACMEAreReadAsTheyAreWritten()

        [Test]
        public void TheSettingsOfACMEAreReadAsTheyAreWritten()
        {

            var issuer = new String('a', 64);

            var json   = JObject.Parse($$"""
                                         { "issuer": "{{issuer}}", "validDays": 30,
                                           "profiles": { "shortlived": { "issuer": "{{issuer}}", "validDays": 7, "description": "A week." },
                                                         "client":     { "issuer": "{{issuer}}", "profile": "client" } },
                                           "externalAccountRequired": true,
                                           "allowedNames": [ "lab.example.org", "10.0.0.0/8", "2001:db8::/32", "192.168.1.7" ],
                                           "challenges": [ "dns-01" ], "http01Port": 8080, "termsOfService": "https://pki.example.org/terms" }
                                         """);

            Assert.That(ACMESettings.TryParse(json, out var settings, out var error), Is.True, error);
            Assert.That(ACMESettings.TryParse(settings!.ToJSON(), out var again, out error), Is.True, error);

            Assert.Multiple(() => {

                Assert.That(again!.Default,                    Is.EqualTo(new ACMEProfile(issuer, CertificateProfile.Server, 30)));
                Assert.That(again.For("shortlived"),           Is.EqualTo(new ACMEProfile(issuer, CertificateProfile.Server, 7, "A week.")));
                Assert.That(again.For("client")!.Profile,      Is.EqualTo(CertificateProfile.Client));
                Assert.That(again.For("client")!.ValidDays,    Is.EqualTo(ACMESettings.DefaultValidDays));
                Assert.That(again.For("nothing"),              Is.Null);
                Assert.That(again.ExternalAccountRequired,     Is.True);
                Assert.That(again.Challenges,                  Is.EqualTo(new[] { "dns-01" }));
                Assert.That(again.HTTP01Port,                  Is.EqualTo(8080));
                Assert.That(again.TermsOfService,              Is.EqualTo("https://pki.example.org/terms"));

                Assert.That(again.Allows("dns", "lab.example.org"),      Is.True,  "a domain stands for itself");
                Assert.That(again.Allows("dns", "cs1.lab.example.org"),  Is.True,  "and for every name below it");
                Assert.That(again.Allows("dns", "evillab.example.org"),  Is.False, "but not for a name that merely ends like it");
                Assert.That(again.Allows("dns", "example.org"),          Is.False);
                Assert.That(again.Allows("ip",  "10.20.30.40"),          Is.True);
                Assert.That(again.Allows("ip",  "11.0.0.1"),             Is.False);
                Assert.That(again.Allows("ip",  "2001:db8::1"),          Is.True);
                Assert.That(again.Allows("ip",  "192.168.1.7"),          Is.True,  "an address stands for itself");
                Assert.That(again.Allows("ip",  "192.168.1.8"),          Is.False);

                Assert.That(ACMESettings.TryParse(null, out var none, out _), Is.True);
                Assert.That(none!.Enabled,                                    Is.False);
                Assert.That(none.Allows("dns", "anything.example"),           Is.True, "no allowed names are every name");

                Assert.That(ACMESettings.TryParse(JObject.Parse($$"""{ "issuer": "{{issuer}}", "profile": "subCA" }"""), out _, out _),     Is.False, "ACME makes no CA");
                Assert.That(ACMESettings.TryParse(JObject.Parse($$"""{ "issuer": "{{issuer}}", "challenges": [ "tls-alpn-01" ] }"""), out _, out _), Is.False, "tls-alpn-01 is not looked at");
                Assert.That(ACMESettings.TryParse(JObject.Parse($$"""{ "issuer": "{{issuer}}", "allowedNames": [ "10.0.0.0/33" ] }"""), out _, out _), Is.False);

            });

        }

        #endregion

        #region AClientIsSignedACertificate_ByHTTP01_AndRenewsAndRevokesIt()

        [Test]
        public async Task AClientIsSignedACertificate_ByHTTP01_AndRenewsAndRevokesIt()
        {

            await Started();

            using var http   = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            using var client = NewClient();

            #region The directory

            var directory = JObject.Parse(await http.GetStringAsync(pki!.ACMEDirectoryAt()));

            Assert.That(directory.Value<String>("newAccount"),  Does.EndWith("/acme/new-account"));
            Assert.That(directory.Value<String>("renewalInfo"), Does.EndWith("/acme/renewal-info"));
            Assert.That(directory["meta"]!.Value<Boolean>("externalAccountRequired"), Is.False);

            #endregion

            var account     = await client.CreateAccountAsync(["admin@example.org"]);
            Assert.That(account.Created, Is.True);

            var certificate = await client.ObtainCertificateAsync(["Localhost", "127.0.0.1"], [ http01! ]);

            #region What was signed, and by whom

            Assert.That(certificate.Identifiers.Select(identifier => identifier.Value), Is.EquivalentTo(new[] { "localhost", "127.0.0.1" }));
            Assert.That(certificate.Certificate.Issuer,                                 Is.EqualTo("CN=ACME Sub"));
            Assert.That(certificate.Certificate.GetNameInfo(X509NameType.SimpleName, false), Is.EqualTo("localhost"));
            Assert.That(certificate.Chain.Intermediates.Select(one => one.Subject),     Is.EqualTo(new[] { "CN=ACME Sub" }), "the sub-CA comes along, the root does not");
            Assert.That(http01!.Open,                                                   Is.EqualTo(0), "the answers are taken away again");

            var issued = pki.Store.Get(PKIStore.Normalized(certificate.Certificate.GetCertHashString(HashAlgorithmName.SHA256)));

            Assert.That(issued,                              Is.Not.Null, "the certificate is in the store, as every certificate the PKI makes");
            Assert.That(issued!.Profile,                     Is.EqualTo(CertificateProfile.Server));
            Assert.That(issued.CreatedBy,                    Does.StartWith("ACME account "));
            Assert.That(issued.HasPrivateKey,                Is.False, "the key stays with the client");
            Assert.That((issued.NotAfter - issued.NotBefore).TotalDays, Is.EqualTo(ACMESettings.DefaultValidDays).Within(1));

            var serverAuth = certificate.Certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.Value);
            Assert.That(serverAuth, Does.Contain("1.3.6.1.5.5.7.3.1"));

            #endregion

            #region Renewal information, and a renewal proven already

            var window = await client.GetRenewalInfoAsync(certificate.Certificate);

            Assert.That(window,                  Is.Not.Null);
            Assert.That(window!.Start,           Is.GreaterThan(DateTimeOffset.UtcNow.AddDays(50)));
            Assert.That(window.End,              Is.LessThan(certificate.NotAfter));

            var renewed = await client.ObtainCertificateAsync(["localhost", "127.0.0.1"], [], Replacing: certificate.Certificate);

            Assert.That(renewed.Certificate.Thumbprint, Is.Not.EqualTo(certificate.Certificate.Thumbprint),
                        "a second certificate, without anybody answering a challenge: the names are proven for the account already");

            var e = await Assert.ThrowsAsync<ACMEException>(() => client.NewOrderAsync([ ACMEIdentifier.From("localhost") ],
                                                                                 Replaces: ACMEClient.CertificateIdentifier(certificate.Certificate)));
            Assert.That(e!.Problem?.ShortType, Is.EqualTo("alreadyReplaced"));

            #endregion

            #region Revoked

            await client.RevokeCertificateAsync(certificate.Certificate, Reason: 4);

            Assert.That(pki.Store.Get(issued.Id)!.RevokedAt, Is.Not.Null);

            window = await client.GetRenewalInfoAsync(certificate.Certificate);
            Assert.That(window!.End, Is.LessThan(DateTimeOffset.UtcNow), "a revoked certificate is renewed at once");

            e = await Assert.ThrowsAsync<ACMEException>(() => client.RevokeCertificateAsync(certificate.Certificate));
            Assert.That(e!.Problem?.ShortType, Is.EqualTo("alreadyRevoked"));

            // Another account proved nothing, and revokes nothing.
            using var stranger = NewClient();
            await stranger.CreateAccountAsync();
            e = await Assert.ThrowsAsync<ACMEException>(() => stranger.RevokeCertificateAsync(renewed.Certificate));
            Assert.That(e!.Problem?.ShortType, Is.EqualTo("unauthorized"));

            #endregion

            #region The account is remembered after a restart

            Assert.That(File.ReadAllText(pki.ACMEState.File), Does.Contain(account.URL.ToString().Split('/').Last()));

            #endregion

        }

        #endregion

        #region AWildcardIsProvenByDNS01_AndAProfileIsTaken()

        [Test]
        public async Task AWildcardIsProvenByDNS01_AndAProfileIsTaken()
        {

            await Started(sub => new JObject(
                                     new JProperty("issuer",    sub),
                                     new JProperty("profiles",  new JObject(
                                                                    new JProperty("shortlived", new JObject(new JProperty("issuer", sub), new JProperty("validDays", 7)))
                                                                ))
                                 ));

            using var client = NewClient();
            await client.CreateAccountAsync();

            var certificate = await client.ObtainCertificateAsync(["*.lab.example.org", "lab.example.org"], [ DNS01() ], Profile: "shortlived");

            Assert.That(certificate.Identifiers.Select(identifier => identifier.Value), Is.EquivalentTo(new[] { "*.lab.example.org", "lab.example.org" }));
            Assert.That((certificate.NotAfter - certificate.NotBefore).TotalDays,       Is.EqualTo(7).Within(1));
            Assert.That(zone.Values.Sum(values => values.Count),                        Is.EqualTo(0), "the records are taken away again");

            var e = await Assert.ThrowsAsync<ACMEException>(() => client.NewOrderAsync([ ACMEIdentifier.From("other.example.org") ], Profile: "longlived"));
            Assert.That(e!.Problem?.ShortType, Is.EqualTo("invalidProfile"));

        }

        #endregion

        #region AChallengeNotAnswered_LeavesTheOrderInvalid()

        [Test]
        public async Task AChallengeNotAnswered_LeavesTheOrderInvalid()
        {

            await Started();

            using var client = NewClient();
            await client.CreateAccountAsync();

            // A dns-01 that publishes nothing: the zone stays empty.
            var silent = new DNS01ChallengeResponder(Publish: (_, _, _) => Task.CompletedTask, Withdraw: (_, _, _) => Task.CompletedTask);

            var e = await Assert.ThrowsAsync<ACMEException>(() => client.ObtainCertificateAsync(["nothing.example.org"], [ silent ]));

            Assert.That(e!.Message, Does.Contain("_acme-challenge.nothing.example.org"));
            Assert.That(pki!.Store.Find(CommonName: "nothing.example.org"), Is.Empty);

        }

        #endregion

        #region OnlyTheNamesAllowedAreSigned()

        [Test]
        public async Task OnlyTheNamesAllowedAreSigned()
        {

            await Started(sub => new JObject(
                                     new JProperty("issuer",        sub),
                                     new JProperty("allowedNames",  new JArray("lab.example.org", "127.0.0.0/8"))
                                 ));

            using var client = NewClient();
            await client.CreateAccountAsync();

            var e = await Assert.ThrowsAsync<ACMEException>(() => client.NewOrderAsync([ ACMEIdentifier.From("www.example.com") ]));
            Assert.That(e!.Problem?.ShortType, Is.EqualTo("rejectedIdentifier"));

            e = await Assert.ThrowsAsync<ACMEException>(() => client.NewOrderAsync([ ACMEIdentifier.From("10.0.0.1") ]));
            Assert.That(e!.Problem?.ShortType, Is.EqualTo("rejectedIdentifier"));

            var order = await client.NewOrderAsync([ ACMEIdentifier.From("cs1.lab.example.org"), ACMEIdentifier.From("127.0.0.2") ]);
            Assert.That(order.Status, Is.EqualTo("pending"));

        }

        #endregion

        #region AnExternalAccountBinding_IsAKeyOfThePKI_UsedOnce()

        [Test]
        public async Task AnExternalAccountBinding_IsAKeyOfThePKI_UsedOnce()
        {

            await Started(sub => new JObject(
                                     new JProperty("issuer",                   sub),
                                     new JProperty("externalAccountRequired",  true)
                                 ));

            var registrar = await Account(User_Id.Parse("registrar7"), "registrar");
            var operator_ = await Account(User_Id.Parse("operator7"),  "operator");

            using var http = new HttpClient { BaseAddress = new Uri(pki!.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(30) };

            async Task<HttpResponseMessage> NewKeyAs(AuthenticationHeaderValue Who)
            {
                using var post = new HttpRequestMessage(HttpMethod.Post, "api/v1/pki/acme/eab") { Content = new StringContent("""{ "description": "CSMS 1" }""", Encoding.UTF8, "application/json") };
                post.Headers.Authorization = Who;
                return await http.SendAsync(post);
            }

            Assert.That((await NewKeyAs(operator_)).StatusCode, Is.EqualTo(HttpStatusCode.Forbidden), "a key is made by whoever may sign certificates");

            var made   = await NewKeyAs(registrar);
            Assert.That(made.StatusCode, Is.EqualTo(HttpStatusCode.Created));

            var key    = JObject.Parse(await made.Content.ReadAsStringAsync());
            var kid    = key.Value<String>("kid")!;
            var hmac   = key.Value<String>("hmacKey")!;

            #region Without the binding, and with a wrong one, nothing is opened

            using var accountKey = ACMEAccountKey.Generate();

            var (status, problem, _) = await PostJWS(http, pki.ACMEDirectoryAt().Replace("/directory", "/new-account"),
                                                     new JObject(new JProperty("termsOfServiceAgreed", true)), accountKey);

            Assert.That(status,           Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(TypeOf(problem),  Is.EqualTo("externalAccountRequired"));

            using var wrong = NewClient(accountKey);
            var e = await Assert.ThrowsAsync<ACMEException>(() => wrong.CreateAccountAsync(EABKeyId: kid, EABHMACKey: Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32))));
            Assert.That(e!.Problem?.ShortType, Is.EqualTo("unauthorized"));

            #endregion

            using var client = NewClient(accountKey);
            var account      = await client.CreateAccountAsync(["csms@example.org"], EABKeyId: kid, EABHMACKey: hmac);

            Assert.That(account.Created, Is.True);
            Assert.That(pki.ACMEState.Accounts().Single().VouchedForBy, Is.EqualTo("registrar7"));
            Assert.That(pki.ACMEState.ExternalAccountKey(kid)!.BoundTo, Is.Not.Null);

            // The key opened one account, and opens no other.
            using var another = NewClient();
            e = await Assert.ThrowsAsync<ACMEException>(() => another.CreateAccountAsync(EABKeyId: kid, EABHMACKey: hmac));
            Assert.That(e!.Problem?.ShortType, Is.EqualTo("unauthorized"));

            // The list says the key, never its MAC key.
            using var list = new HttpRequestMessage(HttpMethod.Get, "api/v1/pki/acme/eab");
            list.Headers.Authorization = registrar;
            var listed = await (await http.SendAsync(list)).Content.ReadAsStringAsync();
            Assert.That(listed, Does.Contain(kid));
            Assert.That(listed, Does.Not.Contain(hmac));

            // And the account is signed its certificate.
            var certificate = await client.ObtainCertificateAsync(["localhost"], [ http01! ]);
            Assert.That(certificate.Certificate.Issuer, Is.EqualTo("CN=ACME Sub"));

            // Eight clients at once with one key of a binding: one account.
            Assert.That(pki.ACMEState.TryNewExternalAccountKey("race", "registrar7", out var raced, out var raceError), Is.True, raceError);

            var racers  = Enumerable.Range(0, 8).Select(_ => NewClient()).ToList();
            var results = await Task.WhenAll(racers.Select(async racer => {
                              try   { return (await racer.CreateAccountAsync(EABKeyId: raced!.KeyId, EABHMACKey: Base64Url.EncodeToString(raced.MACKey))).Created; }
                              catch (ACMEException) { return false; }
                          }));

            Assert.That(results.Count(created => created), Is.EqualTo(1), "a key of an external account binding opens one account");
            Assert.That(pki.ACMEState.Accounts().Count(one => one.ExternalAccount == raced!.KeyId), Is.EqualTo(1));

            racers.ForEach(racer => racer.Dispose());

        }

        #endregion

        #region ARequestIsCheckedAsLetsEncryptChecksIt()

        [Test]
        public async Task ARequestIsCheckedAsLetsEncryptChecksIt()
        {

            await Started();

            using var http      = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            using var key       = ACMEAccountKey.Generate();
            var       newAccount = pki!.ACMEDirectoryAt().Replace("/directory", "/new-account");
            var       newOrder   = pki.ACMEDirectoryAt().Replace("/directory", "/new-order");
            var       body       = new JObject(new JProperty("termsOfServiceAgreed", true));

            var (status, problem, response) = await PostJWS(http, newAccount, body, key, Nonce: "never-handed-out");
            Assert.That(TypeOf(problem),  Is.EqualTo("badNonce"));
            Assert.That(response.Headers.Contains("Replay-Nonce"), Is.True, "a problem comes with a fresh nonce, too");

            var nonce = await NonceOf(http, newAccount);
            (status, problem, _) = await PostJWS(http, newAccount, body, key, Nonce: nonce);
            Assert.That(status, Is.EqualTo(HttpStatusCode.Created));

            (_, problem, _) = await PostJWS(http, newAccount, body, key, Nonce: nonce);
            Assert.That(TypeOf(problem),  Is.EqualTo("badNonce"), "a nonce is good once");

            (status, problem, _) = await PostJWS(http, newAccount, body, key, HeaderURL: newOrder);
            Assert.That(status,           Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(TypeOf(problem),  Is.EqualTo("unauthorized"), "a JWS is good for the URL it names");

            (_, problem, _) = await PostJWS(http, newOrder, new JObject(new JProperty("identifiers", new JArray())), key);
            Assert.That(TypeOf(problem),  Is.EqualTo("malformed"), "an order is signed by the account, named by its kid");

            (_, problem, _) = await PostJWS(http, newOrder, new JObject(), key, KeyId: newAccount.Replace("/new-account", "/acct/0000"));
            Assert.That(TypeOf(problem),  Is.EqualTo("accountDoesNotExist"));

            using var stranger = ACMEAccountKey.Generate();
            var accountURL = (await PostJWS(http, newAccount, new JObject(new JProperty("onlyReturnExisting", true)), key)).Response.Headers.Location!.ToString();

            (status, _, _) = await PostJWS(http, newOrder, new JObject(new JProperty("identifiers", new JArray(new JObject(new JProperty("type", "dns"), new JProperty("value", "x.example.org"))))),
                                          stranger, KeyId: accountURL);
            Assert.That(status, Is.EqualTo(HttpStatusCode.BadRequest), "a request of an account is signed by its key, and by no other");

            (_, problem, _) = await PostJWS(http, newOrder, new JObject(new JProperty("identifiers", new JArray(new JObject(new JProperty("type", "email"), new JProperty("value", "a@example.org"))))),
                                           key, KeyId: accountURL);
            Assert.That(TypeOf(problem),  Is.EqualTo("unsupportedIdentifier"));

            (_, problem, _) = await PostJWS(http, newAccount, new JObject(new JProperty("onlyReturnExisting", true)), stranger);
            Assert.That(TypeOf(problem),  Is.EqualTo("accountDoesNotExist"));

            // Deactivated, the account signs nothing any more.
            (status, _, _) = await PostJWS(http, accountURL, new JObject(new JProperty("status", "deactivated")), key, KeyId: accountURL);
            Assert.That(status, Is.EqualTo(HttpStatusCode.OK));

            (status, problem, _) = await PostJWS(http, newOrder, new JObject(), key, KeyId: accountURL);
            Assert.That(status,           Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(TypeOf(problem),  Is.EqualTo("unauthorized"));

        }

        #endregion

        #region AnAccountGetsANewKey()

        [Test]
        public async Task AnAccountGetsANewKey()
        {

            await Started();

            using var http    = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            using var oldKey  = ACMEAccountKey.Generate();
            using var newKey  = ACMEAccountKey.Generate();

            using var client  = NewClient(oldKey);
            var account       = await client.CreateAccountAsync();
            var keyChange     = pki!.ACMEDirectoryAt().Replace("/directory", "/key-change");

            // The inner JWS: signed by the new key, no nonce, for the same URL.
            var innerHeader   = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(new JObject(new JProperty("alg", "ES256"), new JProperty("jwk", newKey.JWK), new JProperty("url", keyChange)).ToString(Formatting.None)));
            var innerPayload  = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(new JObject(new JProperty("account", account.URL.ToString()), new JProperty("oldKey", oldKey.JWK)).ToString(Formatting.None)));
            var inner         = new JObject(new JProperty("protected", innerHeader),
                                            new JProperty("payload",   innerPayload),
                                            new JProperty("signature", Base64Url.EncodeToString(newKey.Sign(Encoding.ASCII.GetBytes($"{innerHeader}.{innerPayload}")))));

            var (status, _, _) = await PostJWS(http, keyChange, inner, oldKey, KeyId: account.URL.ToString());
            Assert.That(status, Is.EqualTo(HttpStatusCode.OK));

            using var withNew = NewClient(newKey);
            Assert.That((await withNew.FindAccountAsync())?.URL, Is.EqualTo(account.URL), "the new key is the account now");

            using var withOld = NewClient(oldKey);
            Assert.That(await withOld.FindAccountAsync(), Is.Null, "and the old one is none");

        }

        #endregion

        #region WhatACMESignsIsTheAdministratorsToSay()

        [Test]
        public async Task WhatACMESignsIsTheAdministratorsToSay()
        {

            await Started();

            var admin     = await Account(User_Id.Parse("admin8"),     "systemadmin");
            var registrar = await Account(User_Id.Parse("registrar8"), "registrar");

            using var http = new HttpClient { BaseAddress = new Uri(pki!.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(30) };

            async Task<HttpResponseMessage> PutAs(AuthenticationHeaderValue Who, JObject Settings)
            {
                using var put = new HttpRequestMessage(HttpMethod.Put, "api/v1/pki/acme") { Content = new StringContent(Settings.ToString(), Encoding.UTF8, "application/json") };
                put.Headers.Authorization = Who;
                return await http.SendAsync(put);
            }

            var settings = new JObject(new JProperty("issuer", sub!.Id), new JProperty("validDays", 30), new JProperty("allowedNames", new JArray("lab.example.org")));

            Assert.That((await PutAs(registrar, settings)).StatusCode,  Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That((await PutAs(admin,     new JObject(new JProperty("issuer", new String('b', 64))))).StatusCode, Is.EqualTo(HttpStatusCode.BadRequest), "no CA of this PKI");

            var answer = await PutAs(admin, settings);
            Assert.That(answer.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            var json = JObject.Parse(await answer.Content.ReadAsStringAsync());
            Assert.That(json.Value<Int32>("validDays"),            Is.EqualTo(30));
            Assert.That(json.Value<Boolean>("enabled"),            Is.True);
            Assert.That(json["issuers"]![0]!["problem"]!.Type,     Is.EqualTo(JTokenType.Null));

            Assert.That(File.ReadAllText(pki.ConfigFile.Path), Does.Contain("\"acme\""), "kept in the configuration file");

            // Nothing signed any more: the directory is gone.
            Assert.That((await PutAs(admin, new JObject())).StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That((await http.GetAsync("acme/directory")).StatusCode, Is.EqualTo(HttpStatusCode.NotFound));

        }

        #endregion

    }

}
