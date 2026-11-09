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
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.PKI.Enrollment;
using cloud.charging.open.PKI.Issuance;

#endregion

namespace cloud.charging.open.PKI.Tests
{

    /// <summary>
    /// Enrollment over Secure Transport, RFC 7030, against a started PKI and
    /// as an EST client speaks it: the CAs as a certs-only PKCS#7, a CSR in
    /// Base64 signed for an account that may sign, as what the label says -
    /// and, over HTTPS, a certificate of the PKI renewed with itself as the TLS
    /// client certificate.
    /// </summary>
    public class ESTTests
    {

        #region Data

        private const String  NoTimeServers  = """{ "nts": { "groups": { "legal": { "enabled": false } } } }""";

        private String  directory  = "";
        private PKI?    pki;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "pki-est-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public async Task TearDown()
        {

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

        private PKI PKIFrom(NodeArguments? Arguments = null)
        {

            var file  = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(file, NoTimeServers);

            pki = new PKI(HTTPPort:        IPPort.Parse(TestPorts.Free()),
                          AccountsPath:    Path.Combine(directory, "accounts"),
                          ConfigFile:      new WWCPConfigFile(file),
                          LogToConsole:    false,
                          BridgeDebugLog:  false,
                          Web:             Arguments?.Web);

            if (Arguments is not null)
                Assert.That(pki.ImportCertificates(Arguments, out _, new StringWriter(), new StringWriter()), Is.Null);

            return pki;

        }

        /// <summary>
        /// An account made for the purpose, in the group of the given role, and
        /// the HTTP Basic credentials it signs in with.
        /// </summary>
        private async Task<AuthenticationHeaderValue> Account(String Name, String Role)
        {

            var password = "correct-horse-battery-" + Guid.NewGuid().ToString("N")[..8];

            Assert.That(pki!.ExtAPI.TryGetOrganization(Organization_Id.Parse("PKI"), out var organization), Is.True);

            await pki.ExtAPI.CreateUser(User_Id.Parse(Name),
                                        I18NString.Create(Languages.en, Name),
                                        SimpleEMailAddress.Parse($"{Name}@localhost"),
                                        User2OrganizationEdgeLabel.IsMember,
                                        (Organization) organization!,
                                        Password:                  password,
                                        SkipDefaultNotifications:  true,
                                        SkipNewUserEMail:          true,
                                        SkipNewUserNotifications:  true,
                                        AcceptedEULA:              DateTimeOffset.UtcNow.AddSeconds(-1),
                                        IsAuthenticated:           true);

            Assert.That(pki.ExtAPI.TryGetUser(User_Id.Parse(Name), out var stored), Is.True);
            Assert.That(pki.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group), Is.True);
            Assert.That((await pki.ExtAPI.AddUserToUserGroup((User) stored!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!)).IsSuccess, Is.True);

            return new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Name}:{password}")));

        }

        /// <summary>
        /// A key and the CSR for it, as a charging station makes them.
        /// </summary>
        private static (ECDsa Key, Byte[] CSR) KeyAndCSR(String CommonName, String? DNSName = null)
        {

            var key      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request  = new CertificateRequest($"CN={CommonName}", key, HashAlgorithmName.SHA256);

            if (DNSName is not null)
            {
                var names = new SubjectAlternativeNameBuilder();
                names.AddDnsName(DNSName);
                request.CertificateExtensions.Add(names.Build());
            }

            return (key, request.CreateSigningRequest());

        }

        /// <summary>
        /// A CSR as RFC 7030 sends it: Base64, as application/pkcs10.
        /// </summary>
        private static HttpContent AsPKCS10(Byte[] CSR)
        {
            var content = new StringContent(Convert.ToBase64String(CSR, Base64FormattingOptions.InsertLineBreaks), Encoding.ASCII);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/pkcs10");
            return content;
        }

        /// <summary>
        /// The certificates of a certs-only PKCS#7 in Base64, as EST answers.
        /// </summary>
        private static async Task<IReadOnlyList<X509Certificate2>> CertificatesOf(HttpResponseMessage Response)

            => PKCS7.ReadCertsOnly(Convert.FromBase64String(await Response.Content.ReadAsStringAsync()));

        private static String Id(X509Certificate2 Certificate)
            => PKIStore.Normalized(Certificate.GetCertHashString(HashAlgorithmName.SHA256));

        /// <summary>
        /// A key of secp256r1 and a CSR for it, as a charging station makes it
        /// for its SECC certificate: a subject without the DomainComponent, and
        /// a name ISO 15118 has no room for.
        /// </summary>
        private static (ECDsa Key, Byte[] CSR) SECCKeyAndCSR(String CommonName)
        {

            var key      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request  = new CertificateRequest($"CN={CommonName}, O=OpenChargingCloud, C=DE", key, HashAlgorithmName.SHA256);
            var names    = new SubjectAlternativeNameBuilder();
            names.AddDnsName("secc.example.org");
            request.CertificateExtensions.Add(names.Build());

            return (key, request.CreateSigningRequest());

        }

        /// <summary>
        /// A chain of ISO 15118 in the PKI: a V2G root and the two sub-CAs of a
        /// charging station operator below it.
        /// </summary>
        private (IssuedCertificate Root, IssuedCertificate Sub1, IssuedCertificate Sub2) V2GChain()
        {

            Assert.That(pki!.Store.TryCreateRootCA(new SubjectName("V2G Root CA", "OpenChargingCloud", null, "DE"), KeyAlgorithm.ECC_P256, 3650, null, null, null,
                                                   out var root, out var error, out _, V2GDomain.V2G), Is.True, error);
            Assert.That(pki.Store.TryIssue(root!.Id, null, CertificateProfile.SubCA, new SubjectName("CPO Sub-CA 1", "OpenChargingCloud", null, "DE"), KeyAlgorithm.ECC_P256, 1460, [], null, null, null,
                                           out var sub1, out error, out _, V2GDomain.V2G), Is.True, error);
            Assert.That(pki.Store.TryIssue(sub1!.Id, null, CertificateProfile.SubCA, new SubjectName("CPO Sub-CA 2", "OpenChargingCloud", null, "DE"), KeyAlgorithm.ECC_P256, 365, [], null, null, null,
                                           out var sub2, out error, out _, V2GDomain.V2G), Is.True, error);

            return (root, sub1, sub2!);

        }

        private static List<String> Attributes(X500DistinguishedName Name)

            => Name.EnumerateRelativeDistinguishedNames(reversed: false).
                    Select(part => $"{part.GetSingleElementType().FriendlyName ?? part.GetSingleElementType().Value}={part.GetSingleElementValue()}").
                    ToList();

        #endregion


        #region TheSettingsOfESTAreReadAsTheyAreWritten()

        [Test]
        public void TheSettingsOfESTAreReadAsTheyAreWritten()
        {

            var issuer = new String('a', 64);

            var json   = JObject.Parse($$"""
                                         { "issuer": "{{issuer}}", "profile": "client", "validDays": 30,
                                           "labels": { "csms": { "issuer": "{{issuer}}", "profile": "server" } },
                                           "tlsClientCertificates": true }
                                         """);

            Assert.That(ESTSettings.TryParse(json, out var settings, out var error), Is.True, error);
            Assert.That(ESTSettings.TryParse(settings!.ToJSON(), out var again, out error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(again!.Default,                                        Is.EqualTo(new ESTProfile(issuer, CertificateProfile.Client, 30)));
                Assert.That(again.For("csms"),                                     Is.EqualTo(new ESTProfile(issuer, CertificateProfile.Server, ESTSettings.DefaultValidDays)));
                Assert.That(again.For("nothing"),                                  Is.Null);
                Assert.That(again.TLSClientCertificates,                           Is.True);
                Assert.That(ESTSettings.TryParse(null, out var none, out _),       Is.True);
                Assert.That(none!.Enabled,                                         Is.False);
                Assert.That(ESTSettings.TryParse(JObject.Parse($$"""{ "labels": { "cacerts": { "issuer": "{{issuer}}" } } }"""), out _, out _), Is.False, "no label is called as an operation");
                Assert.That(ESTSettings.TryParse(JObject.Parse($$"""{ "issuer": "{{issuer}}", "profile": "subCA" }"""), out _, out _),          Is.False, "EST makes no CA");
            });

        }

        #endregion

        #region ARegistrarEnrollsAStationAndAnybodyReadsTheCAs()

        [Test]
        public async Task ARegistrarEnrollsAStationAndAnybodyReadsTheCAs()
        {

            await TestPorts.StartedOnFreshPorts(() => PKIFrom());

            var admin      = await Account("admin5",     "systemadmin");
            var registrar  = await Account("registrar5", "registrar");
            var operator_  = await Account("operator5",  "operator");

            using var http = new HttpClient { BaseAddress = new Uri(pki!.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(30) };

            Assert.That((await http.GetAsync(".well-known/est/cacerts")).StatusCode, Is.EqualTo(HttpStatusCode.NotFound), "EST signs nothing before it is told a CA");

            Assert.That(pki.Store.TryCreateRootCA(new SubjectName("EST Root"), KeyAlgorithm.ECC_P256, 365, null, null, null, out var root, out var error, out _), Is.True, error);
            Assert.That(pki.Store.TryIssue(root!.Id, null, CertificateProfile.SubCA, new SubjectName("EST Sub"), KeyAlgorithm.ECC_P256, 200, [], null, null, null,
                                           out var sub, out error, out _), Is.True, error);
            Assert.That(pki.Store.TryCreateRootCA(new SubjectName("Locked Root"), KeyAlgorithm.ECC_P256, 365, null, "locked-password", null, out var locked, out error, out _), Is.True, error);

            #region What EST signs, set by the administrator

            var settings = new JObject(
                               new JProperty("issuer",     sub!.Id),
                               new JProperty("profile",    "client"),
                               new JProperty("validDays",  30),
                               new JProperty("labels",     new JObject(
                                                               new JProperty("csms",    new JObject(new JProperty("issuer", sub.Id),    new JProperty("profile", "server"), new JProperty("validDays", 90))),
                                                               new JProperty("locked",  new JObject(new JProperty("issuer", locked!.Id), new JProperty("profile", "client")))
                                                           ))
                           );

            async Task<HttpStatusCode> PutAs(AuthenticationHeaderValue Who)
            {
                using var put = new HttpRequestMessage(HttpMethod.Put, "api/v1/pki/est") { Content = new StringContent(settings.ToString(), Encoding.UTF8, "application/json") };
                put.Headers.Authorization = Who;
                return (await http.SendAsync(put)).StatusCode;
            }

            Assert.That(await PutAs(registrar), Is.EqualTo(HttpStatusCode.Forbidden), "what EST signs is the administrator's to say");
            Assert.That(await PutAs(admin),     Is.EqualTo(HttpStatusCode.OK));

            var file = JObject.Parse(File.ReadAllText(Path.Combine(directory, WWCPConfigFile.DefaultFileName)));
            Assert.That(file["pki"]!["est"]!["issuer"]!.Value<String>(), Is.EqualTo(sub.Id), "kept in the configuration file");

            #endregion

            #region The CAs, to anybody

            using var cacerts = await http.GetAsync(".well-known/est/cacerts");

            Assert.Multiple(async () => {
                Assert.That(cacerts.StatusCode,                                    Is.EqualTo(HttpStatusCode.OK));
                Assert.That(cacerts.Content.Headers.ContentType?.MediaType,        Is.EqualTo("application/pkcs7-mime"));
                Assert.That((await CertificatesOf(cacerts)).Select(Id),            Is.EquivalentTo(new[] { sub.Id, root.Id }), "the CA that signs, and those above it");
                Assert.That((await http.GetAsync(".well-known/est/csrattrs")).StatusCode, Is.EqualTo(HttpStatusCode.NoContent));
                Assert.That((await http.GetAsync(".well-known/est/nowhere/cacerts")).StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            });

            #endregion

            #region Who may enroll, and who not

            var (key, csr) = KeyAndCSR("CS-0042", "cs-0042.example.org");

            using (key)
            {

                async Task<HttpResponseMessage> Enroll(String Path, AuthenticationHeaderValue? Who, HttpContent Content)
                {
                    using var post = new HttpRequestMessage(HttpMethod.Post, Path) { Content = Content };
                    post.Headers.Authorization = Who;
                    return await http.SendAsync(post);
                }

                using var anonymous  = await Enroll(".well-known/est/simpleenroll", null,      AsPKCS10(csr));
                using var operated   = await Enroll(".well-known/est/simpleenroll", operator_, AsPKCS10(csr));
                using var asJSON     = await Enroll(".well-known/est/simpleenroll", registrar, new StringContent("{}", Encoding.UTF8, "application/json"));
                using var garbage    = await Enroll(".well-known/est/simpleenroll", registrar, AsPKCS10([ 1, 2, 3 ]));
                using var lockedCA   = await Enroll(".well-known/est/locked/simpleenroll", registrar, AsPKCS10(csr));

                Assert.Multiple(() => {
                    Assert.That(anonymous.StatusCode,                              Is.EqualTo(HttpStatusCode.Unauthorized));
                    Assert.That(anonymous.Headers.WwwAuthenticate.ToString(),      Does.StartWith("Basic"));
                    Assert.That(operated.StatusCode,                               Is.EqualTo(HttpStatusCode.Forbidden), "an operator signs nothing");
                    Assert.That(asJSON.StatusCode,                                 Is.EqualTo(HttpStatusCode.UnsupportedMediaType));
                    Assert.That(garbage.StatusCode,                                Is.EqualTo(HttpStatusCode.BadRequest));
                    Assert.That(lockedCA.StatusCode,                               Is.EqualTo(HttpStatusCode.ServiceUnavailable), "a CA whose key has a password signs nothing over EST");
                });

                #endregion

                #region Enrolled: a client's certificate below the sub-CA, for the key of the CSR

                using var enrolled = await Enroll(".well-known/est/simpleenroll", registrar, AsPKCS10(csr));

                Assert.That(enrolled.StatusCode, Is.EqualTo(HttpStatusCode.OK), await enrolled.Content.ReadAsStringAsync());

                using var certificate = (await CertificatesOf(enrolled)).Single();
                using var publicKey   = certificate.GetECDsaPublicKey()!;
                var kept              = pki.Store.Get(Id(certificate))!;

                Assert.Multiple(() => {
                    Assert.That(certificate.Subject,                               Is.EqualTo("CN=CS-0042"));
                    Assert.That(publicKey.ExportSubjectPublicKeyInfo(),            Is.EqualTo(key.ExportSubjectPublicKeyInfo()), "for the key of the CSR");
                    Assert.That(kept.Profile,                                      Is.EqualTo(CertificateProfile.Client));
                    Assert.That(kept.IssuerId,                                     Is.EqualTo(sub.Id));
                    Assert.That(kept.SubjectAlternativeNames,                      Is.EqualTo(new[] { "cs-0042.example.org" }));
                    Assert.That(kept.FromCSR,                                      Is.True);
                    Assert.That(kept.CreatedBy,                                    Does.Contain("registrar5"));
                    Assert.That((kept.NotAfter - kept.NotBefore).TotalDays,        Is.EqualTo(30).Within(0.01));
                    Assert.That(pki.Store.Transparency.Find(kept.Id),              Is.Not.Null, "in the transparency log as everything the PKI signs");
                });

                #endregion

                #region At the label "csms": a server's

                var (serverKey, serverCSR) = KeyAndCSR("csms.example.org");

                using (serverKey)
                {

                    using var server = await Enroll(".well-known/est/csms/simpleenroll", registrar, AsPKCS10(serverCSR));

                    Assert.That(server.StatusCode, Is.EqualTo(HttpStatusCode.OK), await server.Content.ReadAsStringAsync());

                    using var serverCertificate = (await CertificatesOf(server)).Single();

                    Assert.That(serverCertificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages[0].Value,
                                Is.EqualTo("1.3.6.1.5.5.7.3.1"));
                    Assert.That(pki.Store.Get(Id(serverCertificate))!.SubjectAlternativeNames, Is.EqualTo(new[] { "csms.example.org" }),
                                "a server's common name among its names");

                }

                #endregion

            }

        }

        #endregion

        #region AStationRenewsItsCertificateWithItself()

        /// <summary>
        /// Over HTTPS, with a TLS client certificate asked for: a certificate of
        /// the PKI is renewed with itself, and nobody signed in - for the same
        /// subject only, and not once it is revoked.
        /// </summary>
        [Test]
        public async Task AStationRenewsItsCertificateWithItself()
        {

            #region A PKI of HTTPS, a root, and EST with TLS client certificates

            using var webKey   = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var webRequest     = new CertificateRequest("CN=PKI web interface", webKey, HashAlgorithmName.SHA256);
            var webNames       = new SubjectAlternativeNameBuilder();
            webNames.AddIpAddress(System.Net.IPAddress.Loopback);
            webRequest.CertificateExtensions.Add(webNames.Build());

            using var web      = webRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            var webFile        = Path.Combine(directory, "web.p12");
            File.WriteAllBytes(webFile, web.Export(X509ContentType.Pkcs12));

            var arguments      = NodeArguments.Parse([ "--https", "--import-certificate", $"tlsServerIdentity={webFile}" ]);

            await TestPorts.StartedOnFreshPorts(() => PKIFrom(arguments));

            Assert.That(pki!.HTTPS, Is.True);
            Assert.That(pki.Store.TryCreateRootCA(new SubjectName("EST Root"), KeyAlgorithm.ECC_P256, 365, null, null, null, out var root, out var error, out _), Is.True, error);
            Assert.That(pki.TrySetEST(new ESTSettings(new ESTProfile(root!.Id, CertificateProfile.Client, 30), new Dictionary<String, ESTProfile>(), true), out error), Is.True, error);

            #endregion

            #region The station's first certificate, signed for its CSR

            var (key, csr) = KeyAndCSR("CS-0077");

            Assert.That(pki.Store.TryIssueFromCSR(root.Id, null, CertificateProfile.Client, Convert.ToBase64String(csr), 30, [], true, null, null,
                                                  out var first, out error, out _), Is.True, error);

            // A key of its own in the machine's key store: SChannel shows no
            // ephemeral key as a client certificate.
            using var withKey  = pki.Store.Load(first!.Id)!.CopyWithPrivateKey(key);
            using var station  = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12, "station"), "station", X509KeyStorageFlags.Exportable);

            HttpClient AsStation(X509Certificate2? ClientCertificate)
            {
                var handler = new HttpClientHandler {
                                  ClientCertificateOptions                   = ClientCertificateOption.Manual,
                                  ServerCertificateCustomValidationCallback  = (message, served, chain, errors) => true
                              };
                if (ClientCertificate is not null)
                    handler.ClientCertificates.Add(ClientCertificate);
                return new HttpClient(handler) { BaseAddress = new Uri(pki.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(30) };
            }

            #endregion

            #region Renewed with itself, for a new key and the same subject

            var (newKey, newCSR)  = KeyAndCSR("CS-0077");
            var (_,      other)   = KeyAndCSR("CS-9999");

            using var asStation   = AsStation(station);
            using var renewed     = await asStation.PostAsync(".well-known/est/simplereenroll", AsPKCS10(newCSR));

            Assert.That(renewed.StatusCode, Is.EqualTo(HttpStatusCode.OK), await renewed.Content.ReadAsStringAsync());

            using var second      = (await CertificatesOf(renewed)).Single();
            using var secondKey   = second.GetECDsaPublicKey()!;

            using var otherSubject  = await asStation.PostAsync(".well-known/est/simplereenroll", AsPKCS10(other));
            using var enrollAsIt    = await asStation.PostAsync(".well-known/est/simpleenroll",   AsPKCS10(newCSR));

            using var nobody        = AsStation(null);
            using var anonymous     = await nobody.PostAsync(".well-known/est/simplereenroll", AsPKCS10(newCSR));

            Assert.Multiple(() => {
                Assert.That(second.Subject,                                        Is.EqualTo("CN=CS-0077"));
                Assert.That(Id(second),                                            Is.Not.EqualTo(first.Id));
                Assert.That(secondKey.ExportSubjectPublicKeyInfo(),                Is.EqualTo(newKey.ExportSubjectPublicKeyInfo()));
                Assert.That(pki.Store.Get(Id(second))!.CreatedBy,                  Does.Contain(first.Id), "said to renew the first");
                Assert.That(otherSubject.StatusCode,                               Is.EqualTo(HttpStatusCode.BadRequest), "renewed for its own subject only");
                Assert.That(enrollAsIt.StatusCode,                                 Is.EqualTo(HttpStatusCode.Unauthorized), "a certificate renews itself; it enrolls nothing new");
                Assert.That(anonymous.StatusCode,                                  Is.EqualTo(HttpStatusCode.Unauthorized));
            });

            #endregion

            #region Not once it is revoked

            Assert.That(pki.Store.TryRevoke(first.Id, X509RevocationReason.KeyCompromise, null, null, out _, out error, out _, out _, out _), Is.True, error);

            using var afterRevocation = AsStation(station);
            using var refused         = await afterRevocation.PostAsync(".well-known/est/simplereenroll", AsPKCS10(newCSR));

            Assert.That(refused.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));

            #endregion

            key.Dispose();
            newKey.Dispose();

        }

        #endregion

        #region AStationWithoutAKeyOfItsOwnIsGivenOne()

        /// <summary>
        /// serverkeygen, RFC 7030, section 4.4: over HTTPS, for a registrar, the
        /// subject and the names of a CSR signed for a key the PKI makes - of the
        /// kind the CSR was signed with - and the key with the certificate, as
        /// multipart/mixed; not where it is not allowed, and not without TLS.
        /// </summary>
        [Test]
        public async Task AStationWithoutAKeyOfItsOwnIsGivenOne()
        {

            #region A PKI of HTTPS, a root, and EST that makes keys

            using var webKey   = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var webRequest     = new CertificateRequest("CN=PKI web interface", webKey, HashAlgorithmName.SHA256);
            var webNames       = new SubjectAlternativeNameBuilder();
            webNames.AddIpAddress(System.Net.IPAddress.Loopback);
            webRequest.CertificateExtensions.Add(webNames.Build());

            using var web      = webRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            var webFile        = Path.Combine(directory, "web.p12");
            File.WriteAllBytes(webFile, web.Export(X509ContentType.Pkcs12));

            await TestPorts.StartedOnFreshPorts(() => PKIFrom(NodeArguments.Parse([ "--https", "--import-certificate", $"tlsServerIdentity={webFile}" ])));

            Assert.That(pki!.Store.TryCreateRootCA(new SubjectName("EST Root"), KeyAlgorithm.ECC_P384, 365, null, null, null, out var root, out var error, out _), Is.True, error);

            var registrar = await Account("registrar6", "registrar");

            var handler   = new HttpClientHandler { ServerCertificateCustomValidationCallback = (message, served, chain, errors) => true };
            using var http = new HttpClient(handler) { BaseAddress = new Uri(pki.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(30) };

            async Task<HttpResponseMessage> KeyGen(Byte[] CSR)
            {
                using var post = new HttpRequestMessage(HttpMethod.Post, ".well-known/est/serverkeygen") { Content = AsPKCS10(CSR) };
                post.Headers.Authorization = registrar;
                return await http.SendAsync(post);
            }

            // An RSA key in the CSR: an RSA key is made, and the CSR's is not it.
            using var csrKey  = RSA.Create(2048);
            var request       = new CertificateRequest("CN=CS-0099", csrKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names         = new SubjectAlternativeNameBuilder();
            names.AddDnsName("cs-0099.example.org");
            request.CertificateExtensions.Add(names.Build());
            var csr           = request.CreateSigningRequest();

            Assert.That(pki.TrySetEST(new ESTSettings(new ESTProfile(root!.Id, CertificateProfile.Client, 30), new Dictionary<String, ESTProfile>(), false), out error), Is.True, error);

            using var notAllowed = await KeyGen(csr);

            Assert.That(notAllowed.StatusCode, Is.EqualTo(HttpStatusCode.NotImplemented), "no keys where EST is not told to make them");

            Assert.That(pki.TrySetEST(new ESTSettings(new ESTProfile(root.Id, CertificateProfile.Client, 30), new Dictionary<String, ESTProfile>(), false, ServerKeyGeneration: true), out error), Is.True, error);

            #endregion

            #region The key and the certificate, as multipart/mixed

            using var made = await KeyGen(csr);

            Assert.That(made.StatusCode, Is.EqualTo(HttpStatusCode.OK), await made.Content.ReadAsStringAsync());
            Assert.That(made.Content.Headers.ContentType?.MediaType, Is.EqualTo("multipart/mixed"));

            var boundary  = made.Content.Headers.ContentType!.Parameters.Single(parameter => parameter.Name == "boundary").Value!.Trim('"');
            var parts     = (await made.Content.ReadAsStringAsync()).
                                Split("--" + boundary).
                                Select(part => part.Trim()).
                                Where (part => part.Length > 0 && part != "--").
                                Select(part => part.Split("\r\n\r\n", 2)).
                                ToDictionary(part => part[0].Split("\r\n").Single(line => line.StartsWith("Content-Type:")).Split(':', 2)[1].Trim(),
                                             part => Convert.FromBase64String(part[1].Trim()));

            using var key          = RSA.Create();
            key.ImportPkcs8PrivateKey(parts["application/pkcs8"], out _);

            using var certificate  = PKCS7.ReadCertsOnly(parts["application/pkcs7-mime; smime-type=certs-only"]).Single();
            using var publicKey    = certificate.GetRSAPublicKey()!;
            var kept               = pki.Store.Get(Id(certificate))!;

            Assert.Multiple(() => {
                Assert.That(certificate.Subject,                                   Is.EqualTo("CN=CS-0099"));
                Assert.That(AlternativeNames.Of(certificate),                      Is.EqualTo(new[] { "cs-0099.example.org" }), "the names of the CSR");
                Assert.That(publicKey.ExportSubjectPublicKeyInfo(),                Is.EqualTo(key.ExportSubjectPublicKeyInfo()), "for the key handed out");
                Assert.That(publicKey.ExportSubjectPublicKeyInfo(),                Is.Not.EqualTo(csrKey.ExportSubjectPublicKeyInfo()), "not for the key of the CSR");
                Assert.That(publicKey.KeySize,                                     Is.EqualTo(2048), "of the kind the CSR was signed with");
                Assert.That(kept.HasPrivateKey,                                    Is.True, "kept as every key the PKI makes");
                Assert.That(kept.FromCSR,                                          Is.False);
                Assert.That(kept.CreatedBy,                                        Does.Contain("registrar6"));
            });

            #endregion

        }

        #endregion

        #region AStationOfISO15118EnrollsAtItsLabel()

        /// <summary>
        /// EST below a CA of ISO 15118: a label signs what its CA signs - a SECC
        /// certificate below one of V2G, a contract certificate below one of MO
        /// - and says so where it is not told; it asks a CSR for a key of
        /// secp256r1, signs it with the DomainComponent first and without the
        /// names it asks for, and signs no other key.
        /// </summary>
        [Test]
        public async Task AStationOfISO15118EnrollsAtItsLabel()
        {

            await TestPorts.StartedOnFreshPorts(() => PKIFrom());

            var admin      = await Account("admin8",     "systemadmin");
            var registrar  = await Account("registrar8", "registrar");

            using var http = new HttpClient { BaseAddress = new Uri(pki!.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(30) };

            var (root, _, sub2) = V2GChain();

            Assert.That(pki.Store.TryCreateRootCA(new SubjectName("MO Root CA", "OpenChargingCloud", null, "DE"), KeyAlgorithm.ECC_P256, 3650, null, null, null,
                                                  out var moRoot, out var error, out _, V2GDomain.MO), Is.True, error);
            Assert.That(pki.Store.TryIssue(moRoot!.Id, null, CertificateProfile.SubCA, new SubjectName("MO Sub-CA 1", "OpenChargingCloud", null, "DE"), KeyAlgorithm.ECC_P256, 1460, [], null, null, null,
                                           out var moSub, out error, out _, V2GDomain.MO), Is.True, error);
            Assert.That(pki.Store.TryCreateRootCA(new SubjectName("X.509 Root"), KeyAlgorithm.ECC_P256, 365, null, null, null, out var plain, out error, out _), Is.True, error);

            #region What EST signs, as its CAs have it

            async Task<HttpResponseMessage> Put(JObject Labels)
            {
                var settings = new JObject(new JProperty("labels", Labels));
                using var put = new HttpRequestMessage(HttpMethod.Put, "api/v1/pki/est") { Content = new StringContent(settings.ToString(), Encoding.UTF8, "application/json") };
                put.Headers.Authorization = admin;
                return await http.SendAsync(put);
            }

            JObject Label(String Issuer, params JProperty[] More)
                => new (new[] { new JProperty("issuer", Issuer) }.Concat(More));

            using var wrongDomain  = await Put(new JObject(new JProperty("secc",  Label(sub2.Id,  new JProperty("v2g", "MO")))));
            using var notV2G       = await Put(new JObject(new JProperty("plain", Label(plain!.Id, new JProperty("v2g", "CPO")))));
            using var wrongProfile = await Put(new JObject(new JProperty("secc",  Label(sub2.Id,  new JProperty("profile", "client")))));
            using var saved        = await Put(new JObject(new JProperty("secc",     Label(sub2.Id,   new JProperty("validDays", 60))),
                                                           new JProperty("contract", Label(moSub!.Id, new JProperty("validDays", 30))),
                                                           new JProperty("plain",    Label(plain.Id))));

            var labels = JObject.Parse(await saved.Content.ReadAsStringAsync())["labels"]!;

            Assert.Multiple(async () => {
                Assert.That(wrongDomain.StatusCode,                                Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(await wrongDomain.Content.ReadAsStringAsync(),         Does.Contain("SECC").Or.Contain("domain"));
                Assert.That(notV2G.StatusCode,                                     Is.EqualTo(HttpStatusCode.BadRequest), "nothing of ISO 15118 below a CA of X.509");
                Assert.That(wrongProfile.StatusCode,                               Is.EqualTo(HttpStatusCode.BadRequest), "below a V2G CA, a client's certificate is nothing of ISO 15118");
                Assert.That(saved.StatusCode,                                      Is.EqualTo(HttpStatusCode.OK), await saved.Content.ReadAsStringAsync());
                Assert.That(labels["secc"]!["v2g"]!.Value<String>(),               Is.EqualTo("CPO"),    "what its CA signs, where it says nothing");
                Assert.That(labels["secc"]!["profile"]!.Value<String>(),           Is.EqualTo("server"));
                Assert.That(labels["contract"]!["v2g"]!.Value<String>(),           Is.EqualTo("MO"));
                Assert.That(labels["contract"]!["profile"]!.Value<String>(),       Is.EqualTo("client"));
                Assert.That(labels["plain"]!["v2g"]!.Type,                         Is.EqualTo(JTokenType.Null));
            });

            #endregion

            #region What a CSR is asked for

            using var seccAttributes   = await http.GetAsync(".well-known/est/secc/csrattrs");
            using var plainAttributes  = await http.GetAsync(".well-known/est/plain/csrattrs");

            Assert.That(seccAttributes.StatusCode,                                 Is.EqualTo(HttpStatusCode.OK));
            Assert.That(seccAttributes.Content.Headers.ContentType?.MediaType,     Is.EqualTo("application/csrattrs"));
            Assert.That(plainAttributes.StatusCode,                                Is.EqualTo(HttpStatusCode.NoContent));

            var asked   = new AsnReader(Convert.FromBase64String(await seccAttributes.Content.ReadAsStringAsync()), AsnEncodingRules.DER).ReadSequence();
            var hash    = asked.ReadObjectIdentifier();
            var keyOf   = asked.ReadSequence();
            var keyType = keyOf.ReadObjectIdentifier();
            var curve   = keyOf.ReadSetOf().ReadObjectIdentifier();

            Assert.Multiple(() => {
                Assert.That(hash,     Is.EqualTo("1.2.840.10045.4.3.2"), "ecdsa-with-SHA256");
                Assert.That(keyType,  Is.EqualTo("1.2.840.10045.2.1"),   "id-ecPublicKey");
                Assert.That(curve,    Is.EqualTo("1.2.840.10045.3.1.7"), "secp256r1");
            });

            #endregion

            #region A SECC certificate and a contract certificate, enrolled

            async Task<HttpResponseMessage> Enroll(String Path, Byte[] CSR)
            {
                using var post = new HttpRequestMessage(HttpMethod.Post, Path) { Content = AsPKCS10(CSR) };
                post.Headers.Authorization = registrar;
                return await http.SendAsync(post);
            }

            var (seccKey, seccCSR) = SECCKeyAndCSR("DE*ABC*E1234567*1");

            using (seccKey)
            {

                using var enrolled  = await Enroll(".well-known/est/secc/simpleenroll", seccCSR);

                Assert.That(enrolled.StatusCode, Is.EqualTo(HttpStatusCode.OK), await enrolled.Content.ReadAsStringAsync());

                using var secc      = (await CertificatesOf(enrolled)).Single();
                using var publicKey = secc.GetECDsaPublicKey()!;
                var kept            = pki.Store.Get(Id(secc))!;

                Assert.Multiple(() => {
                    Assert.That(Attributes(secc.SubjectName).Count,                    Is.EqualTo(4), "the DomainComponent, and the subject of the CSR");
                    Assert.That(Attributes(secc.SubjectName)[0],                       Does.EndWith("=CPO"), "the DomainComponent first");
                    Assert.That(secc.GetNameInfo(X509NameType.SimpleName, false),      Is.EqualTo("DE*ABC*E1234567*1"));
                    Assert.That(secc.Extensions["2.5.29.17"],                          Is.Null, "no names in ISO 15118, whatever the CSR asks for");
                    Assert.That(secc.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages,
                                                                                       Is.EqualTo(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement));
                    Assert.That(secc.RawData.Length,                                   Is.LessThanOrEqualTo(800));
                    Assert.That(publicKey.ExportSubjectPublicKeyInfo(),                Is.EqualTo(seccKey.ExportSubjectPublicKeyInfo()));
                    Assert.That(kept.V2G,                                              Is.EqualTo(V2GDomain.CPO));
                    Assert.That(kept.Profile,                                          Is.EqualTo(CertificateProfile.Server));
                    Assert.That(kept.IssuerId,                                         Is.EqualTo(sub2.Id));
                });

            }

            var (contractKey, contractCSR) = SECCKeyAndCSR("DEABCC12345678");

            using (contractKey)
            {

                using var enrolled  = await Enroll(".well-known/est/contract/simpleenroll", contractCSR);

                Assert.That(enrolled.StatusCode, Is.EqualTo(HttpStatusCode.OK), await enrolled.Content.ReadAsStringAsync());

                using var contract  = (await CertificatesOf(enrolled)).Single();

                Assert.Multiple(() => {
                    Assert.That(Attributes(contract.SubjectName)[0],                   Does.EndWith("=MO"));
                    Assert.That(pki.Store.Get(Id(contract))!.V2G,                      Is.EqualTo(V2GDomain.MO));
                    Assert.That(contract.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages,
                                                                                       Is.EqualTo(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation |
                                                                                                  X509KeyUsageFlags.KeyEncipherment  | X509KeyUsageFlags.KeyAgreement));
                });

            }

            #endregion

            #region No other key, and no other domain

            using var rsaKey    = RSA.Create(2048);
            var rsaCSR          = new CertificateRequest("CN=DE*ABC*E7654321*1", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest();

            using var p384Key   = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            var p384CSR         = new CertificateRequest("CN=DE*ABC*E7654321*2", p384Key, HashAlgorithmName.SHA384).CreateSigningRequest();

            using var otherDC   = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var otherDCCSR      = new CertificateRequest("DC=MO, CN=DE*ABC*E7654321*3", otherDC, HashAlgorithmName.SHA256).CreateSigningRequest();

            using var rsa       = await Enroll(".well-known/est/secc/simpleenroll", rsaCSR);
            using var p384      = await Enroll(".well-known/est/secc/simpleenroll", p384CSR);
            using var wrongDC   = await Enroll(".well-known/est/secc/simpleenroll", otherDCCSR);

            Assert.Multiple(() => {
                Assert.That(rsa.StatusCode,                                        Is.EqualTo(HttpStatusCode.BadRequest), "no RSA in ISO 15118-2");
                Assert.That(p384.StatusCode,                                       Is.EqualTo(HttpStatusCode.BadRequest), "no P-384 in ISO 15118-2");
                Assert.That(wrongDC.StatusCode,                                    Is.EqualTo(HttpStatusCode.BadRequest), "a CSR of another domain");
                Assert.That(pki.Store.Find("DE*ABC*E7654321*1"),                   Is.Empty);
            });

            #endregion

        }

        #endregion

        #region ASECCRenewsItselfAndIsGivenAKeyOfISO15118()

        /// <summary>
        /// Over HTTPS: a SECC certificate renews itself at its label for a CSR
        /// that does not name its domain, and serverkeygen makes a key of
        /// secp256r1 for it, whatever the CSR was signed with.
        /// </summary>
        [Test]
        public async Task ASECCRenewsItselfAndIsGivenAKeyOfISO15118()
        {

            #region A PKI of HTTPS, a V2G chain, and EST at "secc"

            using var webKey   = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var webRequest     = new CertificateRequest("CN=PKI web interface", webKey, HashAlgorithmName.SHA256);
            var webNames       = new SubjectAlternativeNameBuilder();
            webNames.AddIpAddress(System.Net.IPAddress.Loopback);
            webRequest.CertificateExtensions.Add(webNames.Build());

            using var web      = webRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            var webFile        = Path.Combine(directory, "web.p12");
            File.WriteAllBytes(webFile, web.Export(X509ContentType.Pkcs12));

            await TestPorts.StartedOnFreshPorts(() => PKIFrom(NodeArguments.Parse([ "--https", "--import-certificate", $"tlsServerIdentity={webFile}" ])));

            var (_, _, sub2) = V2GChain();

            Assert.That(pki!.TrySetEST(new ESTSettings(null, new Dictionary<String, ESTProfile> { ["secc"] = new ESTProfile(sub2.Id, CertificateProfile.Server, 60) }, true, ServerKeyGeneration: true),
                                       out var error), Is.True, error);
            Assert.That(pki.EST.For("secc")!.V2G, Is.EqualTo(V2GDomain.CPO), "what its CA signs");

            var registrar = await Account("registrar9", "registrar");

            #endregion

            #region The station's first SECC certificate

            var (key, csr) = SECCKeyAndCSR("DE*ABC*E1234567*9");

            Assert.That(pki.Store.TryIssueFromCSR(sub2.Id, null, CertificateProfile.Server, Convert.ToBase64String(csr), 60, [], true, null, null,
                                                  out var first, out error, out _, V2GDomain.CPO), Is.True, error);

            using var withKey  = pki.Store.Load(first!.Id)!.CopyWithPrivateKey(key);
            using var station  = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12, "station"), "station", X509KeyStorageFlags.Exportable);

            HttpClient AsStation(X509Certificate2? ClientCertificate)
            {
                var handler = new HttpClientHandler {
                                  ClientCertificateOptions                   = ClientCertificateOption.Manual,
                                  ServerCertificateCustomValidationCallback  = (message, served, chain, errors) => true
                              };
                if (ClientCertificate is not null)
                    handler.ClientCertificates.Add(ClientCertificate);
                return new HttpClient(handler) { BaseAddress = new Uri(pki.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(30) };
            }

            #endregion

            #region Renewed with itself, for a CSR without its domain

            var (newKey, newCSR) = SECCKeyAndCSR("DE*ABC*E1234567*9");

            using var asStation  = AsStation(station);
            using var renewed    = await asStation.PostAsync(".well-known/est/secc/simplereenroll", AsPKCS10(newCSR));

            Assert.That(renewed.StatusCode, Is.EqualTo(HttpStatusCode.OK), await renewed.Content.ReadAsStringAsync());

            using var second     = (await CertificatesOf(renewed)).Single();

            Assert.Multiple(() => {
                Assert.That(second.SubjectName.Name,                               Is.EqualTo(pki.Store.Load(first.Id)!.SubjectName.Name));
                Assert.That(pki.Store.Get(Id(second))!.V2G,                        Is.EqualTo(V2GDomain.CPO));
                Assert.That(pki.Store.Get(Id(second))!.CreatedBy,                  Does.Contain(first.Id));
            });

            #endregion

            #region A key of secp256r1 made, for a CSR signed with RSA

            using var csrKey  = RSA.Create(2048);
            var rsaCSR        = new CertificateRequest("CN=DE*ABC*E1234567*10, O=OpenChargingCloud, C=DE", csrKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest();

            using var nobody  = AsStation(null);
            using var post    = new HttpRequestMessage(HttpMethod.Post, ".well-known/est/secc/serverkeygen") { Content = AsPKCS10(rsaCSR) };
            post.Headers.Authorization = registrar;

            using var made    = await nobody.SendAsync(post);

            Assert.That(made.StatusCode, Is.EqualTo(HttpStatusCode.OK), await made.Content.ReadAsStringAsync());

            var boundary  = made.Content.Headers.ContentType!.Parameters.Single(parameter => parameter.Name == "boundary").Value!.Trim('"');
            var parts     = (await made.Content.ReadAsStringAsync()).
                                Split("--" + boundary).
                                Select(part => part.Trim()).
                                Where (part => part.Length > 0 && part != "--").
                                Select(part => part.Split("\r\n\r\n", 2)).
                                ToDictionary(part => part[0].Split("\r\n").Single(line => line.StartsWith("Content-Type:")).Split(':', 2)[1].Trim(),
                                             part => Convert.FromBase64String(part[1].Trim()));

            using var madeKey      = ECDsa.Create();
            madeKey.ImportPkcs8PrivateKey(parts["application/pkcs8"], out _);

            using var certificate  = PKCS7.ReadCertsOnly(parts["application/pkcs7-mime; smime-type=certs-only"]).Single();
            using var publicKey    = certificate.GetECDsaPublicKey()!;

            Assert.Multiple(() => {
                Assert.That(madeKey.ExportParameters(false).Curve.Oid.Value,       Is.EqualTo("1.2.840.10045.3.1.7"), "secp256r1");
                Assert.That(publicKey.ExportSubjectPublicKeyInfo(),                Is.EqualTo(madeKey.ExportSubjectPublicKeyInfo()));
                Assert.That(Attributes(certificate.SubjectName)[0],                Does.EndWith("=CPO"));
                Assert.That(pki.Store.Get(Id(certificate))!.V2G,                   Is.EqualTo(V2GDomain.CPO));
            });

            #endregion

            key.Dispose();
            newKey.Dispose();

        }

        #endregion

        #region NoKeyGoesOverPlainHTTP()

        [Test]
        public async Task NoKeyGoesOverPlainHTTP()
        {

            await TestPorts.StartedOnFreshPorts(() => PKIFrom());

            Assert.That(pki!.Store.TryCreateRootCA(new SubjectName("EST Root"), KeyAlgorithm.ECC_P256, 365, null, null, null, out var root, out var error, out _), Is.True, error);
            Assert.That(pki.TrySetEST(new ESTSettings(new ESTProfile(root!.Id, CertificateProfile.Client, 30), new Dictionary<String, ESTProfile>(), false, ServerKeyGeneration: true), out error), Is.True, error);

            var registrar  = await Account("registrar7", "registrar");
            var (key, csr) = KeyAndCSR("CS-0100");

            using (key)
            {

                using var http  = new HttpClient { BaseAddress = new Uri(pki.WebInterfaceURL.ToString()), Timeout = TimeSpan.FromSeconds(30) };
                using var post  = new HttpRequestMessage(HttpMethod.Post, ".well-known/est/serverkeygen") { Content = AsPKCS10(csr) };
                post.Headers.Authorization = registrar;

                using var refused = await http.SendAsync(post);

                Assert.That(refused.StatusCode,                 Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(pki.Store.Find("CS-0100"),           Is.Empty, "nothing signed, no key made");

            }

        }

        #endregion

    }

}
