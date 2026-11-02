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

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.PKI.Tests
{

    /// <summary>
    /// The JSON API of a PKI below "v1/pki", against a started PKI and over
    /// HTTP: what an administrator, a registrar and an operator may each do
    /// there, and what the answers say.
    /// </summary>
    public class PKIAPITests
    {

        #region Data

        private const String  NoTimeServers  = """{ "nts": { "groups": { "legal": { "enabled": false } } } }""";

        private String  directory  = "";
        private PKI?    pki;
        private Uri?    address;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "pki-api-" + Guid.NewGuid().ToString("N")[..12]);
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

        /// <summary>
        /// A PKI whose time client is switched off, on a free port of the
        /// loopback - made, and not yet started.
        /// </summary>
        private PKI PKIFrom()
        {

            var port  = TestPorts.Free();
            var file  = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(file, NoTimeServers);

            pki       = new PKI(
                            HTTPPort:        IPPort.Parse(port),
                            AccountsPath:    Path.Combine(directory, "accounts"),
                            ConfigFile:      new WWCPConfigFile(file),
                            LogToConsole:    false,
                            BridgeDebugLog:  false
                        );

            address   = new Uri($"http://127.0.0.1:{port}/");

            return pki;

        }

        /// <summary>
        /// A client signed in with a password as an account made for the
        /// purpose, in the group of the given role.
        /// </summary>
        private async Task<HttpClient> SignedInAs(String Name, String Role)
        {

            var password = "correct-horse-battery-" + Guid.NewGuid().ToString("N")[..8];

            Assert.That(pki!.ExtAPI.TryGetOrganization(Organization_Id.Parse("PKI"), out var organization) &&
                        organization is Organization, Is.True, "the PKI's organization is not there");

            var account = await pki.ExtAPI.CreateUser(
                                    User_Id.Parse(Name),
                                    I18NString.Create(Languages.en, Name),
                                    SimpleEMailAddress.Parse($"{Name}@localhost"),
                                    User2OrganizationEdgeLabel.IsMember,
                                    (Organization) organization!,
                                    Password:                  password,
                                    SkipDefaultNotifications:  true,
                                    SkipNewUserEMail:          true,
                                    SkipNewUserNotifications:  true,
                                    AcceptedEULA:              DateTimeOffset.UtcNow.AddSeconds(-1),
                                    IsAuthenticated:           true
                                );

            Assert.That(account, Is.Not.Null);
            Assert.That(pki.ExtAPI.TryGetUser(User_Id.Parse(Name), out var stored), Is.True);
            Assert.That(pki.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group), Is.True, $"the PKI has no group '{Role}'");
            Assert.That((await pki.ExtAPI.AddUserToUserGroup((User) stored!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!)).IsSuccess, Is.True);

            var client = new HttpClient { BaseAddress = address, Timeout = TimeSpan.FromSeconds(30) };

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                                                             "Basic",
                                                             Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Name}:{password}"))
                                                         );

            return client;

        }

        private static async Task<(HttpStatusCode Status, JObject JSON)> Post(HttpClient Client, String Path, Object JSON)
        {
            var response = await Client.PostAsync(Path, new StringContent(JObject.FromObject(JSON).ToString(), Encoding.UTF8, "application/json"));
            return (response.StatusCode, JObject.Parse(await response.Content.ReadAsStringAsync()));
        }

        private static async Task<(HttpStatusCode Status, JObject JSON)> Get(HttpClient Client, String Path)
        {
            var response = await Client.GetAsync(Path);
            return (response.StatusCode, JObject.Parse(await response.Content.ReadAsStringAsync()));
        }

        private static async Task<(HttpStatusCode Status, JObject JSON)> Delete(HttpClient Client, String Path)
        {
            var response = await Client.DeleteAsync(Path);
            return (response.StatusCode, JObject.Parse(await response.Content.ReadAsStringAsync()));
        }

        #endregion


        #region AnAdministratorMakesAPKIAndARegistrarSignsBelowIt()

        [Test]
        public async Task AnAdministratorMakesAPKIAndARegistrarSignsBelowIt()
        {

            await TestPorts.StartedOnFreshPorts(PKIFrom);

            using var admin      = await SignedInAs("admin1",     "systemadmin");
            using var registrar  = await SignedInAs("registrar1", "registrar");

            #region A root, and a sub-CA below it

            var (status, root) = await Post(admin, "api/v1/pki/rootCAs", new {
                                     subject       = new { commonName = "OCC Root CA", organization = "OpenChargingCloud", country = "DE" },
                                     keyAlgorithm  = "ecc-p384",
                                     validDays     = 3650
                                 });

            Assert.That(status,                          Is.EqualTo(HttpStatusCode.Created), root.ToString());
            Assert.That(root["profile"]!.Value<String>(), Is.EqualTo("rootCA"));
            Assert.That(root["pem"]!.Value<String>(),     Does.StartWith("-----BEGIN CERTIFICATE-----"));

            (status, var subCA) = await Post(admin, "api/v1/pki/subCAs", new {
                                      issuer      = root["id"]!.Value<String>(),
                                      subject     = new { commonName = "OCC CPO CA" },
                                      validDays   = 1825,
                                      pathLength  = 0
                                  });

            Assert.That(status, Is.EqualTo(HttpStatusCode.Created), subCA.ToString());

            #endregion

            #region The registrar may make no CA ...

            (status, var refused) = await Post(registrar, "api/v1/pki/rootCAs", new { subject = new { commonName = "Rogue Root" } });

            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden), refused.ToString());

            #endregion

            #region ... but signs a client certificate, and the CSR of a station

            (status, var client) = await Post(registrar, "api/v1/pki/certificates", new {
                                       issuer   = subCA["id"]!.Value<String>(),
                                       profile  = "client",
                                       subject  = new { commonName = "CS-0001", organization = "CPO" }
                                   });

            Assert.That(status,                              Is.EqualTo(HttpStatusCode.Created), client.ToString());
            Assert.That(client["chain"]!.Count(),            Is.EqualTo(3));
            Assert.That(client["mayDownloadPrivateKey"]!.Value<Boolean>(), Is.True);

            using var stationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var csr              = new CertificateRequest("CN=CS-0002, O=CPO", stationKey, HashAlgorithmName.SHA256).CreateSigningRequestPem();

            (status, var inspected) = await Post(registrar, "api/v1/pki/csr/inspect", new { csr });

            Assert.That(status,                                  Is.EqualTo(HttpStatusCode.OK), inspected.ToString());
            Assert.That(inspected["commonName"]!.Value<String>(), Is.EqualTo("CS-0002"));

            (status, var signed) = await Post(registrar, "api/v1/pki/csr", new {
                                       issuer   = subCA["id"]!.Value<String>(),
                                       profile  = "client",
                                       csr
                                   });

            Assert.That(status,                               Is.EqualTo(HttpStatusCode.Created), signed.ToString());
            Assert.That(signed["fromCSR"]!.Value<Boolean>(),  Is.True);
            Assert.That(signed["hasPrivateKey"]!.Value<Boolean>(), Is.False);

            #endregion

            #region The list, and its filter

            (status, var all) = await Get(registrar, "api/v1/pki/certificates");

            Assert.That(status,                    Is.EqualTo(HttpStatusCode.OK));
            Assert.That(all["certificates"]!.Count(), Is.EqualTo(4));

            (status, var narrowed) = await Get(registrar, "api/v1/pki/certificates?commonName=cs-000");

            Assert.That(narrowed["certificates"]!.Select(one => one["commonName"]!.Value<String>()), Is.EquivalentTo(new[] { "CS-0001", "CS-0002" }));

            #endregion

            #region Keys: a client's to the registrar, a CA's to nobody

            (status, var key) = await Get(registrar, $"api/v1/pki/certificates/{client["id"]}/key");

            Assert.That(status,                           Is.EqualTo(HttpStatusCode.OK), key.ToString());
            Assert.That(key["privateKey"]!.Value<String>(), Does.StartWith("-----BEGIN PRIVATE KEY-----"));

            (status, var caKey) = await Get(admin, $"api/v1/pki/certificates/{root["id"]}/key");

            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden), caKey.ToString());

            #endregion

            #region Deleting: a CA not alone, and not by the registrar

            (status, var notAlone) = await Delete(admin, $"api/v1/pki/certificates/{subCA["id"]}");

            Assert.That(status, Is.EqualTo(HttpStatusCode.Conflict), notAlone.ToString());

            (status, var notHers) = await Delete(registrar, $"api/v1/pki/certificates/{subCA["id"]}?withIssued=true");

            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden), notHers.ToString());

            (status, var deleted) = await Delete(admin, $"api/v1/pki/certificates/{subCA["id"]}?withIssued=true");

            Assert.That(status,                     Is.EqualTo(HttpStatusCode.OK), deleted.ToString());
            Assert.That(deleted["deleted"]!.Count(), Is.EqualTo(3));
            Assert.That(pki!.Store.Count,           Is.EqualTo(1));

            #endregion

        }

        #endregion

        #region AnOperatorLooksAndSignsNothing()

        #region AKeyWithAPasswordIsAskedForAndHandedOutEncrypted()

        /// <summary>
        /// A root whose key has a password signs only where it is given again;
        /// a client's key with a password goes out encrypted; a password is
        /// changed at the permission the certificate asks for - and none of
        /// them is ever said back, or in the log.
        /// </summary>
        [Test]
        public async Task AKeyWithAPasswordIsAskedForAndHandedOutEncrypted()
        {

            const String rootPassword    = "correct horse battery staple";
            const String clientPassword  = "the station's own password";

            await TestPorts.StartedOnFreshPorts(PKIFrom);

            using var admin      = await SignedInAs("admin2",     "systemadmin");
            using var registrar  = await SignedInAs("registrar2", "registrar");

            var (status, root) = await Post(admin, "api/v1/pki/rootCAs", new {
                                     subject      = new { commonName = "Locked Root" },
                                     keyPassword  = rootPassword
                                 });

            Assert.That(status,                                  Is.EqualTo(HttpStatusCode.Created), root.ToString());
            Assert.That(root["keyEncrypted"]!.Value<Boolean>(),  Is.True);

            var rootId = root["id"]!.Value<String>();

            #region Without the CA's password, nothing is signed

            (status, var refused) = await Post(registrar, "api/v1/pki/certificates", new {
                                        issuer   = rootId,
                                        profile  = "client",
                                        subject  = new { commonName = "CS-0001" }
                                    });

            Assert.That(status,              Is.EqualTo(HttpStatusCode.BadRequest), refused.ToString());
            Assert.That(refused.ToString(),  Does.Contain("has a password, and none was given"));

            (status, refused) = await Post(registrar, "api/v1/pki/certificates", new {
                                    issuer             = rootId,
                                    issuerKeyPassword  = "not the password at all",
                                    profile            = "client",
                                    subject            = new { commonName = "CS-0001" }
                                });

            Assert.That(status,              Is.EqualTo(HttpStatusCode.BadRequest), refused.ToString());
            Assert.That(refused.ToString(),  Does.Not.Contain("not the password at all"));

            #endregion

            #region With it, a client with a password of its own

            (status, var client) = await Post(registrar, "api/v1/pki/certificates", new {
                                       issuer             = rootId,
                                       issuerKeyPassword  = rootPassword,
                                       keyPassword        = clientPassword,
                                       profile            = "client",
                                       subject            = new { commonName = "CS-0001" }
                                   });

            Assert.That(status,                                    Is.EqualTo(HttpStatusCode.Created), client.ToString());
            Assert.That(client["keyEncrypted"]!.Value<Boolean>(),  Is.True);

            (status, var key) = await Get(registrar, $"api/v1/pki/certificates/{client["id"]}/key");

            Assert.That(status,                              Is.EqualTo(HttpStatusCode.OK), key.ToString());
            Assert.That(key["encrypted"]!.Value<Boolean>(),  Is.True);
            Assert.That(key["privateKey"]!.Value<String>(),  Does.StartWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"));

            using (var opened = ECDsa.Create())
                opened.ImportFromEncryptedPem(key["privateKey"]!.Value<String>(), clientPassword);

            #endregion

            #region A CA's password at the permission to make one, a client's at the permission to sign one

            (status, refused) = await Post(registrar, $"api/v1/pki/certificates/{rootId}/key/password", new {
                                    password     = rootPassword,
                                    newPassword  = (String?) null
                                });

            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden), refused.ToString());

            (status, var changed) = await Post(registrar, $"api/v1/pki/certificates/{client["id"]}/key/password", new {
                                        password     = clientPassword,
                                        newPassword  = (String?) null
                                    });

            Assert.That(status,                                     Is.EqualTo(HttpStatusCode.OK), changed.ToString());
            Assert.That(changed["keyEncrypted"]!.Value<Boolean>(),  Is.False);

            (status, var open) = await Post(admin, $"api/v1/pki/certificates/{rootId}/key/password", new {
                                     password     = rootPassword,
                                     newPassword  = ""
                                 });

            Assert.That(status,                                  Is.EqualTo(HttpStatusCode.OK), open.ToString());
            Assert.That(open["keyEncrypted"]!.Value<Boolean>(),  Is.False);

            (status, var unlocked) = await Post(registrar, "api/v1/pki/certificates", new {
                                         issuer   = rootId,
                                         profile  = "server",
                                         subject  = new { commonName = "csms.example.org" }
                                     });

            Assert.That(status, Is.EqualTo(HttpStatusCode.Created), unlocked.ToString());

            #endregion

            #region No password in the log

            var logged = String.Join("\n", Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).
                                                     Where (file => !file.EndsWith(".key", StringComparison.Ordinal)).
                                                     Select(file => { try { return File.ReadAllText(file); } catch (IOException) { return ""; } }));

            Assert.That(logged, Does.Not.Contain(rootPassword).And.Not.Contain(clientPassword));

            #endregion

        }

        #endregion

        [Test]
        public async Task AnOperatorLooksAndSignsNothing()
        {

            await TestPorts.StartedOnFreshPorts(PKIFrom);

            Assert.That(pki!.Store.TryCreateRootCA(new Issuance.SubjectName("Root"), Issuance.KeyAlgorithm.ECC_P256, 365, null, null, null,
                                                   out var root, out var error, out _), Is.True, error);

            using var @operator = await SignedInAs("operator1", "operator");

            var (status, all) = await Get(@operator, "api/v1/pki/certificates");

            Assert.That(status,                       Is.EqualTo(HttpStatusCode.OK));
            Assert.That(all["certificates"]!.Count(), Is.EqualTo(1));

            (status, var refused) = await Post(@operator, "api/v1/pki/certificates", new {
                                        issuer   = root!.Id,
                                        profile  = "server",
                                        subject  = new { commonName = "csms.example.org" }
                                    });

            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden), refused.ToString());
            Assert.That(pki.Store.Count, Is.EqualTo(1));

        }

        #endregion

        #region NobodySignedInIsLetIn()

        [Test]
        public async Task NobodySignedInIsLetIn()
        {

            await TestPorts.StartedOnFreshPorts(PKIFrom);

            using var anybody = new HttpClient { BaseAddress = address };

            Assert.That((await anybody.GetAsync("api/v1/pki/certificates")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

        }

        #endregion

    }

}
