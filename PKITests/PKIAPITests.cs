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

        private static async Task<(HttpStatusCode Status, JObject JSON)> Put(HttpClient Client, String Path, Object JSON)
        {
            var response = await Client.PutAsync(Path, new StringContent(JObject.FromObject(JSON).ToString(), Encoding.UTF8, "application/json"));
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

        #region AMonitorChecksTheTransparencyLogAsRFC6962Says()

        /// <summary>
        /// What a monitor does with the log, over the API and with the public
        /// key the log says it has: the signed tree head checked, every entry
        /// proved in it by the hash of its leaf, the tree proved to have grown
        /// from the one before - and a certificate deleted from the PKI still
        /// in its log.
        /// </summary>
        [Test]
        public async Task AMonitorChecksTheTransparencyLogAsRFC6962Says()
        {

            await TestPorts.StartedOnFreshPorts(PKIFrom);

            using var admin     = await SignedInAs("admin3",    "systemadmin");
            using var operator_ = await SignedInAs("operator3", "operator");

            const String ct = "api/v1/pki/transparency/ct/v1";

            var (status, root) = await Post(admin, "api/v1/pki/rootCAs", new { subject = new { commonName = "CT Root" } });
            Assert.That(status, Is.EqualTo(HttpStatusCode.Created), root.ToString());

            (status, var first) = await Get(operator_, $"{ct}/get-sth");
            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), first.ToString());

            for (var i = 1; i <= 3; i++)
            {
                (status, var made) = await Post(admin, "api/v1/pki/certificates", new {
                                         issuer   = root["id"]!.Value<String>(),
                                         profile  = "client",
                                         subject  = new { commonName = $"CS-{i:D4}" }
                                     });
                Assert.That(status, Is.EqualTo(HttpStatusCode.Created), made.ToString());
                // After the root and its OCSP responder.
                Assert.That(made["transparency"]!["index"]!.Value<Int64>(), Is.EqualTo(i + 1));
                Assert.That(made["transparency"]!["embedded"]!.Value<Boolean>(), Is.True, "a client's certificate carries its timestamp");
            }

            #region The log, and its newest tree head checked with its key

            (status, var log) = await Get(operator_, "api/v1/pki/transparency");

            Assert.That(status,                                Is.EqualTo(HttpStatusCode.OK), log.ToString());
            Assert.That(log["broken"]!.Value<Boolean>(),       Is.False);
            Assert.That(log["treeSize"]!.Value<Int64>(),       Is.EqualTo(5));

            using var publicKey = ECDsa.Create();
            publicKey.ImportFromPem(log["publicKey"]!.Value<String>());

            (status, var sth) = await Get(operator_, $"{ct}/get-sth");

            var treeSize  = sth["tree_size"]!.Value<Int64>();
            var rootHash  = Convert.FromBase64String(sth["sha256_root_hash"]!.Value<String>()!);
            var signature = Convert.FromBase64String(sth["tree_head_signature"]!.Value<String>()!);

            Byte[] signed = [ 0, 1, .. BigEndian(sth["timestamp"]!.Value<Int64>()), .. BigEndian(treeSize), .. rootHash ];

            Assert.That(treeSize, Is.EqualTo(5));
            Assert.That(publicKey.VerifyData(signed, signature[4..], HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence), Is.True);

            #endregion

            #region Every entry proved in it by the hash of its leaf

            (status, var entries) = await Get(operator_, $"{ct}/get-entries?start=0&end=99");

            Assert.That(entries["entries"]!.Count(), Is.EqualTo(5), "as many as there are");

            // The root and its responder as x509_entry, the clients as
            // precert_entry: the entry type after version, leaf type and
            // timestamp - and the precertificate first in their extra_data.
            Assert.That(entries["entries"]!.Select(entry => Convert.FromBase64String(entry["leaf_input"]!.Value<String>()!)[11]),
                        Is.EqualTo(new Byte[] { 0, 0, 1, 1, 1 }));

            foreach (var (entry, index) in entries["entries"]!.Select((entry, index) => (entry, index)))
            {

                var leafHash = Transparency.MerkleTree.LeafHash(Convert.FromBase64String(entry["leaf_input"]!.Value<String>()!));

                (status, var proof) = await Get(operator_, $"{ct}/get-proof-by-hash?hash={Uri.EscapeDataString(Convert.ToBase64String(leafHash))}&tree_size={treeSize}");

                Assert.That(status,                                Is.EqualTo(HttpStatusCode.OK), proof.ToString());
                Assert.That(proof["leaf_index"]!.Value<Int64>(),   Is.EqualTo(index));
                Assert.That(Transparency.MerkleTree.VerifyInclusion(leafHash, index, treeSize,
                                                                    proof["audit_path"]!.Select(hash => Convert.FromBase64String(hash.Value<String>()!)).ToList(),
                                                                    rootHash), Is.True, $"entry {index}");

            }

            #endregion

            #region The tree grew from the one before, and nothing else

            var firstSize  = first["tree_size"]!.Value<Int64>();
            var firstHash  = Convert.FromBase64String(first["sha256_root_hash"]!.Value<String>()!);

            (status, var consistency) = await Get(operator_, $"{ct}/get-sth-consistency?first={firstSize}&second={treeSize}");

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), consistency.ToString());
            Assert.That(Transparency.MerkleTree.VerifyConsistency(firstSize, treeSize, firstHash, rootHash,
                                                                  consistency["consistency"]!.Select(hash => Convert.FromBase64String(hash.Value<String>()!)).ToList()), Is.True);

            #endregion

            #region The roots, and a certificate deleted and still in the log

            (status, var roots) = await Get(operator_, $"{ct}/get-roots");

            Assert.That(roots["certificates"]!.Count(), Is.EqualTo(1));

            (status, var listed) = await Get(operator_, "api/v1/pki/transparency/entries?start=0&end=4");
            var lastId           = listed["entries"]![4]!["id"]!.Value<String>();

            Assert.That(listed["entries"]![1]!["ocspResponder"]!.Value<Boolean>(), Is.True, "the OCSP responder of the root");
            Assert.That(listed["entries"]![4]!["precertificate"]!.Value<Boolean>(), Is.True);

            (status, _) = await Delete(admin, $"api/v1/pki/certificates/{lastId}");
            Assert.That(status, Is.EqualTo(HttpStatusCode.OK));

            (status, listed) = await Get(operator_, "api/v1/pki/transparency/entries?start=0&end=4");

            Assert.That(listed["entries"]!.Count(),                       Is.EqualTo(5));
            Assert.That(listed["entries"]![4]!["inPKI"]!.Value<Boolean>(), Is.False);
            Assert.That(listed["entries"]![4]!["commonName"]!.Value<String>(), Is.EqualTo("CS-0003"));
            Assert.That(listed["entries"]![4]!["profile"]!.Value<String>(),    Is.EqualTo("client"));

            #endregion

            #region Nobody signed in reads nothing of it

            using var anybody = new HttpClient { BaseAddress = address, Timeout = TimeSpan.FromSeconds(30) };

            Assert.That((await anybody.GetAsync($"{ct}/get-sth")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

            #endregion

        }

        #region AV2GPKIIsMadeOverTheAPI()

        /// <summary>
        /// A PKI of ISO 15118 over the JSON API: a V2G root, two sub-CAs and a
        /// SECC certificate, whose profile its domain says - and a domain that
        /// is none refused.
        /// </summary>
        [Test]
        public async Task AV2GPKIIsMadeOverTheAPI()
        {

            await TestPorts.StartedOnFreshPorts(PKIFrom);

            using var admin = await SignedInAs("admin8", "systemadmin");

            var (status, root) = await Post(admin, "api/v1/pki/rootCAs", new { subject = new { commonName = "V2G Root CA", country = "DE" }, v2g = "V2G" });
            Assert.That(status, Is.EqualTo(HttpStatusCode.Created), root.ToString());

            (status, var sub1) = await Post(admin, "api/v1/pki/subCAs", new { issuer = root["id"]!.Value<String>(), subject = new { commonName = "CPO Sub-CA 1" }, v2g = "V2G" });
            Assert.That(status, Is.EqualTo(HttpStatusCode.Created), sub1.ToString());

            (status, var sub2) = await Post(admin, "api/v1/pki/subCAs", new { issuer = sub1["id"]!.Value<String>(), subject = new { commonName = "CPO Sub-CA 2" }, validDays = 365, v2g = "V2G" });
            Assert.That(status, Is.EqualTo(HttpStatusCode.Created), sub2.ToString());

            (status, var secc) = await Post(admin, "api/v1/pki/certificates", new { issuer = sub2["id"]!.Value<String>(), subject = new { commonName = "DE*ABC*E1234567*1" }, validDays = 60, v2g = "CPO" });
            Assert.That(status, Is.EqualTo(HttpStatusCode.Created), secc.ToString());

            (status, var none) = await Post(admin, "api/v1/pki/rootCAs", new { subject = new { commonName = "Nowhere Root" }, v2g = "EMP" });

            Assert.Multiple(() => {
                Assert.That(root["keyAlgorithm"]!.Value<String>(),                  Is.EqualTo("ecc-p256"), "the key of ISO 15118 where none is asked for");
                Assert.That(sub1["pathLength"]!.Value<Int32>(),                     Is.EqualTo(1));
                Assert.That(sub2["pathLength"]!.Value<Int32>(),                     Is.EqualTo(0));
                Assert.That(secc["profile"]!.Value<String>(),                       Is.EqualTo("server"), "a SECC certificate is a server's");
                Assert.That(secc["v2g"]!.Value<String>(),                           Is.EqualTo("CPO"));
                Assert.That(secc["subject"]!.Value<String>(),                       Does.Contain("DC=CPO"));
                Assert.That(secc["chain"]!.Select(one => one["v2g"]!.Value<String>()), Is.EqualTo(new[] { "CPO", "V2G", "V2G", "V2G" }));
                Assert.That(secc["transparency"]!["embedded"]!.Value<Boolean>(),    Is.False, "no timestamps in a certificate of ISO 15118");
                Assert.That(status,                                                 Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(none["description"]?.ToString() ?? none.ToString(),     Does.Contain("V2G, CPO, MO, OEM, CPS"));
            });

        }

        #endregion

        #region AnybodyAsksWhetherACertificateWasRevoked()

        /// <summary>
        /// A registrar revokes, an operator does not; the CRL, the CA and the
        /// OCSP responder answer whoever asks, signed in or not, over POST and
        /// GET; a certificate made after the PKI was told its address names
        /// them; and a certificate goes out with its key as PKCS#12.
        /// </summary>
        [Test]
        public async Task AnybodyAsksWhetherACertificateWasRevoked()
        {

            await TestPorts.StartedOnFreshPorts(PKIFrom);

            using var admin      = await SignedInAs("admin4",     "systemadmin");
            using var registrar  = await SignedInAs("registrar4", "registrar");
            using var operator_  = await SignedInAs("operator4",  "operator");
            using var anybody    = new HttpClient { BaseAddress = address, Timeout = TimeSpan.FromSeconds(30) };

            var (status, root) = await Post(admin, "api/v1/pki/rootCAs", new { subject = new { commonName = "Revocation Root" } });
            Assert.That(status, Is.EqualTo(HttpStatusCode.Created), root.ToString());

            var rootId = root["id"]!.Value<String>()!;

            #region The address the PKI is reached at, named by what is made after it

            (status, var settings) = await Put(registrar, "api/v1/pki/revocation", new { publicURL = "http://pki.example.org" });
            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden), "the address is the administrator's to set");

            (status, settings) = await Put(admin, "api/v1/pki/revocation", new { publicURL = "http://pki.example.org" });
            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), settings.ToString());
            Assert.That(settings["ocspURL"]!.Value<String>(), Is.EqualTo("http://pki.example.org/api/v1/pki/ocsp"));

            (status, var client) = await Post(registrar, "api/v1/pki/certificates", new {
                                       issuer       = rootId,
                                       profile      = "client",
                                       subject      = new { commonName = "CS-0001" },
                                       keyPassword  = "station-key-password"
                                   });
            Assert.That(status, Is.EqualTo(HttpStatusCode.Created), client.ToString());

            using var x509 = X509Certificate2.CreateFromPem(client["pem"]!.Value<String>()!);

            Assert.That(x509.Extensions.OfType<X509AuthorityInformationAccessExtension>().Single().EnumerateOcspUris(),
                        Is.EqualTo(new[] { "http://pki.example.org/api/v1/pki/ocsp" }));

            #endregion

            #region PKCS#12, with the key's password and one of its own

            (status, var pkcs12) = await Post(registrar, $"api/v1/pki/certificates/{client["id"]}/pkcs12", new {
                                       keyPassword     = "station-key-password",
                                       pkcs12Password  = "file-password"
                                   });
            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), pkcs12.ToString());
            Assert.That(pkcs12["fileName"]!.Value<String>(), Is.EqualTo("CS-0001.p12"));
            Assert.That(X509CertificateLoader.LoadPkcs12Collection(Convert.FromBase64String(pkcs12["pkcs12"]!.Value<String>()!), "file-password",
                                                                   X509KeyStorageFlags.EphemeralKeySet).Single().HasPrivateKey, Is.True);

            (status, _) = await Post(operator_, $"api/v1/pki/certificates/{client["id"]}/pkcs12", new { pkcs12Password = "file-password" });
            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden));

            #endregion

            #region Revoked by the registrar, not by the operator

            (status, _) = await Post(operator_, $"api/v1/pki/certificates/{client["id"]}/revoke", new { reason = "keyCompromise" });
            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden));

            (status, var revoked) = await Post(registrar, $"api/v1/pki/certificates/{client["id"]}/revoke", new { reason = "keyCompromise" });
            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), revoked.ToString());

            Assert.Multiple(() => {
                Assert.That(revoked["status"]!.Value<String>(),                         Is.EqualTo("revoked"));
                Assert.That(revoked["revocation"]!["reason"]!.Value<String>(),          Is.EqualTo("keyCompromise"));
                Assert.That(revoked["revocation"]!["revokedBy"]!.Value<String>(),       Is.EqualTo("registrar4"));
                Assert.That(revoked["mayRevoke"]!.Value<Boolean>(),                     Is.False);
            });

            #endregion

            #region The CRL and the CA, to anybody

            var crlResponse = await anybody.GetAsync($"api/v1/pki/crl/{rootId}.crl");
            var crl         = await crlResponse.Content.ReadAsByteArrayAsync();

            Assert.That(crlResponse.StatusCode,                             Is.EqualTo(HttpStatusCode.OK));
            Assert.That(crlResponse.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/pkix-crl"));
            Assert.That(CertificateRevocationListBuilder.Load(crl, out _).RemoveEntry(Convert.FromHexString(x509.SerialNumber)), Is.True);

            var caResponse  = await anybody.GetAsync($"api/v1/pki/ca/{rootId}.crt");
            using var ca    = X509CertificateLoader.LoadCertificate(await caResponse.Content.ReadAsByteArrayAsync());

            Assert.That(Issuance.PKIStore.Normalized(ca.GetCertHashString(HashAlgorithmName.SHA256)), Is.EqualTo(rootId));

            #endregion

            #region The responder, to anybody, over POST and GET

            var request   = Revocation.OCSP.Request(ca, [ x509.SerialNumber ]);
            var content   = new ByteArrayContent(request);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/ocsp-request");

            var posted    = await anybody.PostAsync("api/v1/pki/ocsp", content);

            Assert.That(posted.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/ocsp-response"));
            Assert.That(Revocation.OCSP.TryParseResponse(await posted.Content.ReadAsByteArrayAsync(), out var answer, out var error), Is.True, error);
            Assert.That(answer!.Responses.Single().Status, Is.EqualTo(Revocation.OCSPCertStatus.Revoked));
            Assert.That(answer.IsSignedBy(answer.Certificates.Single()), Is.True);

            // The slashes of Base64 as they are: the HTTP server takes no "%2F".
            var got       = await anybody.GetAsync($"api/v1/pki/ocsp/{Convert.ToBase64String(request).Replace("+", "%2B").Replace("=", "%3D")}");

            Assert.That(Revocation.OCSP.TryParseResponse(await got.Content.ReadAsByteArrayAsync(), out var answerOfGET, out error), Is.True, $"{got.StatusCode} {got.RequestMessage?.RequestUri} {await got.Content.ReadAsStringAsync()}");
            Assert.That(answerOfGET!.Responses.Single().Status, Is.EqualTo(Revocation.OCSPCertStatus.Revoked));

            #endregion

            #region What the revocation page reads, signed in

            (status, var revocation) = await Get(operator_, "api/v1/pki/revocation");

            Assert.Multiple(() => {
                Assert.That(status,                                                         Is.EqualTo(HttpStatusCode.OK));
                Assert.That(revocation["revoked"]!.Single()["commonName"]!.Value<String>(), Is.EqualTo("CS-0001"));
                Assert.That(revocation["cas"]!.Single()["crl"]!["entries"]!.Value<Int32>(), Is.EqualTo(1));
                Assert.That(revocation["cas"]!.Single()["automatic"]!.Value<Boolean>(),     Is.True);
                Assert.That(revocation["cas"]!.Single()["responder"],                       Is.Not.Null);
            });

            Assert.That((await anybody.GetAsync("api/v1/pki/revocation")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

            #endregion

        }

        #endregion

        private static Byte[] BigEndian(Int64 Value)
        {
            var bytes = new Byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(bytes, Value);
            return bytes;
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
