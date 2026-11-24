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
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.PKI.CommandLine;

#endregion

namespace cloud.charging.open.PKI.Tests
{

    /// <summary>
    /// The registration authorities of a PKI, over its JSON API and at its
    /// command line: their connections, their logins and what they sign in
    /// with, at the resource "registrationAuthorities" - which an
    /// administrator may change and a registrar and an operator only read.
    /// </summary>
    public class RegistrationAuthorityAPITests
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
            directory = Path.Combine(Path.GetTempPath(), "pki-ra-" + Guid.NewGuid().ToString("N")[..12]);
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

        private PKI PKIFrom()
        {

            var port  = TestPorts.Free();
            var file  = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(file, NoTimeServers);

            pki       = new PKI(
                            HTTPPort:        port,
                            AccountsPath:    Path.Combine(directory, "accounts"),
                            ConfigFile:      new WWCPConfigFile(file),
                            LogToConsole:    false,
                            BridgeDebugLog:  false
                        );

            address   = new Uri($"http://127.0.0.1:{port}/");

            return pki;

        }

        private async Task<HttpClient> SignedInAs(User_Id Name, String Role)
        {

            var password = "correct-horse-battery-" + Guid.NewGuid().ToString("N")[..8];

            Assert.That(pki!.ExtAPI.TryGetOrganization(Organization_Id.Parse("PKI"), out var organization) &&
                        organization is Organization, Is.True, "the PKI's organization is not there");

            var account = await pki.ExtAPI.CreateUser(
                                    Name,
                                    I18NString.Create(Languages.en, Name.ToString()),
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
            Assert.That(pki.ExtAPI.TryGetUser(Name, out var stored), Is.True);
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

        /// <summary>
        /// The login of the given name, as the list of the logins has it.
        /// </summary>
        private static JObject? LoginIn(JObject Logins, String Login)

            => (Logins["logins"] as JArray)?.OfType<JObject>().FirstOrDefault(login => login.Value<String>("login") == Login);

        #endregion


        #region AnAdministratorLetsARegistrationAuthorityIn()

        /// <summary>
        /// An administrator writes down a registration authority - its
        /// connection, inbound and of the type "RegistrationAuthority", and its
        /// login with a password and a key pin -, switches it off and on, and
        /// forgets it again; the server it connects to is read beside.
        /// </summary>
        [Test]
        public async Task AnAdministratorLetsARegistrationAuthorityIn()
        {

            await TestPorts.StartedOnFreshPorts(PKIFrom);

            using var admin = await SignedInAs(User_Id.Parse("admin1"), "systemadmin");

            #region The server, with nobody in yet

            var (status, server) = await Get(admin, "api/v1/configuration/ra-server");

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), server.ToString());

            Assert.Multiple(() => {
                Assert.That(server["configuration"],                               Is.InstanceOf<JObject>());
                Assert.That(server["state"]?["running"]?.Value<Boolean>(),           Is.False, "the server is switched off where the file says nothing");
                Assert.That(server["connected"] as JArray,                         Is.Empty);
                Assert.That((server["signed"] as JObject)?.Count,                  Is.EqualTo(0));
            });

            #endregion

            #region Its connection

            (status, var added) = await Post(admin, "api/v1/configuration/connections", new JObject(
                                      new JProperty("description",     new JObject(new JProperty("en", "The CSMS, a registration authority"))),
                                      new JProperty("url",             "wss://127.0.0.1:2364/csms-01"),
                                      new JProperty("connectionType",  "RegistrationAuthority"),
                                      new JProperty("autoConnect",     true),
                                      new JProperty("inbound",         true)
                                  ));

            Assert.That(status, Is.EqualTo(HttpStatusCode.Created), added.ToString());

            var connectionId = added["id"]!.Value<String>()!;

            Assert.That(pki!.Connections.Connections.Single(entry => entry.Id == connectionId).InboundName, Is.EqualTo("csms-01"));

            #endregion

            #region Its login, with a password and a key pin

            (status, var logins) = await Post(admin, "api/v1/configuration/ra-server/logins", new {
                                       login     = "csms-01",
                                       password  = "a-long-password-" + Guid.NewGuid().ToString("N")
                                   });

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), logins.ToString());
            Assert.That(LoginIn((JObject) logins["logins"]!, "csms-01"), Is.Not.Null, logins.ToString());

            var pin = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("the public key of the CSMS")));

            (status, var pinned) = await Post(admin, "api/v1/configuration/ra-server/logins/csms-01/keyPins", new { pin, label = "the CSMS's TLS key" });

            Assert.That(status,                              Is.EqualTo(HttpStatusCode.OK), pinned.ToString());
            Assert.That(pinned["keyPin"]?.Value<String>(),   Is.EqualTo(pin).IgnoreCase);

            Assert.That(pki.WebSocketLogins.TryGet(User_Id.Parse("csms-01"), out var login), Is.True);

            Assert.Multiple(() => {
                Assert.That(login!.HasPassword,  Is.True);
                Assert.That(login.HasKeyPin,     Is.True);
                Assert.That(login.Enabled,       Is.True);
            });

            #endregion

            #region Switched off, and on again - and no mark of OCPP

            (status, var off) = await Put(admin, "api/v1/configuration/ra-server/logins/csms-01", new { enabled = false });

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), off.ToString());
            Assert.That(pki.WebSocketLogins.TryGet(User_Id.Parse("csms-01"), out login) && !login.Enabled, Is.True);

            (status, var marked) = await Put(admin, "api/v1/configuration/ra-server/logins/csms-01", new { localController = true });

            Assert.That(status,                                Is.EqualTo(HttpStatusCode.BadRequest), marked.ToString());
            Assert.That(marked["description"]?.ToString() ?? marked.ToString(), Does.Contain("'enabled'").And.Not.Contain("localController"));

            (status, var on) = await Put(admin, "api/v1/configuration/ra-server/logins/csms-01", new { enabled = true });

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), on.ToString());

            #endregion

            #region The chains a client certificate may lead to

            (status, var trust) = await Get(admin, "api/v1/configuration/ra-server/trust");

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), trust.ToString());

            #endregion

            #region Forgotten again

            (status, var forgotten) = await Delete(admin, "api/v1/configuration/ra-server/logins/csms-01");

            Assert.That(status,                                        Is.EqualTo(HttpStatusCode.OK), forgotten.ToString());
            Assert.That(pki.WebSocketLogins.TryGet(User_Id.Parse("csms-01"), out _), Is.False);

            (status, var removed) = await Post(admin, "api/v1/configuration/connections/remove", new { id = connectionId });

            Assert.That(status,                                                     Is.EqualTo(HttpStatusCode.OK), removed.ToString());
            Assert.That(pki.Connections.Connections.Any(entry => entry.Id == connectionId), Is.False);

            #endregion

        }

        #endregion

        #region ARegistrarAndAnOperatorOnlyRead(Role)

        /// <summary>
        /// Who may let a registration authority in may have CSRs signed in its
        /// name: a registrar and an operator read the registration authorities,
        /// and change nothing of them.
        /// </summary>
        [TestCase("registrar")]
        [TestCase("operator")]
        public async Task ARegistrarAndAnOperatorOnlyRead(String Role)
        {

            await TestPorts.StartedOnFreshPorts(PKIFrom);

            using var user = await SignedInAs(User_Id.Parse(Role + "1"), Role);

            var (status, server) = await Get(user, "api/v1/configuration/ra-server");
            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), server.ToString());

            (status, var logins) = await Get(user, "api/v1/configuration/ra-server/logins");
            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), logins.ToString());

            (status, var connections) = await Get(user, "api/v1/configuration/connections");
            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), connections.ToString());

            (status, var login) = await Post(user, "api/v1/configuration/ra-server/logins", new {
                                      login     = "csms-01",
                                      password  = "a-long-password-" + Guid.NewGuid().ToString("N")
                                  });

            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden), login.ToString());

            (status, var connection) = await Post(user, "api/v1/configuration/connections", new JObject(
                                           new JProperty("url",             "wss://127.0.0.1:2364/csms-01"),
                                           new JProperty("connectionType",  "RegistrationAuthority"),
                                           new JProperty("inbound",         true)
                                       ));

            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden), connection.ToString());

            Assert.Multiple(() => {
                Assert.That(pki!.WebSocketLogins.TryGet(User_Id.Parse("csms-01"), out _), Is.False);
                Assert.That(pki.Connections.Connections,                                 Is.Empty);
            });

        }

        #endregion

        #region AtTheConsoleRasListsTheRegistrationAuthorities()

        /// <summary>
        /// 'ras' says where the server is and lists every registration
        /// authority with its connection, what it signs in with and what it
        /// had signed; 'raPins' and 'raKeys' give and list its key pins and
        /// keys, and say what keeps it out.
        /// </summary>
        [Test]
        public async Task AtTheConsoleRasListsTheRegistrationAuthorities()
        {

            PKIFrom();

            using var cli = new PKICLI(pki!);

            var none = await cli.Execute("ras");

            Assert.Multiple(() => {
                Assert.That(none, Has.Some.Contains("switched off"));
                Assert.That(none, Has.Some.EqualTo("No registration authority is written down: none may connect."));
            });

            Assert.That(pki!.Connections.TryAddConnection(I18NString.Create("The CSMS"),
                                                          URL.Parse("wss://127.0.0.1:2364/csms-01"),
                                                          "RegistrationAuthority",
                                                          true,
                                                          null,
                                                          null,
                                                          out _,
                                                          out var error,
                                                          Inbound: true),
                        Is.True, error);

            var pin    = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("the public key of the CSMS")));
            var given  = await cli.Execute($"raPins csms-01 add {pin} the-CSMS");

            Assert.That(String.Join(" | ", given), Does.Contain("is a registration authority of this").And.Contain("key pin"));

            var listed = await cli.Execute("ras");

            Assert.Multiple(() => {
                Assert.That(listed, Has.Some.StartsWith("csms-01  on  not connected  0 certificate(s) signed"));
                Assert.That(listed, Has.Some.Contains("signs in with 1 key pin(s)"));
            });

            var pins   = await cli.Execute("raPins");

            Assert.Multiple(() => {
                Assert.That(pins, Has.Some.EqualTo("csms-01:"));
                Assert.That(pins, Has.Some.Contains("WebSocket server of the registration authorities is switched off"));
            });

            var keys   = await cli.Execute("raKeys");

            Assert.That(keys, Has.Some.EqualTo("No registration authority of this PKI has an SSH key."));

        }

        #endregion

    }

}
