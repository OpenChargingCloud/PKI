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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.PKI.CommandLine;
using cloud.charging.open.PKI.Issuance;

#endregion

namespace cloud.charging.open.PKI.Tests
{

    /// <summary>
    /// The command line of a PKI: that whoever signs in over SSH gets it
    /// without the program PKICLI, and what its own command 'pki' writes, at
    /// the console and for an account that may or may not look.
    /// </summary>
    /// <remarks>
    /// The commands every node has are WWCP_Node's, and tested there. What is
    /// tested here is what only a PKI can be told.
    /// </remarks>
    public class PKICLITests
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
            directory = Path.Combine(Path.GetTempPath(), "pki-cli-" + Guid.NewGuid().ToString("N")[..12]);
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

            var file = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(file, NoTimeServers);

            pki = new PKI(
                      HTTPPort:        IPPort.Parse(TestPorts.Free()),
                      AccountsPath:    Path.Combine(directory, "accounts"),
                      ConfigFile:      new WWCPConfigFile(file),
                      LogToConsole:    false,
                      BridgeDebugLog:  false
                  );

            return pki;

        }

        /// <summary>
        /// A root CA, and a server certificate below it.
        /// </summary>
        private (IssuedCertificate Root, IssuedCertificate Server) ARootAndAServer()
        {

            Assert.That(pki!.Store.TryCreateRootCA(new SubjectName("CLI Root"), KeyAlgorithm.ECC_P256, 365, null, null, null,
                                                   out var root, out var error, out _), Is.True, error);

            Assert.That(pki.Store.TryIssue(root!.Id, null, CertificateProfile.Server, new SubjectName("csms.example.org"), KeyAlgorithm.ECC_P256, 90,
                                           [ "csms.example.org" ], null, null, null, out var server, out error, out _), Is.True, error);

            return (root, server!);

        }

        /// <summary>
        /// The command line an account of the given name gets over SSH - in
        /// the group of the given role, or in none.
        /// </summary>
        private async Task<PKICLI> OverSSHAs(String   Name,
                                             String?  Role)
        {

            Assert.That(pki!.ExtAPI.TryGetOrganization(Organization_Id.Parse("PKI"), out var organization) &&
                        organization is Organization, Is.True, "the PKI's organization is not there");

            await pki.ExtAPI.CreateUser(
                      User_Id.Parse(Name),
                      I18NString.Create(Languages.en, Name),
                      SimpleEMailAddress.Parse($"{Name}@localhost"),
                      User2OrganizationEdgeLabel.IsMember,
                      (Organization) organization!,
                      Password:                  "correct-horse-battery-" + Guid.NewGuid().ToString("N")[..8],
                      SkipDefaultNotifications:  true,
                      SkipNewUserEMail:          true,
                      SkipNewUserNotifications:  true,
                      AcceptedEULA:              DateTimeOffset.UtcNow.AddSeconds(-1),
                      IsAuthenticated:           true
                  );

            Assert.That(pki.ExtAPI.TryGetUser(User_Id.Parse(Name), out var account), Is.True, $"the account '{Name}' was not made");

            if (Role is not null)
            {
                Assert.That(pki.ExtAPI.TryGetUserGroup(UserGroup_Id.Parse(Role), out var group), Is.True, $"the PKI has no group '{Role}'");
                Assert.That((await pki.ExtAPI.AddUserToUserGroup((User) account!, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!)).IsSuccess, Is.True,
                            $"'{Name}' could not be put in '{Role}'");
            }

            return (PKICLI) pki.CommandLines!(new VT100Terminal((bytes, cancellationToken) => ValueTask.CompletedTask),
                                              new CLICaller(account!, null!));

        }

        /// <summary>
        /// What the given command line writes, typed at the given command line.
        /// </summary>
        private static async Task<String[]> Run(PKICLI  CLI,
                                                String  CommandLine)
        {

            var lines = await CLI.Execute(CommandLine);

            TestContext.Out.WriteLine($"> {CommandLine}");
            TestContext.Out.WriteLine(String.Join(Environment.NewLine, lines));

            return lines;

        }

        #endregion


        #region OverSSHThePKIHasItsOwnCommands()

        /// <summary>
        /// Whoever signs in over SSH gets the command line of the PKI, with
        /// its own commands beside the node's, without the program that runs
        /// it having to say so: these tests run a PKI without the program
        /// PKICLI.
        /// </summary>
        [Test]
        public async Task OverSSHThePKIHasItsOwnCommands()
        {

            PKIFrom();

            Assert.That(pki!.CommandLines, Is.Not.Null, "a session over SSH would get the node's command line only");

            await using var terminal  = new VT100Terminal((bytes, cancellationToken) => ValueTask.CompletedTask);
            using       var cli       = pki.CommandLines!(terminal, CLICaller.Console);

            Assert.That(cli, Is.InstanceOf<PKICLI>());

            foreach (var command in new[] { "pki", "syncNTS" })
                Assert.That(String.Join(" | ", await cli.Execute(command)), Does.Not.StartWith("Unknown command"), command);

        }

        #endregion

        #region AtTheConsolePkiListsTheCertificates()

        /// <summary>
        /// 'pki' writes one line a certificate - what it is, its common name,
        /// until when it holds, its status and the beginning of its
        /// fingerprint - and how many there are; with a text, only those with
        /// it in their common name.
        /// </summary>
        [Test]
        public async Task AtTheConsolePkiListsTheCertificates()
        {

            PKIFrom();

            using var cli = new PKICLI(pki!);

            Assert.That((await Run(cli, "pki")).Single(), Does.StartWith("This PKI has no certificate yet."));

            var (root, server) = ARootAndAServer();

            var all = await Run(cli, "pki");

            Assert.That(all,       Has.Length.EqualTo(3));
            Assert.That(all[^1],   Is.EqualTo("2 of 2 certificate(s)."));
            Assert.That(all.Single(line => line.Contains(root.Id[..16])),   Does.StartWith($"{CertificateProfile.RootCA.AsText(),-7} CLI Root"));
            Assert.That(all.Single(line => line.Contains(server.Id[..16])), Does.StartWith($"{CertificateProfile.Server.AsText(),-7} csms.example.org"));
            Assert.That(all.Single(line => line.Contains(server.Id[..16])), Does.Contain($"until {server.NotAfter.ToLocalTime():yyyy-MM-dd}"));

            var found = await Run(cli, "pki csms");

            Assert.That(found,     Has.Length.EqualTo(2));
            Assert.That(found[0],  Does.Contain(server.Id[..16]));
            Assert.That(found[1],  Is.EqualTo("1 of 2 certificate(s)."));

            Assert.That((await Run(cli, "pki nowhere")).Single(), Is.EqualTo("No certificate of this PKI has 'nowhere' in its common name."));

        }

        #endregion

        #region OverSSHPkiIsForWhoeverMayLookAtTheCertificates()

        /// <summary>
        /// Over SSH, 'pki' is for whoever may look at the certificates in the
        /// web interface - an operator - and not for an account in no group of
        /// the PKI, which is told which role would be enough.
        /// </summary>
        [Test]
        public async Task OverSSHPkiIsForWhoeverMayLookAtTheCertificates()
        {

            await TestPorts.StartedOnFreshPorts(PKIFrom);

            var (_, server) = ARootAndAServer();

            using var @operator = await OverSSHAs("operator1", "operator");

            Assert.That(await Run(@operator, "pki csms"), Has.Some.Contains(server.Id[..16]));

            using var nobody = await OverSSHAs("nobody1", null);

            var refused = (await Run(nobody, "pki")).Single();

            Assert.That(refused, Does.StartWith("'nobody1' may not do that here"));
            Assert.That(refused, Does.Contain("operator"));
            Assert.That(refused, Does.Not.Contain(server.Id[..16]));

        }

        #endregion

    }

}
