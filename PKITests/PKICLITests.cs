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

        #region TheNewCommandsAreKnownAndExplained()

        /// <summary>
        /// Every command of the PKI's own is found - a new command is a new
        /// file and nothing else - and 'help' names it.
        /// </summary>
        [Test]
        public async Task TheNewCommandsAreKnownAndExplained()
        {

            PKIFrom();

            using var cli = new PKICLI(pki!);

            var help = String.Join(Environment.NewLine, await Run(cli, "help"));

            foreach (var command in new[] { "pki", "pkiShow", "pkiRevoke", "pkiRevoked", "pkiCRL", "pkiSignCRL", "pkiEST" })
            {
                Assert.That(String.Join(" | ", await cli.Execute(command)), Does.Not.StartWith("Unknown command"), command);
                Assert.That(help, Does.Contain(command + " "), $"'help' does not name {command}");
            }

        }

        #endregion

        #region PkiShowSaysWhatACertificateIs()

        /// <summary>
        /// 'pkiShow' finds a certificate by the beginning of its fingerprint
        /// or by its common name, and says who it is about, who signed it, its
        /// key, its names and its chain - and of a CA how many it signed and
        /// its CRL. Where nothing or more than one answers, it shows none.
        /// </summary>
        [Test]
        public async Task PkiShowSaysWhatACertificateIs()
        {

            PKIFrom();

            using var cli = new PKICLI(pki!);

            var (root, server) = ARootAndAServer();

            var shown = await Run(cli, $"pkiShow {server.Id[..12]}");

            Assert.That(shown[0],  Is.EqualTo($"{server.InWords} 'csms.example.org'"));
            Assert.That(shown,     Has.Some.EqualTo($"  fingerprint  {server.Id}"));
            Assert.That(shown,     Has.Some.EqualTo($"  issuer       {server.Issuer} ({root.Id[..16]})"));
            Assert.That(shown,     Has.Some.EqualTo("  names        csms.example.org"));
            Assert.That(shown,     Has.Some.EqualTo("  chain        csms.example.org < CLI Root"));
            Assert.That(shown,     Has.Some.StartsWith($"  key          {server.KeyAlgorithm}, kept here without a password"));
            Assert.That(shown,     Has.None.StartsWith("  revoked"));
            Assert.That(String.Join("\n", shown), Does.Not.Contain("BEGIN"), "neither a PEM nor a key is written on a screen");

            var ca = await Run(cli, "pkiShow cli root");

            Assert.That(ca[0],     Is.EqualTo($"{root.InWords} 'CLI Root'"));
            Assert.That(ca,        Has.Some.EqualTo("  issuer       itself"));
            Assert.That(ca,        Has.Some.EqualTo("  signed       1 certificate(s) of this PKI"));
            Assert.That(ca,        Has.Some.StartsWith("  CRL          "));

            Assert.That((await Run(cli, "pkiShow")).Single(),              Does.StartWith("Usage: pkiShow <fingerprint | common name>"));
            Assert.That((await Run(cli, "pkiShow nobody.example")).Single(), Does.StartWith("No certificate of this PKI has a fingerprint beginning with 'nobody.example'"));

            // A second certificate of the same name: neither is shown.
            Assert.That(pki!.Store.TryIssue(root.Id, null, CertificateProfile.Server, new SubjectName("csms.example.org"), KeyAlgorithm.ECC_P256, 30,
                                            [], null, null, null, out var second, out var error, out _), Is.True, error);

            var both = (await Run(cli, "pkiShow csms.example.org")).Single();

            Assert.That(both, Does.StartWith("2 certificates of this PKI answer to 'csms.example.org'"));
            Assert.That(both, Does.Contain(server.Id[..16]).And.Contain(second!.Id[..16]));

        }

        #endregion

        #region PkiRevokeRevokesForGoodAndPkiRevokedListsIt()

        /// <summary>
        /// 'pkiRevoke' revokes a certificate for the reason typed, which is
        /// not left out; it is in the CRL of its CA at once, 'pkiRevoked'
        /// lists it, and 'pkiShow' and 'pki' say so. A root is not revoked,
        /// and nothing twice.
        /// </summary>
        [Test]
        public async Task PkiRevokeRevokesForGoodAndPkiRevokedListsIt()
        {

            PKIFrom();

            using var cli = new PKICLI(pki!);

            var (root, server) = ARootAndAServer();

            Assert.That((await Run(cli, "pkiRevoked")).Single(), Is.EqualTo("This PKI revoked no certificate."));

            Assert.That((await Run(cli, $"pkiRevoke {server.Id[..12]}")).Single(),             Does.StartWith("Usage: pkiRevoke"), "no reason");
            Assert.That((await Run(cli, $"pkiRevoke {server.Id[..12]} becauseISaySo")).Single(), Does.StartWith("Usage: pkiRevoke"), "no reason of RFC 5280");
            Assert.That(pki!.Store.Revoked(), Is.Empty);

            var before  = pki.Store.CRLInfoOf(root.Id);
            var revoked = await Run(cli, $"pkiRevoke {server.Id[..12]} keyCompromise");

            Assert.That(revoked.Single(), Is.EqualTo($"The {server.InWords} 'csms.example.org' ({server.Id[..16]}) is revoked for keyCompromise, for good."));

            Assert.That(pki.Store.RevocationOf(server.Id)?.Reason, Is.EqualTo(System.Security.Cryptography.X509Certificates.X509RevocationReason.KeyCompromise));
            Assert.That(pki.Store.CRLInfoOf(root.Id)!.Entries,     Is.EqualTo(1), "the CRL of its CA names it at once");
            Assert.That(pki.Store.CRLInfoOf(root.Id)!.Number,      Is.GreaterThan(before?.Number ?? 0));

            var list = await Run(cli, "pkiRevoked");

            Assert.That(list,      Has.Length.EqualTo(2));
            Assert.That(list[0],   Does.Contain("csms.example.org").And.Contain("keyCompromise").And.Contain("below 'CLI Root'").And.Contain(server.Id[..16]));
            Assert.That(list[1],   Is.EqualTo("1 certificate(s) revoked."));

            Assert.That(await Run(cli, $"pkiShow {server.Id[..12]}"), Has.Some.Matches<String>(line => line.StartsWith("  revoked      ") && line.EndsWith(" for keyCompromise")));
            Assert.That(await Run(cli, "pki csms"),                   Has.Some.Contains("revoked"));

            Assert.That((await Run(cli, $"pkiRevoke {server.Id[..12]} superseded")).Single(), Does.Contain("was revoked already"));
            Assert.That((await Run(cli, "pkiRevoke CLI Root caCompromise")).Single(),        Does.StartWith("The root CA 'CLI Root' is not revoked"));

        }

        #endregion

        #region PkiCRLListsTheCRLsAndPkiSignCRLSignsOneAnew()

        /// <summary>
        /// 'pkiCRL' says of every CA the number of its CRL and until when it
        /// is believed; 'pkiSignCRL' signs one anew, for the days typed - and
        /// not the CRL of something that is no CA.
        /// </summary>
        [Test]
        public async Task PkiCRLListsTheCRLsAndPkiSignCRLSignsOneAnew()
        {

            PKIFrom();

            using var cli = new PKICLI(pki!);

            Assert.That((await Run(cli, "pkiCRL")).Single(), Is.EqualTo("This PKI has no CA yet, and so no CRL."));

            var (root, server) = ARootAndAServer();

            var before = await Run(cli, "pkiCRL");

            Assert.That(before,     Has.Length.EqualTo(2), "one CA, and where the responder is - or that there is none");
            Assert.That(before[0],  Does.StartWith($"CLI Root  {root.Id[..16]}  "));
            Assert.That(before[1],  Does.StartWith("No certificate names a CRL or an OCSP responder"));

            var number = pki!.Store.CRLInfoOf(root.Id)?.Number ?? 0;
            var signed = (await Run(cli, $"pkiSignCRL {root.Id[..12]} 3")).Single();
            var crl    = pki.Store.CRLInfoOf(root.Id)!;

            Assert.That(signed,      Does.StartWith($"The CRL of the {root.InWords} 'CLI Root' is signed anew: number {crl.Number}, 0 revoked, until "));
            Assert.That(crl.Number,  Is.GreaterThan(number));
            Assert.That(crl.NextUpdate!.Value - crl.ThisUpdate, Is.EqualTo(TimeSpan.FromDays(3)).Within(TimeSpan.FromMinutes(10)));

            Assert.That((await Run(cli, "pkiCRL"))[0], Does.Contain($"number {crl.Number}, 0 revoked, until "));

            Assert.That((await Run(cli, "pkiSignCRL")).Single(),                       Does.StartWith("Usage: pkiSignCRL"));
            Assert.That((await Run(cli, "pkiSignCRL CLI Root 9999")).Single(),         Does.StartWith("A CRL is believed for 1 to "));
            Assert.That((await Run(cli, $"pkiSignCRL {server.Id[..12]}")).Single(),    Does.Contain("which signs no CRL"));
            Assert.That(pki.Store.CRLInfoOf(root.Id)!.Number, Is.EqualTo(crl.Number), "nothing else was signed");

        }

        #endregion

        #region NoPasswordIsTypedAtACommandLine()

        /// <summary>
        /// Below a CA whose key has a password nothing is revoked at the
        /// command line, and its CRL is not signed there: no command takes a
        /// password, which a command line would keep. Both say where it is
        /// done.
        /// </summary>
        [Test]
        public async Task NoPasswordIsTypedAtACommandLine()
        {

            PKIFrom();

            using var cli = new PKICLI(pki!);

            const String password = "correct-horse-battery-staple";

            Assert.That(pki!.Store.TryCreateRootCA(new SubjectName("Locked Root"), KeyAlgorithm.ECC_P256, 365, null, password, null,
                                                   out var root, out var error, out _), Is.True, error);

            Assert.That(pki.Store.TryIssue(root!.Id, password, CertificateProfile.Client, new SubjectName("cs001"), KeyAlgorithm.ECC_P256, 90,
                                           [], null, null, null, out var client, out error, out _), Is.True, error);

            var number      = pki.Store.CRLInfoOf(root.Id)?.Number;

            var notRevoked  = (await Run(cli, "pkiRevoke cs001 superseded")).Single();
            var notSigned   = (await Run(cli, "pkiSignCRL Locked Root")).Single();

            Assert.That(notRevoked, Does.StartWith("Nothing was revoked: the CRL of the root CA 'Locked Root' is signed with its key, which has a password"));
            Assert.That(notSigned,  Does.StartWith("The CRL of the root CA 'Locked Root' was not signed, which has a password"));
            Assert.That(notRevoked, Does.EndWith("The web interface asks for the password."));
            Assert.That(notSigned,  Does.EndWith("The web interface asks for the password."));

            Assert.That(pki.Store.RevocationOf(client!.Id),      Is.Null);
            Assert.That(pki.Store.CRLInfoOf(root.Id)?.Number,    Is.EqualTo(number));

            Assert.That(await Run(cli, "pkiCRL"),                Has.Some.Contains("(its key has a password)"));
            Assert.That(await Run(cli, "pkiShow Locked Root"),   Has.Some.EndsWith("kept here with a password"));

        }

        #endregion

        #region PkiESTSaysWhatESTSigns()

        /// <summary>
        /// 'pkiEST' says that EST signs nothing where no CA is named for it,
        /// and otherwise what a CSR becomes without a label and at each label,
        /// below which CA and for how long.
        /// </summary>
        [Test]
        public async Task PkiESTSaysWhatESTSigns()
        {

            PKIFrom();

            using var cli = new PKICLI(pki!);

            Assert.That((await Run(cli, "pkiEST")).Single(), Does.Match("^EST at http.* signs nothing: no CA is named for it\\.$"));

            var (root, _) = ARootAndAServer();

            Assert.That(pki!.TrySetEST(new Enrollment.ESTSettings(new Enrollment.ESTProfile(root.Id, CertificateProfile.Client, 30),
                                                                  new Dictionary<String, Enrollment.ESTProfile> {
                                                                      ["servers"] = new Enrollment.ESTProfile(root.Id, CertificateProfile.Server, 60)
                                                                  },
                                                                  false),
                                       out var error), Is.True, error);

            var lines = await Run(cli, "pkiEST");

            Assert.That(lines[0],  Does.Match("^EST at http.*/\\.well-known/est\\[/<label>\\]/ signs:$"));
            Assert.That(lines[1],  Is.EqualTo($"  without a label  a {CertificateProfile.Client.InWords()} of 30 days below 'CLI Root' ({root.Id[..16]})"));
            Assert.That(lines[2],  Is.EqualTo($"  'servers'        a {CertificateProfile.Server.InWords()} of 60 days below 'CLI Root' ({root.Id[..16]})"));
            Assert.That(lines[3],  Is.EqualTo("No TLS client certificate is asked for."));
            Assert.That(lines[4],  Is.EqualTo("serverkeygen makes no keys."));

        }

        #endregion

        #region OverSSHWhoMayLookMayNotRevokeAndWhoSignsCertificatesRevokesNoCA()

        /// <summary>
        /// Over SSH the commands ask what the web interface asks: an operator
        /// looks and revokes nothing; a registrar revokes a server's
        /// certificate, but no CA, and signs no CRL by hand; and an account in
        /// no group of the PKI sees none of it.
        /// </summary>
        [Test]
        public async Task OverSSHWhoMayLookMayNotRevokeAndWhoSignsCertificatesRevokesNoCA()
        {

            await TestPorts.StartedOnFreshPorts(PKIFrom);

            var (root, server) = ARootAndAServer();

            Assert.That(pki!.Store.TryIssue(root.Id, null, CertificateProfile.SubCA, new SubjectName("CLI Sub"), KeyAlgorithm.ECC_P256, 200,
                                            [], null, null, null, out var sub, out var error, out _), Is.True, error);

            using var @operator = await OverSSHAs("operator2",  "operator");
            using var registrar = await OverSSHAs("registrar2", "registrar");
            using var nobody    = await OverSSHAs("nobody2",    null);

            foreach (var looking in new[] { $"pkiShow {server.Id[..12]}", "pkiRevoked", "pkiCRL", "pkiEST" })
            {
                Assert.That((await Run(@operator, looking))[0],    Does.Not.Contain("may not do that here"),            looking);
                Assert.That((await Run(nobody,    looking)).Single(), Does.StartWith("'nobody2' may not do that here"), looking);
            }

            Assert.That((await Run(@operator, $"pkiRevoke {server.Id[..12]} superseded")).Single(), Does.StartWith("'operator2' may not do that here"));
            Assert.That((await Run(@operator, "pkiSignCRL CLI Root")).Single(),                    Does.StartWith("'operator2' may not do that here"));
            Assert.That(pki.Store.Revoked(), Is.Empty);

            Assert.That((await Run(registrar, "pkiRevoke CLI Sub cessationOfOperation")).Single(), Does.StartWith("'registrar2' may not do that here"));
            Assert.That((await Run(registrar, "pkiSignCRL CLI Root")).Single(),                    Does.StartWith("'registrar2' may not do that here"));
            Assert.That(pki.Store.RevocationOf(sub!.Id), Is.Null);

            Assert.That((await Run(registrar, $"pkiRevoke {server.Id[..12]} superseded")).Single(), Does.EndWith("is revoked for superseded, for good."));
            Assert.That(pki.Store.RevocationOf(server.Id)?.RevokedBy, Is.EqualTo("registrar2"));

        }

        #endregion

    }

}
