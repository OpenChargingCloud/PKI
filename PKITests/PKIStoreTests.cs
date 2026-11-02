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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using cloud.charging.open.PKI.Issuance;

#endregion

namespace cloud.charging.open.PKI.Tests
{

    /// <summary>
    /// The store of a PKI, without a node around it: what it makes, what a
    /// TLS stack makes of what it made, what it refuses, and what is left of
    /// it after a restart and a deletion.
    /// </summary>
    /// <remarks>
    /// Every chain made here is asked of .NET's own chain builder with the
    /// root as its only trust anchor - what a charging station or a CSMS does
    /// with it, short of a handshake - rather than only read back field by
    /// field, which would believe whatever this store wrote.
    /// </remarks>
    public class PKIStoreTests
    {

        #region Data

        private String     directory  = "";
        private PKIStore?  store;

        private PKIStore   Store => store!;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "pki-store-" + Guid.NewGuid().ToString("N")[..12]);
            store     = new PKIStore(directory);
        }

        [TearDown]
        public void TearDown()
        {
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

        private IssuedCertificate Root(String CommonName = "Test Root CA", KeyAlgorithm? Key = null, Int32? PathLength = null, Int32 Days = 3650, String? KeyPassword = null)
        {
            Assert.That(Store.TryCreateRootCA(new SubjectName(CommonName, "OpenChargingCloud", Country: "DE"), Key ?? KeyAlgorithm.ECC_P384, Days, PathLength, KeyPassword, "alice",
                                              out var root, out var error, out _), Is.True, error);
            return root!;
        }

        private IssuedCertificate Issue(IssuedCertificate Issuer, CertificateProfile Profile, String CommonName, KeyAlgorithm? Key = null, Int32 Days = 365, IReadOnlyList<String>? Names = null, Int32? PathLength = null,
                                        String? IssuerKeyPassword = null, String? KeyPassword = null)
        {
            Assert.That(Store.TryIssue(Issuer.Id, IssuerKeyPassword, Profile, new SubjectName(CommonName), Key ?? KeyAlgorithm.ECC_P256, Days, Names ?? [], PathLength, KeyPassword, "alice",
                                       out var issued, out var error, out _), Is.True, error);
            return issued!;
        }

        /// <summary>
        /// Whether .NET builds the chain of a certificate to the given root
        /// alone, with the CAs between them as extra certificates.
        /// </summary>
        private Boolean Chains(IssuedCertificate Leaf, IssuedCertificate Root, out String Problems)
        {

            using var leaf  = Store.Load(Leaf.Id)!;
            using var root  = Store.Load(Root.Id)!;
            using var chain = new X509Chain();

            chain.ChainPolicy.TrustMode          = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.RevocationMode     = X509RevocationMode.NoCheck;
            chain.ChainPolicy.CustomTrustStore.Add(root);

            foreach (var between in Store.Chain(Leaf.Id).Skip(1).Where(one => one.Id != Root.Id))
                chain.ChainPolicy.ExtraStore.Add(Store.Load(between.Id)!);

            var built = chain.Build(leaf);

            Problems = String.Join("; ", chain.ChainStatus.Select(status => status.StatusInformation.Trim()));

            return built;

        }

        private static String CSR(AsymmetricAlgorithm Key, String Subject, params String[] DNSNames)
        {

            var request = Key is ECDsa ecdsa
                              ? new CertificateRequest(Subject, ecdsa, HashAlgorithmName.SHA256)
                              : new CertificateRequest(Subject, (RSA) Key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            if (DNSNames.Length > 0)
            {
                var names = new SubjectAlternativeNameBuilder();
                foreach (var name in DNSNames)
                    names.AddDnsName(name);
                request.CertificateExtensions.Add(names.Build());
            }

            // Asking to be a CA, which the store must not take over.
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

            return request.CreateSigningRequestPem();

        }

        #endregion


        #region A root CA is a CA that signed itself

        [Test]
        public void ARootCAIsACAThatSignedItself()
        {

            var root = Root();

            using var certificate = Store.Load(root.Id)!;

            Assert.Multiple(() => {
                Assert.That(certificate.Subject,                  Is.EqualTo(certificate.Issuer));
                Assert.That(certificate.Subject,                  Is.EqualTo("CN=Test Root CA, O=OpenChargingCloud, C=DE"));
                Assert.That(root.IssuerId,                        Is.Null);
                Assert.That(root.HasPrivateKey,                   Is.True);
                Assert.That(root.KeyAlgorithm,                    Is.EqualTo("ecc-p384"));
                Assert.That(certificate.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority, Is.True);
                Assert.That(certificate.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign), Is.True);
                Assert.That(Chains(root, root, out var problems), Is.True, problems);
            });

        }

        #endregion

        #region Every key algorithm makes a root that chains

        [Test]
        public void EveryKeyAlgorithmMakesARootAndALeafThatChain()
        {

            foreach (var algorithm in KeyAlgorithm.All.Where(algorithm => algorithm.KeySize < 4096))
            {

                var root   = Root($"Root {algorithm}", algorithm);
                var leaf   = Issue(root, CertificateProfile.Client, $"Client {algorithm}", algorithm);

                Assert.That(leaf.KeyAlgorithm,                           Is.EqualTo(algorithm.Name));
                Assert.That(Chains(leaf, root, out var problems), Is.True, $"{algorithm}: {problems}");

            }

        }

        #endregion

        #region A server certificate below a sub-CA chains to the root

        [Test]
        public void AServerCertificateBelowASubCAChainsToTheRoot()
        {

            var root    = Root();
            var subCA   = Issue(root,  CertificateProfile.SubCA,  "Operator CA", KeyAlgorithm.ECC_P384, 1825, PathLength: 0);
            var server  = Issue(subCA, CertificateProfile.Server, "csms.example.org", Names: [ "csms.example.org", "192.168.1.10" ]);

            using var certificate = Store.Load(server.Id)!;

            Assert.Multiple(() => {
                Assert.That(server.IssuerId,                      Is.EqualTo(subCA.Id));
                Assert.That(Store.Chain(server.Id).Select(one => one.Id), Is.EqualTo(new[] { server.Id, subCA.Id, root.Id }));
                Assert.That(Chains(server, root, out var problems), Is.True, problems);
                Assert.That(certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages[0]!.Value, Is.EqualTo("1.3.6.1.5.5.7.3.1"));
                Assert.That(certificate.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority, Is.False);
                Assert.That(server.SubjectAlternativeNames,       Is.EquivalentTo(new[] { "csms.example.org", "192.168.1.10" }));
                Assert.That(certificate.MatchesHostname("csms.example.org"), Is.True);
            });

            // What a server presents: itself and its sub-CA, without the root.
            var chainPEM = Store.ChainPEM(server.Id)!;

            Assert.That(chainPEM.Split("BEGIN CERTIFICATE").Length - 1, Is.EqualTo(2));

        }

        [Test]
        public void AServerCertificateWithoutNamesIsGivenItsCommonName()
        {

            var root    = Root();
            var server  = Issue(root, CertificateProfile.Server, "ocpp.example.org");

            Assert.That(server.SubjectAlternativeNames, Is.EqualTo(new[] { "ocpp.example.org" }));

        }

        #endregion

        #region What a CA allows below it

        [Test]
        public void ASubCAWithPathLengthZeroSignsNoCA()
        {

            var root   = Root();
            var subCA  = Issue(root, CertificateProfile.SubCA, "Operator CA", PathLength: 0);

            var signed = Store.TryIssue(subCA.Id, null, CertificateProfile.SubCA, new SubjectName("Below"), KeyAlgorithm.ECC_P256, 30, [], null, null, null,
                                        out _, out var error, out _);

            Assert.That(signed, Is.False);
            Assert.That(error,  Does.Contain("path length is 0"));

        }

        [Test]
        public void ACertificateMayNotOutliveItsCA()
        {

            var root   = Root(Days: 100);

            var signed = Store.TryIssue(root.Id, null, CertificateProfile.Client, new SubjectName("Too long"), KeyAlgorithm.ECC_P256, 365, [], null, null, null,
                                        out _, out var error, out _);

            Assert.That(signed, Is.False);
            Assert.That(error,  Does.Contain("would outlive"));

        }

        [Test]
        public void ALeafSignsNothing()
        {

            var root    = Root();
            var client  = Issue(root, CertificateProfile.Client, "CS-0001");

            var signed  = Store.TryIssue(client.Id, null, CertificateProfile.Client, new SubjectName("Below a leaf"), KeyAlgorithm.ECC_P256, 30, [], null, null, null,
                                         out _, out var error, out _);

            Assert.That(signed, Is.False);
            Assert.That(error,  Does.Contain("signs nothing"));

        }

        #endregion

        #region A CSR is signed for its key, as what was chosen

        [Test]
        public void ACSRIsSignedForItsKeyAndNotAsWhatItAskedFor()
        {

            var root = Root();

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var csr = CSR(key, "CN=CS-4711, O=Charge Point Operator", "cs-4711.cpo.example");

            Assert.That(PKIStore.TryInspectCSR(csr, out var inspection, out var inspectError), Is.True, inspectError);
            Assert.That(inspection!.CommonName,               Is.EqualTo("CS-4711"));
            Assert.That(inspection.SignatureValid,            Is.True);
            Assert.That(inspection.KeyAlgorithm,              Is.EqualTo("ecc-p256"));
            Assert.That(inspection.SubjectAlternativeNames,   Is.EqualTo(new[] { "cs-4711.cpo.example" }));

            Assert.That(Store.TryIssueFromCSR(root.Id, null, CertificateProfile.Client, csr, 365, [], true, null, "registrar",
                                              out var issued, out var error, out _), Is.True, error);

            using var certificate = Store.Load(issued!.Id)!;
            using var publicKey   = certificate.GetECDsaPublicKey()!;

            Assert.Multiple(() => {
                Assert.That(issued.FromCSR,                       Is.True);
                Assert.That(issued.HasPrivateKey,                 Is.False);
                Assert.That(Store.PrivateKeyPEM(issued.Id),       Is.Null);
                Assert.That(issued.CommonName,                    Is.EqualTo("CS-4711"));
                Assert.That(publicKey.ExportSubjectPublicKeyInfo(), Is.EqualTo(key.ExportSubjectPublicKeyInfo()), "not the key of the CSR");
                Assert.That(certificate.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority, Is.False, "the CSR asked to be a CA, and was made one");
                Assert.That(certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages[0]!.Value, Is.EqualTo("1.3.6.1.5.5.7.3.2"));
                Assert.That(issued.SubjectAlternativeNames,       Is.EqualTo(new[] { "cs-4711.cpo.example" }));
                Assert.That(Chains(issued, root, out var problems), Is.True, problems);
            });

        }

        [Test]
        public void ACSRWhoseSignatureDoesNotHoldIsShownAndNotSigned()
        {

            var root = Root();

            using var key = RSA.Create(2048);

            var csr      = CSR(key, "CN=Tampered");
            var der      = Convert.FromBase64String(String.Concat(csr.Split('\n').Where(line => !line.StartsWith("-----"))));

            // The last byte is the end of the signature.
            der[^1] ^= 0xFF;

            var tampered = "-----BEGIN CERTIFICATE REQUEST-----\n" + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks) + "\n-----END CERTIFICATE REQUEST-----";

            Assert.That(PKIStore.TryInspectCSR(tampered, out var inspection, out var inspectError), Is.True, inspectError);
            Assert.That(inspection!.SignatureValid, Is.False);

            Assert.That(Store.TryIssueFromCSR(root.Id, null, CertificateProfile.Client, tampered, 30, [], true, null, null,
                                              out _, out var error, out _), Is.False);
            Assert.That(error, Does.Contain("signature"));

        }

        [Test]
        public void ACSRForAWeakKeyIsRefused()
        {

            var root = Root();

            using var key = RSA.Create(1024);

            Assert.That(Store.TryIssueFromCSR(root.Id, null, CertificateProfile.Client, CSR(key, "CN=Weak"), 30, [], true, null, null,
                                              out _, out var error, out _), Is.False);
            Assert.That(error, Does.Contain("RSA 1024"));

        }

        #endregion

        #region Finding them

        [Test]
        public void TheListIsFilteredByTheCommonNameWhateverItsCase()
        {

            var root = Root("OCC Root");

            Issue(root, CertificateProfile.Client, "CS-0001");
            Issue(root, CertificateProfile.Client, "CS-0002");
            Issue(root, CertificateProfile.Server, "csms.example.org");

            Assert.Multiple(() => {
                Assert.That(Store.Find().Count,                                    Is.EqualTo(4));
                Assert.That(Store.Find("cs-000").Select(one => one.CommonName),    Is.EquivalentTo(new[] { "CS-0001", "CS-0002" }));
                Assert.That(Store.Find("CSMS").Single().CommonName,               Is.EqualTo("csms.example.org"));
                Assert.That(Store.Find(null, CertificateProfile.RootCA).Single().CommonName, Is.EqualTo("OCC Root"));
                Assert.That(Store.Find("nothing like it"),                         Is.Empty);
            });

        }

        #endregion

        #region A key with a password, and one without

        private const String  CAPassword     = "correct horse battery staple";
        private const String  OtherPassword  = "another one, just as long";

        /// <summary>
        /// A key opened with its password, and checked to be the one of its
        /// certificate: the key the certificate is for, and nothing else.
        /// </summary>
        private void OpensWith(IssuedCertificate Certificate, String Password)
        {

            using var certificate  = Store.Load(Certificate.Id)!;
            using var key          = ECDsa.Create();

            key.ImportFromEncryptedPem(Store.PrivateKeyPEM(Certificate.Id)!, Password);

            using var withKey = certificate.CopyWithPrivateKey(key);

            Assert.That(withKey.HasPrivateKey, Is.True);

        }

        [Test]
        public void AKeyIsKeptUnencryptedUnlessItIsGivenAPassword()
        {

            var open    = Root("Open Root");
            var locked  = Root("Locked Root", KeyPassword: CAPassword);

            Assert.Multiple(() => {
                Assert.That(open.KeyEncrypted,                     Is.False);
                Assert.That(Store.PrivateKeyPEM(open.Id),          Does.StartWith("-----BEGIN PRIVATE KEY-----"));
                Assert.That(locked.KeyEncrypted,                   Is.True);
                Assert.That(locked.HasPrivateKey,                  Is.True);
                Assert.That(Store.PrivateKeyPEM(locked.Id),        Does.StartWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
                Assert.That(Store.PrivateKeyPEM(locked.Id),        Does.Not.Contain(CAPassword));
            });

            OpensWith(locked, CAPassword);

        }

        [Test]
        public void ACAWhoseKeyHasAPasswordSignsOnlyWithIt()
        {

            var root = Root(KeyPassword: CAPassword);

            var withNone   = Store.TryIssue(root.Id, null,          CertificateProfile.Client, new SubjectName("CS-0001"), KeyAlgorithm.ECC_P256, 30, [], null, null, null,
                                            out _, out var noneError, out _);

            var withWrong  = Store.TryIssue(root.Id, OtherPassword, CertificateProfile.Client, new SubjectName("CS-0001"), KeyAlgorithm.ECC_P256, 30, [], null, null, null,
                                            out _, out var wrongError, out _);

            Assert.Multiple(() => {
                Assert.That(withNone,     Is.False);
                Assert.That(noneError,    Does.Contain("has a password, and none was given"));
                Assert.That(withWrong,    Is.False);
                Assert.That(wrongError,   Does.Contain("is not the one of its private key"));
                Assert.That(Store.Count,  Is.EqualTo(1));
            });

            var client = Issue(root, CertificateProfile.Client, "CS-0001", IssuerKeyPassword: CAPassword);

            Assert.Multiple(() => {
                Assert.That(Chains(client, root, out var problems), Is.True, problems);
                Assert.That(client.KeyEncrypted, Is.False, "a key below a CA with a password has none of its own unless it is given one");
            });

        }

        [Test]
        public void ACSRIsSignedBelowACAWithAPasswordOnlyWithIt()
        {

            var root      = Root(KeyPassword: CAPassword);

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var csr       = CSR(key, "CN=CS-0003");

            Assert.That(Store.TryIssueFromCSR(root.Id, null,       CertificateProfile.Client, csr, 30, [], true, null, null, out _, out _, out _), Is.False);
            Assert.That(Store.TryIssueFromCSR(root.Id, CAPassword, CertificateProfile.Client, csr, 30, [], true, null, null, out var issued, out var error, out _), Is.True, error);
            Assert.That(Chains(issued!, root, out var problems), Is.True, problems);

        }

        [Test]
        public void TheKeyOfAClientMayHaveAPasswordOfItsOwn()
        {

            var root    = Root();
            var client  = Issue(root, CertificateProfile.Client, "CS-0004", KeyPassword: OtherPassword);

            Assert.Multiple(() => {
                Assert.That(client.KeyEncrypted,             Is.True);
                Assert.That(Store.PrivateKeyPEM(client.Id),  Does.StartWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
            });

            OpensWith(client, OtherPassword);

        }

        [Test]
        public void APasswordTooShortIsRefusedAndNothingIsKept()
        {

            Assert.That(Store.TryCreateRootCA(new SubjectName("Root"), KeyAlgorithm.ECC_P256, 365, null, "short", null, out _, out var error, out _), Is.False);
            Assert.That(error,        Does.Contain($"{PKIStore.MinKeyPasswordLength} characters at least"));
            Assert.That(Store.Count,  Is.EqualTo(0));

        }

        [Test]
        public void APasswordIsGivenChangedAndTakenAway()
        {

            var root = Root();

            // Given ...
            Assert.That(Store.TryChangeKeyPassword(root.Id, null, CAPassword, out var given, out var error, out _, out _), Is.True, error);
            Assert.That(given!.KeyEncrypted, Is.True);
            OpensWith(root, CAPassword);

            // ... not changed with the wrong one, and the key left as it was ...
            Assert.That(Store.TryChangeKeyPassword(root.Id, OtherPassword, null, out _, out error, out var notFound, out _), Is.False);
            Assert.That(error,     Does.Contain("is not the one of its private key"));
            Assert.That(notFound,  Is.False);
            OpensWith(root, CAPassword);

            // ... changed ...
            Assert.That(Store.TryChangeKeyPassword(root.Id, CAPassword, OtherPassword, out _, out error, out _, out _), Is.True, error);
            OpensWith(root, OtherPassword);
            Issue(root, CertificateProfile.Client, "CS-0005", IssuerKeyPassword: OtherPassword);

            // ... and taken away: the CA signs without one again.
            Assert.That(Store.TryChangeKeyPassword(root.Id, OtherPassword, null, out var open, out error, out _, out _), Is.True, error);
            Assert.That(open!.KeyEncrypted,             Is.False);
            Assert.That(Store.PrivateKeyPEM(root.Id),   Does.StartWith("-----BEGIN PRIVATE KEY-----"));
            Assert.That(Directory.GetFiles(directory, "*.tmp"), Is.Empty);
            Issue(root, CertificateProfile.Client, "CS-0006");

        }

        [Test]
        public void AKeyThatIsNotHereHasNoPasswordToChange()
        {

            var root      = Root();

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            Assert.That(Store.TryIssueFromCSR(root.Id, null, CertificateProfile.Client, CSR(key, "CN=CS-0007"), 30, [], true, null, null, out var issued, out var error, out _), Is.True, error);
            Assert.That(Store.TryChangeKeyPassword(issued!.Id, null, CAPassword, out _, out error, out var notFound, out _), Is.False);
            Assert.That(notFound,  Is.True);
            Assert.That(error,     Does.Contain("signed for a CSR"));

        }

        [Test]
        public void WhetherAKeyHasAPasswordIsReadFromItsFileAfterARestart()
        {

            var locked  = Root("Locked Root", KeyPassword: CAPassword);
            var open    = Root("Open Root");

            // The index says otherwise; the key file is what counts.
            var index = File.ReadAllText(store!.IndexFile).Replace("\"keyEncrypted\": true", "\"keyEncrypted\": false");
            File.WriteAllText(store.IndexFile, index);

            store = new PKIStore(directory);

            Assert.Multiple(() => {
                Assert.That(Store.Get(locked.Id)!.KeyEncrypted,  Is.True);
                Assert.That(Store.Get(open.Id)!.KeyEncrypted,    Is.False);
            });

            Issue(Store.Get(locked.Id)!, CertificateProfile.Server, "csms.example.org", IssuerKeyPassword: CAPassword);

        }

        #endregion

        #region What survives a restart

        [Test]
        public void EverythingIsThereAgainAfterARestart()
        {

            var root    = Root();
            var client  = Issue(root, CertificateProfile.Client, "CS-0001");

            store = new PKIStore(directory);

            Assert.Multiple(() => {
                Assert.That(Store.Count,                          Is.EqualTo(2));
                Assert.That(Store.Get(client.Id),                 Is.EqualTo(client with { SubjectAlternativeNames = Store.Get(client.Id)!.SubjectAlternativeNames }));
                Assert.That(Store.Get(root.Id)!.HasPrivateKey,    Is.True);
                Assert.That(Store.PassedOver,                     Is.Empty);
            });

            // ... and it still signs.
            Issue(root, CertificateProfile.Client, "CS-0002");

        }

        [Test]
        public void ACertificateWhoseFileWentIsPassedOverAndSaid()
        {

            var root    = Root();
            var client  = Issue(root, CertificateProfile.Client, "CS-0001");

            File.Delete(Path.Combine(directory, client.Id + ".crt"));

            store = new PKIStore(directory);

            Assert.That(Store.Get(client.Id),   Is.Null);
            Assert.That(Store.PassedOver.Single(), Does.Contain("CS-0001"));

        }

        #endregion

        #region Deleting

        [Test]
        public void ACAThatSignedIsNotDeletedAloneButWithEverythingBelowIt()
        {

            var root    = Root();
            var subCA   = Issue(root,  CertificateProfile.SubCA,  "Operator CA", Days: 730);
            var client  = Issue(subCA, CertificateProfile.Client, "CS-0001");
            var other   = Issue(root,  CertificateProfile.Client, "CS-0002");

            Assert.That(Store.TryRemove(subCA.Id, false, out _, out var refused, out var notFound, out _), Is.False);
            Assert.That(notFound, Is.False);
            Assert.That(refused,  Does.Contain("signed 1 certificate"));

            Assert.That(Store.TryRemove(subCA.Id, true, out var removed, out var error, out _, out _), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(removed!.Select(one => one.Id),                   Is.EqualTo(new[] { client.Id, subCA.Id }), "the deepest first");
                Assert.That(Store.Find().Select(one => one.Id),               Is.EquivalentTo(new[] { root.Id, other.Id }));
                Assert.That(File.Exists(Path.Combine(directory, client.Id + ".crt")), Is.False);
                Assert.That(File.Exists(Path.Combine(directory, subCA.Id  + ".key")), Is.False);
            });

            store = new PKIStore(directory);

            Assert.That(Store.Count, Is.EqualTo(2), "the deletion did not survive a restart");

        }

        [Test]
        public void ACertificateThatIsNotThereIsNotFound()
        {

            Assert.That(Store.TryRemove("00", false, out _, out _, out var notFound, out _), Is.False);
            Assert.That(notFound, Is.True);

        }

        #endregion

        #region What is refused in the subject

        [Test]
        public void ACountryIsTwoLetters()
        {

            Assert.That(SubjectName.TryParse(Newtonsoft.Json.Linq.JObject.Parse("""{ "commonName": "x", "country": "GER" }"""), out _, out var error), Is.False);
            Assert.That(error, Does.Contain("two letters"));

            Assert.That(SubjectName.TryParse(Newtonsoft.Json.Linq.JObject.Parse("""{ "commonName": "x", "country": "de" }"""), out var subject, out _), Is.True);
            Assert.That(subject!.Country, Is.EqualTo("DE"));

        }

        [Test]
        public void AnAlternativeNameIsOneOfFourThings()
        {

            Assert.Multiple(() => {
                Assert.That(AlternativeNames.IsValid("csms.example.org",     out _), Is.True);
                Assert.That(AlternativeNames.IsValid("*.example.org",        out _), Is.True);
                Assert.That(AlternativeNames.IsValid("fe80::1",              out _), Is.True);
                Assert.That(AlternativeNames.IsValid("ops@example.org",      out _), Is.True);
                Assert.That(AlternativeNames.IsValid("wss://example.org/x",  out _), Is.True);
                Assert.That(AlternativeNames.IsValid("not a name",           out _), Is.False);
            });

        }

        #endregion

    }

}
