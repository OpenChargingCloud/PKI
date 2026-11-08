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
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using cloud.charging.open.PKI.Issuance;
using cloud.charging.open.PKI.Revocation;

#endregion

namespace cloud.charging.open.PKI.Tests
{

    /// <summary>
    /// Revoking: the CRL of a CA, checked as whoever reads one checks it -
    /// its signature with the CA's key, its number, its entries - the OCSP
    /// responder asked as a client asks, and its answer checked with the key
    /// of a responder the CA vouches for; and a certificate with its key as
    /// one PKCS#12 file.
    /// </summary>
    public class RevocationTests
    {

        #region Data

        private const  String  Password  = "correct-horse-battery";

        private String  directory  = "";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "pki-revocation-" + Guid.NewGuid().ToString("N")[..12]);
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

        /// <summary>
        /// A clock that is moved by hand.
        /// </summary>
        private sealed class Clock(DateTimeOffset Start) : TimeProvider
        {

            public DateTimeOffset Now { get; set; } = Start;

            public override DateTimeOffset GetUtcNow() => Now;

        }

        private static IssuedCertificate RootCA(PKIStore Store, String? KeyPassword = null)
        {
            Assert.That(Store.TryCreateRootCA(new SubjectName("Revocation Root"), KeyAlgorithm.ECC_P256, 365, null, KeyPassword, null,
                                              out var root, out var error, out _), Is.True, error);
            return root!;
        }

        private static IssuedCertificate Issue(PKIStore            Store,
                                               IssuedCertificate   CA,
                                               String              CommonName,
                                               CertificateProfile  Profile            = CertificateProfile.Client,
                                               String?             IssuerKeyPassword  = null,
                                               String?             KeyPassword        = null)
        {
            Assert.That(Store.TryIssue(CA.Id, IssuerKeyPassword, Profile, new SubjectName(CommonName), KeyAlgorithm.ECC_P256,
                                       Profile == CertificateProfile.SubCA ? 90 : 30, [], null, KeyPassword, null,
                                       out var certificate, out var error, out _), Is.True, error);
            return certificate!;
        }

        /// <summary>
        /// Whether a CRL was signed with the key of the given CA - checked here,
        /// from its DER, since .NET checks no CRL.
        /// </summary>
        private static Boolean IsSignedBy(Byte[] CRL, X509Certificate2 CA)
        {

            var list       = new AsnReader(CRL, AsnEncodingRules.DER).ReadSequence();
            var tbs        = list.ReadEncodedValue().ToArray();
            var algorithm  = list.ReadSequence().ReadObjectIdentifier();
            var signature  = list.ReadBitString(out _);

            using var key  = CA.GetECDsaPublicKey()!;

            return key.VerifyData(tbs, signature, OCSP.HashOfSignature(algorithm)!.Value, DSASignatureFormat.Rfc3279DerSequence);

        }

        /// <summary>
        /// Whether a CRL names the given serial number.
        /// </summary>
        private static Boolean Names(Byte[] CRL, String SerialNumber)

            => CertificateRevocationListBuilder.Load(CRL, out _).RemoveEntry(Convert.FromHexString(SerialNumber));

        private static BigInteger NumberOf(Byte[] CRL)
        {
            CertificateRevocationListBuilder.Load(CRL, out var number);
            return number;
        }

        /// <summary>
        /// The answer of the store to an OCSP request about the given serial
        /// numbers below the given CA, read as a client reads it.
        /// </summary>
        private static OCSPResponse Ask(PKIStore Store, String CAId, String HashAlgorithm, Byte[]? Nonce, params String[] SerialNumbers)
        {

            using var ca = Store.Load(CAId)!;

            var answer = Store.AnswerOCSP(OCSP.Request(ca, SerialNumbers, HashAlgorithm, Nonce));

            Assert.That(OCSP.TryParseResponse(answer, out var response, out var error), Is.True, error);

            return response!;

        }

        /// <summary>
        /// Whether a responder's certificate is one the given CA vouches for to
        /// sign OCSP responses, as RFC 6960, section 4.2.2.2, has a client
        /// check it.
        /// </summary>
        private static Boolean VouchesFor(X509Certificate2 CA, X509Certificate2 Responder)
        {

            using var chain = new X509Chain();

            chain.ChainPolicy.TrustMode          = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.RevocationMode     = X509RevocationMode.NoCheck;
            chain.ChainPolicy.CustomTrustStore.Add(CA);
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(OCSP.OCSPSigningOID));

            return chain.Build(Responder) &&
                   Responder.Extensions.Any(extension => extension.Oid?.Value == OCSP.NoCheckOID);

        }

        #endregion


        #region The CRL and the responder

        [Test]
        public void ARevokedCertificateIsInTheCRLOfItsCAAndItsResponderSaysSo()
        {

            var store   = new PKIStore(directory);
            var root    = RootCA(store);
            var revoked = Issue(store, root, "CS-0001");
            var good    = Issue(store, root, "CS-0002");

            using var rootCertificate = store.Load(root.Id)!;

            #region Before: an empty CRL, signed at the CA's making

            var empty = store.CRL(root.Id)!;

            Assert.Multiple(() => {
                Assert.That(IsSignedBy(empty, rootCertificate),      Is.True, "signed with the root's key");
                Assert.That(NumberOf(empty),                         Is.EqualTo(BigInteger.One));
                Assert.That(store.CRLInfoOf(root.Id)!.Entries,       Is.Zero);
                Assert.That(store.CRLInfoOf(root.Id)!.NextUpdate,    Is.Not.Null);
            });

            #endregion

            Assert.That(store.TryRevoke(revoked.Id, X509RevocationReason.KeyCompromise, null, "admin",
                                        out var changed, out var error, out var warning, out _, out _), Is.True, error);

            #region After: the CRL names it, numbered anew

            var crl = store.CRL(root.Id)!;

            Assert.Multiple(() => {
                Assert.That(warning,                                 Is.Null);
                Assert.That(changed!.StatusAt(DateTimeOffset.UtcNow),Is.EqualTo("revoked"));
                Assert.That(changed.RevocationReason,                Is.EqualTo("keyCompromise"));
                Assert.That(IsSignedBy(crl, rootCertificate),        Is.True);
                Assert.That(NumberOf(crl),                           Is.EqualTo(new BigInteger(2)));
                Assert.That(Names(crl, revoked.SerialNumber),        Is.True);
                Assert.That(Names(crl, good.SerialNumber),           Is.False);
            });

            #endregion

            #region The responder: revoked, good, and a serial nobody signed unknown

            var nonce     = RandomNumberGenerator.GetBytes(16);
            var response  = Ask(store, root.Id, OCSP.SHA1OID, nonce, revoked.SerialNumber, good.SerialNumber, "0123456789ABCDEF");
            var responder = response.Certificates.Single();

            Assert.Multiple(() => {
                Assert.That(response.Status,                         Is.EqualTo(OCSPResponseStatus.Successful));
                Assert.That(response.IsSignedBy(responder),          Is.True,  "signed with the responder's key");
                Assert.That(response.IsSignedBy(rootCertificate),    Is.False, "and not with the root's");
                Assert.That(VouchesFor(rootCertificate, responder),  Is.True,  "a responder the root vouches for");
                Assert.That(response.ResponderKeyHash,               Is.EqualTo(SHA1.HashData(responder.PublicKey.EncodedKeyValue.RawData)));
                Assert.That(response.Nonce,                          Is.EqualTo(nonce));
                Assert.That(response.Responses.Select(one => one.CertID.SerialNumber),
                                                                     Is.EqualTo(new[] { revoked.SerialNumber, good.SerialNumber, "0123456789ABCDEF" }));
                Assert.That(response.Responses[0].Status,            Is.EqualTo(OCSPCertStatus.Revoked));
                Assert.That(response.Responses[0].Reason,            Is.EqualTo(X509RevocationReason.KeyCompromise));
                Assert.That(response.Responses[1].Status,            Is.EqualTo(OCSPCertStatus.Good));
                Assert.That(response.Responses[2].Status,            Is.EqualTo(OCSPCertStatus.Unknown));
                Assert.That(response.Responses[1].NextUpdate,        Is.GreaterThan(response.Responses[1].ThisUpdate));
                Assert.That(store.Transparency.Find(PKIStore.Normalized(responder.GetCertHashString(HashAlgorithmName.SHA256))),
                                                                     Is.Not.Null, "the responder is in the transparency log");
            });

            #endregion

            #region Asked with SHA-256 for the CA's name and key

            var sha256 = Ask(store, root.Id, OCSP.SHA256OID, null, good.SerialNumber);

            Assert.That(sha256.Responses.Single().Status, Is.EqualTo(OCSPCertStatus.Good));
            Assert.That(sha256.Responses.Single().CertID.HashAlgorithm, Is.EqualTo(OCSP.SHA256OID));

            #endregion

        }

        [Test]
        public void TheResponderAnswersNothingItIsNotAskedAbout()
        {

            var store = new PKIStore(directory);
            RootCA(store);

            using var stranger = new CertificateRequest("CN=Stranger", ECDsa.Create(ECCurve.NamedCurves.nistP256), HashAlgorithmName.SHA256).
                                     CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

            Assert.That(OCSP.TryParseResponse(store.AnswerOCSP(OCSP.Request(stranger, [ "01" ])), out var unknownCA, out _), Is.True);
            Assert.That(OCSP.TryParseResponse(store.AnswerOCSP(new Byte[] { 0x30, 0x03, 0x02, 0x01, 0x00 }), out var malformed, out _), Is.True);

            Assert.Multiple(() => {
                Assert.That(unknownCA!.Status,  Is.EqualTo(OCSPResponseStatus.Unauthorized), "a CA this PKI does not have");
                Assert.That(malformed!.Status,  Is.EqualTo(OCSPResponseStatus.MalformedRequest));
                Assert.That(unknownCA.Responses, Is.Empty);
            });

        }

        [Test]
        public void ARevocationOutlivesTheCertificateAndTheStart()
        {

            var store   = new PKIStore(directory);
            var root    = RootCA(store);
            var sub     = Issue(store, root, "Revocation Sub", CertificateProfile.SubCA);
            var client  = Issue(store, sub,  "CS-0001");
            var deleted = Issue(store, sub,  "CS-0002");

            Assert.That(store.TryRevoke(client.Id, X509RevocationReason.Superseded, null, null, out _, out var error, out _, out _, out _), Is.True, error);
            Assert.That(store.TryRemove(client.Id,  false, out _, out error, out _, out _), Is.True, error);
            Assert.That(store.TryRemove(deleted.Id, false, out _, out error, out _, out _), Is.True, error);

            var again = new PKIStore(directory);

            Assert.Multiple(() => {
                Assert.That(again.RevocationOf(client.Id),           Is.Not.Null, "revoked still, deleted or not");
                Assert.That(again.Get(sub.Id)!.RevokedAt,            Is.Null);
                Assert.That(Names(again.CRL(sub.Id)!, client.SerialNumber), Is.True);
            });

            Assert.That(again.TrySignCRL(sub.Id, null, 10, out var crl, out error, out _, out _), Is.True, error);

            var response = Ask(again, sub.Id, OCSP.SHA1OID, null, client.SerialNumber, deleted.SerialNumber);

            Assert.Multiple(() => {
                Assert.That(crl!.Entries,                            Is.EqualTo(1), "signed anew after the start, and naming it still");
                Assert.That(crl.NextUpdate!.Value - crl.ThisUpdate,  Is.EqualTo(TimeSpan.FromDays(10)));
                Assert.That(response.Responses[0].Status,            Is.EqualTo(OCSPCertStatus.Revoked));
                Assert.That(response.Responses[0].Reason,            Is.EqualTo(X509RevocationReason.Superseded));
                Assert.That(response.Responses[1].Status,            Is.EqualTo(OCSPCertStatus.Good), "deleted is not revoked: the log says it was signed");
            });

            #region What is not revoked: a root, and twice

            Assert.Multiple(() => {
                Assert.That(again.TryRevoke(root.Id,   X509RevocationReason.Unspecified, null, null, out _, out var rootError, out _, out _, out _), Is.False);
                Assert.That(again.TryRevoke(sub.Id,    X509RevocationReason.CACompromise, null, null, out _, out var subError,  out _, out _, out _), Is.True, subError);
                Assert.That(again.TryRevoke(sub.Id,    X509RevocationReason.CACompromise, null, null, out _, out var twice,     out _, out _, out _), Is.False);
                Assert.That(twice,                                   Does.Contain("already"));
            });

            #endregion

            #region A sub-CA deleted takes its CRL and responder along, and stays in its root's CRL

            Assert.That(again.TryRemove(sub.Id, false, out _, out error, out _, out _), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(again.CRL(sub.Id),                       Is.Null);
                Assert.That(again.ResponderOf(sub.Id),               Is.Null);
                Assert.That(Names(again.CRL(root.Id)!, sub.SerialNumber), Is.True);
            });

            #endregion

        }

        #endregion

        #region A CA whose key has a password

        [Test]
        public void ACAWhoseKeyHasAPasswordRevokesNothingWithoutIt()
        {

            var store   = new PKIStore(directory);
            var root    = RootCA(store, Password);
            var client  = Issue(store, root, "CS-0001", IssuerKeyPassword: Password);

            Assert.Multiple(() => {
                Assert.That(store.CRL(root.Id),                      Is.Not.Null, "signed when it was made, its key open then");
                Assert.That(store.ResponderOf(root.Id),              Is.Not.Null, "and its responder");
                Assert.That(store.TryRevoke(client.Id, X509RevocationReason.KeyCompromise, null,      null, out _, out var none,  out _, out _, out _), Is.False);
                Assert.That(none,                                    Does.Contain("password"));
                Assert.That(store.TryRevoke(client.Id, X509RevocationReason.KeyCompromise, "wrong-one", null, out _, out _,       out _, out _, out _), Is.False);
                Assert.That(store.RevocationOf(client.Id),           Is.Null, "nothing revoked");
            });

            Assert.That(store.TryRevoke(client.Id, X509RevocationReason.KeyCompromise, Password, null, out _, out var error, out _, out _, out _), Is.True, error);

            var response = Ask(store, root.Id, OCSP.SHA1OID, null, client.SerialNumber);

            Assert.Multiple(() => {
                Assert.That(Names(store.CRL(root.Id)!, client.SerialNumber), Is.True);
                Assert.That(response.Responses.Single().Status,      Is.EqualTo(OCSPCertStatus.Revoked), "its responder answers without the password");
            });

        }

        [Test]
        public void TheCRLIsSignedAnewBeforeHalfOfItIsOver()
        {

            var clock   = new Clock(DateTimeOffset.UtcNow);
            var store   = new PKIStore(directory, clock);
            var root    = RootCA(store);
            var locked  = RootCA(store, Password);

            Assert.That(store.RefreshRevocation(), Is.Empty);
            Assert.That(NumberOf(store.CRL(root.Id)!), Is.EqualTo(BigInteger.One));

            clock.Now += TimeSpan.FromDays(3);
            Assert.That(store.RefreshRevocation(), Is.Empty);
            Assert.That(NumberOf(store.CRL(root.Id)!), Is.EqualTo(BigInteger.One), "half of a week is not over");

            clock.Now += TimeSpan.FromDays(1);
            Assert.That(store.RefreshRevocation(), Is.Empty);
            Assert.That(NumberOf(store.CRL(root.Id)!), Is.EqualTo(new BigInteger(2)));

            // The CA with a password: its CRL of thirty days runs out, and the
            // PKI says so rather than sign it.
            clock.Now += TimeSpan.FromDays(24);

            var problems = store.RefreshRevocation();

            Assert.Multiple(() => {
                Assert.That(NumberOf(store.CRL(locked.Id)!),         Is.EqualTo(BigInteger.One));
                Assert.That(problems.Single(),                       Does.Contain("runs out").And.Contain("password"));
            });

            Assert.That(store.TrySignCRL(locked.Id, Password, null, out var crl, out var error, out _, out _), Is.True, error);
            Assert.That(crl!.Number, Is.EqualTo(new BigInteger(2)));
            Assert.That(store.RefreshRevocation(), Is.Empty);

        }

        #endregion

        #region Where a certificate says its CRL and responder are

        [Test]
        public void ACertificateNamesItsCRLAndTheResponder()
        {

            var store = new PKIStore(directory);
            var root  = RootCA(store);

            var before = Issue(store, root, "CS-0001");

            Assert.That(RevocationAddresses.TryParse("http://pki.example.org/", "/api", out var addresses, out var error), Is.True, error);
            Assert.That(RevocationAddresses.TryParse("ftp://pki.example.org/",  "/api", out _, out _),                     Is.False);

            store.Addresses = addresses;

            var after = Issue(store, root, "CS-0002");

            using var unnamed  = store.Load(before.Id)!;
            using var named    = store.Load(after.Id)!;

            var access = named.Extensions.OfType<X509AuthorityInformationAccessExtension>().Single();

            Assert.Multiple(() => {
                Assert.That(unnamed.Extensions.Any(extension => extension.Oid?.Value == "2.5.29.31"), Is.False);
                Assert.That(access.EnumerateOcspUris(),              Is.EqualTo(new[] { "http://pki.example.org/api/v1/pki/ocsp" }));
                Assert.That(access.EnumerateCAIssuersUris(),         Is.EqualTo(new[] { $"http://pki.example.org/api/v1/pki/ca/{root.Id}.crt" }));
                Assert.That(System.Text.Encoding.ASCII.GetString(named.Extensions["2.5.29.31"]!.RawData),
                                                                     Does.Contain($"http://pki.example.org/api/v1/pki/crl/{root.Id}.crl"));
            });

        }

        #endregion

        #region PKCS#12

        [Test]
        public void ACertificateGoesOutWithItsKeyAndItsSubCAsAsPKCS12()
        {

            var store   = new PKIStore(directory);
            var root    = RootCA(store);
            var sub     = Issue(store, root, "PKCS12 Sub", CertificateProfile.SubCA);
            var client  = Issue(store, sub,  "CS-0001", KeyPassword: Password);

            Assert.Multiple(() => {
                Assert.That(store.TryExportPKCS12(client.Id, null,     "file-password", false, out _, out var noKey,  out _), Is.False);
                Assert.That(noKey,                                   Does.Contain("password"));
                Assert.That(store.TryExportPKCS12(client.Id, Password, "short",         false, out _, out _,          out _), Is.False);
                Assert.That(store.TryExportPKCS12(sub.Id,    null,     "file-password", false, out _, out var ofACA,  out _), Is.False);
                Assert.That(ofACA,                                   Does.Contain("does not leave"));
            });

            foreach (var legacy in new[] { false, true })
            {

                Assert.That(store.TryExportPKCS12(client.Id, Password, "file-password", legacy, out var pkcs12, out var error, out _), Is.True, error);

                var loaded = X509CertificateLoader.LoadPkcs12Collection(pkcs12!, "file-password", X509KeyStorageFlags.EphemeralKeySet);
                var leaf   = loaded.Single(certificate => certificate.HasPrivateKey);

                Assert.Multiple(() => {
                    Assert.That(loaded.Count,                        Is.EqualTo(2), "the certificate and its sub-CA, without the root");
                    Assert.That(PKIStore.Normalized(leaf.GetCertHashString(HashAlgorithmName.SHA256)), Is.EqualTo(client.Id));
                    Assert.That(loaded.Any(certificate => PKIStore.Normalized(certificate.GetCertHashString(HashAlgorithmName.SHA256)) == sub.Id), Is.True);
                    Assert.That(() => X509CertificateLoader.LoadPkcs12Collection(pkcs12!, "wrong-password"), Throws.InstanceOf<CryptographicException>());
                });

                using var key = leaf.GetECDsaPrivateKey()!;
                Byte[] data      = [ 1, 2, 3 ];
                var signature   = key.SignData(data, HashAlgorithmName.SHA256);

                using var publicKey = leaf.GetECDsaPublicKey()!;
                Assert.That(publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256), Is.True, "the key of the certificate");

            }

        }

        #endregion

    }

}
